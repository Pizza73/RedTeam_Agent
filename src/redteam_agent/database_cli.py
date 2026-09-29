"""Explicit local database provisioning and confirmed removal of unknown schemas.

This administrative command never starts a Mission, imports legacy authority,
deletes keys/TPM state, or runs as a normal-startup fallback. The operator must
stop workers and use the same activation-lock path as the application root.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from redteam_agent.composition.activation_lock import HostActivationLock
from redteam_agent.composition.startup_self_check import check_schema_read_only
from redteam_agent.errors import AuthorizationKernelError, SchemaMigrationRequiredError
from redteam_agent.storage.database import Database


@dataclass(frozen=True)
class DatabaseFile:
    path: Path
    device: int
    inode: int
    size: int
    modified_ns: int
    digest: str


def _snapshot(path: Path) -> DatabaseFile:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("database removal accepts regular, non-hardlinked files only")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("database changed during inspection")
    return DatabaseFile(path, before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, digest)


def _files(path: Path) -> tuple[DatabaseFile, ...]:
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("use a canonical absolute database path without symlinks")
    candidates = tuple(Path(str(path) + suffix) for suffix in ("", "-wal", "-shm", "-journal"))
    return tuple(_snapshot(item) for item in candidates if item.exists() or item.is_symlink())


def _validate_paths(path: Path, lock_path: Path) -> None:
    for item in (path, lock_path):
        if not item.is_absolute() or item.resolve() != item:
            raise ValueError("use canonical absolute paths without symlinks")
    if lock_path in (Path(str(path) + suffix) for suffix in ("", "-wal", "-shm", "-journal")):
        raise ValueError("activation lock must be separate from all database files")


def _is_current(path: Path, preview: tuple[DatabaseFile, ...]) -> bool:
    # SQLite can recover a journal or create shared memory even during schema
    # inspection. Inspect a private disposable copy, never the original files.
    with tempfile.TemporaryDirectory(prefix="redteam-db-inspect-") as directory:
        for item in preview:
            with os.fdopen(os.open(item.path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
                destination = Path(directory) / item.path.name
                with destination.open("xb") as target:
                    shutil.copyfileobj(source, target)
                if _snapshot(destination).digest != item.digest:
                    raise ValueError("database changed during inspection")
        return _inspect_schema(Path(directory) / path.name)


def _inspect_schema(path: Path) -> bool:
    database: Database | None = None
    try:
        database = Database(str(path), create_schema=False)
        check_schema_read_only(database)
        return True
    except (sqlite3.DatabaseError, SchemaMigrationRequiredError):
        return False
    finally:
        if database is not None:
            database.close()


def initialize_database(path: Path, *, lock_path: Path) -> None:
    """Create the current schema only in an empty, explicitly selected namespace."""
    _validate_paths(path, lock_path)
    with HostActivationLock(str(lock_path)):
        if _files(path):
            raise ValueError("existing database or sidecars require separate inspection and confirmation")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        # On failure keep the partial database for inspection; never silently retry
        # creation or continue into application startup.
        database = Database(str(path))
        try:
            check_schema_read_only(database)
        finally:
            database.close()


def remove_unknown_database(
    path: Path, *, lock_path: Path,
    confirm: Callable[[tuple[DatabaseFile, ...]], bool],
) -> bool:
    """Remove only the displayed files after explicit confirmation and revalidation."""
    _validate_paths(path, lock_path)
    with HostActivationLock(str(lock_path)):
        if not path.exists() or path.is_symlink():
            raise ValueError("an existing regular database is required")
        preview = _files(path)
        if _is_current(path, preview):
            raise ValueError("this command does not remove a current-schema database")
        if _files(path) != preview:
            raise ValueError("database changed during inspection")
        if not confirm(preview):
            return False
        if _files(path) != preview:
            raise ValueError("database changed after confirmation; inspect and confirm again")
        # A partial removal is reported as an error and does not trigger provisioning.
        for item in reversed(preview):
            if _snapshot(item.path) != item:
                raise ValueError("database file changed before deletion")
            item.path.unlink()
        return True


def _confirm(files: tuple[DatabaseFile, ...]) -> bool:
    if not sys.stdin.isatty():
        return False
    print("全Workerを停止してください。以下のDBと関連ファイルを削除すると内容は失われます。")
    for item in files:
        print(f"  {item.path} ({item.size} bytes, SHA-256 {item.digest})")
    print("鍵・TPM・DB外のログは削除しません。新規構築は別の initialize 操作です。")
    expected = f"DELETE {files[0].path}"
    try:
        return input(f"削除する場合だけ {expected} と入力してください: ") == expected
    except (EOFError, KeyboardInterrupt):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Stopped-worker database administration")
    parser.add_argument("operation", choices=("initialize", "remove-unknown"))
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--activation-lock", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not args.activation_lock.is_absolute():
            raise ValueError("activation lock path must be absolute")
        if args.operation == "initialize":
            initialize_database(args.database, lock_path=args.activation_lock)
            print("DB Schemaを初期構築しました。Mission実行やTPM初期化は行っていません。")
        elif not remove_unknown_database(
            args.database, lock_path=args.activation_lock, confirm=_confirm,
        ):
            print("削除を中止しました。")
            return 1
    except (OSError, ValueError, sqlite3.DatabaseError, AuthorizationKernelError) as exc:
        print(f"DB管理操作を停止しました: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
