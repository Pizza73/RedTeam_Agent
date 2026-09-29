from pathlib import Path

import pytest

from redteam_agent.composition.activation_lock import HostActivationLock
from redteam_agent.composition.startup_self_check import check_schema_read_only
from redteam_agent.database_cli import initialize_database, remove_unknown_database
from redteam_agent.errors import ActivationLockError, SchemaMigrationRequiredError
from redteam_agent.storage.database import Database


def test_initialize_does_not_overwrite_and_current_schema_cannot_be_removed(tmp_path: Path) -> None:
    path, lock = tmp_path / "app.db", tmp_path / "activation.lock"
    initialize_database(path, lock_path=lock)
    with pytest.raises(ValueError, match="existing database"):
        initialize_database(path, lock_path=lock)
    with pytest.raises(ValueError, match="current-schema"):
        remove_unknown_database(path, lock_path=lock, confirm=lambda _: True)


def test_decline_preserves_unknown_database_and_related_files(tmp_path: Path) -> None:
    path, lock = tmp_path / "app.db", tmp_path / "activation.lock"
    path.write_bytes(b"legacy database")
    sidecar = Path(str(path) + "-wal")
    sidecar.write_bytes(b"legacy wal")
    assert not remove_unknown_database(path, lock_path=lock, confirm=lambda _: False)
    assert path.read_bytes() == b"legacy database"
    assert sidecar.read_bytes() == b"legacy wal"


def test_confirm_removes_only_displayed_files(tmp_path: Path) -> None:
    path, lock = tmp_path / "app.db", tmp_path / "activation.lock"
    path.write_bytes(b"unknown")
    secret = tmp_path / "key"
    secret.write_bytes(b"unrelated")
    displayed: list[Path] = []

    def confirm(files):
        displayed.extend(item.path for item in files)
        return True

    assert remove_unknown_database(path, lock_path=lock, confirm=confirm)
    assert displayed == [path]
    assert not path.exists() and secret.read_bytes() == b"unrelated"
    initialize_database(path, lock_path=lock)


def test_changed_file_or_new_sidecar_invalidates_confirmation(tmp_path: Path) -> None:
    path, lock = tmp_path / "app.db", tmp_path / "activation.lock"
    path.write_bytes(b"unknown")

    def confirm(_files):
        Path(str(path) + "-wal").write_bytes(b"new data")
        return True

    with pytest.raises(ValueError, match="changed after confirmation"):
        remove_unknown_database(path, lock_path=lock, confirm=confirm)
    assert path.exists()


def test_running_root_or_symlink_rejects_before_confirmation(tmp_path: Path) -> None:
    path, lock = tmp_path / "app.db", tmp_path / "activation.lock"
    path.write_bytes(b"unknown")
    with HostActivationLock(str(lock)), pytest.raises(ActivationLockError):
        remove_unknown_database(path, lock_path=lock, confirm=lambda _: pytest.fail("must not ask"))
    link = tmp_path / "link.db"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        remove_unknown_database(link, lock_path=lock, confirm=lambda _: pytest.fail("must not ask"))


def test_normal_database_open_never_creates_a_missing_file(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "absent.db"
    with pytest.raises(sqlite3.OperationalError):
        Database(str(path), create_schema=False)
    assert not path.exists()


def test_wrong_schema_revision_is_unknown_and_requires_confirmed_removal(
    tmp_path: Path,
) -> None:
    path, lock = tmp_path / "app.db", tmp_path / "activation.lock"
    database = Database(str(path))
    database.connection.execute(
        "UPDATE application_schema_metadata SET schema_revision = ? WHERE singleton_id = 1",
        ("legacy-revision",),
    )
    with pytest.raises(SchemaMigrationRequiredError, match="schema revision"):
        check_schema_read_only(database)
    database.close()
    assert not remove_unknown_database(path, lock_path=lock, confirm=lambda _: False)
    assert path.exists()
    assert remove_unknown_database(path, lock_path=lock, confirm=lambda _: True)
    assert not path.exists()
