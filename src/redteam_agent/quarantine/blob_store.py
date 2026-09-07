"""Encrypted-quarantine ciphertext blob store (SystemDesign §33.1).

The blob store holds only ciphertext (each chunk is an :class:`EnvelopeCiphertext`
with its own nonce/tag); no plaintext and no key material. It is physically separate
from the normal application database. Chunks are staged under a fence-specific path
``work_id/deployment_epoch/fencing_token/stream/sequence``; only the current metadata
references a fence's prefix, so a stale writer's bytes stay unreachable garbage.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from redteam_agent.errors import RawResultQuarantineError


def staging_prefix(work_id: str, deployment_epoch: int, fencing_token: int) -> str:
    return f"{work_id}/{deployment_epoch}/{fencing_token}"


def chunk_handle(prefix: str, stream: str, sequence: int) -> str:
    return f"{prefix}/{stream}/{sequence:012d}"


class QuarantineBlobStore(Protocol):
    is_production: bool

    def put(self, handle: str, data: bytes) -> None: ...
    def get(self, handle: str) -> bytes: ...
    def delete_prefix(self, prefix: str) -> int: ...
    def list_prefix(self, prefix: str) -> tuple[str, ...]: ...
    def exists(self, handle: str) -> bool: ...


class InMemoryQuarantineBlobStore:
    """In-memory ciphertext blob store (test double; usable for local composition)."""

    is_production = False

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    def put(self, handle: str, data: bytes) -> None:
        self._data[handle] = bytes(data)

    def get(self, handle: str) -> bytes:
        try:
            return self._data[handle]
        except KeyError:
            raise RawResultQuarantineError(f"quarantine blob not found: {handle}") from None

    def delete_prefix(self, prefix: str) -> int:
        keys = [k for k in self._data if k == prefix or k.startswith(prefix + "/")]
        for key in keys:
            del self._data[key]
        return len(keys)

    def list_prefix(self, prefix: str) -> tuple[str, ...]:
        return tuple(sorted(k for k in self._data if k == prefix or k.startswith(prefix + "/")))

    def exists(self, handle: str) -> bool:
        return handle in self._data


class FilesystemQuarantineBlobStore:
    """Filesystem ciphertext blob store rooted at a dedicated encrypted-quarantine dir.

    Path traversal / symlink escape are rejected: handles are relative, ``..`` segments
    are refused and the resolved path must stay under the root.
    """

    # This local implementation does not fsync the file and parent directory; it
    # remains a development store until a durable production adapter is supplied.
    is_production = False

    def __init__(self, root: str) -> None:
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, handle: str) -> Path:
        if handle.startswith("/") or ".." in Path(handle).parts:
            raise RawResultQuarantineError("illegal quarantine blob handle")
        resolved = (self._root / handle).resolve()
        if self._root not in resolved.parents and resolved != self._root:
            raise RawResultQuarantineError("quarantine blob handle escapes the store root")
        return resolved

    def put(self, handle: str, data: bytes) -> None:
        path = self._path(handle)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    def get(self, handle: str) -> bytes:
        path = self._path(handle)
        if not path.is_file():
            raise RawResultQuarantineError(f"quarantine blob not found: {handle}")
        return path.read_bytes()

    def delete_prefix(self, prefix: str) -> int:
        base = self._path(prefix)
        count = 0
        if base.is_dir():
            for child in sorted(base.rglob("*"), reverse=True):
                if child.is_file():
                    child.unlink()
                    count += 1
                elif child.is_dir():
                    child.rmdir()
            base.rmdir()
        elif base.is_file():
            base.unlink()
            count = 1
        return count

    def list_prefix(self, prefix: str) -> tuple[str, ...]:
        base = self._path(prefix)
        if not base.is_dir():
            return ()
        out = [str(p.relative_to(self._root)) for p in base.rglob("*") if p.is_file()]
        return tuple(sorted(out))

    def exists(self, handle: str) -> bool:
        return self._path(handle).is_file()
