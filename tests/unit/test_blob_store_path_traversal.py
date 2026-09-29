"""Filesystem quarantine/artifact blob store: path traversal / symlink escape (SystemDesign §33)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from redteam_agent.errors import RawResultQuarantineError
from redteam_agent.quarantine.blob_store import FilesystemQuarantineBlobStore


def test_rejects_parent_traversal() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = FilesystemQuarantineBlobStore(str(Path(tmp) / "root"))
        with pytest.raises(RawResultQuarantineError):
            store.put("../escape", b"x")
        with pytest.raises(RawResultQuarantineError):
            store.get("../../etc/passwd")


def test_rejects_absolute_handle() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = FilesystemQuarantineBlobStore(str(Path(tmp) / "root"))
        with pytest.raises(RawResultQuarantineError):
            store.put("/etc/shadow", b"x")


def test_normal_put_get_delete_round_trip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = FilesystemQuarantineBlobStore(str(Path(tmp) / "root"))
        store.put("q-1/5/1/stdout/000000000000", b"ciphertext")
        assert store.exists("q-1/5/1/stdout/000000000000")
        assert store.get("q-1/5/1/stdout/000000000000") == b"ciphertext"
        assert store.list_prefix("q-1/5/1") == ("q-1/5/1/stdout/000000000000",)
        removed = store.delete_prefix("q-1/5/1")
        assert removed >= 1 and not store.exists("q-1/5/1/stdout/000000000000")


def test_symlink_escape_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        store = FilesystemQuarantineBlobStore(str(root))
        outside = Path(tmp) / "outside"
        outside.mkdir()
        # A symlink inside the root pointing outside must not let a handle escape.
        link = root / "link"
        os.symlink(outside, link)
        with pytest.raises(RawResultQuarantineError):
            store.put("link/secret", b"x")
