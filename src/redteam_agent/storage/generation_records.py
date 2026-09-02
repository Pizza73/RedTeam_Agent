"""SQLite records for authenticated generation anchors and immutable blobs."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import final


class GenerationStorageError(RuntimeError):
    """Raised when the durable generation record store is unavailable."""


@final
class SqliteAuthenticatedGenerationRecords:
    """Storage-layer transaction boundary for generation records."""

    def __init__(self, path: Path) -> None:
        try:
            self._connection = sqlite3.connect(
                path,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.execute("PRAGMA journal_mode = DELETE")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS authenticated_generation_blobs (
                    blob_id TEXT PRIMARY KEY,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    authentication_tag BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS authenticated_generation_anchors (
                    namespace TEXT PRIMARY KEY,
                    anchor_json BLOB NOT NULL,
                    authentication_tag BLOB NOT NULL
                );
                """
            )
        except sqlite3.Error as exc:
            raise GenerationStorageError("generation record store is unavailable") from exc

    def begin(self) -> None:
        self._execute("BEGIN IMMEDIATE")

    def commit(self) -> None:
        self._execute("COMMIT")

    def rollback(self) -> None:
        self._execute("ROLLBACK")

    def get_blob(self, blob_id: str) -> tuple[bytes, bytes, bytes] | None:
        row = self._execute(
            "SELECT nonce, ciphertext, authentication_tag "
            "FROM authenticated_generation_blobs WHERE blob_id = ?",
            (blob_id,),
        ).fetchone()
        if row is None:
            return None
        return bytes(row[0]), bytes(row[1]), bytes(row[2])

    def insert_blob(
        self,
        *,
        blob_id: str,
        nonce: bytes,
        ciphertext: bytes,
        authentication_tag: bytes,
    ) -> None:
        self._execute(
            "INSERT INTO authenticated_generation_blobs "
            "(blob_id, nonce, ciphertext, authentication_tag) VALUES (?, ?, ?, ?)",
            (blob_id, nonce, ciphertext, authentication_tag),
        )

    def get_anchor(self, namespace: str) -> tuple[bytes, bytes] | None:
        row = self._execute(
            "SELECT anchor_json, authentication_tag "
            "FROM authenticated_generation_anchors WHERE namespace = ?",
            (namespace,),
        ).fetchone()
        if row is None:
            return None
        return bytes(row[0]), bytes(row[1])

    def insert_anchor(
        self,
        *,
        namespace: str,
        anchor_json: bytes,
        authentication_tag: bytes,
    ) -> None:
        self._execute(
            "INSERT INTO authenticated_generation_anchors "
            "(namespace, anchor_json, authentication_tag) VALUES (?, ?, ?)",
            (namespace, anchor_json, authentication_tag),
        )

    def update_anchor(
        self,
        *,
        namespace: str,
        anchor_json: bytes,
        authentication_tag: bytes,
        expected_anchor_json: bytes,
    ) -> bool:
        cursor = self._execute(
            "UPDATE authenticated_generation_anchors "
            "SET anchor_json = ?, authentication_tag = ? "
            "WHERE namespace = ? AND anchor_json = ?",
            (anchor_json, authentication_tag, namespace, expected_anchor_json),
        )
        return cursor.rowcount == 1

    def _execute(
        self,
        statement: str,
        parameters: tuple[object, ...] = (),
    ) -> sqlite3.Cursor:
        try:
            return self._connection.execute(statement, parameters)
        except sqlite3.Error as exc:
            raise GenerationStorageError("generation record operation failed") from exc
