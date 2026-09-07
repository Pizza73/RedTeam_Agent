"""SQLite database, schema and unit of work (SystemDesign §32).

Phase 0A stores each security artifact as a validated JSON row keyed within a
namespace. Writes are idempotent for an identical payload under the same key but
reject a conflicting payload for that key (deterministic id + no silent
overwrite). A relational expansion is a later-phase concern; the repository
abstraction keeps that migration possible.
"""

from __future__ import annotations

import sqlite3

from redteam_agent.errors import RepositoryIntegrityError


class Database:
    def __init__(self, path: str = ":memory:") -> None:
        # ``isolation_level=None`` gives explicit transaction control; the unit
        # of work issues BEGIN/COMMIT. Foreign keys are enabled per §32.
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_store (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            )
            """
        )

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    @property
    def in_transaction(self) -> bool:
        return self._conn.in_transaction

    def close(self) -> None:
        self._conn.close()

    # --- low-level kv operations -----------------------------------------

    def put_idempotent(self, namespace: str, key: str, json_text: str) -> None:
        """Insert, allowing an identical re-write but rejecting a conflicting one."""
        row = self._conn.execute(
            "SELECT json FROM kv_store WHERE namespace = ? AND key = ?", (namespace, key)
        ).fetchone()
        if row is not None:
            if row[0] != json_text:
                raise RepositoryIntegrityError(
                    f"conflicting payload for existing key {namespace}/{key}"
                )
            return
        self._conn.execute(
            "INSERT INTO kv_store (namespace, key, json) VALUES (?, ?, ?)",
            (namespace, key, json_text),
        )

    def overwrite(self, namespace: str, key: str, json_text: str) -> None:
        """Unconditionally upsert (used for OCC-guarded records like mission state)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO kv_store (namespace, key, json) VALUES (?, ?, ?)",
            (namespace, key, json_text),
        )

    def get(self, namespace: str, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT json FROM kv_store WHERE namespace = ? AND key = ?", (namespace, key)
        ).fetchone()
        return None if row is None else str(row[0])

    def get_all(self, namespace: str) -> list[tuple[str, str]]:
        """Return ``(row_key, json)`` pairs so callers can verify the real key."""
        rows = self._conn.execute(
            "SELECT key, json FROM kv_store WHERE namespace = ? ORDER BY key", (namespace,)
        ).fetchall()
        return [(str(row[0]), str(row[1])) for row in rows]


class UnitOfWork:
    """A single-transaction boundary. Repositories participate; only this commits."""

    def __init__(self, database: Database) -> None:
        self._conn = database.connection

    def __enter__(self) -> UnitOfWork:
        self._conn.execute("BEGIN")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is not None:
            self._conn.rollback()
        else:
            self._conn.commit()
