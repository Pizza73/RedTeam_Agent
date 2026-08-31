"""SQLite persistence primitives for the mission audit chain."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import AbstractContextManager
from typing import cast

from redteam_agent.storage import Database


class AuditLogRepository:
    """Owns all SQL used by the durable append-only audit implementation."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def transaction(self) -> AbstractContextManager[sqlite3.Connection]:
        return self.database.transaction(immediate=True)

    def events_for(self, mission_id: str) -> tuple[sqlite3.Row, ...]:
        rows: Iterator[sqlite3.Row] = self.database.connection.execute(
            "SELECT event_id, mission_id, sequence_number, event_hash, payload_json "
            "FROM audit_logs WHERE mission_id = ? ORDER BY sequence_number",
            (mission_id,),
        )
        return tuple(rows)

    def event_by_id(self, event_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self.database.connection.execute(
                "SELECT event_id, mission_id, sequence_number, event_hash, payload_json "
                "FROM audit_logs WHERE event_id = ?",
                (event_id,),
            ).fetchone(),
        )

    def head(self, mission_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self.database.connection.execute(
                "SELECT sequence_number, event_hash FROM audit_log_heads "
                "WHERE mission_id = ?",
                (mission_id,),
            ).fetchone(),
        )

    def has_event(self, mission_id: str) -> bool:
        return (
            self.database.connection.execute(
                "SELECT 1 FROM audit_logs WHERE mission_id = ? LIMIT 1",
                (mission_id,),
            ).fetchone()
            is not None
        )

    def insert_event(
        self,
        *,
        event_id: str,
        mission_id: str,
        sequence_number: int,
        event_hash: str,
        payload_json: str,
    ) -> None:
        self.database.connection.execute(
            "INSERT INTO audit_logs"
            "(event_id, mission_id, sequence_number, event_hash, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_id, mission_id, sequence_number, event_hash, payload_json),
        )

    def insert_head(
        self, *, mission_id: str, sequence_number: int, event_hash: str
    ) -> None:
        self.database.connection.execute(
            "INSERT INTO audit_log_heads"
            "(mission_id, sequence_number, event_hash) VALUES (?, ?, ?)",
            (mission_id, sequence_number, event_hash),
        )

    def update_head(
        self,
        *,
        mission_id: str,
        previous_sequence_number: int,
        previous_event_hash: str,
        sequence_number: int,
        event_hash: str,
    ) -> bool:
        cursor = self.database.connection.execute(
            "UPDATE audit_log_heads SET sequence_number = ?, event_hash = ? "
            "WHERE mission_id = ? AND sequence_number = ? AND event_hash = ?",
            (
                sequence_number,
                event_hash,
                mission_id,
                previous_sequence_number,
                previous_event_hash,
            ),
        )
        return cursor.rowcount == 1
