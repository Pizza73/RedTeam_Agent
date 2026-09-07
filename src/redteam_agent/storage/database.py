"""SQLite database, schema and unit of work (SystemDesign §32).

Phase 0A stores each security artifact as a validated JSON row keyed within a
namespace. Writes are idempotent for an identical payload under the same key but
reject a conflicting payload for that key (deterministic id + no silent
overwrite). A relational expansion is a later-phase concern; the repository
abstraction keeps that migration possible.
"""

from __future__ import annotations

import hashlib
import sqlite3

from redteam_agent.errors import RepositoryIntegrityError

_ROW_DIGEST_DOMAIN = b"kv-row-integrity-v1"


def _row_digest(namespace: str, key: str, json_text: str) -> str:
    body = b"\x00".join(part.encode("utf-8") for part in (namespace, key, json_text))
    return hashlib.sha256(_ROW_DIGEST_DOMAIN + b"\x00" + body).hexdigest()


def row_digest(namespace: str, key: str, json_text: str) -> str:
    """Public row-integrity digest binding (namespace/table, key, json).

    Phase 0B dedicated tables reuse this so a raw single-row edit that changes
    the JSON without recomputing the digest is caught on read (same guarantee as
    ``kv_store``).
    """
    return _row_digest(namespace, key, json_text)


class Database:
    def __init__(self, path: str = ":memory:") -> None:
        # ``isolation_level=None`` gives explicit transaction control; the unit
        # of work issues BEGIN/COMMIT. Foreign keys are enabled per §32.
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        # ``row_digest`` binds (namespace, key, json) so a raw single-row edit
        # that changes the JSON without recomputing the digest is caught on read
        # (R10). This is simple-edit integrity, not TPM rollback resistance.
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_store (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            )
            """
        )
        self._create_execution_schema()

    def _create_execution_schema(self) -> None:
        # Phase 0B durable execution-safety tables. Uniqueness and OCC are
        # enforced by the database itself: one policy decision yields at most one
        # execution (UNIQUE policy_decision_id); at most one unconsumed dispatch
        # claim exists per execution (partial UNIQUE index); state transitions
        # use ``execution_state_version``/``state_version`` OCC updates. Each row
        # also stores a row_digest binding its identity to its JSON payload.
        statements = (
            """
            CREATE TABLE IF NOT EXISTS executions (
                execution_id TEXT PRIMARY KEY,
                policy_decision_id TEXT NOT NULL UNIQUE,
                mission_id TEXT NOT NULL,
                execution_state_version INTEGER NOT NULL,
                provider_execution_state TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dispatch_claims (
                claim_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                claim_state TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            # At most one unconsumed dispatch claim may exist for an execution.
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_dispatch_claims_unconsumed
                ON dispatch_claims (execution_id)
                WHERE claim_state = 'unconsumed'
            """,
            """
            CREATE TABLE IF NOT EXISTS result_collection_authorities (
                collection_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL UNIQUE,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS result_collection_states (
                collection_state_id TEXT PRIMARY KEY,
                collection_id TEXT NOT NULL UNIQUE,
                execution_id TEXT NOT NULL,
                state_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (collection_id) REFERENCES result_collection_authorities(collection_id),
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS result_task_bindings (
                result_task_binding_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL UNIQUE,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS raw_control_metadata (
                control_record_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL UNIQUE,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS result_ingestion_states (
                ingestion_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL UNIQUE,
                state_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS execution_result_projections (
                projection_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL UNIQUE,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS execution_results (
                execution_id TEXT PRIMARY KEY,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS execution_recovery_authorities (
                authority_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                allowed_operation TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS cancel_attempts (
                cancel_attempt_id TEXT PRIMARY KEY,
                execution_id TEXT NOT NULL,
                provider_task_id TEXT NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                UNIQUE (execution_id, provider_task_id),
                FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS mission_execution_budgets (
                mission_id TEXT NOT NULL,
                mission_revision INTEGER NOT NULL,
                budget_version INTEGER NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                PRIMARY KEY (mission_id, mission_revision)
            )
            """,
        )
        for statement in statements:
            self._conn.execute(statement)

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
            "INSERT INTO kv_store (namespace, key, json, row_digest) VALUES (?, ?, ?, ?)",
            (namespace, key, json_text, _row_digest(namespace, key, json_text)),
        )

    def overwrite(self, namespace: str, key: str, json_text: str) -> None:
        """Unconditionally upsert (used for OCC-guarded records like mission state)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO kv_store (namespace, key, json, row_digest) VALUES (?, ?, ?, ?)",
            (namespace, key, json_text, _row_digest(namespace, key, json_text)),
        )

    def _verify_row(self, namespace: str, key: str, json_text: str, stored_digest: str) -> str:
        if _row_digest(namespace, key, json_text) != stored_digest:
            raise RepositoryIntegrityError(f"row integrity check failed for {namespace}/{key}")
        return json_text

    def get(self, namespace: str, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM kv_store WHERE namespace = ? AND key = ?", (namespace, key)
        ).fetchone()
        if row is None:
            return None
        return self._verify_row(namespace, key, str(row[0]), str(row[1]))

    def get_all(self, namespace: str) -> list[tuple[str, str]]:
        """Return ``(row_key, json)`` pairs after verifying each row's integrity."""
        rows = self._conn.execute(
            "SELECT key, json, row_digest FROM kv_store WHERE namespace = ? ORDER BY key", (namespace,)
        ).fetchall()
        return [(str(k), self._verify_row(namespace, str(k), str(j), str(rd))) for k, j, rd in rows]


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
