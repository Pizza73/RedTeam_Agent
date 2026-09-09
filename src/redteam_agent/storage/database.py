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
from collections.abc import Callable
from dataclasses import dataclass

from redteam_agent.errors import (
    ExecutionStateConflictError,
    RepositoryIntegrityError,
)

_ROW_DIGEST_DOMAIN = b"kv-row-integrity-v1"


@dataclass(frozen=True)
class CriticalMutation:
    """Exact security projection emitted by its owning service in the current txn."""

    mission_id: str
    event_type: str
    actor_id: str
    occurred_at_iso: str
    record_type: str
    record_id: str
    state_version: int
    security_projection_digest: str


CriticalMutationRecorder = Callable[[CriticalMutation], None]


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
    def __init__(self, path: str = ":memory:", *, create_schema: bool = True) -> None:
        # ``isolation_level=None`` gives explicit transaction control; the unit
        # of work issues BEGIN/COMMIT. Foreign keys are enabled per §32.
        self._path = path
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._after_commit: list[Callable[[], None]] = []
        self._critical_mutation_recorder: CriticalMutationRecorder | None = None
        self._transaction_counter = 0
        self._transaction_identity: str | None = None
        self._conn.execute("PRAGMA foreign_keys = ON")
        # Generation records and their content-addressed blobs must survive a
        # successful commit before an NV Extend is attempted (§34.2.1).
        self._conn.execute("PRAGMA synchronous = FULL")
        if create_schema:
            self._create_schema()

    def has_table(self, name: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
        return row is not None

    def graph_checkpoint_schema_is_current(self) -> bool:
        expected = {
            "PRAGMA table_info(checkpoints)": (
                "thread_id", "checkpoint_ns", "checkpoint_id", "parent_checkpoint_id",
                "type", "checkpoint", "metadata",
            ),
            "PRAGMA table_info(writes)": (
                "thread_id", "checkpoint_ns", "checkpoint_id", "task_id", "idx",
                "channel", "type", "value",
            ),
        }
        for statement, columns in expected.items():
            actual = tuple(row[1] for row in self._conn.execute(statement).fetchall())
            if actual != columns:
                return False
        return True

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
        # An ApprovalRequest has exactly one immutable human decision.  Keeping
        # the public row key as approval_id preserves record identity, while the
        # partial expression index makes request-level single assignment a
        # database invariant (and therefore race safe), not a scan-then-insert
        # convention in ApprovalService.
        self._conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_approval_record_request
            ON kv_store(json_extract(json, '$.approval_request_id'))
            WHERE namespace = 'approvals'
            """
        )
        self._create_execution_schema()
        self._create_phase0c_schema()
        self._create_graph_checkpoint_schema()

    def _create_graph_checkpoint_schema(self) -> None:
        # Pinned langgraph-checkpoint-sqlite 3.1.1 schema. Provisioning owns
        # creation so a normal Phase 1 start never performs an implicit migration.
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoints (
                thread_id TEXT NOT NULL,
                checkpoint_ns TEXT NOT NULL DEFAULT '',
                checkpoint_id TEXT NOT NULL,
                parent_checkpoint_id TEXT,
                type TEXT,
                checkpoint BLOB,
                metadata BLOB,
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS writes (
                thread_id TEXT NOT NULL,
                checkpoint_ns TEXT NOT NULL DEFAULT '',
                checkpoint_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                idx INTEGER NOT NULL,
                channel TEXT NOT NULL,
                type TEXT,
                value BLOB,
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, idx)
            )
            """
        )

    def _create_phase0c_schema(self) -> None:
        # Phase 0C generic OCC row store (SystemDesign §32). Every Phase 0C durable
        # record lives here under a fixed namespace with a composite ``key`` that
        # encodes any DB-enforced uniqueness invariant (e.g. one audit sequence per
        # mission, one generation per (namespace, trust_epoch, generation), one
        # deletion_intent_id). ``version`` drives optimistic concurrency; the
        # row_digest binds (namespace, key, json) so a raw single-row edit that does
        # not recompute the digest is caught on read. Namespace + key uniqueness is
        # enforced by the primary key, not by the repository. This keeps the schema
        # literal (no identifier interpolation) while avoiding per-table SQL sprawl.
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS occ_store (
                namespace TEXT NOT NULL,
                key TEXT NOT NULL,
                version INTEGER NOT NULL,
                json TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                PRIMARY KEY (namespace, key)
            )
            """
        )

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
    def path(self) -> str:
        return self._path

    @property
    def in_transaction(self) -> bool:
        return self._conn.in_transaction

    @property
    def transaction_identity(self) -> str:
        if self._transaction_identity is None or not self._conn.in_transaction:
            raise RepositoryIntegrityError("no identified transaction is active")
        return self._transaction_identity

    def begin(self, label: str) -> None:
        self._conn.execute("BEGIN")
        self._transaction_counter += 1
        self._transaction_identity = f"{self._transaction_counter}:{label}"

    def end_transaction(self) -> None:
        self._transaction_identity = None

    def close(self) -> None:
        self._conn.close()

    def register_after_commit(self, callback: Callable[[], None]) -> None:
        """Register trusted post-commit work for the current transaction.

        Critical witness intents use this to keep TPM I/O outside SQLite while
        withholding the caller's success response until the witness read-back passes.
        """
        if not self._conn.in_transaction:
            raise RepositoryIntegrityError("after-commit callback requires an active transaction")
        self._after_commit.append(callback)

    def discard_after_commit(self) -> None:
        self._after_commit.clear()

    def run_after_commit(self) -> None:
        callbacks, self._after_commit = self._after_commit, []
        for callback in callbacks:
            callback()

    def set_critical_mutation_recorder(self, recorder: CriticalMutationRecorder) -> None:
        """Install the Phase 0C audit/witness bridge once at composition time."""
        if self._critical_mutation_recorder is not None:
            raise RepositoryIntegrityError("critical mutation recorder is already configured")
        self._critical_mutation_recorder = recorder

    @property
    def critical_mutation_recording_enabled(self) -> bool:
        return self._critical_mutation_recorder is not None

    def record_critical_mutation(self, mutation: CriticalMutation) -> None:
        """Forward an owner-produced projection without adding another domain state."""
        if not self._conn.in_transaction:
            raise RepositoryIntegrityError("critical mutation requires an active transaction")
        if mutation.state_version < 1:
            raise RepositoryIntegrityError("critical mutation state version must be positive")
        if self._critical_mutation_recorder is not None:
            self._critical_mutation_recorder(mutation)

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

    # --- generic OCC row store (Phase 0C) --------------------------------

    def _occ_key(self, namespace: str, key: str) -> str:
        return f"{namespace}\x00{key}"

    def occ_insert(self, namespace: str, key: str, version: int, json_text: str) -> None:
        """Insert a new OCC row; raise if the (namespace, key) already exists."""
        if not self._conn.in_transaction:
            raise RepositoryIntegrityError("occ write requires an active unit of work")
        digest = _row_digest(self._occ_key(namespace, key), str(version), json_text)
        try:
            self._conn.execute(
                "INSERT INTO occ_store (namespace, key, version, json, row_digest) VALUES (?, ?, ?, ?, ?)",
                (namespace, key, version, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise RepositoryIntegrityError(f"occ row already exists for {namespace}/{key}") from None

    def occ_insert_idempotent(self, namespace: str, key: str, version: int, json_text: str) -> None:
        """Insert allowing an identical re-write (create-or-verify) but rejecting a
        conflicting payload for the same (namespace, key)."""
        existing = self._occ_row(namespace, key)
        if existing is not None:
            stored_version, stored_json = existing
            if stored_version != version or stored_json != json_text:
                raise RepositoryIntegrityError(f"conflicting occ payload for {namespace}/{key}")
            return
        self.occ_insert(namespace, key, version, json_text)

    def occ_update(
        self, namespace: str, key: str, *, expected_version: int, new_version: int, json_text: str
    ) -> None:
        """OCC update: succeed only if the stored version equals ``expected_version``."""
        if not self._conn.in_transaction:
            raise RepositoryIntegrityError("occ write requires an active unit of work")
        digest = _row_digest(self._occ_key(namespace, key), str(new_version), json_text)
        cursor = self._conn.execute(
            "UPDATE occ_store SET version = ?, json = ?, row_digest = ? "
            "WHERE namespace = ? AND key = ? AND version = ?",
            (new_version, json_text, digest, namespace, key, expected_version),
        )
        if cursor.rowcount != 1:
            raise ExecutionStateConflictError(f"occ conflict (stale version) for {namespace}/{key}")

    def _occ_row(self, namespace: str, key: str) -> tuple[int, str] | None:
        row = self._conn.execute(
            "SELECT version, json, row_digest FROM occ_store WHERE namespace = ? AND key = ?",
            (namespace, key),
        ).fetchone()
        if row is None:
            return None
        version, json_text, stored_digest = int(row[0]), str(row[1]), str(row[2])
        if _row_digest(self._occ_key(namespace, key), str(version), json_text) != stored_digest:
            raise RepositoryIntegrityError(f"occ row integrity check failed for {namespace}/{key}")
        return version, json_text

    def occ_get(self, namespace: str, key: str) -> tuple[int, str] | None:
        """Return ``(version, json)`` after verifying the row's integrity, or ``None``."""
        return self._occ_row(namespace, key)

    def occ_get_all(self, namespace: str) -> list[tuple[str, int, str]]:
        """Return ``(key, version, json)`` triples after verifying each row's integrity."""
        rows = self._conn.execute(
            "SELECT key, version, json, row_digest FROM occ_store WHERE namespace = ? ORDER BY key",
            (namespace,),
        ).fetchall()
        out: list[tuple[str, int, str]] = []
        for key, version, json_text, stored_digest in rows:
            k, v, j = str(key), int(version), str(json_text)
            if _row_digest(self._occ_key(namespace, k), str(v), j) != str(stored_digest):
                raise RepositoryIntegrityError(f"occ row integrity check failed for {namespace}/{k}")
            out.append((k, v, j))
        return out

    def occ_delete(self, namespace: str, key: str) -> None:
        if not self._conn.in_transaction:
            raise RepositoryIntegrityError("occ write requires an active unit of work")
        self._conn.execute("DELETE FROM occ_store WHERE namespace = ? AND key = ?", (namespace, key))


class UnitOfWork:
    """A single-transaction boundary. Repositories participate; only this commits."""

    def __init__(self, database: Database) -> None:
        self._database = database
        self._conn = database.connection

    def __enter__(self) -> UnitOfWork:
        self._database.begin("plain-unit-of-work")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is not None:
            self._conn.rollback()
            self._database.discard_after_commit()
            self._database.end_transaction()
        else:
            self._conn.commit()
            self._database.end_transaction()
            self._database.run_after_commit()
