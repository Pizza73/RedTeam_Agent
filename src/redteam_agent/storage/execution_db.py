"""Low-level SQL for the Phase 0B execution-safety tables (SystemDesign §32).

All statements are literal (no string interpolation of identifiers), so the
column/table names are fixed schema constants, not caller input. Uniqueness is
raised by the database (``sqlite3.IntegrityError``) and mapped to a typed
:class:`ExecutionUniquenessError`; OCC updates check the affected row count and
raise :class:`ExecutionStateConflictError` on a stale version. Each accessor
verifies the row-integrity digest binding (table, key, json) on read.

This class shares the :class:`Database` connection, so every method participates
in the enclosing :class:`UnitOfWork` transaction.
"""

from __future__ import annotations

import sqlite3
from typing import ClassVar

from redteam_agent.errors import (
    ExecutionStateConflictError,
    ExecutionUniquenessError,
    RepositoryIntegrityError,
)
from redteam_agent.storage.database import Database, row_digest


class ExecutionStore:
    def __init__(self, database: Database) -> None:
        self._db = database
        self._conn = database.connection

    # --- helpers ----------------------------------------------------------

    def _digest(self, table: str, key: str, json_text: str) -> str:
        return row_digest(table, key, json_text)

    def _verify(self, table: str, key: str, json_text: str, stored: str) -> str:
        if self._digest(table, key, json_text) != stored:
            raise RepositoryIntegrityError(f"row integrity check failed for {table}/{key}")
        return json_text

    def _verify_keyed(self, table: str, key: str, json_text: str, stored: str) -> tuple[str, str]:
        return key, self._verify(table, key, json_text, stored)

    def _require_txn(self) -> None:
        if not self._db.in_transaction:
            raise RepositoryIntegrityError("write requires an active unit of work")

    @staticmethod
    def _require_affected(cursor: sqlite3.Cursor) -> None:
        if cursor.rowcount != 1:
            raise ExecutionStateConflictError("optimistic concurrency conflict (stale version)")

    # --- executions -------------------------------------------------------

    def insert_execution(
        self,
        *,
        execution_id: str,
        policy_decision_id: str,
        mission_id: str,
        execution_state_version: int,
        provider_execution_state: str,
        json_text: str,
    ) -> None:
        self._require_txn()
        digest = self._digest("executions", execution_id, json_text)
        try:
            self._conn.execute(
                "INSERT INTO executions (execution_id, policy_decision_id, mission_id, "
                "execution_state_version, provider_execution_state, json, row_digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    execution_id,
                    policy_decision_id,
                    mission_id,
                    execution_state_version,
                    provider_execution_state,
                    json_text,
                    digest,
                ),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError(
                "execution uniqueness violated (duplicate execution_id or policy_decision_id)"
            ) from None

    def update_execution(
        self,
        *,
        execution_id: str,
        expected_version: int,
        new_version: int,
        provider_execution_state: str,
        json_text: str,
    ) -> None:
        self._require_txn()
        digest = self._digest("executions", execution_id, json_text)
        cursor = self._conn.execute(
            "UPDATE executions SET execution_state_version = ?, provider_execution_state = ?, "
            "json = ?, row_digest = ? WHERE execution_id = ? AND execution_state_version = ?",
            (new_version, provider_execution_state, json_text, digest, execution_id, expected_version),
        )
        self._require_affected(cursor)

    def get_execution(self, execution_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM executions WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        if row is None:
            return None
        return self._verify("executions", execution_id, str(row[0]), str(row[1]))

    def get_execution_by_decision(self, policy_decision_id: str) -> tuple[str, str] | None:
        row = self._conn.execute(
            "SELECT execution_id, json, row_digest FROM executions WHERE policy_decision_id = ?",
            (policy_decision_id,),
        ).fetchone()
        if row is None:
            return None
        return self._verify_keyed("executions", str(row[0]), str(row[1]), str(row[2]))

    # --- dispatch claims --------------------------------------------------

    def insert_claim(self, *, claim_id: str, execution_id: str, claim_state: str, json_text: str) -> None:
        self._require_txn()
        digest = self._digest("dispatch_claims", claim_id, json_text)
        try:
            self._conn.execute(
                "INSERT INTO dispatch_claims (claim_id, execution_id, claim_state, json, row_digest) "
                "VALUES (?, ?, ?, ?, ?)",
                (claim_id, execution_id, claim_state, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError(
                "dispatch claim uniqueness violated (duplicate claim or unconsumed claim exists)"
            ) from None

    def update_claim_state(
        self, *, claim_id: str, expected_state: str, new_state: str, json_text: str
    ) -> None:
        self._require_txn()
        digest = self._digest("dispatch_claims", claim_id, json_text)
        cursor = self._conn.execute(
            "UPDATE dispatch_claims SET claim_state = ?, json = ?, row_digest = ? "
            "WHERE claim_id = ? AND claim_state = ?",
            (new_state, json_text, digest, claim_id, expected_state),
        )
        self._require_affected(cursor)

    def get_claim(self, claim_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM dispatch_claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row is None:
            return None
        return self._verify("dispatch_claims", claim_id, str(row[0]), str(row[1]))

    def find_unconsumed_claim(self, execution_id: str) -> tuple[str, str] | None:
        row = self._conn.execute(
            "SELECT claim_id, json, row_digest FROM dispatch_claims "
            "WHERE execution_id = ? AND claim_state = 'unconsumed'",
            (execution_id,),
        ).fetchone()
        if row is None:
            return None
        return self._verify_keyed("dispatch_claims", str(row[0]), str(row[1]), str(row[2]))

    def claims_for(self, execution_id: str) -> list[tuple[str, str]]:
        rows = self._conn.execute(
            "SELECT claim_id, json, row_digest FROM dispatch_claims WHERE execution_id = ? ORDER BY claim_id",
            (execution_id,),
        ).fetchall()
        return [self._verify_keyed("dispatch_claims", str(k), str(j), str(d)) for k, j, d in rows]

    # --- single-row-per-key JSON tables -----------------------------------

    def _insert_simple(self, table: str, key: str, execution_id: str, json_text: str) -> None:
        self._require_txn()
        digest = self._digest(table, key, json_text)
        sql = self._SIMPLE_INSERTS[table]
        try:
            self._conn.execute(sql, (key, execution_id, json_text, digest))
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError(f"uniqueness violated for {table}") from None

    _SIMPLE_INSERTS: ClassVar[dict[str, str]] = {
        "result_collection_authorities": (
            "INSERT INTO result_collection_authorities (collection_id, execution_id, json, row_digest) "
            "VALUES (?, ?, ?, ?)"
        ),
        "result_task_bindings": (
            "INSERT INTO result_task_bindings (result_task_binding_id, execution_id, json, row_digest) "
            "VALUES (?, ?, ?, ?)"
        ),
        "raw_control_metadata": (
            "INSERT INTO raw_control_metadata (control_record_id, execution_id, json, row_digest) "
            "VALUES (?, ?, ?, ?)"
        ),
        "execution_result_projections": (
            "INSERT INTO execution_result_projections (projection_id, execution_id, json, row_digest) "
            "VALUES (?, ?, ?, ?)"
        ),
    }

    def insert_collection_authority(self, *, collection_id: str, execution_id: str, json_text: str) -> None:
        self._insert_simple("result_collection_authorities", collection_id, execution_id, json_text)

    def get_collection_authority(self, collection_id: str) -> str | None:
        return self._get_simple("result_collection_authorities", collection_id)

    def find_collection_authority_by_execution(self, execution_id: str) -> tuple[str, str] | None:
        return self._get_by_execution("result_collection_authorities", execution_id)

    def insert_task_binding(self, *, result_task_binding_id: str, execution_id: str, json_text: str) -> None:
        self._insert_simple("result_task_bindings", result_task_binding_id, execution_id, json_text)

    def get_task_binding(self, result_task_binding_id: str) -> str | None:
        return self._get_simple("result_task_bindings", result_task_binding_id)

    def find_task_binding_by_execution(self, execution_id: str) -> tuple[str, str] | None:
        return self._get_by_execution("result_task_bindings", execution_id)

    def insert_control_metadata(self, *, control_record_id: str, execution_id: str, json_text: str) -> None:
        self._insert_simple("raw_control_metadata", control_record_id, execution_id, json_text)

    def get_control_metadata(self, control_record_id: str) -> str | None:
        return self._get_simple("raw_control_metadata", control_record_id)

    def find_control_metadata_by_execution(self, execution_id: str) -> tuple[str, str] | None:
        return self._get_by_execution("raw_control_metadata", execution_id)

    def insert_projection(self, *, projection_id: str, execution_id: str, json_text: str) -> None:
        self._insert_simple("execution_result_projections", projection_id, execution_id, json_text)

    def get_projection(self, projection_id: str) -> str | None:
        return self._get_simple("execution_result_projections", projection_id)

    def find_projection_by_execution(self, execution_id: str) -> tuple[str, str] | None:
        return self._get_by_execution("execution_result_projections", execution_id)

    _SIMPLE_SELECTS: ClassVar[dict[str, tuple[str, str]]] = {
        "result_collection_authorities": (
            "SELECT json, row_digest FROM result_collection_authorities WHERE collection_id = ?",
            "SELECT collection_id, json, row_digest FROM result_collection_authorities WHERE execution_id = ?",
        ),
        "result_task_bindings": (
            "SELECT json, row_digest FROM result_task_bindings WHERE result_task_binding_id = ?",
            "SELECT result_task_binding_id, json, row_digest FROM result_task_bindings WHERE execution_id = ?",
        ),
        "raw_control_metadata": (
            "SELECT json, row_digest FROM raw_control_metadata WHERE control_record_id = ?",
            "SELECT control_record_id, json, row_digest FROM raw_control_metadata WHERE execution_id = ?",
        ),
        "execution_result_projections": (
            "SELECT json, row_digest FROM execution_result_projections WHERE projection_id = ?",
            "SELECT projection_id, json, row_digest FROM execution_result_projections WHERE execution_id = ?",
        ),
    }

    def _get_simple(self, table: str, key: str) -> str | None:
        row = self._conn.execute(self._SIMPLE_SELECTS[table][0], (key,)).fetchone()
        if row is None:
            return None
        return self._verify(table, key, str(row[0]), str(row[1]))

    def _get_by_execution(self, table: str, execution_id: str) -> tuple[str, str] | None:
        row = self._conn.execute(self._SIMPLE_SELECTS[table][1], (execution_id,)).fetchone()
        if row is None:
            return None
        return self._verify_keyed(table, str(row[0]), str(row[1]), str(row[2]))

    # --- result collection states (OCC) -----------------------------------

    def insert_collection_state(
        self, *, collection_state_id: str, collection_id: str, execution_id: str, state_version: int,
        status: str, json_text: str,
    ) -> None:
        self._require_txn()
        digest = self._digest("result_collection_states", collection_state_id, json_text)
        try:
            self._conn.execute(
                "INSERT INTO result_collection_states (collection_state_id, collection_id, execution_id, "
                "state_version, status, json, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (collection_state_id, collection_id, execution_id, state_version, status, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError("result collection state uniqueness violated") from None

    def update_collection_state(
        self, *, collection_state_id: str, expected_version: int, new_version: int, status: str, json_text: str
    ) -> None:
        self._require_txn()
        digest = self._digest("result_collection_states", collection_state_id, json_text)
        cursor = self._conn.execute(
            "UPDATE result_collection_states SET state_version = ?, status = ?, json = ?, row_digest = ? "
            "WHERE collection_state_id = ? AND state_version = ?",
            (new_version, status, json_text, digest, collection_state_id, expected_version),
        )
        self._require_affected(cursor)

    def get_collection_state(self, collection_state_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM result_collection_states WHERE collection_state_id = ?",
            (collection_state_id,),
        ).fetchone()
        if row is None:
            return None
        return self._verify("result_collection_states", collection_state_id, str(row[0]), str(row[1]))

    # --- result ingestion states (OCC) ------------------------------------

    def insert_ingestion_state(
        self, *, ingestion_id: str, execution_id: str, state_version: int, status: str, json_text: str
    ) -> None:
        self._require_txn()
        digest = self._digest("result_ingestion_states", ingestion_id, json_text)
        try:
            self._conn.execute(
                "INSERT INTO result_ingestion_states (ingestion_id, execution_id, state_version, status, "
                "json, row_digest) VALUES (?, ?, ?, ?, ?, ?)",
                (ingestion_id, execution_id, state_version, status, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError("result ingestion state uniqueness violated") from None

    def update_ingestion_state(
        self, *, ingestion_id: str, expected_version: int, new_version: int, status: str, json_text: str
    ) -> None:
        self._require_txn()
        digest = self._digest("result_ingestion_states", ingestion_id, json_text)
        cursor = self._conn.execute(
            "UPDATE result_ingestion_states SET state_version = ?, status = ?, json = ?, row_digest = ? "
            "WHERE ingestion_id = ? AND state_version = ?",
            (new_version, status, json_text, digest, ingestion_id, expected_version),
        )
        self._require_affected(cursor)

    def get_ingestion_state(self, ingestion_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM result_ingestion_states WHERE ingestion_id = ?", (ingestion_id,)
        ).fetchone()
        if row is None:
            return None
        return self._verify("result_ingestion_states", ingestion_id, str(row[0]), str(row[1]))

    def find_ingestion_state_by_execution(self, execution_id: str) -> tuple[str, str] | None:
        row = self._conn.execute(
            "SELECT ingestion_id, json, row_digest FROM result_ingestion_states WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            return None
        return self._verify_keyed("result_ingestion_states", str(row[0]), str(row[1]), str(row[2]))

    # --- execution results ------------------------------------------------

    def upsert_execution_result(self, *, execution_id: str, json_text: str) -> None:
        self._require_txn()
        digest = self._digest("execution_results", execution_id, json_text)
        existing = self._conn.execute(
            "SELECT json FROM execution_results WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != json_text:
                raise ExecutionUniquenessError("conflicting execution result for execution")
            return
        self._conn.execute(
            "INSERT INTO execution_results (execution_id, json, row_digest) VALUES (?, ?, ?)",
            (execution_id, json_text, digest),
        )

    def get_execution_result(self, execution_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM execution_results WHERE execution_id = ?", (execution_id,)
        ).fetchone()
        if row is None:
            return None
        return self._verify("execution_results", execution_id, str(row[0]), str(row[1]))

    # --- recovery authorities ---------------------------------------------

    def insert_recovery_authority(
        self, *, authority_id: str, execution_id: str, allowed_operation: str, json_text: str
    ) -> None:
        self._require_txn()
        digest = self._digest("execution_recovery_authorities", authority_id, json_text)
        try:
            self._conn.execute(
                "INSERT INTO execution_recovery_authorities (authority_id, execution_id, allowed_operation, "
                "json, row_digest) VALUES (?, ?, ?, ?, ?)",
                (authority_id, execution_id, allowed_operation, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError("recovery authority uniqueness violated") from None

    def get_recovery_authority(self, authority_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM execution_recovery_authorities WHERE authority_id = ?",
            (authority_id,),
        ).fetchone()
        if row is None:
            return None
        return self._verify("execution_recovery_authorities", authority_id, str(row[0]), str(row[1]))

    # --- cancel attempts --------------------------------------------------

    def insert_cancel_attempt(
        self, *, cancel_attempt_id: str, execution_id: str, provider_task_id: str, json_text: str
    ) -> None:
        self._require_txn()
        digest = self._digest("cancel_attempts", cancel_attempt_id, json_text)
        try:
            self._conn.execute(
                "INSERT INTO cancel_attempts (cancel_attempt_id, execution_id, provider_task_id, json, row_digest) "
                "VALUES (?, ?, ?, ?, ?)",
                (cancel_attempt_id, execution_id, provider_task_id, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError(
                "cancel attempt uniqueness violated (attempt exists for execution/task)"
            ) from None

    def update_cancel_attempt(self, *, cancel_attempt_id: str, json_text: str) -> None:
        self._require_txn()
        digest = self._digest("cancel_attempts", cancel_attempt_id, json_text)
        cursor = self._conn.execute(
            "UPDATE cancel_attempts SET json = ?, row_digest = ? WHERE cancel_attempt_id = ?",
            (json_text, digest, cancel_attempt_id),
        )
        self._require_affected(cursor)

    def get_cancel_attempt(self, cancel_attempt_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT json, row_digest FROM cancel_attempts WHERE cancel_attempt_id = ?", (cancel_attempt_id,)
        ).fetchone()
        if row is None:
            return None
        return self._verify("cancel_attempts", cancel_attempt_id, str(row[0]), str(row[1]))

    def find_cancel_attempt(self, execution_id: str, provider_task_id: str) -> tuple[str, str] | None:
        row = self._conn.execute(
            "SELECT cancel_attempt_id, json, row_digest FROM cancel_attempts "
            "WHERE execution_id = ? AND provider_task_id = ?",
            (execution_id, provider_task_id),
        ).fetchone()
        if row is None:
            return None
        return self._verify_keyed("cancel_attempts", str(row[0]), str(row[1]), str(row[2]))

    # --- mission execution budgets (OCC) ----------------------------------

    def insert_budget(
        self, *, mission_id: str, mission_revision: int, budget_version: int, json_text: str
    ) -> None:
        self._require_txn()
        key = f"{mission_id}/{mission_revision}"
        digest = self._digest("mission_execution_budgets", key, json_text)
        try:
            self._conn.execute(
                "INSERT INTO mission_execution_budgets (mission_id, mission_revision, budget_version, "
                "json, row_digest) VALUES (?, ?, ?, ?, ?)",
                (mission_id, mission_revision, budget_version, json_text, digest),
            )
        except sqlite3.IntegrityError:
            raise ExecutionUniquenessError("mission execution budget already exists") from None

    def update_budget(
        self, *, mission_id: str, mission_revision: int, expected_version: int, new_version: int, json_text: str
    ) -> None:
        self._require_txn()
        key = f"{mission_id}/{mission_revision}"
        digest = self._digest("mission_execution_budgets", key, json_text)
        cursor = self._conn.execute(
            "UPDATE mission_execution_budgets SET budget_version = ?, json = ?, row_digest = ? "
            "WHERE mission_id = ? AND mission_revision = ? AND budget_version = ?",
            (new_version, json_text, digest, mission_id, mission_revision, expected_version),
        )
        self._require_affected(cursor)

    def get_budget(self, mission_id: str, mission_revision: int) -> str | None:
        key = f"{mission_id}/{mission_revision}"
        row = self._conn.execute(
            "SELECT json, row_digest FROM mission_execution_budgets WHERE mission_id = ? AND mission_revision = ?",
            (mission_id, mission_revision),
        ).fetchone()
        if row is None:
            return None
        return self._verify("mission_execution_budgets", key, str(row[0]), str(row[1]))
