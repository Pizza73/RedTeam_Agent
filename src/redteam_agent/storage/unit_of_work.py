"""ApplicationUnitOfWork: the transaction-aggregate boundary (SystemDesign §32.1).

Each cross-repository invariant is owned by exactly one aggregate service that opens
one :class:`ApplicationUnitOfWork`, drives every child repository write inside it, and
commits once. Child repositories never commit on their own: they only execute on the
shared connection, and this unit of work asserts the transaction is still open at exit
(so a stray mid-transaction commit is caught as :class:`AggregateConsistencyError`).

Every aggregate command carries ``aggregate_name``, ``operation_id`` and an
``input_digest``. The operation id is reserved in the same transaction, so a retry with
the *same* input replays idempotently (``already_applied``) and a retry with a
*different* input for the same id fails closed. A ``FaultInjector`` can trip at named
commit boundaries so crash-recovery tests exercise the exact ``DB commit`` / ``read-back``
seams without a real crash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Protocol

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.errors import AggregateConsistencyError, AuthorizationKernelError
from redteam_agent.storage.database import Database, UnitOfWork

_AGG_NAMESPACE = "aggregate_operations"


class CommitBoundaryFault(AuthorizationKernelError):
    """Injected fault at a named commit boundary (tests only)."""


class FaultInjector(Protocol):
    def check(self, point: str) -> None: ...


class NoFaultInjector:
    def check(self, point: str) -> None:
        return None


class ArmedFaultInjector:
    """Trips :class:`CommitBoundaryFault` once for each armed point (tests only)."""

    def __init__(self, *points: str) -> None:
        self._points = list(points)

    def check(self, point: str) -> None:
        if point in self._points:
            self._points.remove(point)
            raise CommitBoundaryFault(point)


@dataclass(frozen=True)
class AggregateDefinition:
    aggregate_name: str
    owner_component: str
    record_families: frozenset[str]


# Version-fixed transaction-aggregate catalog (SystemDesign §32.1). Only the aggregate
# named here may open a unit of work, and the architecture test checks that the owner
# component and no other declares each record family.
AGGREGATE_CATALOG: dict[str, AggregateDefinition] = {
    "SecretLifecycleAggregate": AggregateDefinition(
        "SecretLifecycleAggregate", "secrets",
        frozenset({"secret_version", "secret_lifecycle_event", "secret_confirmation",
                   "secret_logical_head", "secret_active_head"}),
    ),
    "CollectionLeaseAggregate": AggregateDefinition(
        "CollectionLeaseAggregate", "leases",
        frozenset({"result_collection_lease"}),
    ),
    "IngestionLeaseAggregate": AggregateDefinition(
        "IngestionLeaseAggregate", "leases",
        frozenset({"secure_ingestion_lease"}),
    ),
    "IngestionPublicationAggregate": AggregateDefinition(
        "IngestionPublicationAggregate", "ingestion",
        frozenset({"artifact", "secure_ingestion_manifest", "quarantine_deletion_intent"}),
    ),
    "QuarantineAggregate": AggregateDefinition(
        "QuarantineAggregate", "quarantine",
        frozenset({"raw_result_quarantine_metadata"}),
    ),
    "ErasureClaimAggregate": AggregateDefinition(
        "ErasureClaimAggregate", "verified_erasure",
        frozenset({"quarantine_erasure_claim", "resource_cleanup_intent", "resource_cleanup_claim"}),
    ),
    "AuditAppendAggregate": AggregateDefinition(
        "AuditAppendAggregate", "logging",
        frozenset({"audit_log", "audit_chain_head"}),
    ),
    "AnchorGenerationAggregate": AggregateDefinition(
        "AnchorGenerationAggregate", "logging",
        frozenset({"generation_record", "generation_blob", "critical_witness_intent",
                   "wrapped_key_state"}),
    ),
    "TrustRecoveryAggregate": AggregateDefinition(
        "TrustRecoveryAggregate", "logging",
        frozenset({"trust_recovery_approval", "trust_recovery_consumption"}),
    ),
    "DeploymentEpochAggregate": AggregateDefinition(
        "DeploymentEpochAggregate", "composition",
        frozenset({"deployment_epoch_mirror"}),
    ),
    "EncryptionKeyAggregate": AggregateDefinition(
        "EncryptionKeyAggregate", "crypto",
        frozenset({"domain_key_metadata", "encryption_metadata"}),
    ),
}


def compute_input_digest(payload: object) -> str:
    """Deterministic input digest for an aggregate command (canonical JSON)."""
    return hashlib.sha256(b"aggregate-input-v1\x00" + canonical_dumps(payload)).hexdigest()


@dataclass
class _OperationRow:
    input_digest: str
    result_digest: str


@dataclass
class ApplicationUnitOfWork:
    database: Database
    aggregate_name: str
    operation_id: str
    input_digest: str
    fault_injector: FaultInjector = field(default_factory=NoFaultInjector)

    already_applied: bool = field(default=False, init=False)
    prior_result_digest: str = field(default="", init=False)
    _result_recorded: bool = field(default=False, init=False)
    _entered: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.aggregate_name not in AGGREGATE_CATALOG:
            raise AggregateConsistencyError(f"unknown aggregate: {self.aggregate_name}")

    def _op_key(self) -> str:
        return f"{self.aggregate_name}/{self.operation_id}"

    def __enter__(self) -> ApplicationUnitOfWork:
        conn = self.database.connection
        self.database.begin(self._op_key())
        self._entered = True
        try:
            existing = self.database.occ_get(_AGG_NAMESPACE, self._op_key())
            if existing is not None:
                _version, json_text = existing
                row = _OperationRow(**json.loads(json_text))
                if row.input_digest != self.input_digest:
                    raise AggregateConsistencyError(
                        f"operation {self._op_key()} replayed with a different input digest"
                    )
                self.already_applied = True
                self.prior_result_digest = row.result_digest
            else:
                # Reserve the operation id in this transaction so a concurrent duplicate
                # conflicts on the primary key and a rollback removes the reservation.
                self._write_op(result_digest="")
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            self.database.discard_after_commit()
            self.database.end_transaction()
            self._entered = False
            raise
        return self

    def _write_op(self, *, result_digest: str) -> None:
        payload = {"input_digest": self.input_digest, "result_digest": result_digest}
        existing = self.database.occ_get(_AGG_NAMESPACE, self._op_key())
        if existing is None:
            self.database.occ_insert(_AGG_NAMESPACE, self._op_key(), 1, json.dumps(payload, sort_keys=True))
        else:
            version, _ = existing
            self.database.occ_update(
                _AGG_NAMESPACE, self._op_key(), expected_version=version, new_version=version + 1,
                json_text=json.dumps(payload, sort_keys=True),
            )

    def record_result(self, result_digest: str) -> None:
        """Record the aggregate's result digest in this transaction (idempotency key)."""
        if self.already_applied:
            return
        self._write_op(result_digest=result_digest)
        self._result_recorded = True

    def fault(self, point: str) -> None:
        """Trip an injected fault at a named boundary (no-op in production)."""
        self.fault_injector.check(point)

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        conn = self.database.connection
        if not self._entered:  # pragma: no cover - defensive
            return
        if exc_type is not None:
            conn.rollback()
            self.database.discard_after_commit()
            self.database.end_transaction()
            return
        # No child repository may have committed mid-transaction.
        if not conn.in_transaction:
            self.database.discard_after_commit()
            self.database.end_transaction()
            raise AggregateConsistencyError(
                f"{self.aggregate_name}: a child repository committed inside the unit of work"
            )
        # A ``before_commit`` fault models a crash before the durable commit: the
        # open transaction is discarded (as SQLite would on connection loss).
        try:
            self.fault_injector.check("before_commit")
        except BaseException:
            conn.rollback()
            self.database.discard_after_commit()
            self.database.end_transaction()
            raise
        conn.commit()
        self.database.end_transaction()
        # An ``after_commit`` fault models a crash after the durable commit but before
        # the service's post-commit read-back/witness; the data stays committed and
        # recovery re-runs from the committed operation row.
        try:
            self.fault_injector.check("after_commit")
        except BaseException:
            # A real process crash loses in-memory callbacks. The durable intent is
            # recovered explicitly on restart, so the test seam must model that.
            self.database.discard_after_commit()
            raise
        self.database.run_after_commit()


def open_simple_txn(database: Database) -> UnitOfWork:
    """A plain single-transaction boundary for a non-aggregate internal write."""
    return UnitOfWork(database)


def peek_operation(database: Database, aggregate_name: str, operation_id: str) -> _OperationRow | None:
    """Read a recorded aggregate operation (idempotency key) without a transaction.

    Returns the stored input/result digests if the operation was already applied, so a
    retry can resolve the committed result instead of rebuilding it from advanced state.
    """
    existing = database.occ_get(_AGG_NAMESPACE, f"{aggregate_name}/{operation_id}")
    if existing is None:
        return None
    return _OperationRow(**json.loads(existing[1]))
