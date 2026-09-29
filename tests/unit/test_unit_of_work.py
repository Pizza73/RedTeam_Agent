"""ApplicationUnitOfWork aggregate boundary + commit-boundary faults (SystemDesign §32.1)."""

from __future__ import annotations

import pytest

from redteam_agent.errors import AggregateConsistencyError
from redteam_agent.storage.database import Database
from redteam_agent.storage.unit_of_work import (
    AGGREGATE_CATALOG,
    ApplicationUnitOfWork,
    ArmedFaultInjector,
    CommitBoundaryFault,
    compute_input_digest,
    peek_operation,
)


def _db() -> Database:
    return Database(":memory:")


def test_state_audit_intent_commit_together() -> None:
    db = _db()
    idig = compute_input_digest({"op": 1})
    with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-1",
                               input_digest=idig) as uow:
        db.occ_insert("audit_log", "m/1", 1, '{"event": "start"}')
        uow.record_result("res")
    assert db.occ_get("audit_log", "m/1") is not None
    assert peek_operation(db, "AuditAppendAggregate", "op-1") is not None


def test_sqlite_generation_durability_uses_synchronous_full() -> None:
    db = _db()
    assert db.connection.execute("PRAGMA synchronous").fetchone() == (2,)


def test_same_operation_same_input_replays() -> None:
    db = _db()
    idig = compute_input_digest({"op": 1})
    with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-1",
                               input_digest=idig) as uow:
        db.occ_insert("audit_log", "m/1", 1, '{"event": "start"}')
        uow.record_result("res")
    with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-1",
                               input_digest=idig) as uow:
        assert uow.already_applied and uow.prior_result_digest == "res"


def test_same_operation_different_input_fails_closed() -> None:
    db = _db()
    with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-1",
                               input_digest=compute_input_digest({"op": 1})) as uow:
        uow.record_result("res")
    with pytest.raises(AggregateConsistencyError):
        with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-1",
                                   input_digest=compute_input_digest({"op": 2})):
            pass
    assert not db.in_transaction


def test_unknown_aggregate_rejected() -> None:
    with pytest.raises(AggregateConsistencyError):
        ApplicationUnitOfWork(_db(), aggregate_name="NopeAggregate", operation_id="x",
                              input_digest=compute_input_digest({}))


def test_before_commit_fault_rolls_back() -> None:
    db = _db()
    with pytest.raises(CommitBoundaryFault):
        with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-2",
                                   input_digest=compute_input_digest({}),
                                   fault_injector=ArmedFaultInjector("before_commit")) as uow:
            db.occ_insert("audit_log", "m/2", 1, '{"event": "x"}')
            uow.record_result("res")
    assert db.occ_get("audit_log", "m/2") is None  # rolled back
    assert not db.in_transaction


def test_after_commit_fault_keeps_durable_state() -> None:
    db = _db()
    with pytest.raises(CommitBoundaryFault):
        with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-3",
                                   input_digest=compute_input_digest({}),
                                   fault_injector=ArmedFaultInjector("after_commit")) as uow:
            db.occ_insert("audit_log", "m/3", 1, '{"event": "x"}')
            uow.record_result("res")
    assert db.occ_get("audit_log", "m/3") is not None  # durable


def test_child_mid_transaction_commit_rejected() -> None:
    db = _db()
    with pytest.raises(AggregateConsistencyError):
        with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="op-4",
                                   input_digest=compute_input_digest({})) as uow:
            uow.record_result("res")
            db.connection.commit()  # a stray child commit ends the transaction early


def test_catalog_families_disjoint() -> None:
    seen: dict[str, str] = {}
    for name, definition in AGGREGATE_CATALOG.items():
        for family in definition.record_families:
            assert family not in seen, f"{family} owned by {seen.get(family)} and {name}"
            seen[family] = name
