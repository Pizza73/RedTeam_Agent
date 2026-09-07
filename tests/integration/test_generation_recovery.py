"""TPM-witnessed authenticated generation + audit hash chain (SystemDesign §34.2)."""

from __future__ import annotations

import json

import pytest

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.generation_store import GenerationRecordStore, InMemoryRecordAuthenticationKey
from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.audit.nv_witness import InMemoryNvExtendWitness
from redteam_agent.canonical.digest_catalog import CATALOG_REVISION
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AnchorRecoveryRequiredError, AuditChainError, GenerationWitnessError
from redteam_agent.storage.database import Database, row_digest
from redteam_agent.storage.unit_of_work import (
    ApplicationUnitOfWork,
    ArmedFaultInjector,
    CommitBoundaryFault,
    compute_input_digest,
)


def _coordinator(db: Database, witness: InMemoryNvExtendWitness, ds: DigestService, **kw: object):
    store = GenerationRecordStore(db, ds, InMemoryRecordAuthenticationKey(b"k" * 32))
    return AuthenticatedGenerationCoordinator(
        database=db, witness=witness, record_store=store, digest_service=ds,
        digest_catalog_revision=CATALOG_REVISION, **kw,  # type: ignore[arg-type]
    )


def _fresh():
    ds = DigestService()
    db = Database(":memory:")
    witness = InMemoryNvExtendWitness(digest_service=ds)
    return ds, db, witness, _coordinator(db, witness, ds)


def test_genesis_then_commit_advances_generation() -> None:
    ds, db, witness, c = _fresh()
    assert c.current("audit_head") is None
    g = c.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    assert g.generation == 0 and g.previous_anchor_digest is None
    r1 = c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    assert r1.generation == 1 and r1.previous_witness_digest == g.witness_digest
    assert c.current("audit_head").generation == 1


def test_commit_replay_is_idempotent() -> None:
    ds, db, witness, c = _fresh()
    c.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    r1 = c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    again = c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    assert again.witness_digest == r1.witness_digest


def test_tpm_reset_enters_anchor_recovery() -> None:
    ds, db, witness, c = _fresh()
    c.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    witness.simulate_reset()
    with pytest.raises(AnchorRecoveryRequiredError):
        c.current("audit_head")


def test_nv_identity_mismatch_enters_anchor_recovery() -> None:
    ds, db, witness, c = _fresh()
    c.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    witness.simulate_identity_change("device-b")
    with pytest.raises(AnchorRecoveryRequiredError):
        c.current("audit_head")


def test_db_rollback_below_witness_enters_anchor_recovery() -> None:
    ds, db, witness, c = _fresh()
    c.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    r1 = c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    # TPM stays at generation 1 but the DB record for it is rolled back (deleted).
    db.connection.execute(
        "DELETE FROM occ_store WHERE namespace = 'generation_record_witness' AND key LIKE ?",
        (f"audit_head/1/{r1.witness_digest}",),
    )
    db.connection.commit()
    with pytest.raises(AnchorRecoveryRequiredError):
        c.current("audit_head")


def test_same_generation_different_content_rejected() -> None:
    ds, db, witness, c = _fresh()
    c.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    c.commit("audit_head", new_state_digest="s1", new_content="a", operation_id="op-1")
    # A second commit with the same op id but different content is a different input.
    from redteam_agent.errors import AggregateConsistencyError
    with pytest.raises(AggregateConsistencyError):
        c.commit("audit_head", new_state_digest="s2", new_content="different", operation_id="op-1")


def test_crash_before_extend_reconciles_same_payload() -> None:
    ds = DigestService()
    db = Database(":memory:")
    witness = InMemoryNvExtendWitness(digest_service=ds)
    store = GenerationRecordStore(db, ds, InMemoryRecordAuthenticationKey(b"k" * 32))
    faulted = AuthenticatedGenerationCoordinator(
        database=db, witness=witness, record_store=store, digest_service=ds,
        digest_catalog_revision=CATALOG_REVISION, fault_injector=ArmedFaultInjector("before_extend"),
    )
    with pytest.raises(CommitBoundaryFault):
        faulted.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    # The record is persisted but the TPM was not extended; a clean coordinator completes it.
    clean = AuthenticatedGenerationCoordinator(
        database=db, witness=witness, record_store=store, digest_service=ds,
        digest_catalog_revision=CATALOG_REVISION,
    )
    clean.genesis("audit_head", initial_state_digest="s0", initial_content="{}")
    assert clean.current("audit_head").generation == 0


def test_deployment_epoch_counter_advances_measured() -> None:
    ds, db, witness, c = _fresh()
    with pytest.raises(GenerationWitnessError):
        c.read_deployment_epoch()
    first = c.initialize_deployment_epoch()
    second = c.advance_deployment_epoch()
    assert first == 1 and second == 2


def test_audit_hash_chain_tamper_detected() -> None:
    ds = DigestService()
    db = Database(":memory:")
    audit = AuditStore(db, ds)
    with ApplicationUnitOfWork(db, aggregate_name="AuditAppendAggregate", operation_id="a1",
                               input_digest=compute_input_digest({})) as uow:
        audit.append_in_txn(mission_id="m1", event_type="MISSION_START", payload_digest="p1", actor_id="op",
                            occurred_at_iso="2026-01-01T00:00:00Z")
        audit.append_in_txn(mission_id="m1", event_type="DISPATCH", payload_digest="p2", actor_id="op",
                            occurred_at_iso="2026-01-01T00:00:01Z")
        uow.record_result("r")
    audit.verify_chain("m1")
    # Tamper with the first event's stored content while keeping the row digest consistent.
    key0 = db.connection.execute(
        "SELECT key FROM occ_store WHERE namespace = 'audit_log' ORDER BY key"
    ).fetchone()[0]
    current = json.loads(db.connection.execute(
        "SELECT json FROM occ_store WHERE namespace = 'audit_log' AND key = ?", (key0,)
    ).fetchone()[0])
    current["event_type"] = "TAMPERED"
    tampered = json.dumps(current, sort_keys=True)
    rd = row_digest("audit_log\x00" + key0, "1", tampered)
    db.connection.execute(
        "UPDATE occ_store SET json = ?, row_digest = ? WHERE namespace = 'audit_log' AND key = ?",
        (tampered, rd, key0),
    )
    db.connection.commit()
    with pytest.raises(AuditChainError):
        audit.verify_chain("m1")


def test_extend_role_only_for_extend_indices() -> None:
    ds, db, witness, c = _fresh()
    with pytest.raises(GenerationWitnessError):
        witness.read_witness("deployment_epoch")
