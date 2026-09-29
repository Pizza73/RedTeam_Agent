"""Critical event and wrapped-key-state TPM witness barriers (SystemDesign §34.2)."""

from __future__ import annotations

import json

import pytest

import support
import support_phase0b as p0b
import support_phase0c as s
from redteam_agent.audit.models import CriticalWitnessIntent
from redteam_agent.auth.models import MissionRoleAssignment
from redteam_agent.errors import (
    AnchorRecoveryRequiredError,
    CriticalWitnessError,
    EncryptionUnavailableError,
    GenerationWitnessError,
    RepositoryIntegrityError,
)
from redteam_agent.storage.unit_of_work import ApplicationUnitOfWork, ArmedFaultInjector, CommitBoundaryFault


def test_critical_audit_event_is_witnessed_before_success() -> None:
    kernel = s.make_phase0c()
    before = kernel.generation_coordinator.current("audit_head")
    assert before is not None
    ingestion_id = s.collect(kernel, execution_id=s.seed_dispatched(kernel).execution_id)
    assert ingestion_id
    after = kernel.generation_coordinator.current("audit_head")
    assert after is not None and after.generation > before.generation
    intents = kernel.phase0b.phase0a.database.occ_get_all("critical_witness_intent")
    parsed = [CriticalWitnessIntent.model_validate_json(row[2]) for row in intents]
    assert any(
        binding.record_type == "result_ingestion_state"
        for intent in parsed
        for binding in intent.bindings
    )


def test_multiple_critical_events_in_one_transaction_share_one_generation() -> None:
    kernel = s.make_phase0c()
    db = kernel.phase0b.phase0a.database
    before = kernel.generation_coordinator.current("audit_head")
    assert before is not None
    with ApplicationUnitOfWork(
        db, aggregate_name="AuditAppendAggregate", operation_id="two-events", input_digest="input"
    ) as uow:
        for index in (1, 2):
            kernel.audit_store.append_in_txn(
                mission_id="mission-two", event_type="SECRET_REVOKED",
                payload_digest=f"payload-{index}", actor_id="operator",
                occurred_at_iso=f"2026-01-15T12:00:0{index}Z",
                record_type="audit_chain_head", record_id="mission-two",
                state_version=index, security_projection_digest=f"payload-{index}",
            )
        uow.record_result("two-events")
    after = kernel.generation_coordinator.current("audit_head")
    assert after is not None and after.generation == before.generation + 1
    intents = [
        CriticalWitnessIntent.model_validate_json(text)
        for _key, _version, text in db.occ_get_all("critical_witness_intent")
    ]
    assert len(intents) == 1 and len(intents[0].bindings) == 2


def test_post_commit_crash_recovers_witness_without_replaying_mutation() -> None:
    kernel = s.make_phase0c()
    db = kernel.phase0b.phase0a.database
    before = kernel.generation_coordinator.current("audit_head")
    assert before is not None
    with pytest.raises(CommitBoundaryFault):
        with ApplicationUnitOfWork(
            db, aggregate_name="AuditAppendAggregate", operation_id="crash-event", input_digest="input",
            fault_injector=ArmedFaultInjector("after_commit"),
        ) as uow:
            kernel.audit_store.append_in_txn(
                mission_id="mission-crash", event_type="SECRET_REVOKED", payload_digest="payload",
                actor_id="operator", occurred_at_iso="2026-01-15T12:00:00Z",
                record_type="audit_chain_head", record_id="mission-crash",
                state_version=1, security_projection_digest="payload",
            )
            uow.record_result("crash-event")
    still_before = kernel.generation_coordinator.current("audit_head")
    assert still_before is not None and still_before.generation == before.generation
    with pytest.raises(CriticalWitnessError, match="still pending"):
        with ApplicationUnitOfWork(
            db, aggregate_name="AuditAppendAggregate", operation_id="must-block", input_digest="blocked"
        ) as uow:
            kernel.audit_store.append_in_txn(
                mission_id="mission-blocked", event_type="SECRET_REVOKED", payload_digest="blocked",
                actor_id="operator", occurred_at_iso="2026-01-15T12:00:01Z",
                record_type="audit_chain_head", record_id="mission-blocked",
                state_version=1, security_projection_digest="blocked",
            )
            uow.record_result("must-block")
    recovered = kernel.critical_witness_barrier.recover_pending()
    assert len(recovered) == 1
    after = kernel.generation_coordinator.current("audit_head")
    assert after is not None and after.generation == before.generation + 1
    assert len(kernel.audit_store.events("mission-crash")) == 1


def test_phase0b_critical_families_use_exact_state_bindings() -> None:
    kernel = s.make_phase0c()
    s.seed_dispatched(kernel)
    intents = [
        CriticalWitnessIntent.model_validate_json(text)
        for _key, _version, text in kernel.phase0b.phase0a.database.occ_get_all("critical_witness_intent")
    ]
    record_types = {
        binding.record_type for intent in intents for binding in intent.bindings
    }
    assert {
        "mission_authorization",
        "mission_execution_budget",
        "dispatch_claim",
        "result_task_binding",
    } <= record_types
    assert any(
        {binding.record_type for binding in intent.bindings}
        >= {"mission_execution_budget", "dispatch_claim"}
        for intent in intents
    )
    current = kernel.generation_coordinator.current("audit_head")
    assert current is not None
    content = json.loads(kernel.generation_coordinator.record_content(current))
    current_types = {item["record_type"] for item in content["bindings"]}
    assert {
        "mission_authorization",
        "mission_execution_budget",
        "dispatch_claim",
        "result_task_binding",
    } <= current_types


def test_selective_security_row_rollback_is_rejected_by_current_witness() -> None:
    kernel = s.make_phase0c()
    seeded = p0b.seed_authorized(kernel.phase0b)
    mission_id = seeded.seeded.revision.mission_id
    db = kernel.phase0b.phase0a.database
    running_json = db.get("mission_states", mission_id)
    assert running_json is not None
    kernel.phase0b.phase0a.mission_manager.pause_mission(
        mission_id,
        expected_version=seeded.seeded.running_state.mission_state_version,
        actor_token=support.OPERATOR_ACTOR_TOKEN,
    )
    # Restore a previously valid row and its row checksum while leaving the TPM
    # generation/audit records current: the witnessed projection must still stop it.
    db.overwrite("mission_states", mission_id, running_json)
    with pytest.raises(AnchorRecoveryRequiredError, match="mission_authorization"):
        kernel.critical_witness_barrier.verify_current_security_state()


def test_runtime_rbac_update_cannot_bypass_mission_witness() -> None:
    kernel = s.make_phase0c()
    seeded = p0b.seed_authorized(kernel.phase0b)
    with pytest.raises(RepositoryIntegrityError, match="witnessed mission authorization"):
        kernel.phase0b.phase0a.role_assignment_repository.save(
            MissionRoleAssignment(
                mission_id=seeded.seeded.revision.mission_id,
                principal_id="operator-1",
                role="mission_operator",
                active=False,
            )
        )


def test_phase1_knowledge_boundary_is_fixed_in_phase0c_policy() -> None:
    kernel = s.make_phase0c()
    assert "KNOWLEDGE_EVIDENCE_CHANGED" in kernel.critical_witness_barrier.policy.force_event_types
    assert "knowledge_evidence_head" in kernel.critical_witness_barrier.critical_record_types
    with pytest.raises(CriticalWitnessError, match="unregistered record type"):
        db = kernel.phase0b.phase0a.database
        with ApplicationUnitOfWork(
            db,
            aggregate_name="AuditAppendAggregate",
            operation_id="unknown-critical-type",
            input_digest="unknown-critical-type",
        ) as uow:
            kernel.audit_store.append_in_txn(
                mission_id="phase1-boundary",
                event_type="KNOWLEDGE_EVIDENCE_CHANGED",
                payload_digest="knowledge-head",
                actor_id="knowledge-service",
                occurred_at_iso="2026-01-15T12:00:00Z",
                record_type="unknown_knowledge_state",
                record_id="head-1",
                state_version=1,
                security_projection_digest="knowledge-head",
            )
            uow.record_result("must-not-commit")


def test_dispatch_does_not_reach_adapter_when_claim_witness_fails(monkeypatch) -> None:
    kernel = s.make_phase0c()
    seeded = p0b.seed_authorized(kernel.phase0b)
    p0b.authorize(seeded)

    def fail_witness(_intent_id: str):
        raise CriticalWitnessError("injected witness failure")

    monkeypatch.setattr(kernel.critical_witness_barrier, "complete", fail_witness)
    with pytest.raises(CriticalWitnessError, match="injected witness failure"):
        kernel.phase0b.executor.dispatch(execution_id=seeded.execution_id, plan=seeded.plan)
    assert kernel.phase0b.mock_adapter.submit_calls == 0


def test_normal_audit_batch_is_witnessed_at_fixed_event_threshold() -> None:
    kernel = s.make_phase0c()
    db = kernel.phase0b.phase0a.database
    before = kernel.generation_coordinator.current("audit_head")
    assert before is not None
    with ApplicationUnitOfWork(
        db, aggregate_name="AuditAppendAggregate", operation_id="telemetry-batch", input_digest="batch"
    ) as uow:
        for index in range(256):
            kernel.audit_store.append_in_txn(
                mission_id="telemetry-mission", event_type="TELEMETRY",
                payload_digest=f"telemetry-{index}", actor_id="telemetry",
                occurred_at_iso=f"2026-01-15T12:{index // 60:02d}:{index % 60:02d}Z",
            )
        uow.record_result("batch")
    after = kernel.generation_coordinator.current("audit_head")
    assert after is not None and after.generation == before.generation + 1


def test_normal_audit_batch_is_witnessed_at_fixed_time_threshold() -> None:
    kernel = s.make_phase0c()
    db = kernel.phase0b.phase0a.database
    with ApplicationUnitOfWork(
        db, aggregate_name="AuditAppendAggregate", operation_id="time-baseline", input_digest="baseline"
    ) as uow:
        kernel.audit_store.append_in_txn(
            mission_id="time-mission", event_type="SECRET_REVOKED", payload_digest="forced",
            actor_id="operator", occurred_at_iso="2026-01-15T12:00:00Z",
            record_type="audit_chain_head", record_id="time-mission",
            state_version=1, security_projection_digest="forced",
        )
        uow.record_result("baseline")
    before = kernel.generation_coordinator.current("audit_head")
    assert before is not None
    with ApplicationUnitOfWork(
        db, aggregate_name="AuditAppendAggregate", operation_id="time-threshold", input_digest="threshold"
    ) as uow:
        kernel.audit_store.append_in_txn(
            mission_id="time-mission", event_type="TELEMETRY", payload_digest="normal",
            actor_id="telemetry", occurred_at_iso="2026-01-15T12:05:00Z",
        )
        uow.record_result("threshold")
    after = kernel.generation_coordinator.current("audit_head")
    assert after is not None and after.generation == before.generation + 1


def test_first_normal_audit_window_is_witnessed_after_300_seconds() -> None:
    kernel = s.make_phase0c()
    db = kernel.phase0b.phase0a.database
    before = kernel.generation_coordinator.current("audit_head")
    assert before is not None
    for operation_id, timestamp in (
        ("first-normal", "2026-01-15T12:00:00Z"),
        ("first-window-due", "2026-01-15T12:05:00Z"),
    ):
        with ApplicationUnitOfWork(
            db,
            aggregate_name="AuditAppendAggregate",
            operation_id=operation_id,
            input_digest=operation_id,
        ) as uow:
            kernel.audit_store.append_in_txn(
                mission_id="first-window",
                event_type="TELEMETRY",
                payload_digest=operation_id,
                actor_id="telemetry",
                occurred_at_iso=timestamp,
            )
            uow.record_result(operation_id)
    after = kernel.generation_coordinator.current("audit_head")
    assert after is not None and after.generation == before.generation + 1


def _wrapped_envelope(kernel):
    metadata = kernel.eraser._keys.create_resource_key(
        domain="audit_signing", resource_binding_type="provider_state", resource_binding_id="provider-state-1"
    )
    with kernel.eraser._keys.open_resource_key_handle(metadata=metadata, operation="encrypt") as handle:
        envelope = handle.encrypt(
            encryption_metadata_id=metadata.resource_key_id,
            nonce=b"\x07" * 12,
            plaintext=b"opaque-encrypted-provider-state",
            aad_fields={"provider_identity": kernel.key_provider_identity},
        )
    digests = tuple(
        kernel.eraser._keys.get_active_domain_key_metadata(domain).metadata_digest
        for domain in ("secret_store", "raw_result_quarantine", "artifact_store", "audit_signing")
    )
    return envelope, digests


def test_provider_mutation_is_witnessed_before_key_use(monkeypatch) -> None:
    kernel = s.make_phase0c()
    before = kernel.generation_coordinator.current("wrapped_key_state")
    assert before is not None
    metadata = kernel.eraser._keys.create_resource_key(
        domain="secret_store", resource_binding_type="secret_version_id", resource_binding_id="auto-v1"
    )
    after = kernel.generation_coordinator.current("wrapped_key_state")
    assert after is not None and after.generation == before.generation + 1
    assert kernel.wrapped_key_state_service.current().state_digest == after.state_digest

    def fail_commit(**_kwargs):
        raise GenerationWitnessError("injected wrapped-state failure")

    monkeypatch.setattr(kernel.wrapped_key_state_service, "commit", fail_commit)
    with pytest.raises(GenerationWitnessError, match="injected wrapped-state failure"):
        kernel.eraser._keys.create_resource_key(
            domain="secret_store", resource_binding_type="secret_version_id", resource_binding_id="blocked-v2"
        )
    with pytest.raises(EncryptionUnavailableError, match="not selected"):
        kernel.eraser._keys.open_resource_key_handle(metadata=metadata, operation="encrypt")


def test_wrapped_provider_state_is_content_witnessed_and_replay_safe() -> None:
    kernel = s.make_phase0c()
    envelope, digests = _wrapped_envelope(kernel)
    state = kernel.wrapped_key_state_service.commit(
        operation_id="provider-state-1", provider_identity=kernel.key_provider_identity,
        domain_key_metadata_digests=digests, active_domain_key_bindings_digest="active-bindings",
        wrapped_envelope=envelope,
    )
    current = kernel.generation_coordinator.current("wrapped_key_state")
    assert current is not None and current.state_digest == state.state_digest
    replay = kernel.wrapped_key_state_service.commit(
        operation_id="provider-state-1", provider_identity=kernel.key_provider_identity,
        domain_key_metadata_digests=digests, active_domain_key_bindings_digest="active-bindings",
        wrapped_envelope=envelope,
    )
    assert replay.state_digest == state.state_digest


def test_missing_witnessed_provider_blob_fails_closed() -> None:
    kernel = s.make_phase0c()
    envelope, digests = _wrapped_envelope(kernel)
    state = kernel.wrapped_key_state_service.commit(
        operation_id="provider-state-1", provider_identity=kernel.key_provider_identity,
        domain_key_metadata_digests=digests, active_domain_key_bindings_digest="active-bindings",
        wrapped_envelope=envelope,
    )
    kernel.wrapped_state_blobs.delete_prefix(state.wrapped_provider_state_blob_id)
    with pytest.raises(GenerationWitnessError):
        kernel.wrapped_key_state_service.current()
