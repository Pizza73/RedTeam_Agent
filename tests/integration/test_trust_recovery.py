"""Explicit offline trust recovery and one-time approval consumption (§34.2.2)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

import support
import support_phase0c as s
from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.nv_witness import InMemoryNvExtendWitness
from redteam_agent.audit.trust_recovery import OfflineTrustRecoveryService, StaticWorkerStopVerifier
from redteam_agent.canonical.digest_catalog import CATALOG_REVISION
from redteam_agent.errors import LeaseError, TrustRecoveryError
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.execution.records import finalize_provider_task_binding
from redteam_agent.storage.unit_of_work import ArmedFaultInjector, CommitBoundaryFault


def _new_coordinator(kernel):
    ds = kernel.phase0b.phase0a.digest_service
    witness = InMemoryNvExtendWitness(
        digest_service=ds, trust_epoch=2, device_identity="replacement-device", incarnation="replacement-1"
    )
    coordinator = AuthenticatedGenerationCoordinator(
        database=kernel.phase0b.phase0a.database, witness=witness,
        record_store=kernel.generation_store, digest_service=ds,
        trust_epoch=2, digest_catalog_revision=CATALOG_REVISION,
    )
    return witness, coordinator


def _service(kernel, evidence: str = "workers-stopped", fault_injector=None) -> OfflineTrustRecoveryService:
    return OfflineTrustRecoveryService(
        database=kernel.phase0b.phase0a.database,
        digest_service=kernel.phase0b.phase0a.digest_service,
        clock=kernel.monotonic_clock,
        recovery_guard=kernel.data_guard,
        epoch_service=kernel.epoch_service,
        lease_service=kernel.lease_service,
        worker_stop_verifier=StaticWorkerStopVerifier(evidence),
        authorization_invalidator=kernel.phase0b.phase0a.mission_manager,
        fault_injector=fault_injector,
    )


def _approval(kernel, coordinator, service, *, expires_delta: int = 3600):
    old_records = {
        namespace: kernel.generation_coordinator.current(namespace)
        for namespace in ("audit_head", "wrapped_key_state")
    }
    assert all(record is not None for record in old_records.values())
    adopted = {
        "audit_head": ("adopted-audit-state", '{"recovered":"audit"}'),
        "wrapped_key_state": ("adopted-key-state", '{"recovered":"keys"}'),
    }
    old_ids = tuple(
        kernel.generation_coordinator.witness_identity(role).identity_digest
        for role in ("audit_head", "wrapped_key_state", "deployment_epoch")
    )
    new_ids = tuple(
        coordinator.witness_identity(role).identity_digest
        for role in ("audit_head", "wrapped_key_state", "deployment_epoch")
    )
    approval = service.build_approval(
        guard=kernel.data_guard, approval_id="recovery-1", old_trust_epoch=1, new_trust_epoch=2,
        old_nv_identity_digests=old_ids, new_nv_identity_digests=new_ids,
        last_verified={
            namespace: (record.record_digest, record.witness_digest)
            for namespace, record in old_records.items() if record is not None
        },
        adopted=adopted, worker_stop_evidence_digest="workers-stopped",
        adoption_reason="TPM replacement after verified reset", approver_id="security-admin",
        issued_at=support.T0, expires_at=support.T0 + timedelta(seconds=expires_delta),
    )
    return approval, {namespace: value[1] for namespace, value in adopted.items()}


def _live_lease(kernel):
    ds = kernel.phase0b.phase0a.digest_service
    binding = finalize_provider_task_binding(
        ProviderTaskBinding(
            task_id="task", execution_id="exec", adapter_identity_digest="adapter",
            provider_identity_digest="provider", provider_task_id="provider-task",
            dispatch_claim_id="claim", binding_digest="pending",
        ),
        ds,
    )
    return kernel.lease_service.acquire_collection_lease(
        collection_id="recovery-lease", execution_id="exec", authority_digest="authority",
        task_binding=binding, sink_id="sink", owner_id="old-worker",
        expected_execution_state_version=1,
        caps=(support.T0 + timedelta(days=1),),
    )


def test_recovery_consumes_exact_approval_and_invalidates_old_leases() -> None:
    kernel = s.make_phase0c()
    dispatched = s.seed_dispatched(kernel)
    before_mission = kernel.phase0b.phase0a.state_repository.get(dispatched.mission_id)
    assert before_mission is not None
    lease = _live_lease(kernel)
    _witness, coordinator = _new_coordinator(kernel)
    service = _service(kernel)
    approval, contents = _approval(kernel, coordinator, service)
    consumed = service.recover(
        approval_id=approval.approval_id, new_coordinator=coordinator,
        adopted_contents=contents, provider_identity=kernel.key_provider_identity,
    )
    assert consumed.new_trust_epoch == 2 and consumed.deployment_epoch == 1
    assert consumed.invalidated_authorization_count == 1
    mirror = kernel.epoch_service.current()
    assert mirror is not None and mirror.trust_epoch == 2
    after_mission = kernel.phase0b.phase0a.state_repository.get(dispatched.mission_id)
    assert after_mission is not None
    assert after_mission.authorization_epoch == before_mission.authorization_epoch + 1
    assert after_mission.mission_state_version == before_mission.mission_state_version + 1
    recovery_witness = coordinator.current("audit_head")
    assert recovery_witness is not None and recovery_witness.generation == 1
    recovery_content = json.loads(coordinator.record_content(recovery_witness))
    assert recovery_witness.state_digest == kernel.phase0b.phase0a.digest_service.compute(
        "security_projection_digest", {
            "trust_recovery_consumption_digest": consumed.consumption_digest,
            "audit_head_state": recovery_content,
        },
    )
    assert recovery_content["recovered"] == "audit"
    assert recovery_content["trust_recovery_consumption"]["consumption_digest"] == (
        consumed.consumption_digest
    )
    with pytest.raises(LeaseError):
        kernel.lease_service.validate_collection_lease(
            collection_id="recovery-lease", owner_id="old-worker", lease_id=lease.lease_id,
            fence=lease.fence, authority_digest="authority", expected_execution_state_version=1,
        )
    replay = service.recover(
        approval_id=approval.approval_id, new_coordinator=coordinator,
        adopted_contents=contents, provider_identity=kernel.key_provider_identity,
    )
    assert replay.consumption_digest == consumed.consumption_digest


def test_recovery_replay_rejects_rolled_back_mission_authorization() -> None:
    kernel = s.make_phase0c()
    dispatched = s.seed_dispatched(kernel)
    before = kernel.phase0b.phase0a.state_repository.get(dispatched.mission_id)
    assert before is not None
    _witness, coordinator = _new_coordinator(kernel)
    service = _service(kernel)
    approval, contents = _approval(kernel, coordinator, service)
    service.recover(
        approval_id=approval.approval_id,
        new_coordinator=coordinator,
        adopted_contents=contents,
        provider_identity=kernel.key_provider_identity,
    )
    kernel.phase0b.phase0a.database.overwrite(
        "mission_states",
        dispatched.mission_id,
        json.dumps(before.model_dump(mode="json"), sort_keys=True),
    )
    with pytest.raises(TrustRecoveryError, match="mission authorization state"):
        service.recover(
            approval_id=approval.approval_id,
            new_coordinator=coordinator,
            adopted_contents=contents,
            provider_identity=kernel.key_provider_identity,
        )


def test_recovery_replay_completes_consumption_witness_after_commit_crash() -> None:
    kernel = s.make_phase0c()
    _witness, coordinator = _new_coordinator(kernel)
    service = _service(kernel, fault_injector=ArmedFaultInjector("after_recovery_consumption_commit"))
    approval, contents = _approval(kernel, coordinator, service)
    with pytest.raises(CommitBoundaryFault):
        service.recover(
            approval_id=approval.approval_id, new_coordinator=coordinator,
            adopted_contents=contents, provider_identity=kernel.key_provider_identity,
        )
    current = coordinator.current("audit_head")
    assert current is not None and current.generation == 0
    recovered = service.recover(
        approval_id=approval.approval_id, new_coordinator=coordinator,
        adopted_contents=contents, provider_identity=kernel.key_provider_identity,
    )
    current = coordinator.current("audit_head")
    assert current is not None and current.generation == 1
    recovery_content = json.loads(coordinator.record_content(current))
    assert current.state_digest == kernel.phase0b.phase0a.digest_service.compute(
        "security_projection_digest", {
            "trust_recovery_consumption_digest": recovered.consumption_digest,
            "audit_head_state": recovery_content,
        },
    )


def test_recovery_rejects_unapproved_adopted_content_before_genesis() -> None:
    kernel = s.make_phase0c()
    witness, coordinator = _new_coordinator(kernel)
    service = _service(kernel)
    approval, contents = _approval(kernel, coordinator, service)
    contents["audit_head"] = '{"attacker":"selected"}'
    with pytest.raises(TrustRecoveryError, match="adopted content"):
        service.recover(
            approval_id=approval.approval_id, new_coordinator=coordinator,
            adopted_contents=contents, provider_identity=kernel.key_provider_identity,
        )
    assert not witness.public_area("audit_head").written


def test_recovery_rejects_a_preadvanced_new_witness() -> None:
    kernel = s.make_phase0c()
    _witness, coordinator = _new_coordinator(kernel)
    service = _service(kernel)
    approval, contents = _approval(kernel, coordinator, service)
    audit = next(item for item in approval.adoptions if item.namespace == "audit_head")
    coordinator.genesis(
        "audit_head", initial_state_digest=audit.adopted_state_digest,
        initial_content=contents["audit_head"],
    )
    coordinator.commit(
        "audit_head", new_state_digest="attacker-state", new_content='{"attacker":true}',
        operation_id="unapproved-before-recovery",
    )
    with pytest.raises(TrustRecoveryError, match="unapproved generation"):
        service.recover(
            approval_id=approval.approval_id, new_coordinator=coordinator,
            adopted_contents=contents, provider_identity=kernel.key_provider_identity,
        )


def test_recovery_rejects_worker_stop_mismatch_and_expired_approval() -> None:
    kernel = s.make_phase0c()
    _witness, coordinator = _new_coordinator(kernel)
    wrong_workers = _service(kernel, evidence="workers-still-running")
    approval, contents = _approval(kernel, coordinator, wrong_workers)
    with pytest.raises(TrustRecoveryError, match="worker-stop"):
        wrong_workers.recover(
            approval_id=approval.approval_id, new_coordinator=coordinator,
            adopted_contents=contents, provider_identity=kernel.key_provider_identity,
        )

    expired_kernel = s.make_phase0c()
    expired_kernel.monotonic_clock.advance(seconds=10)
    _witness2, coordinator2 = _new_coordinator(expired_kernel)
    expired_service = _service(expired_kernel)
    expired, expired_contents = _approval(expired_kernel, coordinator2, expired_service, expires_delta=5)
    with pytest.raises(TrustRecoveryError, match="not currently valid"):
        expired_service.recover(
            approval_id=expired.approval_id, new_coordinator=coordinator2,
            adopted_contents=expired_contents, provider_identity=expired_kernel.key_provider_identity,
        )


def test_recovery_without_stored_approval_fails_closed() -> None:
    kernel = s.make_phase0c()
    _witness, coordinator = _new_coordinator(kernel)
    with pytest.raises(TrustRecoveryError, match="missing"):
        _service(kernel).recover(
            approval_id="absent", new_coordinator=coordinator, adopted_contents={},
            provider_identity=kernel.key_provider_identity,
        )
