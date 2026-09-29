"""Regression tests for the Phase 0C independent Common Gate review findings."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest

import support
import support_phase0b as p0b
import support_phase0c as p0c
from redteam_agent.audit.models import ImmutableGenerationBlob
from redteam_agent.composition.phase0c import build_phase0c_kernel
from redteam_agent.errors import (
    ExecutionRecordError,
    GenerationWitnessError,
    LeaseError,
    RawResultQuarantineError,
    ResultCollectionError,
    ResultIngestionError,
)
from redteam_agent.runtime.clock import ManualMonotonicClock
from redteam_agent.storage.database import UnitOfWork


def test_phase0b_compatibility_callers_converge_on_encrypted_pipeline() -> None:
    phase0b = p0b.make_kernel(stdout_chunks=(p0c.DEFAULT_STDOUT,))
    kernel = build_phase0c_kernel(
        phase0b=phase0b, monotonic_clock=ManualMonotonicClock(support.T0)
    )
    seeded = p0b.seed_authorized(kernel.phase0b)
    p0b.authorize(seeded)
    kernel.phase0b.executor.dispatch(execution_id=seeded.execution_id, plan=seeded.plan)

    kernel.phase0b.collection_coordinator.start_collection(execution_id=seeded.execution_id)
    collected = kernel.phase0b.collection_coordinator.collect(execution_id=seeded.execution_id)
    assert collected.status == "COMPLETE"
    metadata = kernel.quarantine_metadata.get(f"q-{seeded.execution_id}")
    assert metadata is not None and metadata.status == "COMMITTED" and metadata.chunk_count > 0

    published = kernel.phase0b.ingestion_coordinator.ingest(execution_id=seeded.execution_id)
    assert published.status == "DELETE_PENDING"
    assert published.redacted_artifact_ids and published.detected_secret_version_ids


def test_retained_phase0b_service_references_are_irreversibly_retired() -> None:
    phase0b = p0b.make_kernel(stdout_chunks=(p0c.DEFAULT_STDOUT,))
    legacy_collection = phase0b.collection_coordinator
    legacy_ingestion = phase0b.ingestion_coordinator
    kernel = build_phase0c_kernel(
        phase0b=phase0b, monotonic_clock=ManualMonotonicClock(support.T0)
    )
    phase0b.collection_coordinator = legacy_collection
    phase0b.ingestion_coordinator = legacy_ingestion
    with pytest.raises(ResultCollectionError, match="retired"):
        legacy_collection.start_collection(execution_id="missing")
    with pytest.raises(ResultIngestionError, match="retired"):
        legacy_ingestion.ingest(execution_id="missing")
    assert kernel.phase0b is phase0b


def test_phase0c_collection_requires_recovery_authority_after_valid_until() -> None:
    kernel = p0c.make_phase0c()
    dispatched = p0c.seed_dispatched(kernel)
    mission = kernel.phase0b.phase0a.revision_repository.get(dispatched.mission_id, 1)
    assert mission is not None
    kernel.phase0b.phase0a.clock.set(mission.valid_until)
    seconds = (mission.valid_until - support.T0).total_seconds()
    kernel.monotonic_clock.advance(seconds=seconds)
    with pytest.raises(RawResultQuarantineError, match="recovery authority"):
        kernel.collection_service.collect(
            execution_id=dispatched.execution_id, stdout=b"{}", stderr=b"",
            control=p0c.collection_control(),
        )
    authority = kernel.phase0b.recovery_service.issue_authority(
        authority_id="phase0c-collect", execution_id=dispatched.execution_id,
        allowed_operation="collect_result", reason="resume encrypted collection",
    )
    kernel.collection_service.validate_collection_request(
        execution_id=dispatched.execution_id,
        recovery_authority_id=authority.authority_id,
    )


def test_local_result_dispatch_streams_directly_to_encrypted_quarantine() -> None:
    tool = support.network_tool().model_copy(update={"adapter": "local"})
    phase0b = p0b.make_kernel(
        result_delivery_mode="local_result", stdout_chunks=(p0c.DEFAULT_STDOUT,)
    )
    kernel = build_phase0c_kernel(
        phase0b=phase0b, monotonic_clock=ManualMonotonicClock(support.T0)
    )
    seeded = p0b.seed_authorized(kernel.phase0b, tool=tool)
    p0b.authorize(seeded)
    outcome = kernel.phase0b.executor.dispatch(execution_id=seeded.execution_id, plan=seeded.plan)
    assert outcome.reason_code == "LOCAL_COMPLETE"
    metadata = kernel.quarantine_metadata.get(f"q-{seeded.execution_id}")
    assert metadata is not None and metadata.status == "COMMITTED" and metadata.chunk_count == 1
    assert kernel.phase0b.ingestion_repository.find_by_execution(seeded.execution_id) is not None


def test_phase0c_kernel_exposes_only_metadata_views() -> None:
    kernel = p0c.make_phase0c()
    assert not hasattr(kernel, "quarantine_store")
    assert not hasattr(kernel, "secret_store")
    assert not hasattr(kernel, "artifact_store")
    assert not hasattr(kernel, "key_provider")
    assert not hasattr(kernel, "quarantine_blobs")
    assert not hasattr(kernel.quarantine_metadata, "open_reader")
    assert not hasattr(kernel.quarantine_metadata, "unlink_ciphertext")
    assert not hasattr(kernel.secret_metadata, "open_version")
    assert not hasattr(kernel.secret_metadata, "confirm")


def test_executor_phase0c_dependencies_cannot_be_rebound() -> None:
    kernel = p0c.make_phase0c()
    with pytest.raises(ExecutionRecordError, match="already bound"):
        kernel.phase0b.executor.bind_phase0c_dependencies(
            guard=kernel.phase0b.execution_guard,
            collection_coordinator=kernel.phase0b.collection_coordinator,
            secret_source=object(),  # type: ignore[arg-type]
            secret_metadata_reader=kernel.secret_metadata,
        )


def test_measured_epoch_mismatch_stops_leases_and_scheduler() -> None:
    kernel = p0c.make_phase0c()
    kernel.nv_witness.increment_counter("deployment_epoch")
    with pytest.raises(LeaseError):
        kernel.lease_service.verify_current_epoch()
    with pytest.raises(ResultIngestionError):
        kernel.retention_scheduler.expire_evidence_retention(
            ingestion_id="missing", expected_state_version=1
        )


def test_generation_blob_row_key_and_content_address_are_verified() -> None:
    kernel = p0c.make_phase0c()
    record = kernel.generation_coordinator.current("audit_head")
    assert record is not None
    row = kernel.phase0b.phase0a.database.occ_get("generation_blob", record.immutable_blob_id)
    assert row is not None
    content = '{"attacker": true}'
    digest = hashlib.sha256(f"gen-blob-v1\x00{content}".encode()).hexdigest()
    substituted = ImmutableGenerationBlob(
        blob_id=f"blob-audit_head-{digest}", namespace="audit_head",
        content_kind="audit_head_set", content=content, blob_digest=digest,
    )
    with UnitOfWork(kernel.phase0b.phase0a.database):
        kernel.phase0b.phase0a.database.occ_update(
            "generation_blob", record.immutable_blob_id,
            expected_version=row[0], new_version=row[0] + 1,
            json_text=json.dumps(substituted.model_dump(mode="json"), sort_keys=True),
        )
    with pytest.raises(GenerationWitnessError):
        kernel.generation_coordinator.current("audit_head")


def test_collection_splits_outputs_larger_than_one_mib_into_bounded_chunks() -> None:
    kernel = p0c.make_phase0c()
    dispatched = p0c.seed_dispatched(kernel)
    payload = b"x" * (1024 * 1024 + 1)
    p0c.collect(kernel, execution_id=dispatched.execution_id, stdout=payload)
    metadata = kernel.quarantine_metadata.get(f"q-{dispatched.execution_id}")
    assert metadata is not None
    assert metadata.size_bytes == len(payload)
    assert metadata.chunk_count == 2


def test_stale_sink_cannot_write_after_fence_takeover() -> None:
    clock = ManualMonotonicClock(support.T0)
    kernel = p0c.make_phase0c(monotonic_clock=clock)
    dispatched = p0c.seed_dispatched(kernel)
    record = kernel.phase0b.execution_repository.get(dispatched.execution_id)
    binding = kernel.phase0b.task_binding_repository.find_by_execution(dispatched.execution_id)
    assert record is not None and binding is not None
    collection_id = f"collection-{record.execution_id}"
    quarantine_id = f"q-{record.execution_id}"
    authority_digest = kernel.phase0b.phase0a.digest_service.compute(
        "result_progress_digest", {"authority": collection_id, "task": binding.binding_digest}
    )
    caps = (support.T0 + timedelta(days=1),)
    first = kernel.lease_service.acquire_collection_lease(
        collection_id=collection_id, execution_id=record.execution_id,
        authority_digest=authority_digest, task_binding=binding, sink_id="sink",
        owner_id="old", expected_execution_state_version=record.execution_state_version, caps=caps,
    )
    with UnitOfWork(kernel.phase0b.phase0a.database):
        kernel.collection_service._quarantine.create_quarantine(
            quarantine_id=quarantine_id, mission_id=record.mission_id,
            mission_revision=record.mission_revision, execution_id=record.execution_id,
            task_binding=binding, deployment_epoch=first.fence.deployment_epoch,
            fencing_token=first.fence.fencing_token, retention_until=caps[0],
        )
    stale_sink = kernel.collection_service._quarantine.open_writer(
        quarantine_id, sink_id="sink", task_binding_digest=binding.binding_digest,
        max_output_bytes=8 * 1024 * 1024,
        deployment_epoch=first.fence.deployment_epoch,
        fencing_token=first.fence.fencing_token,
        authorize_mutation=lambda mutation: kernel.lease_service.run_collection_mutation(
            collection_id=collection_id, owner_id="old", lease_id=first.lease_id,
            fence=first.fence, authority_digest=authority_digest,
            expected_execution_state_version=record.execution_state_version, mutation=mutation,
        ),
    )
    clock.advance(seconds=kernel.lease_service.policy.lease_duration_seconds + 1)
    second = kernel.lease_service.takeover_collection_lease(
        collection_id=collection_id, execution_id=record.execution_id,
        authority_digest=authority_digest, task_binding=binding, sink_id="sink",
        new_owner_id="new", expected_execution_state_version=record.execution_state_version, caps=caps,
    )
    with UnitOfWork(kernel.phase0b.phase0a.database):
        metadata = kernel.collection_service._quarantine.create_quarantine(
            quarantine_id=quarantine_id, mission_id=record.mission_id,
            mission_revision=record.mission_revision, execution_id=record.execution_id,
            task_binding=binding, deployment_epoch=second.fence.deployment_epoch,
            fencing_token=second.fence.fencing_token, retention_until=caps[0],
        )
    assert metadata.storage_handle.endswith(f"/{second.fence.fencing_token}")
    with pytest.raises(LeaseError):
        stale_sink.write_stdout(b"stale")
