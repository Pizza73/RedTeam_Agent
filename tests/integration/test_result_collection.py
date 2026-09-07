"""Result collection: trusted-clock authority, fixed limits, streaming, separation."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
import support_phase0b as p0b
from redteam_agent.errors import ResultCollectionError


def _dispatched(kernel: object):  # type: ignore[no-untyped-def]
    k = kernel  # type: ignore[assignment]
    seeded = p0b.seed_authorized(k)  # type: ignore[arg-type]
    p0b.authorize(seeded)
    k.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # type: ignore[attr-defined]
    return seeded


def test_authority_fixes_deadline_retention_and_output_cap() -> None:
    kernel = p0b.make_kernel()
    seeded = _dispatched(kernel)
    authority = kernel.collection_coordinator.start_collection(execution_id="exec-1")
    mission = seeded.seeded.revision
    assert authority.collection_deadline == mission.recovery_until
    # retention is min(start + policy, evidence_retention_until); here capped by evidence.
    assert authority.retention_until == mission.evidence_retention_until
    # output cap is the tool's cap (never widened by a global/system setting).
    assert authority.max_output_bytes == seeded.seeded.tool.max_output_bytes


def test_retention_not_recomputed_on_resume() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    authority1 = kernel.collection_coordinator.start_collection(execution_id="exec-1")
    # Advance the trusted clock, then "resume" collection: the fixed authority must
    # be returned unchanged (retention/deadline/start not recomputed).
    kernel.phase0a.clock.set(authority1.collection_started_at + timedelta(hours=1))  # type: ignore[attr-defined]
    authority2 = kernel.collection_coordinator.start_collection(execution_id="exec-1")
    assert authority2.collection_started_at == authority1.collection_started_at
    assert authority2.retention_until == authority1.retention_until
    assert authority2.collection_deadline == authority1.collection_deadline


def test_collect_streams_to_complete_and_starts_ingestion() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    result = kernel.collection_coordinator.collect(execution_id="exec-1")
    assert result.status == "COMPLETE"
    assert result.receipt_id is not None
    assert result.ingestion_id is not None
    # Provider terminal state settled from the confirmed control metadata.
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and record.provider_execution_state == "SUCCEEDED"
    # Ingestion started independently at PENDING.
    ingestion = kernel.ingestion_repository.get(result.ingestion_id)
    assert ingestion is not None and ingestion.status == "PENDING"
    control = kernel.control_metadata_repository.find_by_execution("exec-1")
    assert control is not None and control.provider_status == "succeeded"


def test_collection_and_ingestion_states_are_separate_records() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    kernel.collection_coordinator.collect(execution_id="exec-1")
    coll = kernel.collection_state_repository.get("collection-state-exec-1")
    ing = kernel.ingestion_repository.find_by_execution("exec-1")
    assert coll is not None and coll.status == "COMPLETE"
    assert ing is not None and ing.status == "PENDING"
    # Distinct records with distinct ids and version counters.
    assert coll.collection_state_id != ing.ingestion_id


def test_collect_is_idempotent_after_complete() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    first = kernel.collection_coordinator.collect(execution_id="exec-1")
    calls = kernel.mock_adapter.collect_calls
    second = kernel.collection_coordinator.collect(execution_id="exec-1")
    assert second.status == "COMPLETE"
    assert first.receipt_id == second.receipt_id
    assert kernel.mock_adapter.collect_calls == calls  # no re-stream


def test_abandon_from_streaming_is_terminal() -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    result = kernel.collection_coordinator.abandon(execution_id="exec-1", reason="recovery window elapsed")
    assert result.status == "ABANDONED"
    # An abandoned collection is never re-collected into a provider result.
    again = kernel.collection_coordinator.collect(execution_id="exec-1")
    assert again.status == "ABANDONED"
    assert kernel.mock_adapter.collect_calls == 0


def test_local_result_streams_during_submit_without_provider_collection() -> None:
    kernel = p0b.make_kernel(result_delivery_mode="local_result")
    tool = support.network_tool().model_copy(update={"adapter": "local"})
    seeded = p0b.seed_authorized(kernel, tool=tool)
    p0b.authorize(seeded)
    outcome = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert outcome.provider_execution_state == "SUCCEEDED"
    assert outcome.task_binding is not None
    assert outcome.task_binding.binding_type == "local_result"
    assert kernel.mock_adapter.submissions[0].capture_id == outcome.task_binding.capture_id
    assert kernel.mock_adapter.submit_calls == 1
    assert kernel.mock_adapter.collect_calls == 0
    assert kernel.mock_adapter.get_control_calls == 0
    collection = kernel.collection_state_repository.get("collection-state-exec-1")
    ingestion = kernel.ingestion_repository.find_by_execution("exec-1")
    assert collection is not None and collection.status == "COMPLETE"
    assert ingestion is not None and ingestion.status == "PENDING"
    assert not hasattr(outcome.task_binding, "provider_task_id")


def test_collection_at_valid_until_requires_fresh_authority_for_each_step() -> None:
    kernel = p0b.make_kernel()
    seeded = _dispatched(kernel)
    kernel.phase0a.clock.set(seeded.seeded.revision.valid_until)
    with pytest.raises(ResultCollectionError):
        kernel.collection_coordinator.start_collection(execution_id="exec-1")
    start_auth = kernel.recovery_service.issue_authority(
        authority_id="ra-start", execution_id="exec-1",
        allowed_operation="collect_result", reason="start",
    )
    kernel.collection_coordinator.start_collection(
        execution_id="exec-1", recovery_authority_id=start_auth.authority_id
    )
    with pytest.raises(ResultCollectionError):
        kernel.collection_coordinator.collect(execution_id="exec-1")
    collect_auth = kernel.recovery_service.issue_authority(
        authority_id="ra-collect", execution_id="exec-1",
        allowed_operation="collect_result", reason="collect",
    )
    result = kernel.collection_coordinator.collect(
        execution_id="exec-1", recovery_authority_id=collect_auth.authority_id
    )
    assert result.status == "COMPLETE"


def test_collection_at_recovery_until_never_reads_provider() -> None:
    kernel = p0b.make_kernel()
    seeded = _dispatched(kernel)
    kernel.phase0a.clock.set(seeded.seeded.revision.recovery_until)
    with pytest.raises(ResultCollectionError):
        kernel.collection_coordinator.start_collection(execution_id="exec-1")
    assert kernel.mock_adapter.collect_calls == 0


def test_collection_rejects_unregistered_normalization_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = p0b.make_kernel()
    _dispatched(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    original = kernel.mock_adapter._control

    def wrong_rule():  # type: ignore[no-untyped-def]
        return original().model_copy(update={"status_normalization_rule_id": "attacker-rule"})

    monkeypatch.setattr(kernel.mock_adapter, "_control", wrong_rule)
    with pytest.raises(ResultCollectionError):
        kernel.collection_coordinator.collect(execution_id="exec-1")
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and record.provider_execution_state == "RUNNING"
