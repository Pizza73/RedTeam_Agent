"""Crash boundaries: restart resumes ingestion only, never re-runs the external action."""

from __future__ import annotations

import pytest

import support
import support_phase0b as p0b
from redteam_agent.composition.execution_testing import build_phase0b_kernel
from redteam_agent.execution.records import compute_progress_digest, finalize_object_digest
from redteam_agent.storage.database import UnitOfWork


def _seed_and_dispatch_on(kernel: object):  # type: ignore[no-untyped-def]
    seeded = p0b.seed_authorized(kernel)  # type: ignore[arg-type]
    p0b.authorize(seeded)
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)  # type: ignore[attr-defined]
    return seeded


def test_restart_after_dispatch_does_not_resubmit() -> None:
    kernel1 = p0b.make_kernel()
    _seed_and_dispatch_on(kernel1)
    assert kernel1.mock_adapter.submit_calls == 1
    before = kernel1.execution_repository.get("exec-1")
    assert before is not None and before.provider_execution_state == "DISPATCHED"

    # Simulate a process restart: a fresh execution-safety worker (new services,
    # new adapter, new write guard) over the same durable database + authorization
    # kernel. The external action already happened; the durable state persists.
    kernel2 = build_phase0b_kernel(phase0a=kernel1.phase0a, clock=kernel1.phase0a.clock)
    after = kernel2.execution_repository.get("exec-1")
    assert after is not None and after.provider_execution_state == "DISPATCHED"
    # The restarted worker performs no external submit on its own.
    assert kernel2.mock_adapter.submit_calls == 0
    # Result collection resumes against the durable state (ingestion only).
    kernel2.collection_coordinator.start_collection(execution_id="exec-1")
    result = kernel2.collection_coordinator.collect(execution_id="exec-1")
    assert result.status == "COMPLETE"
    assert kernel2.mock_adapter.submit_calls == 0  # still no resubmit


def test_collection_resume_after_commit_is_metadata_only() -> None:
    kernel = p0b.make_kernel()
    _seed_and_dispatch_on(kernel)
    kernel.collection_coordinator.start_collection(execution_id="exec-1")
    # Simulate a crash after sink commit: durable state at COMMITTED_METADATA_PENDING
    # with a committed receipt, before control-metadata normalization.
    state = kernel.collection_state_repository.get("collection-state-exec-1")
    ds = kernel.phase0a.digest_service
    committed = finalize_object_digest(
        state.model_copy(
            update={
                "state_version": state.state_version + 1, "status": "COMMITTED_METADATA_PENDING",
                "receipt_id": "receipt-exec-1", "receipt_digest": "rcpt-digest",
                "last_committed_chunk_sequence": 1,
                "last_progress_digest": compute_progress_digest(
                    collection_id=state.collection_id, status="COMMITTED_METADATA_PENDING",
                    last_committed_chunk_sequence=1, receipt_digest="rcpt-digest", digest_service=ds,
                ),
            }
        ),
        digest_field="record_digest", digest_name="result_collection_state_digest", digest_service=ds,
    )
    with UnitOfWork(kernel.phase0a.database):
        kernel.collection_state_repository.update(
            committed, expected_version=state.state_version, guard=kernel.execution_guard
        )
    # Resume: metadata-only recovery completes without re-streaming.
    result = kernel.collection_coordinator.collect(execution_id="exec-1")
    assert result.status == "COMPLETE"
    assert kernel.mock_adapter.collect_calls == 0  # no re-stream
    assert kernel.mock_adapter.get_control_calls == 1  # metadata-only


def test_uncertain_submit_crash_reconciles_without_resubmit() -> None:
    kernel = p0b.make_kernel(fail_on_submit=True, reconcile_status="UNKNOWN")
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "OUTCOME_UNKNOWN"
    assert kernel.mock_adapter.submit_calls == 1  # the single attempt is not repeated


def test_local_result_restart_finishes_from_durable_metadata_only(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel1 = p0b.make_kernel(result_delivery_mode="local_result")
    tool = support.network_tool().model_copy(update={"adapter": "local"})
    seeded = p0b.seed_authorized(kernel1, tool=tool)
    p0b.authorize(seeded)

    def crash_before_complete(**_: object) -> object:
        raise RuntimeError("simulated crash after local receipt/control commit")

    monkeypatch.setattr(kernel1.collection_coordinator, "_complete", crash_before_complete)
    with pytest.raises(RuntimeError):
        kernel1.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    state = kernel1.collection_state_repository.get("collection-state-exec-1")
    assert state is not None and state.status == "COMMITTED_METADATA_PENDING"
    assert kernel1.mock_adapter.submit_calls == 1

    kernel2 = build_phase0b_kernel(
        phase0a=kernel1.phase0a,
        clock=kernel1.phase0a.clock,
        result_delivery_mode="local_result",
    )
    result = kernel2.collection_coordinator.collect(execution_id="exec-1")
    assert result.status == "COMPLETE"
    assert kernel2.mock_adapter.submit_calls == 0
    assert kernel2.mock_adapter.collect_calls == 0
    assert kernel2.mock_adapter.get_control_calls == 0
