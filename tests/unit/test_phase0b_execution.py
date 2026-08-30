from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from redteam_agent.errors import RawResultQuarantineError, WorkflowRunBindingError
from redteam_agent.executor import MockRawResultSink, create_workflow_run, load_checkpoint_run
from redteam_agent.repositories import WorkflowRunRepository
from redteam_agent.seeds import FIXED_TIME
from tests.phase0b_helpers import build_execution_harness, prepare_execution


def test_raw_result_sink_streams_and_commit_is_idempotent() -> None:
    sink = MockRawResultSink(
        execution_id="execution-1",
        sink_id="sink-1",
        committed_at=FIXED_TIME,
        max_bytes=512,
    )

    async def exercise() -> None:
        for _ in range(32):
            await sink.write_stdout(b"0123456789")
        first = await sink.commit()
        second = await sink.commit()
        assert first == second

    asyncio.run(exercise())
    assert sink.bytes_received == 320
    assert sink.max_observed_chunk_bytes == 10
    assert not any("buffer" in name or "chunks" in name for name in vars(sink))


def test_raw_result_sink_fails_closed_on_quota() -> None:
    sink = MockRawResultSink(
        execution_id="execution-1",
        sink_id="sink-1",
        committed_at=FIXED_TIME,
        max_bytes=4,
    )
    with pytest.raises(RawResultQuarantineError):
        asyncio.run(sink.write_stdout(b"12345"))


def test_one_policy_decision_prepares_only_one_execution() -> None:
    harness = build_execution_harness()
    first = prepare_execution(harness)
    second_run = create_workflow_run(
        mission_id=first.mission_id,
        mission_revision=first.mission_revision,
        run_seed="second-run",
        created_at=FIXED_TIME + timedelta(minutes=2),
    )
    WorkflowRunRepository(harness.database).add(second_run)
    second = harness.executor.prepare(
        run=second_run,
        plan_id=first.plan_id,
        policy_decision_id=first.policy_decision_id,
        now=FIXED_TIME + timedelta(minutes=2),
    )
    count = harness.database.connection.execute(
        "SELECT COUNT(*) FROM execution_records WHERE policy_decision_id = ?",
        (first.policy_decision_id,),
    ).fetchone()[0]
    assert second == first
    assert count == 1


def test_workflow_run_changes_with_revision_and_rejects_checkpoint_mixup() -> None:
    first = create_workflow_run(
        mission_id="mission-1",
        mission_revision=1,
        run_seed="seed",
        created_at=FIXED_TIME,
    )
    second = create_workflow_run(
        mission_id="mission-1",
        mission_revision=2,
        run_seed="seed",
        created_at=FIXED_TIME,
    )
    assert first.run_id != second.run_id
    assert first.thread_id != second.thread_id

    harness = build_execution_harness()
    with pytest.raises(WorkflowRunBindingError):
        load_checkpoint_run(
            WorkflowRunRepository(harness.database),
            thread_id=harness.run.thread_id,
            mission_id=harness.run.mission_id,
            mission_revision=harness.run.mission_revision + 1,
        )
