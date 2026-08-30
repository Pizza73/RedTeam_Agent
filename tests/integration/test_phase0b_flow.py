from __future__ import annotations

import asyncio
from datetime import timedelta

from redteam_agent.executor import (
    Executor,
    MockExecutionAdapter,
    MockRawResultSinkFactory,
    MockSecureResultIngester,
)
from redteam_agent.models.execution import SecureIngestionSummary
from redteam_agent.seeds import FIXED_TIME
from tests.phase0b_helpers import ExecutionHarness, build_execution_harness, prepare_execution


def _restart_executor(harness: ExecutionHarness, *, now) -> Executor:
    restarted_factory = MockRawResultSinkFactory(
        now=now,
        max_bytes=harness.environment.tool.max_output_bytes,
        store=harness.sink_factory.store,
    )
    return Executor(
        runtime_resolver=harness.kernel.runtime_resolver,
        plans=harness.kernel.plans,
        decisions=harness.kernel.decisions,
        resources=harness.kernel.resources,
        approval_requests=harness.kernel.approval_requests,
        approvals=harness.kernel.approvals,
        executions=harness.executions,
        receipts=harness.receipts,
        recovery=harness.recovery,
        ingestions=harness.ingestions,
        results=harness.results,
        sink_factory=restarted_factory,
    )


def test_mock_execution_streams_to_quarantine_and_application_normalizes_result() -> None:
    harness = build_execution_harness()
    raw_marker = b"RAW-SECRET-MUST-NOT-ENTER-NORMAL-DB"
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
        stdout_chunks=(raw_marker[:12], raw_marker[12:24], raw_marker[24:]),
        stderr_chunks=(b"mock stderr",),
    )
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            adapter=adapter,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    assert running.provider_execution_state == "RUNNING"
    assert running.dispatch_attempts == 1

    restarted_executor = _restart_executor(
        harness, now=FIXED_TIME + timedelta(minutes=5)
    )
    metadata = asyncio.run(
        restarted_executor.collect_result(
            running.execution_id,
            adapter=adapter,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    assert not hasattr(metadata, "stdout")
    ingester = MockSecureResultIngester(
        summary=SecureIngestionSummary(
            secure_ingestion_id="secure-ingestion-1",
            stdout_preview="[REDACTED]",
            stderr_preview="mock stderr",
            redacted_artifact_references=("artifact:redacted:1",),
        )
    )
    result = asyncio.run(
        harness.executor.ingest_result(
            running.execution_id,
            adapter_result=metadata,
            ingester=ingester,
            now=FIXED_TIME + timedelta(minutes=5),
        )
    )
    current = harness.executions.get(running.execution_id)
    assert current is not None
    assert current.provider_execution_state == "SUCCEEDED"
    assert current.result_ingestion_state == "SUCCEEDED"
    assert result.normalized_targets == harness.kernel.decision.normalized_targets
    assert result.stdout_preview == "[REDACTED]"
    assert adapter.submit_calls == 1
    retried = asyncio.run(
        harness.executor.ingest_result(
            running.execution_id,
            adapter_result=metadata,
            ingester=ingester,
            now=FIXED_TIME + timedelta(minutes=6),
        )
    )
    assert retried == result
    assert ingester.calls == 1

    marker = raw_marker.decode("ascii")
    for table in (
        "execution_records",
        "raw_result_receipts",
        "raw_result_recovery_metadata",
        "result_ingestions",
        "execution_results",
    ):
        rows = harness.database.connection.execute(
            f"SELECT payload_json FROM {table}"  # noqa: S608 - fixed test table allowlist
        ).fetchall()
        assert all(marker not in str(row["payload_json"]) for row in rows)


def test_stream_collection_resumes_without_resubmitting_action() -> None:
    harness = build_execution_harness()
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
        stdout_chunks=(b"one", b"two", b"three"),
        fail_collection_after_chunks=1,
    )
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            adapter=adapter,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    from redteam_agent.errors import RawResultStreamingError

    try:
        asyncio.run(
            harness.executor.collect_result(
                running.execution_id,
                adapter=adapter,
                now=FIXED_TIME + timedelta(minutes=4),
            )
        )
    except RawResultStreamingError:
        pass
    else:
        raise AssertionError("mock interruption must fail closed")

    restarted_executor = _restart_executor(
        harness, now=FIXED_TIME + timedelta(minutes=5)
    )
    metadata = asyncio.run(
        restarted_executor.collect_result(
            running.execution_id,
            adapter=adapter,
            now=FIXED_TIME + timedelta(minutes=5),
        )
    )
    assert metadata.receipt.stdout_bytes == 11
    assert adapter.submit_calls == 1
    assert adapter.collect_calls == 2


def test_failed_ingestion_resumes_without_external_action_resubmit() -> None:
    harness = build_execution_harness()
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=FIXED_TIME + timedelta(minutes=3),
        stdout_chunks=(b"raw",),
    )
    prepared = prepare_execution(harness)
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            adapter=adapter,
            now=FIXED_TIME + timedelta(minutes=3),
        )
    )
    metadata = asyncio.run(
        harness.executor.collect_result(
            running.execution_id,
            adapter=adapter,
            now=FIXED_TIME + timedelta(minutes=4),
        )
    )
    failing = MockSecureResultIngester(
        summary=SecureIngestionSummary(secure_ingestion_id="secure-retry"),
        fail=True,
    )
    from redteam_agent.errors import ResultIngestionError

    try:
        asyncio.run(
            harness.executor.ingest_result(
                running.execution_id,
                adapter_result=metadata,
                ingester=failing,
                now=FIXED_TIME + timedelta(minutes=5),
            )
        )
    except ResultIngestionError:
        pass
    else:
        raise AssertionError("mock ingestion failure must be recorded")

    failed = harness.executions.get(running.execution_id)
    assert failed is not None
    assert failed.provider_execution_state == "SUCCEEDED"
    assert failed.result_ingestion_state == "FAILED"
    assert harness.results.get_by_execution(running.execution_id) is None

    result = asyncio.run(
        harness.executor.resume_result_ingestion(
            running.execution_id,
            adapter=adapter,
            ingester=failing,
            now=FIXED_TIME + timedelta(minutes=6),
        )
    )
    assert result.secure_ingestion_id == "secure-retry"
    assert adapter.submit_calls == 1
