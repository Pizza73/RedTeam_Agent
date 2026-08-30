"""Provider-neutral execution contract and side-effect-free mock implementation."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from redteam_agent.canonical import stable_id
from redteam_agent.errors import AdapterDispatchUncertainError, AdapterOperationError
from redteam_agent.models.capabilities import AdapterCapabilities
from redteam_agent.models.execution import (
    AdapterRawResult,
    CancelResult,
    ExecutionRequest,
    RawArtifactMetadata,
    ReconciliationResult,
    ReconciliationStatus,
    TaskHandle,
    TaskStatus,
)

from .raw_results import MockRawResultSink, RawResultSink


class ExecutionAdapter(Protocol):
    async def get_capabilities(self) -> AdapterCapabilities: ...

    async def submit(self, request: ExecutionRequest, idempotency_key: str) -> TaskHandle: ...

    async def get_task(self, task_id: str) -> TaskStatus: ...

    async def collect_result(
        self,
        task_id: str,
        sink: RawResultSink,
    ) -> AdapterRawResult: ...

    async def cancel_task(self, task_id: str) -> CancelResult: ...

    async def reconcile(
        self,
        execution_id: str,
        idempotency_key: str,
    ) -> ReconciliationResult: ...


@dataclass(frozen=True)
class MockArtifact:
    metadata: RawArtifactMetadata
    chunks: tuple[bytes, ...]


class MockExecutionAdapter:
    """Deterministic adapter that never calls an OS command or external provider."""

    def __init__(
        self,
        *,
        capabilities: AdapterCapabilities,
        now: datetime,
        stdout_chunks: tuple[bytes, ...] = (),
        stderr_chunks: tuple[bytes, ...] = (),
        artifacts: tuple[MockArtifact, ...] = (),
        provider_status: Literal["SUCCEEDED", "FAILED", "CANCELLED"] = "SUCCEEDED",
        submit_uncertain: bool = False,
        reconcile_status: ReconciliationStatus = "RUNNING",
        fail_collection_after_chunks: int | None = None,
    ) -> None:
        self._capabilities = capabilities
        self._now = now
        self._stdout_chunks = stdout_chunks
        self._stderr_chunks = stderr_chunks
        self._artifacts = artifacts
        self._provider_status = provider_status
        self._submit_uncertain = submit_uncertain
        self._reconcile_status = reconcile_status
        self._fail_collection_after_chunks = fail_collection_after_chunks
        self._handles_by_execution: dict[str, TaskHandle] = {}
        self._execution_by_task: dict[str, str] = {}
        self._collection_offsets: dict[str, int] = {}
        self.submit_calls = 0
        self.reconcile_calls = 0
        self.collect_calls = 0

    async def get_capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    async def submit(self, request: ExecutionRequest, idempotency_key: str) -> TaskHandle:
        self.submit_calls += 1
        existing = self._handles_by_execution.get(request.execution_id)
        if existing is not None:
            return existing
        provider_task_id = stable_id(
            "provider_task",
            {
                "schema_version": "mock-provider-task-v1",
                "execution_id": request.execution_id,
                "idempotency_key": idempotency_key,
            },
        )
        handle = TaskHandle(
            execution_id=request.execution_id,
            task_id=provider_task_id,
            provider_task_id=provider_task_id,
            state="running",
            submitted_at=self._now,
        )
        self._handles_by_execution[request.execution_id] = handle
        self._execution_by_task[handle.task_id] = request.execution_id
        if self._submit_uncertain:
            raise AdapterDispatchUncertainError("mock submit result was intentionally uncertain")
        return handle

    async def get_task(self, task_id: str) -> TaskStatus:
        if task_id not in self._execution_by_task:
            return TaskStatus(task_id=task_id, state="unknown", updated_at=self._now)
        if self._provider_status == "SUCCEEDED":
            state: Literal["succeeded", "failed", "cancelled"] = "succeeded"
        elif self._provider_status == "FAILED":
            state = "failed"
        else:
            state = "cancelled"
        return TaskStatus(task_id=task_id, state=state, updated_at=self._now)

    async def collect_result(
        self,
        task_id: str,
        sink: RawResultSink,
    ) -> AdapterRawResult:
        self.collect_calls += 1
        execution_id = self._execution_by_task.get(task_id)
        if execution_id is None:
            raise AdapterOperationError("mock task is not bound to an execution")
        if isinstance(sink, MockRawResultSink) and sink.committed:
            receipt = await sink.commit()
            return self._metadata(execution_id, task_id, receipt)

        operations: list[tuple[str, bytes | MockArtifact]] = []
        operations.extend(("stdout", chunk) for chunk in self._stdout_chunks)
        operations.extend(("stderr", chunk) for chunk in self._stderr_chunks)
        operations.extend(("artifact", artifact) for artifact in self._artifacts)
        offset = self._collection_offsets.get(task_id, 0)
        for index in range(offset, len(operations)):
            if (
                self._fail_collection_after_chunks is not None
                and index >= self._fail_collection_after_chunks
            ):
                self._fail_collection_after_chunks = None
                raise AdapterOperationError("mock result stream interrupted")
            channel, value = operations[index]
            if channel == "stdout":
                assert isinstance(value, bytes)
                await sink.write_stdout(value)
            elif channel == "stderr":
                assert isinstance(value, bytes)
                await sink.write_stderr(value)
            else:
                assert isinstance(value, MockArtifact)
                await sink.write_artifact(value.metadata, _chunks(value.chunks))
            self._collection_offsets[task_id] = index + 1
        receipt = await sink.commit()
        return self._metadata(execution_id, task_id, receipt)

    def _metadata(
        self,
        execution_id: str,
        task_id: str,
        receipt: object,
    ) -> AdapterRawResult:
        from redteam_agent.models.execution import RawResultReceipt

        if not isinstance(receipt, RawResultReceipt):
            raise AdapterOperationError("mock sink returned invalid receipt metadata")
        return AdapterRawResult(
            execution_id=execution_id,
            provider_task_id=task_id,
            provider_status=self._provider_status,
            receipt=receipt,
            exit_code=0 if self._provider_status == "SUCCEEDED" else 1,
            started_at=self._now,
            finished_at=self._now,
        )

    async def cancel_task(self, task_id: str) -> CancelResult:
        known = task_id in self._execution_by_task
        return CancelResult(task_id=task_id, requested=known, confirmed=known)

    async def reconcile(
        self,
        execution_id: str,
        idempotency_key: str,
    ) -> ReconciliationResult:
        del idempotency_key
        self.reconcile_calls += 1
        handle = self._handles_by_execution.get(execution_id)
        provider_task_id = None if handle is None else handle.provider_task_id
        return ReconciliationResult(
            execution_id=execution_id,
            status=self._reconcile_status,
            provider_task_id=provider_task_id,
            checked_at=self._now,
        )


async def _chunks(chunks: tuple[bytes, ...]) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk
