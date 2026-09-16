"""ExecutionAdapter contract, task handle, reconciliation and a mock adapter.

The adapter is swappable behind a fixed contract so the executor core never
changes when the adapter changes (SystemDesign §9 / §13). Secret plaintext is
never a normal ``submit`` argument or written back into ``ExecutionRequest``;
the trusted dispatch port passes ephemeral secret bindings in the same call
(SystemDesign §10.2). ``reconcile`` maps ``UNSUPPORTED``/``UNKNOWN``/an
uncertain ``NOT_FOUND`` to an outcome the executor records as ``OUTCOME_UNKNOWN``.

The ``MockExecutionAdapter`` is a Phase 0B test double: it records the call
count and non-secret control metadata only, and never copies a secret value into
any field, log, exception or snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, model_validator

from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.errors import ResultCollectionError
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.models import (
    AdapterCollectionControl,
    CollectionCancellation,
    CollectionResumeCursor,
    LocalResultBinding,
    ProviderTaskBinding,
    ResultDeliveryMode,
    ResultTaskBinding,
)
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import RawResultSink
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ToolRef
from redteam_agent.policy.target_binding import TargetDispatchBinding


class ExecutionRequest(StrictImmutableBoundaryModel):
    """A secret-free external submission request built by the executor.

    ``arguments`` carry secret *references* only; secret values are supplied out
    of band as ephemeral bindings and never written back here (SystemDesign §10.2).
    """

    execution_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    tool_ref: ToolRef
    adapter_id: str = Field(min_length=1)
    provider_tool_name: str = Field(min_length=1)
    result_delivery_mode: ResultDeliveryMode
    idempotency_key: str = Field(min_length=1)
    timeout_seconds: int = Field(gt=0)
    arguments: CanonicalJsonObject
    # These bindings are produced by the authorization kernel, not by the
    # planner or MCP server.  Network-capable adapters must use them as the
    # authoritative destinations and reject any argument/binding mismatch.
    target_dispatch_bindings: tuple[TargetDispatchBinding, ...] = ()


class AdapterIdentity(StrictImmutableBoundaryModel):
    adapter_id: str = Field(min_length=1)
    adapter_identity_digest: str = Field(min_length=1)
    provider_identity_digest: str = Field(min_length=1)
    result_delivery_mode: ResultDeliveryMode


class TaskHandle(StrictImmutableBoundaryModel):
    """The adapter's post-submit handle. ``provider_task_id`` is set for the
    provider_task mode and ``None`` for local_result (SystemDesign §10.5)."""

    task_id: str = Field(min_length=1)
    result_delivery_mode: ResultDeliveryMode
    provider_task_id: str | None
    adapter_identity_digest: str = Field(min_length=1)
    provider_identity_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _delivery_fields_match_mode(self) -> TaskHandle:
        if self.result_delivery_mode == "provider_task" and self.provider_task_id is None:
            raise ValueError("provider_task handle requires provider_task_id")
        if self.result_delivery_mode == "local_result" and self.provider_task_id is not None:
            raise ValueError("local_result handle must not carry provider_task_id")
        return self


ReconcileStatus = Literal[
    "FOUND_RUNNING",
    "FOUND_TERMINAL",
    "NOT_FOUND_CONFIRMED",
    "NOT_FOUND_UNCERTAIN",
    "UNKNOWN",
    "UNSUPPORTED",
]


class ReconciliationResult(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    status: ReconcileStatus
    task_binding: ResultTaskBinding | None
    provider_status: Literal["succeeded", "failed", "cancelled"] | None
    provider_task_id: str | None
    observed_at: datetime

    @model_validator(mode="after")
    def _status_fields_are_consistent(self) -> ReconciliationResult:
        if self.status == "FOUND_TERMINAL":
            if self.task_binding is None or self.provider_status is None:
                raise ValueError("terminal reconciliation requires task binding and provider status")
        elif self.provider_status is not None:
            raise ValueError("non-terminal reconciliation must not carry provider status")
        return self


class CancelOutcome(StrictImmutableBoundaryModel):
    execution_id: str = Field(min_length=1)
    provider_task_id: str = Field(min_length=1)
    result: Literal["ACKNOWLEDGED", "CONFIRMED", "UNKNOWN", "FAILED"]
    observed_at: datetime


class ExecutionAdapter(Protocol):
    """The adapter contract. In production it is reachable only through the
    trusted dispatch port's internal registry, never injected into the executor
    core directly (SystemDesign §10.2)."""

    def identity(self) -> AdapterIdentity: ...

    def submit(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle: ...

    def reconcile(self, execution_id: str, task_binding: ResultTaskBinding | None) -> ReconciliationResult: ...

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome: ...

    def collect_result(
        self,
        execution_id: str,
        task_binding: ResultTaskBinding,
        sink: RawResultSink,
        resume: CollectionResumeCursor | None = None,
        cancellation: CollectionCancellation | None = None,
    ) -> AdapterCollectionControl: ...

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl: ...


@dataclass
class _MockSubmissionLog:
    """Non-secret control metadata recorded by the mock adapter for assertions."""

    execution_id: str
    task_id: str
    idempotency_key: str
    provider_tool_name: str
    capture_id: str
    secret_binding_count: int
    secret_binding_lengths: tuple[int, ...]
    secret_version_ids: tuple[str, ...]


class MockExecutionAdapter:
    """A deterministic, side-effect-free execution adapter for Phase 0B tests."""

    def __init__(
        self,
        *,
        adapter_id: str,
        result_delivery_mode: ResultDeliveryMode = "provider_task",
        adapter_identity_digest: str = "adapter-identity-mock",
        provider_identity_digest: str = "provider-identity-mock",
        reconcile_status: ReconcileStatus = "UNKNOWN",
        reconcile_provider_status: Literal["succeeded", "failed", "cancelled"] | None = None,
        cancel_result: Literal["ACKNOWLEDGED", "CONFIRMED", "UNKNOWN", "FAILED"] = "UNKNOWN",
        clock_value: datetime | None = None,
        fail_on_submit: bool = False,
        stdout_chunks: tuple[bytes, ...] = (b"result-line-1\n", b"result-line-2\n"),
        stderr_chunks: tuple[bytes, ...] = (),
        collect_status: Literal["succeeded", "failed", "cancelled"] = "succeeded",
        collect_exit_code: int | None = 0,
        collect_timed_out: bool = False,
    ) -> None:
        self._adapter_id = adapter_id
        self._mode = result_delivery_mode
        self._adapter_identity_digest = adapter_identity_digest
        self._provider_identity_digest = provider_identity_digest
        self._reconcile_status = reconcile_status
        self._reconcile_provider_status = reconcile_provider_status
        self._cancel_result = cancel_result
        self._clock_value = clock_value
        self._fail_on_submit = fail_on_submit
        self._stdout_chunks = stdout_chunks
        self._stderr_chunks = stderr_chunks
        self._collect_status = collect_status
        self._collect_exit_code = collect_exit_code
        self._collect_timed_out = collect_timed_out
        self.submissions: list[_MockSubmissionLog] = []
        self.submit_calls = 0
        self.cancel_calls = 0
        self.reconcile_calls = 0
        self.collect_calls = 0
        self.get_control_calls = 0

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id=self._adapter_id,
            adapter_identity_digest=self._adapter_identity_digest,
            provider_identity_digest=self._provider_identity_digest,
            result_delivery_mode=self._mode,
        )

    def submit(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle:
        self.submit_calls += 1
        # Record only non-secret control metadata: the *length* of each borrowed
        # secret proves injection without copying the value anywhere.
        lengths = tuple(binding.length() for binding in secret_bindings)
        version_ids = tuple(binding.secret_version_id for binding in secret_bindings)
        self.submissions.append(
            _MockSubmissionLog(
                execution_id=request.execution_id,
                task_id=request.task_id,
                idempotency_key=idempotency_key,
                provider_tool_name=request.provider_tool_name,
                capture_id=result_capture.capture_id,
                secret_binding_count=len(secret_bindings),
                secret_binding_lengths=lengths,
                secret_version_ids=version_ids,
            )
        )
        if self._fail_on_submit:
            raise RuntimeError("mock adapter submit failure (no secret material in message)")
        if self._mode == "local_result":
            # Local mode: stream inline into the composition-owned capture sink and
            # commit control metadata in the same dispatch call (SystemDesign §10.5).
            sink = result_capture.sink
            if sink is None:
                raise ResultCollectionError("local_result submit requires a capture sink")
            for chunk in self._stdout_chunks:
                sink.write_stdout(chunk)
            for chunk in self._stderr_chunks:
                sink.write_stderr(chunk)
            result_capture.commit_control_metadata(self._control())
            provider_task_id = None
        else:
            provider_task_id = f"provider-{request.task_id}"
        return TaskHandle(
            task_id=request.task_id,
            result_delivery_mode=self._mode,
            provider_task_id=provider_task_id,
            adapter_identity_digest=self._adapter_identity_digest,
            provider_identity_digest=self._provider_identity_digest,
        )

    def _control(self) -> AdapterCollectionControl:
        observed = self._observed_at()
        return AdapterCollectionControl(
            provider_status=self._collect_status,
            exit_code=self._collect_exit_code,
            timed_out=self._collect_timed_out,
            started_at=observed,
            finished_at=observed,
            status_normalization_rule_id="status-normalization-v1",
        )

    def reconcile(self, execution_id: str, task_binding: ResultTaskBinding | None) -> ReconciliationResult:
        self.reconcile_calls += 1
        provider_task_id = task_binding.provider_task_id if isinstance(task_binding, ProviderTaskBinding) else None
        return ReconciliationResult(
            execution_id=execution_id,
            status=self._reconcile_status,
            task_binding=task_binding if self._reconcile_status == "FOUND_TERMINAL" else None,
            provider_status=self._reconcile_provider_status if self._reconcile_status == "FOUND_TERMINAL" else None,
            provider_task_id=provider_task_id,
            observed_at=self._observed_at(),
        )

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome:
        self.cancel_calls += 1
        return CancelOutcome(
            execution_id=execution_id,
            provider_task_id=provider_task_id,
            result=self._cancel_result,
            observed_at=self._observed_at(),
        )

    def collect_result(
        self,
        execution_id: str,
        task_binding: ResultTaskBinding,
        sink: RawResultSink,
        resume: CollectionResumeCursor | None = None,
        cancellation: CollectionCancellation | None = None,
    ) -> AdapterCollectionControl:
        # Only the provider_task branch reads a live provider result. A local
        # binding must never reach provider collection (SystemDesign §10.5).
        if isinstance(task_binding, LocalResultBinding):
            raise ResultCollectionError("provider collect_result must not be called for a local_result binding")
        self.collect_calls += 1
        # Non-authority resume/cancellation controls must bind the exact task/sink.
        if resume is not None and (
            resume.execution_id != execution_id
            or resume.collection_id != f"collection-{execution_id}"
            or resume.sink_id != sink.sink_id
            or resume.task_binding_digest != task_binding.binding_digest
            or resume.result_delivery_mode != "provider_task"
        ):
            raise ResultCollectionError("resume cursor is bound to a different task/mode")
        if cancellation is not None and (
            cancellation.execution_id != execution_id
            or cancellation.collection_id != f"collection-{execution_id}"
            or cancellation.sink_id != sink.sink_id
            or cancellation.task_binding_digest != task_binding.binding_digest
        ):
            raise ResultCollectionError("cancellation is bound to a different task")
        # Stream chunk-by-chunk into the composition-owned sink; never buffer the
        # whole result here. A cancellation stops receiving after the first chunk.
        for index, chunk in enumerate(self._stdout_chunks):
            if cancellation is not None and index > 0:
                break
            sink.write_stdout(chunk)
        if cancellation is None:
            for chunk in self._stderr_chunks:
                sink.write_stderr(chunk)
        return self._control()

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl:
        # Metadata-only recovery: return control without re-streaming any content.
        if isinstance(task_binding, LocalResultBinding):
            raise ResultCollectionError("provider control read must not be called for a local_result binding")
        self.get_control_calls += 1
        return self._control()

    def _observed_at(self) -> datetime:
        if self._clock_value is None:
            from datetime import UTC

            return datetime.now(tz=UTC)
        return self._clock_value
