"""Fixed trusted adapter dispatch port (SystemDesign §10.2 / §10.5).

The executor core never holds a production ``ExecutionAdapter``; the only port
for an external submit is the ``TrustedAdapterDispatchPort``, which the
composition root constructs over a fixed trusted adapter registry. A caller
cannot construct this port, choose an adapter, endpoint, environment name or
command line, or add an authority argument to a public method: the port resolves
the adapter from the request's already-resolved ``adapter_id`` (from the
PolicyDecision/registry, not the caller) and passes ephemeral secret bindings to
the adapter in the same call.

The port also verifies the returned ``TaskHandle`` against the *registered*
adapter identity: the adapter/provider identity digests, delivery mode and task
id must match, so a malicious or swapped adapter cannot return a handle claiming
a different identity or mode (SystemDesign §10.5, §13).

``DispatchResultCapture`` is a Root-generated, non-serializable TCB capability;
Planner/Operator/Plugin code cannot inject an arbitrary object, callback or sink.
For a ``local_result`` submit it carries the composition-owned sink the adapter
streams into and receives the adapter's control metadata exactly once.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from redteam_agent.errors import SecretInjectionError
from redteam_agent.execution.adapter import AdapterIdentity, ExecutionAdapter, ExecutionRequest, TaskHandle
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.secret_binding import EphemeralSecretBinding

__all__ = ["DispatchResultCapture", "FixedTrustedAdapterDispatchPort", "TrustedAdapterDispatchPort"]


class TrustedAdapterDispatchPort(Protocol):
    def dispatch_once(
        self,
        *,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle: ...

    def adapter_identity(self, adapter_id: str) -> AdapterIdentity: ...


class FixedTrustedAdapterDispatchPort:
    """The composition-only concrete dispatch port over a fixed adapter registry."""

    def __init__(self, adapters: Mapping[str, ExecutionAdapter]) -> None:
        self._adapters = dict(adapters)

    def _require_adapter(self, adapter_id: str) -> ExecutionAdapter:
        adapter = self._adapters.get(adapter_id)
        if adapter is None:
            raise SecretInjectionError("no trusted adapter registered for the resolved adapter id")
        return adapter

    def adapter_identity(self, adapter_id: str) -> AdapterIdentity:
        return self._require_adapter(adapter_id).identity()

    def dispatch_once(
        self,
        *,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle:
        adapter = self._require_adapter(request.adapter_id)
        if result_capture.mode != request.result_delivery_mode:
            raise SecretInjectionError("result capture mode does not match the request delivery mode")
        if idempotency_key != request.idempotency_key:
            raise SecretInjectionError("idempotency key mismatch at dispatch port")
        registered = adapter.identity()
        if registered.result_delivery_mode != request.result_delivery_mode:
            raise SecretInjectionError("registered adapter delivery mode does not match the request")
        handle = adapter.submit(request, secret_bindings, result_capture, idempotency_key)
        # The returned handle must match the *registered* adapter identity, mode
        # and task id: a swapped/malicious adapter cannot claim another identity
        # or an implicit mode switch (SystemDesign §10.5, §13).
        if handle.result_delivery_mode != request.result_delivery_mode:
            raise SecretInjectionError("adapter returned a task handle with a mismatched delivery mode")
        if handle.task_id != request.task_id:
            raise SecretInjectionError("adapter returned a task handle with a mismatched task id")
        if handle.adapter_identity_digest != registered.adapter_identity_digest:
            raise SecretInjectionError("adapter returned a mismatched adapter identity digest")
        if handle.provider_identity_digest != registered.provider_identity_digest:
            raise SecretInjectionError("adapter returned a mismatched provider identity digest")
        if request.result_delivery_mode == "provider_task" and handle.provider_task_id is None:
            raise SecretInjectionError("provider_task adapter returned no provider task id")
        if request.result_delivery_mode == "local_result" and handle.provider_task_id is not None:
            raise SecretInjectionError("local_result adapter must not return a provider task id")
        return handle
