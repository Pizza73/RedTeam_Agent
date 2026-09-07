"""Executor-owned just-in-time secret injection (SystemDesign §10.2).

There is no public secret resolver, broker, channel registry, callback, consumer,
or caller-constructible token. Plaintext is released only inside a single-use,
non-serializable continuation whose *only* operation is to pass the full secret
set to the fixed adapter dispatch port in the same call stack, and buffers are
zeroized regardless of outcome.

The continuation is obtainable only through :func:`open_dispatch_continuation`,
which re-loads the dispatch claim and execution from the trusted repositories and
verifies, against the durable store (not caller-supplied objects), that:

* the claim is in state ``consumed`` with the exact deterministic
  ``consumption_id`` for this attempt (i.e. the caller won the OCC consumption);
* the execution is still ``DISPATCH_CLAIMED`` at the claim's state version;
* the secret binding set matches the claim's ``secret_version_bindings_digest``;
* the request's execution id and idempotency key match the durable execution.

Because the secret source and dispatch port are private to the executor and are
never exported, and because construction requires the module-private provenance
sentinel, presenting a fabricated object/id set can neither open plaintext nor
reach the adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import SecretInjectionError
from redteam_agent.execution.adapter import ExecutionRequest, TaskHandle
from redteam_agent.execution.dispatch_port import DispatchResultCapture, TrustedAdapterDispatchPort
from redteam_agent.execution.records import compute_secret_version_bindings_digest
from redteam_agent.execution.secret_binding import _EphemeralSecretBinding
from redteam_agent.execution.secret_source import TrustedSecretSource

if TYPE_CHECKING:
    from redteam_agent.storage.execution_repositories import (
        DispatchClaimRepository,
        ExecutionRecordRepository,
    )

# Module-private provenance sentinel. The continuation constructor rejects any
# value that is not this object, so a caller cannot build one directly.
_PROVENANCE = object()


@dataclass(frozen=True)
class SecretBindingSpec:
    """The (path, exact version) pairs to inject, derived from the claim/tool."""

    secret_argument_path: str
    secret_version_id: str


class _SecretDispatchContinuation:
    """A single-use, non-serializable continuation held only by the executor."""

    __slots__ = ("_capture", "_idempotency_key", "_port", "_request", "_source", "_specs", "_used")

    def __init__(
        self,
        provenance: object,
        *,
        source: TrustedSecretSource,
        port: TrustedAdapterDispatchPort,
        request: ExecutionRequest,
        capture: DispatchResultCapture,
        specs: tuple[SecretBindingSpec, ...],
        idempotency_key: str,
    ) -> None:
        if provenance is not _PROVENANCE:
            raise SecretInjectionError("secret dispatch continuation has no valid provenance")
        self._source = source
        self._port = port
        self._request = request
        self._capture = capture
        self._specs = specs
        self._idempotency_key = idempotency_key
        self._used = False

    def run(self) -> TaskHandle:
        if self._used:
            raise SecretInjectionError("secret dispatch continuation already used")
        self._used = True
        bindings: list[_EphemeralSecretBinding] = []
        try:
            for spec in self._specs:
                buffer = self._source.open_version(spec.secret_version_id)
                bindings.append(
                    _EphemeralSecretBinding(
                        secret_argument_path=spec.secret_argument_path,
                        secret_version_id=spec.secret_version_id,
                        buffer=buffer,
                    )
                )
            return self._port.dispatch_once(
                request=self._request,
                secret_bindings=tuple(bindings),
                result_capture=self._capture,
                idempotency_key=self._idempotency_key,
            )
        finally:
            for binding in bindings:
                binding.zeroize()

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretDispatchContinuation is not serializable")


def _open_dispatch_continuation(
    *,
    source: TrustedSecretSource,
    port: TrustedAdapterDispatchPort,
    digest_service: DigestService,
    claim_repository: DispatchClaimRepository,
    execution_repository: ExecutionRecordRepository,
    execution_id: str,
    claim_id: str,
    expected_consumption_id: str,
    request: ExecutionRequest,
    capture: DispatchResultCapture,
    specs: tuple[SecretBindingSpec, ...],
) -> _SecretDispatchContinuation:
    """Return a one-shot continuation only for the durable consumption winner.

    Every precondition is re-verified against the trusted repositories, so an
    object/id set alone is never sufficient to obtain plaintext or reach the
    adapter.
    """
    claim = claim_repository.get(claim_id)
    if claim is None or claim.claim_state != "consumed":
        raise SecretInjectionError("dispatch continuation requires a durably consumed claim")
    if claim.consumption_id != expected_consumption_id:
        raise SecretInjectionError("dispatch continuation consumption id does not match the consumed claim")
    if claim.execution_id != execution_id:
        raise SecretInjectionError("dispatch continuation claim/execution mismatch")
    execution = execution_repository.get(execution_id)
    if execution is None or execution.provider_execution_state != "DISPATCH_CLAIMED":
        raise SecretInjectionError("dispatch continuation requires a DISPATCH_CLAIMED execution")
    if execution.execution_state_version != claim.execution_state_version:
        raise SecretInjectionError("dispatch continuation execution state version mismatch")
    version_ids = tuple(spec.secret_version_id for spec in specs)
    if compute_secret_version_bindings_digest(version_ids, digest_service) != claim.secret_version_bindings_digest:
        raise SecretInjectionError("dispatch continuation secret binding set does not match the consumed claim")
    if request.execution_id != execution_id or request.idempotency_key != execution.idempotency_key:
        raise SecretInjectionError("dispatch continuation request does not match the durable execution")
    if capture.mode != request.result_delivery_mode:
        raise SecretInjectionError("dispatch continuation capture mode does not match the request")
    return _SecretDispatchContinuation(
        _PROVENANCE, source=source, port=port, request=request, capture=capture, specs=specs,
        idempotency_key=execution.idempotency_key,
    )


__all__ = ["SecretBindingSpec"]
