"""Durable Shared LLM Gateway (SystemDesign §6.3 / §27.1).

The gateway reserves every logical call, then reserves a durable attempt row *before*
the preflight, and (for a real model attempt) runs the mandatory preflight after that
row exists but strictly before any network I/O. The preflight re-checks the current
binding (mission RUNNING / revision / epoch / profile), the finite deadline, and the
token budget equation; if the request is over budget, unmeasurable, or the binding
changed, it raises and the attempt reaches no network, leaving an auditable attempt
row (``preflight_rejected``) and a FAILED logical operation. Every attempt records its
final outcome (``preflight_rejected`` / ``output_invalid`` / ``completed`` /
``transport_unknown``) on that same row without adding any workflow state.

A deterministic Phase 1 mock ``invoke`` is a plain callable that does not satisfy the
:class:`PreflightInvocation` protocol, so it takes the explicit legacy/mock path with
no preflight and unchanged behaviour. A real Local LLM invocation satisfies that named
protocol, so its preflight is mandatory; the boundary is the protocol, not an ad-hoc
attribute lookup.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import TypeAdapter, ValidationError

from redteam_agent.agent.models import PlannerContextEnvelope
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.errors import AgentLoopError, AuthorizationKernelError, LLMOutputValidationError
from redteam_agent.knowledge.models import AnalyzerCandidateObservation
from redteam_agent.plan.models import PlannerOutput
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork

_PLANNER: TypeAdapter[PlannerOutput] = TypeAdapter(PlannerOutput)
_ANALYZER: TypeAdapter[AnalyzerCandidateObservation] = TypeAdapter(AnalyzerCandidateObservation)

# A pre-attempt hook returns safe/redacted attempt metadata to persist, or raises an
# AuthorizationKernelError to reject the attempt before any network I/O.
PreAttemptHook = Callable[[int], "Mapping[str, object] | None"]

# Per-attempt final outcome persisted on the attempt row (no new workflow state).
AttemptOutcome = Literal[
    "reserved", "preflight_rejected", "completed", "output_invalid", "transport_unknown"
]


@runtime_checkable
class PreflightInvocation(Protocol):
    """Explicit protocol for a real Local LLM invocation whose preflight is mandatory.

    A real Local LLM adapter implements ``before_attempt`` (the current-binding /
    deadline / token-budget preflight) and is only invoked after it runs. A plain
    deterministic Phase 1 mock callable does not implement this protocol, so it takes
    the explicit legacy/mock path with no preflight. The security boundary is this
    named protocol, not an ad-hoc attribute lookup.
    """

    def before_attempt(self, attempt_index: int) -> Mapping[str, object]:
        ...


class SharedLLMGateway:
    """Reserves every call before invocation and reuses a completed logical output."""

    MAX_OUTPUT_RETRIES = 3

    def __init__(self, *, database: Database, digest_service: DigestService, clock: Clock) -> None:
        self._db, self._ds, self._clock = database, digest_service, clock
        self._planner_context_revalidator: Callable[[str], PlannerContextEnvelope] | None = None

    def bind_planner_context_revalidator(
        self, revalidator: Callable[[str], PlannerContextEnvelope]
    ) -> None:
        if self._planner_context_revalidator is not None:
            raise AgentLoopError("Planner context revalidator is already bound")
        self._planner_context_revalidator = revalidator

    def invoke_planner(
        self, *, operation_id: str, envelope: PlannerContextEnvelope,
        invoke: Callable[[PlannerContextEnvelope], object],
    ) -> PlannerOutput:
        if self._planner_context_revalidator is None:
            raise AgentLoopError("Planner context revalidator is not bound")
        current = self._planner_context_revalidator(envelope.planner_context_id)
        if current.envelope_digest != envelope.envelope_digest:
            raise AgentLoopError("Planner context input differs from its current stored envelope")
        pre_attempt = _resolve_preflight(invoke)
        raw = self._invoke(
            mission_id=current.mission_id, mission_revision=current.mission_revision,
            operation_id=operation_id, role="planner", input_payload=current.model_dump(mode="python"),
            invoke=lambda: invoke(current), adapter=_PLANNER, pre_attempt=pre_attempt,
        )
        return _PLANNER.validate_json(json.dumps(raw, sort_keys=True))

    def invoke_analyzer(
        self, *, mission_id: str, mission_revision: int, operation_id: str,
        execution_id: str, result_digest: str,
        context_grant_id: str, context_grant_digest: str,
        authorized_context: CanonicalJsonObject,
        invoke: Callable[[], object],
    ) -> AnalyzerCandidateObservation:
        raw = self._invoke(
            mission_id=mission_id, mission_revision=mission_revision,
            operation_id=operation_id, role="analyzer",
            input_payload={
                "execution_id": execution_id,
                "result_digest": result_digest,
                "context_grant_id": context_grant_id,
                "context_grant_digest": context_grant_digest,
                "authorized_context": authorized_context,
            },
            invoke=invoke, adapter=_ANALYZER, pre_attempt=_resolve_preflight(invoke),
        )
        return _ANALYZER.validate_json(json.dumps(raw, sort_keys=True))

    def _invoke(
        self, *, mission_id: str, mission_revision: int, operation_id: str,
        role: Literal["planner", "analyzer"], input_payload: dict[str, Any],
        invoke: Callable[[], object], adapter: TypeAdapter[Any],
        pre_attempt: PreAttemptHook | None = None,
    ) -> dict[str, Any]:
        input_digest = self._ds.compute("llm_gateway_input_digest", input_payload)
        key = f"{mission_id}:{mission_revision}:{role}:{operation_id}"
        existing = self._db.occ_get("llm_gateway_operation", key)
        if existing is not None:
            record = json.loads(existing[1])
            record_digest = record.pop("record_digest")
            self._ds.verify("llm_gateway_operation_digest", record, record_digest)
            if record["input_digest"] != input_digest:
                raise AgentLoopError("LLM logical operation input changed")
            if record["state"] == "COMPLETED":
                output = record["output"]
                if not isinstance(output, dict):
                    raise AgentLoopError("stored LLM output is malformed")
                return output
            raise AgentLoopError("LLM logical operation has an unresolved attempt")
        input_key = f"{mission_id}:{mission_revision}:{role}:{input_digest}"
        if self._db.occ_get("llm_gateway_input", input_key) is not None:
            raise AgentLoopError("LLM input cannot reset its budget with a new operation id")
        with UnitOfWork(self._db):
            self._db.occ_insert(
                "llm_gateway_input", input_key, 1,
                json.dumps({"operation_id": operation_id}, sort_keys=True),
            )
        last_error = ""
        for attempt_index in range(self.MAX_OUTPUT_RETRIES + 1):
            attempt_key = f"{key}:{attempt_index}"
            # 1) Reserve a durable attempt row BEFORE the preflight and any network I/O,
            #    so a rejected preflight still leaves an auditable attempt row.
            self._reserve_attempt(
                attempt_key=attempt_key, mission_id=mission_id, mission_revision=mission_revision,
                operation_id=operation_id, role=role, attempt_index=attempt_index,
                input_digest=input_digest,
            )
            # 2) Preflight: re-check binding, deadline and token budget. A rejection here
            #    (over budget, unmeasurable, or a changed binding) reaches no network; we
            #    record it on the same attempt row and fail the logical operation.
            attempt_metadata: Mapping[str, object] | None = None
            if pre_attempt is not None:
                try:
                    attempt_metadata = pre_attempt(attempt_index)
                except AuthorizationKernelError:
                    self._update_attempt(attempt_key=attempt_key, outcome="preflight_rejected")
                    self._save_operation(
                        key=key, input_digest=input_digest, state="FAILED", output=None,
                        attempts=attempt_index + 1,
                    )
                    raise
            self._update_attempt(
                attempt_key=attempt_key, outcome="reserved", metadata=attempt_metadata
            )
            # 3) Invoke and record the per-attempt final outcome on the same row.
            try:
                output = adapter.validate_python(invoke())
            except ValidationError as exc:
                last_error = exc.title
                self._update_attempt(attempt_key=attempt_key, outcome="output_invalid")
                continue
            except LLMOutputValidationError:
                # A local model's structured body failed the strict boundary: an output
                # validation retry (never a transport-unknown). The retry re-uses the same
                # request envelope; the invalid body is not echoed into the next prompt.
                last_error = "output_validation"
                self._update_attempt(attempt_key=attempt_key, outcome="output_invalid")
                continue
            except Exception as exc:
                self._update_attempt(attempt_key=attempt_key, outcome="transport_unknown")
                self._save_operation(
                    key=key, input_digest=input_digest, state="UNKNOWN", output=None,
                    attempts=attempt_index + 1,
                )
                raise AgentLoopError("LLM transport outcome is unknown and is not retried") from exc
            dumped = adapter.dump_python(output, mode="json")
            if not isinstance(dumped, dict):
                raise AgentLoopError("LLM output must be a structured object")
            self._update_attempt(attempt_key=attempt_key, outcome="completed")
            self._save_operation(
                key=key, input_digest=input_digest, state="COMPLETED", output=dumped,
                attempts=attempt_index + 1,
            )
            return dumped
        self._save_operation(
            key=key, input_digest=input_digest, state="FAILED", output=None,
            attempts=self.MAX_OUTPUT_RETRIES + 1,
        )
        raise AgentLoopError(f"LLM output retry budget exhausted: {last_error}")

    def _reserve_attempt(
        self, *, attempt_key: str, mission_id: str, mission_revision: int, operation_id: str,
        role: str, attempt_index: int, input_digest: str,
    ) -> None:
        attempt: dict[str, Any] = {
            "mission_id": mission_id, "mission_revision": mission_revision,
            "operation_id": operation_id, "role": role, "attempt_index": attempt_index,
            "input_digest": input_digest, "attempted_at": self._clock.now().isoformat(),
            "outcome": "reserved", "attempt_metadata": None,
        }
        with UnitOfWork(self._db):
            self._db.occ_insert(
                "llm_gateway_attempt", attempt_key, 1,
                json.dumps({
                    **attempt,
                    "attempt_digest": self._ds.compute("llm_gateway_attempt_digest", attempt),
                }, sort_keys=True),
            )

    def _update_attempt(
        self, *, attempt_key: str, outcome: AttemptOutcome,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        row = self._db.occ_get("llm_gateway_attempt", attempt_key)
        if row is None:
            raise AgentLoopError("attempt row missing before outcome update")
        version, payload = row
        record = json.loads(payload)
        stored_digest = record.pop("attempt_digest", None)
        if not isinstance(stored_digest, str):
            raise AgentLoopError("attempt row is missing its integrity digest")
        # Verify the existing attempt record's integrity BEFORE mutating its outcome
        # (fail closed): a tampered attempt row must not be silently overwritten.
        self._ds.verify("llm_gateway_attempt_digest", record, stored_digest)
        record["outcome"] = outcome
        if metadata is not None:
            record["attempt_metadata"] = dict(metadata)
        record["attempt_digest"] = self._ds.compute("llm_gateway_attempt_digest", {
            k: v for k, v in record.items() if k != "attempt_digest"
        })
        with UnitOfWork(self._db):
            self._db.occ_update(
                "llm_gateway_attempt", attempt_key, expected_version=version,
                new_version=version + 1, json_text=json.dumps(record, sort_keys=True),
            )

    def _save_operation(
        self, *, key: str, input_digest: str,
        state: Literal["COMPLETED", "FAILED", "UNKNOWN"], output: object | None,
        attempts: int,
    ) -> None:
        fields = {
            "input_digest": input_digest, "state": state, "output": output,
            "attempts": attempts,
        }
        with UnitOfWork(self._db):
            self._db.occ_insert(
                "llm_gateway_operation", key, 1,
                json.dumps({
                    **fields,
                    "record_digest": self._ds.compute("llm_gateway_operation_digest", fields),
                }, sort_keys=True),
            )


def _resolve_preflight(invoke: object) -> PreAttemptHook | None:
    """Resolve the mandatory preflight from an explicit Local LLM invocation protocol.

    A real Local LLM invocation is a :class:`PreflightInvocation`; its ``before_attempt``
    preflight is mandatory and returned here. A plain deterministic Phase 1 mock callable
    does not satisfy the protocol, so it takes the explicit legacy/mock path with no
    preflight and unchanged behaviour. This uses a named protocol rather than an ad-hoc
    attribute probe as the security boundary.
    """
    if isinstance(invoke, PreflightInvocation):
        return invoke.before_attempt
    return None
