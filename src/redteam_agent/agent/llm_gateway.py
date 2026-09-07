"""Durable Shared LLM Gateway used by deterministic Phase 1 agents."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Literal

from pydantic import TypeAdapter, ValidationError

from redteam_agent.agent.models import PlannerContextEnvelope
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError
from redteam_agent.knowledge.models import AnalyzerCandidateObservation
from redteam_agent.plan.models import PlannerOutput
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork

_PLANNER: TypeAdapter[PlannerOutput] = TypeAdapter(PlannerOutput)
_ANALYZER: TypeAdapter[AnalyzerCandidateObservation] = TypeAdapter(AnalyzerCandidateObservation)


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
        invoke: Callable[[], object],
    ) -> PlannerOutput:
        if self._planner_context_revalidator is None:
            raise AgentLoopError("Planner context revalidator is not bound")
        current = self._planner_context_revalidator(envelope.planner_context_id)
        if current.envelope_digest != envelope.envelope_digest:
            raise AgentLoopError("Planner context input differs from its current stored envelope")
        raw = self._invoke(
            mission_id=current.mission_id, mission_revision=current.mission_revision,
            operation_id=operation_id, role="planner", input_payload=current.model_dump(mode="python"),
            invoke=invoke, adapter=_PLANNER,
        )
        return _PLANNER.validate_json(json.dumps(raw, sort_keys=True))

    def invoke_analyzer(
        self, *, mission_id: str, mission_revision: int, operation_id: str,
        execution_id: str, result_digest: str, invoke: Callable[[], object],
    ) -> AnalyzerCandidateObservation:
        raw = self._invoke(
            mission_id=mission_id, mission_revision=mission_revision,
            operation_id=operation_id, role="analyzer",
            input_payload={"execution_id": execution_id, "result_digest": result_digest},
            invoke=invoke, adapter=_ANALYZER,
        )
        return _ANALYZER.validate_json(json.dumps(raw, sort_keys=True))

    def _invoke(
        self, *, mission_id: str, mission_revision: int, operation_id: str,
        role: Literal["planner", "analyzer"], input_payload: dict[str, Any],
        invoke: Callable[[], object], adapter: TypeAdapter[Any],
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
            attempt = {
                "mission_id": mission_id, "mission_revision": mission_revision,
                "operation_id": operation_id, "role": role, "attempt_index": attempt_index,
                "input_digest": input_digest, "attempted_at": self._clock.now().isoformat(),
            }
            with UnitOfWork(self._db):
                self._db.occ_insert(
                    "llm_gateway_attempt", f"{key}:{attempt_index}", 1,
                    json.dumps({
                        **attempt,
                        "attempt_digest": self._ds.compute("llm_gateway_attempt_digest", attempt),
                    }, sort_keys=True),
                )
            try:
                output = adapter.validate_python(invoke())
            except ValidationError as exc:
                last_error = exc.title
                continue
            except Exception as exc:
                self._save_operation(
                    key=key, input_digest=input_digest, state="UNKNOWN", output=None,
                    attempts=attempt_index + 1,
                )
                raise AgentLoopError("LLM transport outcome is unknown and is not retried") from exc
            dumped = adapter.dump_python(output, mode="json")
            if not isinstance(dumped, dict):
                raise AgentLoopError("LLM output must be a structured object")
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
