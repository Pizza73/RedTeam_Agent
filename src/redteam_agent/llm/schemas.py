"""Actual Planner / Analyzer output schemas and the strict LLM JSON boundary.

The Phase 2 capability check, the shared gateway and the Local LLM adapters all
validate model output through *the same* strict boundary against the *actual*
mission schemas, so there is one place where JSON text becomes a typed object:

* ``planner_output``            -> :class:`~redteam_agent.plan.models.PlannerOutput`
* ``execution_plan_proposal``   -> :class:`~redteam_agent.plan.models.ExecutionPlanProposal`
* ``analysis_result``           -> :class:`~redteam_agent.knowledge.models.AnalyzerCandidateObservation`

The boundary rejects duplicate JSON keys, ``NaN`` / ``Infinity`` constants,
unknown fields and implicit coercion. Error text is content-free: it never
echoes the raw model output or offending field values, so an invalid or
prompt-injected body cannot leak into an exception, a retry prompt, or a log.
"""

from __future__ import annotations

import json
from typing import Any, Literal, get_args

from pydantic import BaseModel, TypeAdapter, ValidationError

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import _redact_validation_error, _reject_duplicate_pairs
from redteam_agent.errors import DuplicateJsonKeyError, LLMTransportError, PydanticBoundaryValidationError
from redteam_agent.knowledge.models import AnalyzerCandidateObservation
from redteam_agent.plan.models import ExecutionPlanProposal, PlannerOutput

ActualSchemaName = Literal["planner_output", "execution_plan_proposal", "analysis_result"]

ACTUAL_SCHEMA_NAMES: tuple[ActualSchemaName, ...] = get_args(ActualSchemaName)

_PLANNER_OUTPUT: TypeAdapter[PlannerOutput] = TypeAdapter(PlannerOutput)
_EXECUTION_PLAN_PROPOSAL: TypeAdapter[ExecutionPlanProposal] = TypeAdapter(ExecutionPlanProposal)
_ANALYSIS_RESULT: TypeAdapter[AnalyzerCandidateObservation] = TypeAdapter(AnalyzerCandidateObservation)

_ADAPTERS: dict[str, TypeAdapter[Any]] = {
    "planner_output": _PLANNER_OUTPUT,
    "execution_plan_proposal": _EXECUTION_PLAN_PROPOSAL,
    "analysis_result": _ANALYSIS_RESULT,
}


def _reject_non_finite(value: str) -> float:
    """``parse_constant`` hook that rejects ``NaN`` / ``Infinity`` / ``-Infinity``."""
    raise PydanticBoundaryValidationError("non-finite JSON constant at the LLM boundary")


def parse_llm_json(raw: str | bytes) -> Any:
    """Parse untrusted model output rejecting duplicate keys and non-finite constants.

    Error messages are position/type only; they never include the raw body.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PydanticBoundaryValidationError("LLM output is not valid UTF-8") from exc
    try:
        return json.loads(
            raw, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_non_finite
        )
    except DuplicateJsonKeyError:
        raise PydanticBoundaryValidationError("duplicate JSON key in LLM output") from None
    except json.JSONDecodeError as exc:
        raise PydanticBoundaryValidationError(
            f"malformed LLM JSON at line {exc.lineno} column {exc.colno}"
        ) from None


def validate_actual_schema(schema_name: str, raw: str | bytes) -> BaseModel:
    """Validate raw model output at the strict boundary against an actual schema.

    Raises :class:`PydanticBoundaryValidationError` (content-free) on any duplicate
    key, non-finite constant, unknown field, coercion, or schema violation.
    """
    adapter = _ADAPTERS.get(schema_name)
    if adapter is None:
        raise LLMTransportError("unknown actual schema name")
    parse_llm_json(raw)  # reject dup keys / NaN / Infinity before typed validation
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    try:
        model = adapter.validate_json(text)
    except ValidationError as exc:
        raise PydanticBoundaryValidationError(_redact_validation_error(exc)) from None
    if not isinstance(model, BaseModel):
        raise PydanticBoundaryValidationError("actual schema output is not a structured object")
    return model


def actual_schema_json_schema(schema_name: str) -> dict[str, Any]:
    """Return the JSON Schema for an actual schema (used for native structured output)."""
    adapter = _ADAPTERS.get(schema_name)
    if adapter is None:
        raise LLMTransportError("unknown actual schema name")
    return adapter.json_schema()


def compute_schema_digest(schema_name: str, digest_service: DigestService) -> str:
    """Digest the canonical JSON Schema of an actual schema (SystemDesign §6.2).

    Any change to the actual model shape changes this digest, which invalidates a
    stored capability result bound to the old digest.
    """
    schema = actual_schema_json_schema(schema_name)
    return digest_service.compute("llm_schema_digest", {"schema_name": schema_name, "schema": schema})


__all__ = [
    "ACTUAL_SCHEMA_NAMES",
    "ActualSchemaName",
    "actual_schema_json_schema",
    "compute_schema_digest",
    "parse_llm_json",
    "validate_actual_schema",
]
