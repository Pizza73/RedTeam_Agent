"""Unit tests for the strict LLM JSON boundary and actual-schema digests (§6.2)."""

from __future__ import annotations

import json

import pytest

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import PydanticBoundaryValidationError
from redteam_agent.llm.schemas import (
    ACTUAL_SCHEMA_NAMES,
    compute_schema_digest,
    validate_actual_schema,
)

_VALID_ANALYSIS = json.dumps({
    "observation_id": "o1", "condition_id": "c1", "source_execution_id": "e1",
    "observation_type": "asset", "subject_ref": "host:h", "predicate": "p",
    "object_ref": None, "attributes": {"k": 1}, "source_artifact_ids": ["a1"],
    "llm_confidence": 0.5, "subject_entity_type": None, "subject_strong_key_type": None,
    "subject_strong_key_value": None,
})


def test_valid_bodies_accepted() -> None:
    validate_actual_schema("analysis_result", _VALID_ANALYSIS)


def test_nan_and_infinity_rejected() -> None:
    for token in ("NaN", "Infinity", "-Infinity"):
        raw = '{"observation_id": "o", "llm_confidence": ' + token + "}"
        with pytest.raises(PydanticBoundaryValidationError):
            validate_actual_schema("analysis_result", raw)


def test_duplicate_key_rejected() -> None:
    raw = '{"observation_id": "o", "observation_id": "p"}'
    with pytest.raises(PydanticBoundaryValidationError):
        validate_actual_schema("analysis_result", raw)


def test_unknown_field_and_coercion_rejected() -> None:
    unknown = json.loads(_VALID_ANALYSIS)
    unknown["adapter"] = "c2"
    with pytest.raises(PydanticBoundaryValidationError):
        validate_actual_schema("analysis_result", json.dumps(unknown))
    coerced = json.loads(_VALID_ANALYSIS)
    coerced["llm_confidence"] = "0.5"
    with pytest.raises(PydanticBoundaryValidationError):
        validate_actual_schema("analysis_result", json.dumps(coerced))


def test_error_is_content_free() -> None:
    secret = "SECRET-TOKEN-XYZ"
    raw = json.dumps({"observation_id": secret, "adapter": secret})
    with pytest.raises(PydanticBoundaryValidationError) as exc:
        validate_actual_schema("analysis_result", raw)
    assert secret not in str(exc.value)


def test_schema_digest_stable_and_distinct() -> None:
    ds = DigestService()
    digests = {name: compute_schema_digest(name, ds) for name in ACTUAL_SCHEMA_NAMES}
    assert len(set(digests.values())) == len(ACTUAL_SCHEMA_NAMES)
    # Deterministic across calls.
    assert digests["planner_output"] == compute_schema_digest("planner_output", ds)
