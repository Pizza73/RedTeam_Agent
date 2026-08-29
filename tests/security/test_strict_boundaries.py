from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from redteam_agent.canonical import CanonicalJsonObject
from redteam_agent.models.common import OperationalPhase
from redteam_agent.models.plans import ExecutionPlanProposal
from redteam_agent.models.tools import ToolRef


def valid_payload() -> dict[str, object]:
    return {
        "objective": "inspect",
        "phase": OperationalPhase.DISCOVERY,
        "tool_ref": ToolRef(tool_id="tool-1", registry_revision=1),
        "requested_targets": (),
        "session_id": None,
        "arguments": CanonicalJsonObject({"target": "10.0.0.1"}),
    }


@pytest.mark.parametrize(
    "injected",
    ["adapter", "risk", "approval", "scope", "plan_id", "execution_id", "unknown"],
)
def test_execution_proposal_rejects_unknown_fields(injected: str) -> None:
    payload = valid_payload()
    payload[injected] = "injected"
    with pytest.raises(ValidationError):
        ExecutionPlanProposal.model_validate(payload)


def test_nested_tool_ref_rejects_unknown_field() -> None:
    data = valid_payload()
    data["tool_ref"] = {"tool_id": "tool-1", "registry_revision": 1, "adapter": "c2"}
    with pytest.raises(ValidationError):
        ExecutionPlanProposal.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [("tool_ref", {"tool_id": "tool-1", "registry_revision": "1"}), ("requested_targets", [])],
)
def test_python_boundary_rejects_type_coercion(field: str, value: object) -> None:
    data = valid_payload()
    data[field] = value
    with pytest.raises(ValidationError):
        ExecutionPlanProposal.model_validate(data)


def test_wire_json_accepts_typed_enum_but_not_string_integer() -> None:
    wire = {
        "objective": "inspect",
        "phase": "DISCOVERY",
        "tool_ref": {"tool_id": "tool-1", "registry_revision": "1"},
        "requested_targets": [],
        "session_id": None,
        "arguments": {},
    }
    with pytest.raises(ValidationError):
        ExecutionPlanProposal.model_validate_json(json.dumps(wire))


def test_canonical_json_object_is_deeply_immutable() -> None:
    original = {"nested": {"values": [1, 2]}}
    frozen = CanonicalJsonObject(original)
    original["nested"]["values"].append(3)
    assert frozen.to_dict() == {"nested": {"values": [1, 2]}}
    with pytest.raises(TypeError):
        frozen["new"] = "value"  # type: ignore[index]

