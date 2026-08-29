from __future__ import annotations

import pytest

from redteam_agent.errors import MissionValidationError, PydanticBoundaryValidationError
from redteam_agent.mission import validate_mission_for_state, validate_mission_payload
from redteam_agent.models.plans import ExecutionPlanProposal
from redteam_agent.repositories import LLMProfileRepository
from redteam_agent.seeds import mock_mission, mock_profile
from redteam_agent.storage import Database
from redteam_agent.validation import validate_boundary


def test_mission_requires_registered_matching_profile() -> None:
    with Database() as database:
        repository = LLMProfileRepository(database)
        with pytest.raises(MissionValidationError):
            validate_mission_for_state(mock_mission(), repository)
        repository.add(mock_profile())
        validate_mission_for_state(mock_mission(), repository)


def test_mission_schema_errors_use_typed_taxonomy() -> None:
    payload = mock_mission().model_dump(mode="python")
    payload["success_conditions"] = ()
    with pytest.raises(MissionValidationError):
        validate_mission_payload(payload)


def test_boundary_schema_errors_use_typed_taxonomy() -> None:
    with pytest.raises(PydanticBoundaryValidationError):
        validate_boundary(ExecutionPlanProposal, {"adapter": "c2"})
