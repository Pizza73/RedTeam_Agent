"""Cross-repository mission validation."""

from __future__ import annotations

from redteam_agent.errors import MissionValidationError
from redteam_agent.models.llm import LocalLLMProfile, MockAgentProfile
from redteam_agent.models.mission import Mission
from redteam_agent.repositories.llm import LLMProfileRepository

from .goal_registry import KnownGoalIdentifierRegistry


def validate_mission_for_state(
    mission: Mission,
    profile_repository: LLMProfileRepository,
    *,
    goal_identifiers: KnownGoalIdentifierRegistry | None = None,
    target_state: str = "VALIDATED",
) -> None:
    """Fail closed before a mission can enter VALIDATED or RUNNING."""

    if target_state not in {"VALIDATED", "RUNNING"}:
        raise MissionValidationError("mission validation only gates VALIDATED/RUNNING")
    profile = profile_repository.get(mission.llm_profile_revision)
    if profile is None:
        raise MissionValidationError("mission LLM/mock profile is not registered")
    if profile.profile_digest != mission.llm_profile_digest:
        raise MissionValidationError("mission profile digest mismatch")
    if isinstance(profile, LocalLLMProfile):
        result = profile_repository.latest_capability_result(profile.profile_revision)
        if result is None or result.status != "PASSED":
            raise MissionValidationError("local LLM profile lacks a passing capability result")
    elif not isinstance(profile, MockAgentProfile):
        raise MissionValidationError("unknown agent profile type")
    (goal_identifiers or KnownGoalIdentifierRegistry()).validate(mission)


def validate_mission_payload(value: object) -> Mission:
    """Turn schema failures into the Phase 0A mission error taxonomy."""

    from pydantic import ValidationError

    try:
        return Mission.model_validate(value)
    except ValidationError as exc:
        raise MissionValidationError(str(exc)) from exc
