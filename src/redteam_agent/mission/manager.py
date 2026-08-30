"""Mission lifecycle application service and sole authorization entry point."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.errors import MissionLifecycleAuthorizationError, MissionValidationError
from redteam_agent.models.mission import (
    Mission,
    MissionLifecycleState,
    MissionRevision,
    MissionRoot,
)
from redteam_agent.repositories.llm import LLMProfileRepository
from redteam_agent.repositories.mission import (
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    compose_mission,
)

from .authorization_registry import AuthorizationReferenceRegistry
from .goal_registry import KnownGoalIdentifierRegistry
from .validation import validate_mission_for_state


class MissionManager:
    """Validates security configuration before every executable lifecycle boundary."""

    def __init__(
        self,
        roots: MissionRepository,
        revisions: MissionRevisionRepository,
        states: MissionStateRepository,
        profiles: LLMProfileRepository,
        goal_identifiers: KnownGoalIdentifierRegistry | None = None,
        authorization_references: AuthorizationReferenceRegistry | None = None,
    ) -> None:
        self.roots = roots
        self.revisions = revisions
        self.states = states
        self.profiles = profiles
        self.goal_identifiers = goal_identifiers or KnownGoalIdentifierRegistry()
        self.authorization_references = authorization_references or AuthorizationReferenceRegistry(
            frozenset()
        )

    def create(self, root: MissionRoot, revision: MissionRevision, *, now: datetime) -> Mission:
        if root.mission_id != revision.mission_id:
            raise MissionValidationError("mission root/revision identity mismatch")
        with self.roots.database.transaction(immediate=True):
            self.roots.add(root)
            self.revisions.add(revision)
            state = self.states._initialize_draft(root.mission_id, updated_at=now)
        return compose_mission(revision, state)

    def current(self, mission_id: str) -> Mission:
        revision = self.revisions.latest(mission_id)
        state = self.states.get(mission_id)
        if revision is None or state is None:
            raise MissionValidationError("mission root/revision/state is incomplete")
        return compose_mission(revision, state)

    def transition_to_validated(self, mission_id: str, *, now: datetime) -> Mission:
        mission = self.current(mission_id)
        if mission.state != "DRAFT":
            raise MissionLifecycleAuthorizationError("only DRAFT can become VALIDATED")
        validate_mission_for_state(
            mission,
            self.profiles,
            goal_identifiers=self.goal_identifiers,
            target_state="VALIDATED",
        )
        self.authorization_references.require(mission.authorization_reference)
        state = self.states._transition(
            mission_id,
            expected_mission_state_version=mission.mission_state_version,
            expected_authorization_epoch=mission.authorization_epoch,
            new_state="VALIDATED",
            updated_at=now,
        )
        return compose_mission(mission.revision_record(), state)

    def start(self, mission_id: str, *, now: datetime) -> Mission:
        mission = self.current(mission_id)
        if mission.state != "VALIDATED":
            raise MissionLifecycleAuthorizationError("mission must be VALIDATED before RUNNING")
        if not (mission.valid_from <= now < mission.valid_until):
            raise MissionLifecycleAuthorizationError("mission validity window is not active")
        validate_mission_for_state(
            mission,
            self.profiles,
            goal_identifiers=self.goal_identifiers,
            target_state="RUNNING",
        )
        self.authorization_references.require(mission.authorization_reference)
        state = self.states._transition(
            mission_id,
            expected_mission_state_version=mission.mission_state_version,
            expected_authorization_epoch=mission.authorization_epoch,
            new_state="RUNNING",
            updated_at=now,
        )
        return compose_mission(mission.revision_record(), state)

    def pause(self, mission_id: str, *, now: datetime) -> Mission:
        return self._lifecycle_transition(mission_id, "RUNNING", "PAUSED", now)

    def pause_for_result_ingestion_failure(
        self, mission_id: str, *, now: datetime
    ) -> Mission:
        """Fail closed after secure ingestion fails, including repeated recovery attempts."""

        mission = self.current(mission_id)
        if mission.state == "PAUSED":
            return mission
        if mission.state != "RUNNING":
            raise MissionLifecycleAuthorizationError(
                "result-ingestion failure can pause only a RUNNING mission"
            )
        return self.pause(mission_id, now=now)

    def resume(self, mission_id: str, *, now: datetime) -> Mission:
        mission = self.current(mission_id)
        if mission.state != "PAUSED":
            raise MissionLifecycleAuthorizationError("only PAUSED can resume")
        if not (mission.valid_from <= now < mission.valid_until):
            raise MissionLifecycleAuthorizationError("mission validity window is not active")
        validate_mission_for_state(
            mission,
            self.profiles,
            goal_identifiers=self.goal_identifiers,
            target_state="RUNNING",
        )
        self.authorization_references.require(mission.authorization_reference)
        state = self.states._transition(
            mission_id,
            expected_mission_state_version=mission.mission_state_version,
            expected_authorization_epoch=mission.authorization_epoch,
            new_state="RUNNING",
            updated_at=now,
        )
        return compose_mission(mission.revision_record(), state)

    def finalize(self, mission_id: str, *, now: datetime) -> Mission:
        mission = self.current(mission_id)
        if mission.state not in {"RUNNING", "PAUSED"}:
            raise MissionLifecycleAuthorizationError("mission cannot enter FINALIZING")
        state = self.states._transition(
            mission_id,
            expected_mission_state_version=mission.mission_state_version,
            expected_authorization_epoch=mission.authorization_epoch,
            new_state="FINALIZING",
            updated_at=now,
            invalidate_authorization=True,
        )
        return compose_mission(mission.revision_record(), state)

    def _lifecycle_transition(
        self,
        mission_id: str,
        expected: MissionLifecycleState,
        new_state: MissionLifecycleState,
        now: datetime,
    ) -> Mission:
        mission = self.current(mission_id)
        if mission.state != expected:
            raise MissionLifecycleAuthorizationError(f"expected mission state {expected}")
        state = self.states._transition(
            mission_id,
            expected_mission_state_version=mission.mission_state_version,
            expected_authorization_epoch=mission.authorization_epoch,
            new_state=new_state,
            updated_at=now,
        )
        return compose_mission(mission.revision_record(), state)
