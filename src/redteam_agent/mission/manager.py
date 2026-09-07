"""Mission Manager: the single legitimate lifecycle entry point (SystemDesign §21.1).

Only this component transitions a mission between lifecycle states. Every
transition validates the fixed state machine, the expected version/epoch/state,
and commits the new state together with a mission-owned lifecycle event in one
SQLite transaction (real OCC). Starting or resuming a mission additionally
re-checks the trusted clock against the mission validity window, the presence of
an authorization reference, and that the bound LLM profile is still registered
and usable. Revocation boundaries (PAUSE, resume, emergency stop, authorization
invalidation) rotate the authorization epoch (B-03 / B-04 / C).
"""

from __future__ import annotations

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MissionLifecycleError, MissionValidationError
from redteam_agent.mission.models import (
    MissionLifecycleEvent,
    MissionLifecycleState,
    MissionRevision,
    MissionState,
)
from redteam_agent.mission.validation import MissionValidationPolicy, validate_mission_revision
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    AgentProfileRepository,
    MissionLifecycleEventRepository,
    MissionRevisionRepository,
    MissionStateRepository,
)


class MissionManager:
    def __init__(
        self,
        *,
        database: Database,
        revision_repository: MissionRevisionRepository,
        state_repository: MissionStateRepository,
        event_repository: MissionLifecycleEventRepository,
        profile_repository: AgentProfileRepository,
        digest_service: DigestService,
        validation_policy: MissionValidationPolicy,
        clock: Clock,
        write_guard: WriteGuard,
    ) -> None:
        self._db = database
        self._revisions = revision_repository
        self._states = state_repository
        self._events = event_repository
        self._profiles = profile_repository
        self._digests = digest_service
        self._validation_policy = validation_policy
        self._clock = clock
        self._guard = write_guard
        state_repository.bind_owner(write_guard)
        event_repository.bind_owner(write_guard)

    # --- creation ---------------------------------------------------------

    def create_mission(self, revision: MissionRevision) -> MissionState:
        state = MissionState(
            mission_id=revision.mission_id,
            mission_revision=revision.mission_revision,
            mission_state_version=0,
            authorization_epoch=0,
            state="DRAFT",
        )
        with UnitOfWork(self._db):
            self._revisions.save(revision)
            self._states.create(state, guard=self._guard)
            self._events.append(
                guard=self._guard,
                event=MissionLifecycleEvent(
                    mission_id=revision.mission_id,
                    sequence_number=self._events.next_sequence(revision.mission_id),
                    from_state="DRAFT",
                    to_state="DRAFT",
                    mission_state_version=0,
                    authorization_epoch=0,
                    actor="mission_manager",
                    reason="created",
                    occurred_at=self._clock.now(),
                )
            )
        return state

    # --- helpers ----------------------------------------------------------

    def _current(self, mission_id: str) -> MissionState:
        state = self._states.get(mission_id)
        if state is None:
            raise MissionLifecycleError("mission does not exist")
        return state

    def _revision(self, mission_id: str, mission_revision: int) -> MissionRevision:
        revision = self._revisions.get(mission_id, mission_revision)
        if revision is None:
            raise MissionValidationError("mission revision not found")
        return revision

    def _transition(
        self, mission_id: str, target: MissionLifecycleState, expected_version: int, *, actor: str, reason: str
    ) -> MissionState:
        with UnitOfWork(self._db):
            current = self._current(mission_id)
            new_state = self._states.apply_transition(
                guard=self._guard,
                mission_id=mission_id,
                expected_version=expected_version,
                expected_epoch=current.authorization_epoch,
                expected_state=current.state,
                target_state=target,
            )
            self._events.append(
                guard=self._guard,
                event=MissionLifecycleEvent(
                    mission_id=mission_id,
                    sequence_number=self._events.next_sequence(mission_id),
                    from_state=current.state,
                    to_state=target,
                    mission_state_version=new_state.mission_state_version,
                    authorization_epoch=new_state.authorization_epoch,
                    actor=actor,
                    reason=reason,
                    occurred_at=self._clock.now(),
                )
            )
        return new_state

    def _check_startable(self, revision: MissionRevision) -> None:
        now = self._clock.now()
        if not (revision.valid_from <= now < revision.valid_until):
            raise MissionLifecycleError("mission cannot enter RUNNING outside its validity window")
        if revision.authorization_reference.strip() == "":
            raise MissionLifecycleError("mission lacks an authorization reference")
        profile = self._profiles.get(revision.llm_profile_revision)
        if profile is None or profile.profile_digest != revision.llm_profile_digest or not profile.is_usable():
            raise MissionLifecycleError("mission LLM profile is unregistered, changed, or unusable")

    # --- transitions ------------------------------------------------------

    def validate_mission(self, mission_id: str, expected_version: int) -> MissionState:
        current = self._current(mission_id)
        revision = self._revision(mission_id, current.mission_revision)
        profile = self._profiles.get(revision.llm_profile_revision)
        validate_mission_revision(
            revision, digest_service=self._digests, profile=profile, policy=self._validation_policy
        )
        return self._transition(mission_id, "VALIDATED", expected_version, actor="mission_manager", reason="validated")

    def start_mission(self, mission_id: str, expected_version: int) -> MissionState:
        current = self._current(mission_id)
        self._check_startable(self._revision(mission_id, current.mission_revision))
        return self._transition(mission_id, "RUNNING", expected_version, actor="mission_manager", reason="started")

    def pause_mission(self, mission_id: str, expected_version: int) -> MissionState:
        return self._transition(mission_id, "PAUSED", expected_version, actor="mission_manager", reason="paused")

    def resume_mission(self, mission_id: str, expected_version: int) -> MissionState:
        current = self._current(mission_id)
        self._check_startable(self._revision(mission_id, current.mission_revision))
        return self._transition(mission_id, "RUNNING", expected_version, actor="mission_manager", reason="resumed")

    def begin_finalization(self, mission_id: str, expected_version: int) -> MissionState:
        return self._transition(
            mission_id, "FINALIZING", expected_version, actor="mission_manager", reason="finalizing"
        )

    def complete_mission(self, mission_id: str, expected_version: int) -> MissionState:
        return self._transition(mission_id, "COMPLETED", expected_version, actor="mission_manager", reason="completed")

    def abort_mission(self, mission_id: str, expected_version: int) -> MissionState:
        return self._transition(mission_id, "ABORTED", expected_version, actor="mission_manager", reason="aborted")

    def invalidate_authorization(self, mission_id: str, expected_version: int) -> MissionState:
        with UnitOfWork(self._db):
            current = self._current(mission_id)
            new_state = self._states.rotate_epoch_in_place(
                guard=self._guard,
                mission_id=mission_id,
                expected_version=expected_version,
                expected_epoch=current.authorization_epoch,
            )
            self._events.append(
                guard=self._guard,
                event=MissionLifecycleEvent(
                    mission_id=mission_id,
                    sequence_number=self._events.next_sequence(mission_id),
                    from_state=current.state,
                    to_state=current.state,
                    mission_state_version=new_state.mission_state_version,
                    authorization_epoch=new_state.authorization_epoch,
                    actor="mission_manager",
                    reason="authorization_invalidated",
                    occurred_at=self._clock.now(),
                )
            )
        return new_state
