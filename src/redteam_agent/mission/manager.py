"""Mission Manager: the single legitimate lifecycle entry point (SystemDesign §21.1).

Only this component transitions a mission between lifecycle states. Every public
operation requires an authenticated actor (resolved from a Root-fixed principal
resolver) that holds the required mission role, and records that authenticated
principal as the audit actor (R18). A bare caller string is never authority.

Transitions validate the fixed state machine, the expected version/epoch/state,
and commit the new state together with a mission-owned lifecycle event in one
SQLite transaction (real OCC). Starting or resuming additionally re-checks the
trusted clock against the mission validity window, the authorization reference,
and the bound LLM profile. Revocation boundaries rotate the authorization epoch.
"""

from __future__ import annotations

from redteam_agent.auth.principal import PrincipalResolver
from redteam_agent.auth.rbac import RbacPolicy
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    MissionAuthorizationError,
    MissionLifecycleError,
    MissionValidationError,
    TrustRecoveryError,
)
from redteam_agent.mission.models import (
    MissionLifecycleEvent,
    MissionLifecycleState,
    MissionRevision,
    MissionState,
)
from redteam_agent.mission.validation import MissionValidationPolicy, validate_mission_revision
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import CriticalMutation, Database, UnitOfWork
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    AgentProfileRepository,
    MissionLifecycleEventRepository,
    MissionRevisionRepository,
    MissionStateRepository,
)

MISSION_ADMIN_ROLE = "mission_admin"
MISSION_OPERATOR_ROLE = "mission_operator"


class MissionManager:
    def __init__(
        self,
        *,
        database: Database,
        revision_repository: MissionRevisionRepository,
        state_repository: MissionStateRepository,
        event_repository: MissionLifecycleEventRepository,
        profile_repository: AgentProfileRepository,
        principal_resolver: PrincipalResolver,
        rbac: RbacPolicy,
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
        self._principals = principal_resolver
        self._rbac = rbac
        self._digests = digest_service
        self._validation_policy = validation_policy
        self._clock = clock
        self._guard = write_guard
        self._trust_recovery_guard: WriteGuard | None = None
        state_repository.bind_owner(write_guard)
        event_repository.bind_owner(write_guard)

    def bind_trust_recovery_guard(self, guard: WriteGuard) -> None:
        if self._trust_recovery_guard is not None:
            raise TrustRecoveryError("mission trust recovery guard is already configured")
        self._trust_recovery_guard = guard

    def invalidate_all_authorizations_for_trust_recovery_in_txn(
        self, *, guard: WriteGuard, new_trust_epoch: int
    ) -> tuple[int, str]:
        """Rotate every mission epoch in the recovery transaction and return its root."""
        if guard is not self._trust_recovery_guard or not self._db.in_transaction:
            raise TrustRecoveryError("authorization invalidation requires the offline recovery guard")
        for current in self._states.all_states():
            updated = self._states.rotate_epoch_for_trust_recovery(guard=self._guard, current=current)
            occurred_at = self._clock.now()
            self._events.append(
                guard=self._guard,
                event=MissionLifecycleEvent(
                    mission_id=current.mission_id,
                    sequence_number=self._events.next_sequence(current.mission_id),
                    from_state=current.state,
                    to_state=updated.state,
                    mission_state_version=updated.mission_state_version,
                    authorization_epoch=updated.authorization_epoch,
                    actor="offline-trust-recovery",
                    reason=f"trust_epoch_{new_trust_epoch}_authorization_invalidation",
                    occurred_at=occurred_at,
                ),
            )
        return self.current_authorizations_for_trust_recovery(new_trust_epoch=new_trust_epoch)

    def current_authorizations_for_trust_recovery(
        self, *, new_trust_epoch: int
    ) -> tuple[int, str]:
        """Recompute the recovery authorization root without changing mission state."""
        projections = tuple(
            {
                "mission_id": state.mission_id,
                "mission_state_version": state.mission_state_version,
                "authorization_epoch": state.authorization_epoch,
                "state": state.state,
            }
            for state in self._states.all_states()
        )
        return len(projections), self._digests.compute(
            "security_projection_digest",
            {"new_trust_epoch": new_trust_epoch, "invalidated_authorizations": projections},
        )

    # --- actor authorization ----------------------------------------------

    def _authorize_actor(self, mission_id: str, actor_token: str, role: str) -> str:
        principal = self._principals.authenticate(actor_token)
        if principal is None:
            raise MissionAuthorizationError("mission actor is not authenticated")
        if not self._rbac.has_role(mission_id, principal.principal_id, role):
            raise MissionAuthorizationError(f"actor lacks the required mission role: {role}")
        return principal.principal_id

    def authorize_operator(self, mission_id: str, actor_token: str) -> str:
        """Authenticate an operator and confirm the mission operator role (R18).

        The durable-resume trigger is operator-initiated, so it must present an
        authenticated principal that holds the mission operator role, exactly like
        pause/resume. A bare caller string is never authority.
        """
        return self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)

    # --- creation ---------------------------------------------------------

    def create_mission(self, revision: MissionRevision, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(revision.mission_id, actor_token, MISSION_ADMIN_ROLE)
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
            self._append_event(revision.mission_id, "DRAFT", "DRAFT", state, actor, "created")
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

    def _append_event(
        self,
        mission_id: str,
        from_state: MissionLifecycleState,
        to_state: MissionLifecycleState,
        new_state: MissionState,
        actor: str,
        reason: str,
    ) -> None:
        occurred_at = self._clock.now()
        self._events.append(
            guard=self._guard,
            event=MissionLifecycleEvent(
                mission_id=mission_id,
                sequence_number=self._events.next_sequence(mission_id),
                from_state=from_state,
                to_state=to_state,
                mission_state_version=new_state.mission_state_version,
                authorization_epoch=new_state.authorization_epoch,
                actor=actor,
                reason=reason,
                occurred_at=occurred_at,
            ),
        )
        projection = self.current_security_projection(new_state.mission_id)[1]
        self._db.record_critical_mutation(
            CriticalMutation(
                mission_id=mission_id,
                event_type="MISSION_AUTHORIZATION_CHANGED",
                actor_id=actor,
                occurred_at_iso=occurred_at.isoformat(),
                record_type="mission_authorization",
                record_id=mission_id,
                state_version=new_state.mission_state_version + 1,
                security_projection_digest=projection,
            )
        )

    def current_security_projection(self, mission_id: str) -> tuple[int, str]:
        """Rebuild the current Mission/Authorization projection from owner records."""
        state = self._current(mission_id)
        projection = self._digests.compute(
            "security_projection_digest",
            {
                "mission_id": state.mission_id,
                "mission_revision": state.mission_revision,
                "mission_state_version": state.mission_state_version,
                "authorization_epoch": state.authorization_epoch,
                "state": state.state,
                "active_revision_digest": self._revision(
                    state.mission_id, state.mission_revision
                ).mission_revision_digest,
                "rbac_projection": tuple(
                    assignment.model_dump(mode="python")
                    for assignment in sorted(
                        self._rbac.assignments_for(state.mission_id),
                        key=lambda item: (item.principal_id, item.role),
                    )
                ),
            },
        )
        return state.mission_state_version + 1, projection

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
            self._append_event(mission_id, current.state, target, new_state, actor, reason)
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

    def validate_mission(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        current = self._current(mission_id)
        revision = self._revision(mission_id, current.mission_revision)
        profile = self._profiles.get(revision.llm_profile_revision)
        validate_mission_revision(
            revision, digest_service=self._digests, profile=profile, policy=self._validation_policy
        )
        return self._transition(mission_id, "VALIDATED", expected_version, actor=actor, reason="validated")

    def start_mission(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        current = self._current(mission_id)
        self._check_startable(self._revision(mission_id, current.mission_revision))
        return self._transition(mission_id, "RUNNING", expected_version, actor=actor, reason="started")

    def pause_mission(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        return self._transition(mission_id, "PAUSED", expected_version, actor=actor, reason="paused")

    def resume_mission(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        current = self._current(mission_id)
        self._check_startable(self._revision(mission_id, current.mission_revision))
        return self._transition(mission_id, "RUNNING", expected_version, actor=actor, reason="resumed")

    def begin_finalization(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        return self._transition(mission_id, "FINALIZING", expected_version, actor=actor, reason="finalizing")

    def complete_mission(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        return self._transition(mission_id, "COMPLETED", expected_version, actor=actor, reason="completed")

    def abort_mission(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        return self._transition(mission_id, "ABORTED", expected_version, actor=actor, reason="aborted")

    def wait_for_human_review(
        self, mission_id: str, expected_version: int, *, actor_token: str
    ) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        return self._transition(
            mission_id,
            "WAITING_HUMAN_REVIEW",
            expected_version,
            actor=actor,
            reason="unresolved_recovery",
        )

    def invalidate_authorization(self, mission_id: str, expected_version: int, *, actor_token: str) -> MissionState:
        actor = self._authorize_actor(mission_id, actor_token, MISSION_OPERATOR_ROLE)
        with UnitOfWork(self._db):
            current = self._current(mission_id)
            new_state = self._states.rotate_epoch_in_place(
                guard=self._guard,
                mission_id=mission_id,
                expected_version=expected_version,
                expected_epoch=current.authorization_epoch,
            )
            self._append_event(
                mission_id, current.state, current.state, new_state, actor, "authorization_invalidated"
            )
        return new_state
