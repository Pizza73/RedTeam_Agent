"""Context read-authorization service (owner of context_data_access_grants).

Issues a ``ContextDataAccessGrant`` from index *metadata* only: each candidate
resource is checked against the mission's data-access policy, the resource
binding is taken from the trusted index record (source of truth, not a caller
value), and the session view is bound to the current session security-context
digest. Grants are persisted with the write guard. Verification at use time
rejects a stale grant whose mission revision/epoch or session context has
changed (B-04). No resource body is read and no secret is resolved here.
"""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.context.models import ContextDataAccessGrant
from redteam_agent.errors import (
    ContextSelectionError,
    DataAccessResourceError,
    SessionContextGrantStaleError,
)
from redteam_agent.models.common import ResourceBinding
from redteam_agent.policy.data_access import evaluate_data_access
from redteam_agent.policy.models import DataAccessGrant, SessionContextGrant
from redteam_agent.policy.ttl import enforce_ttl
from redteam_agent.runtime.clock import Clock
from redteam_agent.session.models import compute_session_security_context_digest
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    ContextDataAccessGrantRepository,
    ContextResourceIndexRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    SessionSecurityContextSnapshotRepository,
)


class ContextAuthorizationService:
    def __init__(
        self,
        *,
        state_repository: MissionStateRepository,
        revision_repository: MissionRevisionRepository,
        index_repository: ContextResourceIndexRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        grant_repository: ContextDataAccessGrantRepository,
        digest_service: DigestService,
        clock: Clock,
        write_guard: WriteGuard,
    ) -> None:
        self._states = state_repository
        self._revisions = revision_repository
        self._index = index_repository
        self._sessions = session_repository
        self._grants = grant_repository
        self._digests = digest_service
        self._clock = clock
        self._guard = write_guard
        grant_repository.bind_owner(write_guard)

    def _current_session_digest(self, session_ids: tuple[str, ...]) -> str:
        contexts = []
        for session_id in session_ids:
            snap = self._sessions.get(session_id)
            if snap is None:
                raise SessionContextGrantStaleError("session not found for grant")
            contexts.append(snap.context)
        return compute_session_security_context_digest(tuple(contexts), self._digests)

    def issue_grant(
        self,
        *,
        grant_id: str,
        mission_id: str,
        service_identity: str,
        candidate_resource_ids: tuple[str, ...],
        session_ids: tuple[str, ...],
        ttl_seconds: int = 900,
    ) -> ContextDataAccessGrant:
        state = self._states.get(mission_id)
        if state is None:
            raise ContextSelectionError("mission state not found")
        revision = self._revisions.get(mission_id, state.mission_revision)
        if revision is None:
            raise ContextSelectionError("mission revision not found")
        index = {record.resource_id: record for record in self._index.query_by_mission(mission_id)}

        grants: list[DataAccessGrant] = []
        for resource_id in candidate_resource_ids:
            record = index.get(resource_id)
            if record is None:
                raise DataAccessResourceError("candidate resource not present in the trusted index")
            decision = evaluate_data_access(revision.data_access_policy, record.resource_type, resource_id, "read")
            if not decision.allowed:
                raise DataAccessResourceError(f"read not permitted for {resource_id}: {decision.reason_code}")
            state_digest = self._digests.compute(
                "authorization_state_digest",
                {
                    "resource_type": record.resource_type,
                    "resource_id": record.origin_record_id,
                    "resource_version": record.origin_record_version,
                    "resource_digest": record.origin_record_digest,
                    "operations": ["read"],
                },
            )
            grants.append(
                DataAccessGrant(
                    resource_type=record.resource_type,
                    resource=ResourceBinding(
                        resource_id=record.origin_record_id,
                        resource_version=record.origin_record_version,
                        resource_digest=record.origin_record_digest,
                    ),
                    authorization_state_digest=state_digest,
                    operations=frozenset({"read"}),
                )
            )
        grants.sort(key=lambda g: (g.resource_type, g.resource.resource_id))

        ordered_sessions = tuple(sorted(session_ids))
        session_context = SessionContextGrant(
            authorized_session_ids=ordered_sessions,
            session_security_context_digest=self._current_session_digest(ordered_sessions),
        )
        now = self._clock.now()
        expires_at = revision.valid_until
        enforce_ttl(
            label="context_grant", issued_at=now, expires_at=expires_at, mission_valid_until=revision.valid_until
        )
        stub = ContextDataAccessGrant(
            grant_id=grant_id,
            grant_digest="pending",
            mission_id=mission_id,
            mission_revision=revision.mission_revision,
            authorization_epoch=state.authorization_epoch,
            service_identity=service_identity,
            resources=tuple(grants),
            session_context=session_context,
            policy_version="context-grant-v1",
            issued_at=now,
            expires_at=expires_at,
        )
        payload = stub.model_dump(mode="python")
        payload.pop("grant_digest", None)
        grant = stub.model_copy(update={"grant_digest": self._digests.compute("grant_digest", payload)})
        self._grants.save(grant, guard=self._guard)
        return grant

    def verify_grant(self, grant: ContextDataAccessGrant, *, mission_id: str, now: datetime) -> None:
        """Fail closed if the grant is stale relative to the current mission (B-04)."""
        state = self._states.get(mission_id)
        if state is None:
            raise ContextSelectionError("mission state not found")
        if grant.mission_id != mission_id or grant.mission_revision != state.mission_revision:
            raise SessionContextGrantStaleError("grant mission revision is stale")
        if grant.authorization_epoch != state.authorization_epoch:
            raise SessionContextGrantStaleError("grant authorization epoch is stale")
        if not (now < grant.expires_at):
            raise SessionContextGrantStaleError("grant expired")
        current_digest = self._current_session_digest(grant.session_context.authorized_session_ids)
        if current_digest != grant.session_context.session_security_context_digest:
            raise SessionContextGrantStaleError("session security context changed since grant issuance")
