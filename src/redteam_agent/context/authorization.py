"""Context read-authorization service (owner of context_data_access_grants).

Issues a ``ContextDataAccessGrant`` from index *metadata* only, and binds each
resource to the current version/metadata digest resolved from the resource
metadata source of truth (the index is a candidate view and must agree with it).
The grant is bound to the current mission revision/epoch, current policy version,
service identity and session security-context digest, with an explicitly
requested TTL bounded by the mission validity, a fixed maximum, and session
freshness (out-of-range TTLs are rejected, not silently clamped).

Verification at use time loads the *stored* grant by id from the repository
(never trusting a caller-supplied grant model), reads time from the trusted
clock (never a caller ``now``), and re-checks mission RUNNING / validity window /
revision / epoch / current policy / service identity / session presence and
freshness / session-context digest / source-resource current binding, failing
closed on any drift (Codex C/F/#5, B-04).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.context.models import ContextDataAccessGrant
from redteam_agent.errors import (
    ContextSelectionError,
    DataAccessResourceError,
    SessionContextGrantStaleError,
)
from redteam_agent.mission.models import MissionRevision, MissionState
from redteam_agent.models.common import ResourceBinding
from redteam_agent.policy.data_access import evaluate_data_access
from redteam_agent.policy.models import DataAccessGrant, SessionContextGrant
from redteam_agent.policy.ttl import enforce_ttl
from redteam_agent.resources.resource_metadata import ResourceMetadataReader
from redteam_agent.runtime.clock import Clock
from redteam_agent.session.models import compute_session_security_context_digest
from redteam_agent.storage.guard import WriteGuard
from redteam_agent.storage.repositories import (
    ContextDataAccessGrantRepository,
    ContextResourceIndexRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PolicyRevisionRepository,
    SessionSecurityContextSnapshotRepository,
)

_VALID_SERVICE_IDENTITIES = frozenset({"planner_context", "analyzer_context"})
DEFAULT_MAX_CONTEXT_GRANT_TTL_SECONDS = 900


class ContextAuthorizationService:
    def __init__(
        self,
        *,
        state_repository: MissionStateRepository,
        revision_repository: MissionRevisionRepository,
        policy_repository: PolicyRevisionRepository,
        index_repository: ContextResourceIndexRepository,
        session_repository: SessionSecurityContextSnapshotRepository,
        grant_repository: ContextDataAccessGrantRepository,
        resource_metadata_reader: ResourceMetadataReader,
        digest_service: DigestService,
        clock: Clock,
        write_guard: WriteGuard,
        policy_version: str,
        max_ttl_seconds: int = DEFAULT_MAX_CONTEXT_GRANT_TTL_SECONDS,
    ) -> None:
        self._states = state_repository
        self._revisions = revision_repository
        self._policy_repo = policy_repository
        self._index = index_repository
        self._sessions = session_repository
        self._grants = grant_repository
        self._resource_metadata = resource_metadata_reader
        self._digests = digest_service
        self._clock = clock
        self._guard = write_guard
        self._policy_version = policy_version
        self._max_ttl_seconds = max_ttl_seconds
        grant_repository.bind_owner(write_guard)

    # --- shared checks ----------------------------------------------------

    def _current_policy_version(self) -> str:
        policy = self._policy_repo.get(self._policy_version)
        if policy is None:
            raise ContextSelectionError("current policy revision not found")
        return policy.policy_version

    def _running_revision(self, mission_id: str, now: datetime) -> tuple[MissionState, MissionRevision]:
        state = self._states.get(mission_id)
        if state is None:
            raise ContextSelectionError("mission state not found")
        if state.state != "RUNNING":
            raise SessionContextGrantStaleError("mission is not RUNNING")
        revision = self._revisions.get(mission_id, state.mission_revision)
        if revision is None:
            raise ContextSelectionError("mission revision not found")
        if not (revision.valid_from <= now < revision.valid_until):
            raise SessionContextGrantStaleError("mission is outside its validity window")
        return state, revision

    def _session_digest_and_freshness(self, session_ids: tuple[str, ...], now: datetime) -> str:
        contexts = []
        for session_id in session_ids:
            snap = self._sessions.get(session_id)
            if snap is None:
                raise SessionContextGrantStaleError("session not found for grant")
            if not (now < snap.session_fresh_until):
                raise SessionContextGrantStaleError("session is stale (past freshness bound)")
            contexts.append(snap.context)
        return compute_session_security_context_digest(tuple(contexts), self._digests)

    def _verify_resource_binding(self, grant: DataAccessGrant) -> None:
        source = self._resource_metadata.get(grant.resource.resource_id)
        if source is None:
            raise DataAccessResourceError("granted resource no longer exists in the source of truth")
        if (
            source.version != grant.resource.resource_version
            or source.metadata_digest != grant.resource.resource_digest
        ):
            raise DataAccessResourceError("granted resource version/digest changed since issuance")

    # --- issuance ---------------------------------------------------------

    def issue_grant(
        self,
        *,
        grant_id: str,
        mission_id: str,
        service_identity: str,
        candidate_resource_ids: tuple[str, ...],
        session_ids: tuple[str, ...],
        ttl_seconds: int,
    ) -> ContextDataAccessGrant:
        if service_identity not in _VALID_SERVICE_IDENTITIES:
            raise ContextSelectionError(f"unknown context service identity: {service_identity!r}")
        now = self._clock.now()
        state, revision = self._running_revision(mission_id, now)
        policy_version = self._current_policy_version()
        index = {record.resource_id: record for record in self._index.query_by_mission(mission_id)}

        grants: list[DataAccessGrant] = []
        for resource_id in candidate_resource_ids:
            record = index.get(resource_id)
            if record is None:
                raise DataAccessResourceError("candidate resource not present in the trusted index")
            # The index entry is only a candidate pointer; the authoritative
            # resource identity is its origin record. Policy, source-of-truth
            # binding and the granted resource id are all keyed off the origin,
            # so a benign-looking index alias cannot smuggle in a prohibited
            # origin under an allowed index id (R08).
            origin_id = record.origin_record_id
            source = self._resource_metadata.get(origin_id)
            if source is None:
                raise DataAccessResourceError("candidate origin resource not present in the source of truth")
            if record.resource_type != source.resource_type:
                raise DataAccessResourceError("index/source resource type mismatch")
            if record.origin_record_version != source.version or record.origin_record_digest != source.metadata_digest:
                raise DataAccessResourceError("index/source resource binding mismatch")
            decision = evaluate_data_access(revision.data_access_policy, source.resource_type, origin_id, "read")
            if not decision.allowed:
                raise DataAccessResourceError(f"read not permitted for {origin_id}: {decision.reason_code}")
            state_digest = self._digests.compute(
                "authorization_state_digest",
                {
                    "resource_type": source.resource_type,
                    "resource_id": origin_id,
                    "resource_version": source.version,
                    "resource_digest": source.metadata_digest,
                    "operations": ["read"],
                },
            )
            grants.append(
                DataAccessGrant(
                    resource_type=source.resource_type,
                    resource=ResourceBinding(
                        resource_id=origin_id, resource_version=source.version, resource_digest=source.metadata_digest
                    ),
                    authorization_state_digest=state_digest,
                    operations=frozenset({"read"}),
                )
            )
        grants.sort(key=lambda g: (g.resource_type, g.resource.resource_id))

        ordered_sessions = tuple(sorted(session_ids))
        session_context = SessionContextGrant(
            authorized_session_ids=ordered_sessions,
            session_security_context_digest=self._session_digest_and_freshness(ordered_sessions, now),
        )

        expires_at = now + timedelta(seconds=ttl_seconds)
        # Explicit rejection: TTL must be positive and within the mission
        # validity, the fixed maximum, and every used session's freshness.
        enforce_ttl(
            label="context_grant", issued_at=now, expires_at=expires_at, mission_valid_until=revision.valid_until
        )
        enforce_ttl(
            label="context_grant_max", issued_at=now, expires_at=expires_at,
            mission_valid_until=now + timedelta(seconds=self._max_ttl_seconds),
        )
        for session_id in ordered_sessions:
            snap = self._sessions.get(session_id)
            assert snap is not None  # freshness already validated above
            enforce_ttl(
                label="context_grant_session", issued_at=now, expires_at=expires_at,
                mission_valid_until=snap.session_fresh_until,
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
            policy_version=policy_version,
            issued_at=now,
            expires_at=expires_at,
        )
        payload = stub.model_dump(mode="python")
        payload.pop("grant_digest", None)
        grant = stub.model_copy(update={"grant_digest": self._digests.compute("grant_digest", payload)})
        self._grants.save(grant, guard=self._guard)
        return grant

    # --- verification (use time) ------------------------------------------

    def verify_grant(self, *, grant_id: str, mission_id: str) -> ContextDataAccessGrant:
        """Load the stored grant and fail closed on any staleness (B-04)."""
        now = self._clock.now()
        grant = self._grants.get(grant_id)  # authoritative, digest-verified
        if grant is None:
            raise SessionContextGrantStaleError("grant not found")
        state, _revision = self._running_revision(mission_id, now)
        if grant.mission_id != mission_id or grant.mission_revision != state.mission_revision:
            raise SessionContextGrantStaleError("grant mission revision is stale")
        if grant.authorization_epoch != state.authorization_epoch:
            raise SessionContextGrantStaleError("grant authorization epoch is stale")
        if grant.policy_version != self._current_policy_version():
            raise SessionContextGrantStaleError("grant policy version is stale")
        if grant.service_identity not in _VALID_SERVICE_IDENTITIES:
            raise SessionContextGrantStaleError("grant service identity is invalid")
        if not (now < grant.expires_at):
            raise SessionContextGrantStaleError("grant expired")
        current_digest = self._session_digest_and_freshness(grant.session_context.authorized_session_ids, now)
        if current_digest != grant.session_context.session_security_context_digest:
            raise SessionContextGrantStaleError("session security context changed since grant issuance")
        for resource_grant in grant.resources:
            self._verify_resource_binding(resource_grant)
        return grant
