"""Context read authorization and stale-binding enforcement."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.authorization_runtime import AuthorizationRuntimeContextResolver
from redteam_agent.canonical import digest_model, sha256_digest, stable_id, verify_model_digest
from redteam_agent.errors import (
    AuthorizationEpochMismatchError,
    ContextAuthorizationError,
    DataAccessDeniedError,
    MissionTTLExceededError,
    SessionContextGrantStaleError,
)
from redteam_agent.models.capabilities import SessionSecurityContextSnapshot
from redteam_agent.models.context import (
    CandidateContextResource,
    ContextDataAccessGrant,
    ContextServiceIdentity,
    DataAccessGrant,
    ResourceBinding,
    SessionContextGrant,
)
from redteam_agent.models.mission import Mission
from redteam_agent.models.scope import SessionScopeRule
from redteam_agent.policy.data_access import DataAccessEvaluator
from redteam_agent.repositories.context import (
    ContextAuthorizationRepository,
    ContextResourceIndexRepository,
)

_CONTEXT_AUTHORIZER_TOKEN = object()


def session_context_digest(
    snapshot: SessionSecurityContextSnapshot, authorized_session_ids: tuple[str, ...]
) -> str:
    contexts = [
        context.model_dump(mode="python")
        for context in snapshot.contexts
        if context.session_id in authorized_session_ids
    ]
    contexts.sort(key=lambda item: item["session_id"])
    return sha256_digest({"schema_version": "session-context-v1", "contexts": contexts})


class ContextAuthorizationService:
    def __init__(self, data_access: DataAccessEvaluator | None = None) -> None:
        self.data_access = data_access or DataAccessEvaluator()

    def calculate(
        self,
        *,
        mission: Mission,
        service_identity: ContextServiceIdentity,
        candidates: tuple[CandidateContextResource, ...],
        requested_session_ids: tuple[str, ...],
        session_snapshot: SessionSecurityContextSnapshot,
        policy_version: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> ContextDataAccessGrant:
        if service_identity not in {"planner_context", "analyzer_context"}:
            raise ContextAuthorizationError("unknown context service identity")
        if issued_at >= expires_at or expires_at > mission.valid_until:
            raise MissionTTLExceededError("context authorization TTL violates mission validity")
        if mission.state != "RUNNING":
            raise ContextAuthorizationError("context authorization requires a RUNNING mission")

        grants: list[DataAccessGrant] = []
        for candidate in candidates:
            grant = DataAccessGrant(
                resource_type=candidate.resource_type,
                resource=candidate.binding,
                operations=frozenset({"read"}),
            )
            if self.data_access.allows(grant, mission.data_access_policy):
                grants.append(grant)
        grants.sort(
            key=lambda item: (
                item.resource_type,
                item.resource.resource_id,
                item.resource.resource_version,
                tuple(sorted(item.operations)),
            )
        )

        in_scope_sessions = {
            rule.session_id
            for rule in mission.allowed_execution_scope
            if isinstance(rule, SessionScopeRule)
        }
        prohibited_sessions = {
            rule.session_id
            for rule in mission.prohibited_execution_scope
            if isinstance(rule, SessionScopeRule)
        }
        existing_sessions = {context.session_id for context in session_snapshot.contexts}
        authorized_sessions = tuple(
            sorted(
                set(requested_session_ids)
                & in_scope_sessions
                & existing_sessions - prohibited_sessions
            )
        )
        session_grant = SessionContextGrant(
            authorized_session_ids=authorized_sessions,
            session_security_context_digest=session_context_digest(
                session_snapshot, authorized_sessions
            ),
        )
        base = {
            "schema_version": "context-grant-v1",
            "mission_id": mission.mission_id,
            "mission_revision": mission.mission_revision,
            "authorization_epoch": mission.authorization_epoch,
            "service_identity": service_identity,
            "resources": [grant.model_dump(mode="python") for grant in grants],
            "session_context": session_grant.model_dump(mode="python"),
            "policy_version": policy_version,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        grant_id = stable_id("ctxgrant", base)
        provisional = ContextDataAccessGrant(
            grant_id=grant_id,
            grant_digest="pending",
            mission_id=mission.mission_id,
            mission_revision=mission.mission_revision,
            authorization_epoch=mission.authorization_epoch,
            service_identity=service_identity,
            resources=tuple(grants),
            session_context=session_grant,
            policy_version=policy_version,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return provisional.model_copy(
            update={"grant_digest": digest_model(provisional, exclude={"grant_digest"})}
        )


class ContextAccessGate:
    """Validates metadata bindings before a separate content repository may be called."""

    def __init__(
        self,
        index_repository: ContextResourceIndexRepository,
        grant_repository: ContextAuthorizationRepository,
        runtime_resolver: AuthorizationRuntimeContextResolver,
    ) -> None:
        self.index_repository = index_repository
        self.grant_repository = grant_repository
        self.runtime_resolver = runtime_resolver

    def authorize_resource(
        self,
        *,
        grant_id: str,
        mission_id: str,
        service_identity: ContextServiceIdentity,
        resource_id: str,
        operation: str,
        now: datetime,
    ) -> ResourceBinding:
        grant = self.grant_repository.get(grant_id)
        if grant is None:
            raise DataAccessDeniedError("context grant is required")
        try:
            runtime = self.runtime_resolver.resolve(mission_id)
        except Exception as exc:
            raise DataAccessDeniedError("current context authorization state is invalid") from exc
        mission = runtime.mission
        if mission.state != "RUNNING":
            raise DataAccessDeniedError("context grants require a RUNNING mission")
        verify_model_digest(grant, grant.grant_digest, exclude={"grant_digest"})
        if (
            grant.mission_id != mission.mission_id
            or grant.mission_revision != mission.mission_revision
        ):
            raise DataAccessDeniedError("context grant mission binding mismatch")
        if grant.authorization_epoch != mission.authorization_epoch:
            raise AuthorizationEpochMismatchError("context grant authorization epoch is stale")
        if grant.service_identity != service_identity:
            raise DataAccessDeniedError("context grant service identity mismatch")
        if grant.policy_version != runtime.policy_state.policy_version:
            raise DataAccessDeniedError("context grant policy version is stale")
        if now >= grant.expires_at:
            raise DataAccessDeniedError("context grant has expired")
        expected_session_digest = session_context_digest(
            runtime.session_snapshot, grant.session_context.authorized_session_ids
        )
        if expected_session_digest != grant.session_context.session_security_context_digest:
            raise SessionContextGrantStaleError("session security context changed")
        matching = [
            entry
            for entry in grant.resources
            if entry.resource.resource_id == resource_id and operation in entry.operations
        ]
        if len(matching) != 1:
            raise DataAccessDeniedError("resource operation is not granted")
        if not DataAccessEvaluator().allows(matching[0], mission.data_access_policy):
            raise DataAccessDeniedError("current data access policy denies the resource")
        try:
            current = self.index_repository.current_binding(mission.mission_id, resource_id)
        except Exception as exc:
            raise DataAccessDeniedError("resource index integrity failure") from exc
        if current is None or current.binding != matching[0].resource:
            raise DataAccessDeniedError("resource version or digest changed after grant issuance")
        return matching[0].resource


class ContextAuthorizationApplicationService:
    """Only regular issuance path: resolve current state, calculate, then persist."""

    def __init__(
        self,
        calculator: ContextAuthorizationService,
        repository: ContextAuthorizationRepository,
        runtime_resolver: AuthorizationRuntimeContextResolver,
    ) -> None:
        self.calculator = calculator
        self.repository = repository
        self.runtime_resolver = runtime_resolver

    def issue(
        self,
        *,
        mission_id: str,
        service_identity: ContextServiceIdentity,
        candidates: tuple[CandidateContextResource, ...],
        requested_session_ids: tuple[str, ...],
        issued_at: datetime,
        expires_at: datetime,
    ) -> ContextDataAccessGrant:
        runtime = self.runtime_resolver.resolve(mission_id)
        grant = self.calculator.calculate(
            mission=runtime.mission,
            service_identity=service_identity,
            candidates=candidates,
            requested_session_ids=requested_session_ids,
            session_snapshot=runtime.session_snapshot,
            policy_version=runtime.policy_state.policy_version,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return self.repository._store_issued(grant, authorizer_token=_CONTEXT_AUTHORIZER_TOKEN)
