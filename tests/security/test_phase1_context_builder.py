"""Context bodies are reachable only through a verified exact grant."""

from __future__ import annotations

import pytest

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.context.authorization import ContextAuthorizationService
from redteam_agent.context.builder import ContextBodyRecord, ContextBodyStore, ContextBuilder
from redteam_agent.context.models import ContextDataAccessGrant
from redteam_agent.errors import SessionContextGrantStaleError
from redteam_agent.models.common import ResourceBinding
from redteam_agent.policy.models import DataAccessGrant, SessionContextGrant


class _FixedAuthorization(ContextAuthorizationService):
    def __init__(self, grant: ContextDataAccessGrant | None) -> None:
        self._grant = grant

    def verify_grant(self, *, grant_id: str, mission_id: str) -> ContextDataAccessGrant:
        if self._grant is None or self._grant.grant_id != grant_id or self._grant.mission_id != mission_id:
            raise SessionContextGrantStaleError("grant not found")
        return self._grant


def _body_digest(ds: DigestService) -> str:
    return ds.compute("security_projection_digest", {"body": {"status": "open"}})


def _grant(ds: DigestService) -> ContextDataAccessGrant:
    body_digest = _body_digest(ds)
    state = ds.compute("authorization_state_digest", {
        "resource_type": "artifact", "resource_id": "artifact-1",
        "resource_version": "v1", "resource_digest": body_digest, "operations": ["read"],
    })
    return ContextDataAccessGrant(
        grant_id="grant-1", grant_digest="grant-digest", mission_id="mission-1",
        mission_revision=1, authorization_epoch=0, service_identity="planner_context",
        resources=(DataAccessGrant(
            resource_type="artifact",
            resource=ResourceBinding(
                resource_id="artifact-1", resource_version="v1", resource_digest=body_digest
            ),
            authorization_state_digest=state, operations=frozenset({"read"}),
        ),),
        session_context=SessionContextGrant(
            authorized_session_ids=(), session_security_context_digest="session-digest"
        ),
        policy_version="policy-v1", issued_at=support.T0,
        expires_at=support.T0.replace(year=support.T0.year + 1),
    )


def test_context_builder_reads_only_the_body_bound_by_verified_grant() -> None:
    ds = DigestService()
    grant = _grant(ds)
    store = ContextBodyStore(ds)
    store.put(ContextBodyRecord(
        resource_id="artifact-1", resource_type="artifact", resource_version="v1",
        resource_digest=_body_digest(ds), classification="redacted", body={"status": "open"},
    ))
    context = ContextBuilder(
        authorization_service=_FixedAuthorization(grant), body_store=store
    ).build(grant_id="grant-1", mission_id="mission-1")
    assert context["resources"][0]["body"] == {"status": "open"}


def test_context_builder_cannot_read_body_without_stored_grant() -> None:
    ds = DigestService()
    store = ContextBodyStore(ds)
    store.put(ContextBodyRecord(
        resource_id="artifact-1", resource_type="artifact", resource_version="v1",
        resource_digest=_body_digest(ds), classification="redacted", body={"status": "open"},
    ))
    with pytest.raises(SessionContextGrantStaleError):
        ContextBuilder(
            authorization_service=_FixedAuthorization(None), body_store=store
        ).build(grant_id="missing", mission_id="mission-1")
