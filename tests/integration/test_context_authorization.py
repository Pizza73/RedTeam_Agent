"""Context read-authorization grant tests (Codex C/F/#5, B-04 stale grant)."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.context.models import ContextResourceIndexRecord
from redteam_agent.errors import (
    AuthorizationTtlError,
    ContextSelectionError,
    DataAccessResourceError,
    SessionContextGrantStaleError,
)
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.resources.resource_metadata import ResourceMetadata
from redteam_agent.runtime.clock import ManualClock

_RES_VERSION = "1"
_RES_DIGEST = "artifact-digest-1"


def _index_record(resource_id: str = "res-1") -> ContextResourceIndexRecord:
    return ContextResourceIndexRecord(
        resource_id=resource_id,
        resource_type="artifact",
        mission_id=support.MISSION_ID,
        target_references=(),
        verification_state="verified",
        observed_at=support.T0,
        classification="internal",
        summary_metadata={"size": 10},
        origin_record_id=resource_id,
        origin_record_version=_RES_VERSION,
        origin_record_digest=_RES_DIGEST,
    )


def _resource_metadata(resource_id: str = "res-1", *, version: str = _RES_VERSION, digest: str = _RES_DIGEST) -> ResourceMetadata:
    return ResourceMetadata(
        resource_id=resource_id, resource_type="artifact", version=version, metadata_digest=digest, classification="internal"
    )


def _read_policy() -> DataAccessPolicy:
    return DataAccessPolicy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="exact:res-1", operations=frozenset({"read"})),),
        prohibited=(),
    )


def _kernel(clock=None):
    return build_test_kernel(clock=clock or ManualClock(support.T0))


def _seed(kernel, *, data_access_policy=None):
    tool = support.network_tool()
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service), data_access_policy=data_access_policy
    )
    return support.seed_running_mission(kernel, tool=tool, revision=revision, session_ids=("sess-1",))


def _seed_resource(kernel):
    kernel.index_repository.save(_index_record())
    kernel.resource_metadata_store.put(_resource_metadata())


def _issue(kernel, *, candidates=("res-1",), sessions=("sess-1",), ttl=300, service="planner_context"):
    return kernel.context_authorization_service.issue_grant(
        grant_id="grant-1", mission_id=support.MISSION_ID, service_identity=service,
        candidate_resource_ids=candidates, session_ids=sessions, ttl_seconds=ttl,
    )


def test_issue_and_verify_grant() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    _seed_resource(kernel)
    grant = _issue(kernel)
    assert grant.resources[0].resource.resource_id == "res-1"
    kernel.context_authorization_service.verify_grant(grant_id="grant-1", mission_id=support.MISSION_ID)


def test_requested_ttl_is_honored_not_extended() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    grant = _issue(kernel, candidates=(), sessions=(), ttl=1)
    assert grant.expires_at == support.T0 + timedelta(seconds=1)
    assert grant.expires_at != kernel.revision_repository.get(support.MISSION_ID, 1).valid_until


def test_zero_ttl_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    with pytest.raises(AuthorizationTtlError):
        _issue(kernel, candidates=(), sessions=(), ttl=0)


def test_over_max_ttl_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    with pytest.raises(AuthorizationTtlError):
        _issue(kernel, candidates=(), sessions=(), ttl=10 * 24 * 3600)


def test_forged_grant_model_is_not_trusted() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    _issue(kernel, candidates=(), sessions=())
    # A caller-forged grant id that was never persisted is rejected.
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant_id="not-persisted", mission_id=support.MISSION_ID)


def test_issue_rejected_when_mission_paused() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    kernel.mission_manager.pause_mission(
        support.MISSION_ID, expected_version=2, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    with pytest.raises(SessionContextGrantStaleError):
        _issue(kernel, candidates=(), sessions=())


def test_verify_rejected_when_mission_paused() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    _issue(kernel, candidates=(), sessions=())
    kernel.mission_manager.pause_mission(
        support.MISSION_ID, expected_version=2, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant_id="grant-1", mission_id=support.MISSION_ID)


def test_grant_stale_after_epoch_rotation() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    _issue(kernel, candidates=(), sessions=())
    kernel.mission_manager.invalidate_authorization(
        support.MISSION_ID, expected_version=2, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant_id="grant-1", mission_id=support.MISSION_ID)


def test_grant_expired_rejected() -> None:
    clock = ManualClock(support.T0)
    kernel = _kernel(clock)
    _seed(kernel, data_access_policy=_read_policy())
    grant = _issue(kernel, candidates=(), sessions=(), ttl=60)
    clock.set(grant.expires_at + timedelta(seconds=1))
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant_id="grant-1", mission_id=support.MISSION_ID)


def test_grant_stale_after_session_context_change() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    _issue(kernel, candidates=(), sessions=("sess-1",))
    kernel.session_repository.save(support.session_snapshot(session_id="sess-1", privileged=True))
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant_id="grant-1", mission_id=support.MISSION_ID)


def test_wrong_service_identity_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    with pytest.raises(ContextSelectionError):
        _issue(kernel, candidates=(), sessions=(), service="bogus_context")


def test_read_not_permitted_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=DataAccessPolicy(allowed=(), prohibited=()))
    _seed_resource(kernel)
    with pytest.raises(DataAccessResourceError):
        _issue(kernel)


def test_candidate_not_in_index_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    kernel.resource_metadata_store.put(_resource_metadata())  # in source but not index
    with pytest.raises(DataAccessResourceError):
        _issue(kernel)


def test_index_source_binding_mismatch_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    kernel.index_repository.save(_index_record())
    kernel.resource_metadata_store.put(_resource_metadata(version="2"))  # source disagrees with index
    with pytest.raises(DataAccessResourceError):
        _issue(kernel)


def test_source_substitution_after_issue_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    _seed_resource(kernel)
    _issue(kernel)
    # Substitute the resource in the source of truth (version bump) after issuance.
    kernel.resource_metadata_store.put(_resource_metadata(version="2", digest="artifact-digest-2"))
    with pytest.raises(DataAccessResourceError):
        kernel.context_authorization_service.verify_grant(grant_id="grant-1", mission_id=support.MISSION_ID)
