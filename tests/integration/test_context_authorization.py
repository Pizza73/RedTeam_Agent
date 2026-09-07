"""Context read-authorization grant tests (Codex #5, B-04 stale session grant)."""

from __future__ import annotations

import pytest

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.context.models import ContextResourceIndexRecord
from redteam_agent.errors import DataAccessResourceError, SessionContextGrantStaleError
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.runtime.clock import ManualClock


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
        origin_record_version="1",
        origin_record_digest="artifact-digest-1",
    )


def _read_policy() -> DataAccessPolicy:
    return DataAccessPolicy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="exact:res-1", operations=frozenset({"read"})),),
        prohibited=(),
    )


def _seed(kernel, *, data_access_policy=None):
    tool = support.network_tool()
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service), data_access_policy=data_access_policy
    )
    return support.seed_running_mission(kernel, tool=tool, revision=revision, session_ids=("sess-1",))


def _kernel():
    return build_test_kernel(clock=ManualClock(support.T0))


def test_issue_and_verify_grant() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    kernel.index_repository.save(_index_record())
    grant = kernel.context_authorization_service.issue_grant(
        grant_id="grant-1", mission_id=support.MISSION_ID, service_identity="planner_context",
        candidate_resource_ids=("res-1",), session_ids=("sess-1",),
    )
    assert grant.resources[0].resource.resource_id == "res-1"
    kernel.context_authorization_service.verify_grant(grant, mission_id=support.MISSION_ID, now=support.T0)


def test_grant_stale_after_epoch_rotation() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    kernel.index_repository.save(_index_record())
    grant = kernel.context_authorization_service.issue_grant(
        grant_id="grant-1", mission_id=support.MISSION_ID, service_identity="planner_context",
        candidate_resource_ids=("res-1",), session_ids=("sess-1",),
    )
    kernel.mission_manager.invalidate_authorization(support.MISSION_ID, expected_version=2)
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant, mission_id=support.MISSION_ID, now=support.T0)


def test_grant_stale_after_session_context_change() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    kernel.index_repository.save(_index_record())
    grant = kernel.context_authorization_service.issue_grant(
        grant_id="grant-1", mission_id=support.MISSION_ID, service_identity="planner_context",
        candidate_resource_ids=("res-1",), session_ids=("sess-1",),
    )
    # Change the session's security-relevant context (privilege escalation).
    kernel.session_repository.save(support.session_snapshot(session_id="sess-1", privileged=True))
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant, mission_id=support.MISSION_ID, now=support.T0)


def test_read_not_permitted_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=DataAccessPolicy(allowed=(), prohibited=()))
    kernel.index_repository.save(_index_record())
    with pytest.raises(DataAccessResourceError):
        kernel.context_authorization_service.issue_grant(
            grant_id="grant-1", mission_id=support.MISSION_ID, service_identity="planner_context",
            candidate_resource_ids=("res-1",), session_ids=("sess-1",),
        )


def test_candidate_not_in_index_rejected() -> None:
    kernel = _kernel()
    _seed(kernel, data_access_policy=_read_policy())
    with pytest.raises(DataAccessResourceError):
        kernel.context_authorization_service.issue_grant(
            grant_id="grant-1", mission_id=support.MISSION_ID, service_identity="planner_context",
            candidate_resource_ids=("res-1",), session_ids=("sess-1",),
        )
