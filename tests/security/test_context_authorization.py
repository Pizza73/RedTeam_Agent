from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from redteam_agent.canonical import CanonicalJsonObject
from redteam_agent.context import (
    ContextAccessGate,
    ContextAuthorizationApplicationService,
    ContextAuthorizationService,
    ContextSelector,
)
from redteam_agent.errors import DataAccessDeniedError
from redteam_agent.mission import AuthorizationReferenceRegistry, MissionManager
from redteam_agent.models.common import OperationalPhase
from redteam_agent.models.context import (
    ContextResourceIndexRecord,
    ContextSelectionRequest,
    ResourceBinding,
)
from redteam_agent.models.scope import HostTargetReference
from redteam_agent.repositories import (
    ContextAuthorizationRepository,
    LLMProfileRepository,
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
)
from redteam_agent.seeds import FIXED_TIME, mock_context_index
from redteam_agent.storage import Database
from tests.helpers import build_environment, persist_environment


def setup_context(database: Database):
    kernel = persist_environment(database, build_environment())
    record = mock_context_index(kernel.environment.mission.mission_id)
    kernel.resources.add(record)
    candidates = ContextSelector(kernel.resources).select(
        ContextSelectionRequest(
            mission_id=record.mission_id,
            current_targets=(HostTargetReference(type="host", host_id="host-1"),),
            candidate_session_ids=("session-1",),
            operational_phase=OperationalPhase.DISCOVERY,
        )
    )
    grants = ContextAuthorizationRepository(database)
    grant = ContextAuthorizationApplicationService(
        ContextAuthorizationService(), grants, kernel.runtime_resolver
    ).issue(
        mission_id=record.mission_id,
        service_identity="planner_context",
        candidates=candidates,
        requested_session_ids=("session-1", "session-not-in-scope"),
        issued_at=FIXED_TIME,
        expires_at=FIXED_TIME + timedelta(minutes=10),
    )
    gate = ContextAccessGate(kernel.resources, grants, kernel.runtime_resolver)
    return kernel, record, candidates, grants, grant, gate


def test_context_index_rejects_body_and_secret_metadata() -> None:
    base = mock_context_index("mission-phase-0a").model_dump(mode="python")
    base["summary_metadata"] = CanonicalJsonObject({"body": "forbidden"})
    with pytest.raises(ValidationError):
        ContextResourceIndexRecord.model_validate(base)
    base["summary_metadata"] = CanonicalJsonObject({"secret_value": "forbidden"})
    with pytest.raises(ValidationError):
        ContextResourceIndexRecord.model_validate(base)


def test_selector_returns_references_not_content() -> None:
    with Database() as database:
        _, record, candidates, _, _, _ = setup_context(database)
        assert candidates[0].binding == record.binding
        assert "body" not in type(candidates[0]).model_fields


def test_grant_excludes_session_not_explicitly_in_scope() -> None:
    with Database() as database:
        _, _, _, _, grant, _ = setup_context(database)
        assert grant.session_context.authorized_session_ids == ("session-1",)


def test_grant_persistence_is_idempotent() -> None:
    with Database() as database:
        _, _, _, repository, grant, _ = setup_context(database)
        from redteam_agent.context.authorization import _CONTEXT_AUTHORIZER_TOKEN

        repository._store_issued(grant, authorizer_token=_CONTEXT_AUTHORIZER_TOKEN)
        assert database.connection.execute(
            "SELECT COUNT(*) FROM context_data_access_grants"
        ).fetchone()[0] == 1


def test_grant_id_is_required_and_ungranted_resource_is_denied() -> None:
    with Database() as database:
        kernel, _, _, _, grant, gate = setup_context(database)
        with pytest.raises(DataAccessDeniedError):
            gate.authorize_resource(
                grant_id="missing",
                mission_id=kernel.environment.mission.mission_id,
                service_identity="planner_context",
                resource_id="knowledge:host-1",
                operation="read",
                now=FIXED_TIME + timedelta(minutes=1),
            )
        with pytest.raises(DataAccessDeniedError):
            gate.authorize_resource(
                grant_id=grant.grant_id,
                mission_id=kernel.environment.mission.mission_id,
                service_identity="planner_context",
                resource_id="knowledge:not-granted",
                operation="read",
                now=FIXED_TIME + timedelta(minutes=1),
            )


def test_resource_version_or_digest_change_makes_old_grant_stale() -> None:
    with Database() as database:
        kernel, record, _, _, grant, gate = setup_context(database)
        changed = record.model_copy(
            update={
                "index_id": "index-knowledge-1-v2",
                "binding": ResourceBinding(
                    resource_id=record.binding.resource_id,
                    resource_version="2",
                    resource_digest="sha256:knowledge-host-1-v2",
                ),
            }
        )
        kernel.resources.add(changed)
        with pytest.raises(DataAccessDeniedError, match="version or digest"):
            gate.authorize_resource(
                grant_id=grant.grant_id,
                mission_id=kernel.environment.mission.mission_id,
                service_identity="planner_context",
                resource_id=record.binding.resource_id,
                operation="read",
                now=FIXED_TIME + timedelta(minutes=1),
            )


@pytest.mark.parametrize("new_state", ["PAUSED", "FINALIZING"])
def test_context_grant_rejected_when_mission_not_running(new_state: str) -> None:
    with Database() as database:
        kernel, record, _, _, grant, gate = setup_context(database)
        state = database.connection.execute(
            "SELECT payload_json FROM mission_states WHERE mission_id = ?",
            (kernel.environment.mission.mission_id,),
        ).fetchone()
        from redteam_agent.models.mission import MissionState
        from redteam_agent.repositories.base import model_json

        current = MissionState.model_validate_json(state["payload_json"])
        updated = current.model_copy(
            update={
                "state": new_state,
                "mission_state_version": current.mission_state_version + 1,
                "authorization_epoch": current.authorization_epoch + 1,
            }
        )
        database.connection.execute(
            "UPDATE mission_states SET state = ?, mission_state_version = ?, "
            "authorization_epoch = ?, payload_json = ? WHERE mission_id = ?",
            (
                updated.state,
                updated.mission_state_version,
                updated.authorization_epoch,
                model_json(updated),
                updated.mission_id,
            ),
        )
        with pytest.raises(DataAccessDeniedError):
            gate.authorize_resource(
                grant_id=grant.grant_id,
                mission_id=updated.mission_id,
                service_identity="planner_context",
                resource_id=record.binding.resource_id,
                operation="read",
                now=FIXED_TIME + timedelta(minutes=1),
            )


def test_old_epoch_context_grant_rejected_after_pause_resume() -> None:
    with Database() as database:
        kernel, record, _, _, grant, gate = setup_context(database)
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            LLMProfileRepository(database),
            authorization_references=AuthorizationReferenceRegistry(
                frozenset({kernel.environment.mission.authorization_reference})
            ),
        )
        manager.pause(
            kernel.environment.mission.mission_id,
            now=FIXED_TIME + timedelta(minutes=1),
        )
        manager.resume(
            kernel.environment.mission.mission_id,
            now=FIXED_TIME + timedelta(minutes=2),
        )

        with pytest.raises(DataAccessDeniedError):
            gate.authorize_resource(
                grant_id=grant.grant_id,
                mission_id=kernel.environment.mission.mission_id,
                service_identity="planner_context",
                resource_id=record.binding.resource_id,
                operation="read",
                now=FIXED_TIME + timedelta(minutes=3),
            )
