from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from redteam_agent.errors import (
    AuthorizationEpochMismatchError,
    MissionLifecycleAuthorizationError,
    MissionValidationError,
    MissionStateVersionConflictError,
)
from redteam_agent.mission import AuthorizationReferenceRegistry, MissionManager
from redteam_agent.models.goals import ADPrincipalPrivilegeCondition
from redteam_agent.models.mission import Mission
from redteam_agent.models.scope import NetworkScopeRule
from redteam_agent.repositories import (
    LLMProfileRepository,
    MissionRepository,
    MissionRevisionRepository,
    MissionStateRepository,
)
from redteam_agent.seeds import FIXED_TIME, mission_records, mock_mission, mock_profile
from redteam_agent.storage import Database


def mission_data() -> dict[str, object]:
    return mock_mission().model_dump(mode="python")


def test_zero_success_conditions_rejected() -> None:
    data = mission_data()
    data["success_conditions"] = ()
    with pytest.raises(ValidationError):
        Mission.model_validate(data)


def test_duplicate_condition_ids_rejected() -> None:
    data = mission_data()
    condition = data["success_conditions"][0]
    data["success_conditions"] = (condition, condition)
    with pytest.raises(ValidationError, match="condition_id"):
        Mission.model_validate(data)


@pytest.mark.parametrize(
    "updates",
    [
        {"valid_until": mock_mission().valid_from},
        {"allowed_execution_scope": ()},
        {"max_iterations": 0},
        {"max_runtime_minutes": 0},
        {"max_indeterminate_retries": 0},
        {"mission_revision": 0},
        {"mission_state_version": -1},
    ],
)
def test_invalid_mission_boundaries_rejected(updates: dict[str, object]) -> None:
    data = mission_data()
    data.update(updates)
    with pytest.raises(ValidationError):
        Mission.model_validate(data)


def seeded_repositories(database: Database):
    mission = mock_mission()
    root, revision, _ = mission_records(mission)
    profiles = LLMProfileRepository(database)
    profiles.add(mock_profile())
    manager = MissionManager(
        MissionRepository(database),
        MissionRevisionRepository(database),
        MissionStateRepository(database),
        profiles,
        authorization_references=AuthorizationReferenceRegistry(
            frozenset({mission.authorization_reference})
        ),
    )
    manager.create(root, revision, now=FIXED_TIME - timedelta(minutes=2))
    manager.transition_to_validated(mission.mission_id, now=FIXED_TIME - timedelta(minutes=1))
    return manager.start(mission.mission_id, now=FIXED_TIME), manager


def test_pause_changes_occ_and_epoch_but_not_revision() -> None:
    with Database() as database:
        mission, manager = seeded_repositories(database)
        updated = manager.pause(
            mission.mission_id, now=FIXED_TIME + timedelta(minutes=1)
        )
        assert updated.mission_state_version == mission.mission_state_version + 1
        assert updated.authorization_epoch == mission.authorization_epoch + 1
        assert MissionRevisionRepository(database).latest(mission.mission_id).mission_revision == 1


def test_scope_change_creates_new_revision_without_mutating_old() -> None:
    with Database() as database:
        mission, _ = seeded_repositories(database)
        new_revision = mission.revision_record().model_copy(
            update={
                "mission_revision": 2,
                "allowed_execution_scope": (
                    NetworkScopeRule(type="network", cidrs=("10.1.0.0/16",)),
                ),
            }
        )
        MissionRevisionRepository(database).add(new_revision)
        assert MissionRevisionRepository(database).get_for_mission(mission.mission_id, 1)
        assert MissionRevisionRepository(database).latest(mission.mission_id).mission_revision == 2


def test_occ_mismatch_and_epoch_mismatch_fail_closed() -> None:
    with Database() as database:
        mission, _ = seeded_repositories(database)
        repository = MissionStateRepository(database)
        with pytest.raises(MissionStateVersionConflictError):
            repository._transition(
                mission.mission_id,
                expected_mission_state_version=999,
                expected_authorization_epoch=mission.authorization_epoch,
                new_state="PAUSED",
                updated_at=FIXED_TIME + timedelta(minutes=1),
            )
        with pytest.raises(AuthorizationEpochMismatchError):
            repository._transition(
                mission.mission_id,
                expected_mission_state_version=mission.mission_state_version,
                expected_authorization_epoch=999,
                new_state="PAUSED",
                updated_at=FIXED_TIME + timedelta(minutes=1),
            )


def test_draft_cannot_start_and_unregistered_profile_cannot_validate() -> None:
    with Database() as database:
        mission = mock_mission()
        root, revision, _ = mission_records(mission)
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            LLMProfileRepository(database),
        )
        manager.create(root, revision, now=FIXED_TIME - timedelta(minutes=1))
        with pytest.raises(MissionLifecycleAuthorizationError):
            manager.start(mission.mission_id, now=FIXED_TIME)
        with pytest.raises(MissionValidationError):
            manager.transition_to_validated(mission.mission_id, now=FIXED_TIME)


def test_profile_removed_after_validation_prevents_running() -> None:
    with Database() as database:
        mission = mock_mission()
        root, revision, _ = mission_records(mission)
        profiles = LLMProfileRepository(database)
        profiles.add(mock_profile())
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            profiles,
            authorization_references=AuthorizationReferenceRegistry(
                frozenset({mission.authorization_reference})
            ),
        )
        manager.create(root, revision, now=FIXED_TIME - timedelta(minutes=2))
        manager.transition_to_validated(
            mission.mission_id, now=FIXED_TIME - timedelta(minutes=1)
        )
        database.connection.execute(
            "DELETE FROM llm_profiles WHERE profile_revision = ?",
            (mission.llm_profile_revision,),
        )
        with pytest.raises(MissionValidationError):
            manager.start(mission.mission_id, now=FIXED_TIME)


def test_unknown_ad_privilege_identifier_is_rejected() -> None:
    with Database() as database:
        mission = mock_mission()
        condition = ADPrincipalPrivilegeCondition(
            type="ad_principal_privilege",
            condition_id="unknown-goal",
            principal_ref="principal-1",
            privilege_identifier="caller_defined_super_admin",
            target_ref="domain-1",
        )
        revision = mission.revision_record().model_copy(
            update={"success_conditions": (condition,)}
        )
        root, _, _ = mission_records(mission)
        profiles = LLMProfileRepository(database)
        profiles.add(mock_profile())
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            profiles,
            authorization_references=AuthorizationReferenceRegistry(
                frozenset({mission.authorization_reference})
            ),
        )
        manager.create(root, revision, now=FIXED_TIME - timedelta(minutes=1))
        with pytest.raises(MissionValidationError):
            manager.transition_to_validated(mission.mission_id, now=FIXED_TIME)


def test_unregistered_authorization_reference_cannot_validate() -> None:
    with Database() as database:
        mission = mock_mission()
        root, revision, _ = mission_records(mission)
        profiles = LLMProfileRepository(database)
        profiles.add(mock_profile())
        manager = MissionManager(
            MissionRepository(database),
            MissionRevisionRepository(database),
            MissionStateRepository(database),
            profiles,
        )
        manager.create(root, revision, now=FIXED_TIME - timedelta(minutes=1))
        with pytest.raises(MissionValidationError, match="authorization reference"):
            manager.transition_to_validated(mission.mission_id, now=FIXED_TIME)


def test_pause_and_resume_each_increment_authorization_epoch() -> None:
    with Database() as database:
        running, manager = seeded_repositories(database)
        paused = manager.pause(running.mission_id, now=FIXED_TIME + timedelta(minutes=1))
        resumed = manager.resume(running.mission_id, now=FIXED_TIME + timedelta(minutes=2))
        assert resumed.mission_revision == running.mission_revision
        assert resumed.mission_state_version == paused.mission_state_version + 1
        assert resumed.authorization_epoch == running.authorization_epoch + 2
