"""Phase 2 mission validation: real-LLM missions require passed real-local-LLM capability
results and reject mock profiles / test-double evidence (SystemDesign §7 / §21 / Phase 2)."""

from __future__ import annotations

import pytest

import support
import support_phase2 as fake
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.errors import LLMCapabilityError, MissionValidationError
from redteam_agent.llm.evaluation import SyntheticCapabilityProbe
from redteam_agent.llm.profile import build_mock_agent_profile
from redteam_agent.llm.schemas import ACTUAL_SCHEMA_NAMES


def _phase0a(kernel):
    return kernel.phase1.phase0c.phase0b.phase0a


def _persist_real_capability(kernel, profile) -> None:
    """Construct integrity-valid real-labelled capability records at the repository
    boundary (no fake server pretends a real evaluation happened)."""
    ds = _phase0a(kernel).digest_service
    for schema_name in ACTUAL_SCHEMA_NAMES:
        result = fake.real_capability_result(
            ds, profile=profile, schema_name=schema_name, corpus=kernel.schema_corpus
        )
        kernel.capability_repository.save(result)


def test_local_profile_with_real_capability_validates() -> None:
    kernel = build_phase2_kernel()
    a = _phase0a(kernel)
    ds = a.digest_service
    profile = fake.local_profile(ds, profile_revision="local-verified")
    a.profile_repository.save(profile)
    _persist_real_capability(kernel, profile)
    revision = support.mission_revision(ds, profile=profile)
    support.provision_lifecycle_roles(a)
    a.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    state = a.mission_manager.validate_mission(support.MISSION_ID, 0, actor_token=support.OPERATOR_ACTOR_TOKEN)
    assert state.state == "VALIDATED"


def test_test_double_capability_is_not_persistable_and_mission_fails() -> None:
    kernel = build_phase2_kernel()
    a = _phase0a(kernel)
    ds = a.digest_service
    profile = fake.local_profile(ds, profile_revision="local-testdouble")
    a.profile_repository.save(profile)
    # Running a test-double evaluation must NOT persist anything into the qualification repo.
    results = kernel.run_capability_evaluation(profile=profile, probe=SyntheticCapabilityProbe())
    assert all(r.evidence_kind == "test_double" for r in results)
    # A direct save of a test-double result is rejected.
    with pytest.raises(LLMCapabilityError):
        kernel.capability_repository.save(results[0])
    revision = support.mission_revision(ds, profile=profile)
    support.provision_lifecycle_roles(a)
    a.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    with pytest.raises(MissionValidationError):
        a.mission_manager.validate_mission(support.MISSION_ID, 0, actor_token=support.OPERATOR_ACTOR_TOKEN)


def test_mock_profile_rejected_for_real_llm_mission() -> None:
    kernel = build_phase2_kernel()
    a = _phase0a(kernel)
    ds = a.digest_service
    profile = build_mock_agent_profile(digest_service=ds)
    a.profile_repository.save(profile)
    revision = support.mission_revision(ds, profile=profile)
    support.provision_lifecycle_roles(a)
    a.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    with pytest.raises(MissionValidationError):
        a.mission_manager.validate_mission(support.MISSION_ID, 0, actor_token=support.OPERATOR_ACTOR_TOKEN)


def test_local_profile_without_capability_rejected() -> None:
    kernel = build_phase2_kernel()
    a = _phase0a(kernel)
    ds = a.digest_service
    profile = fake.local_profile(ds, profile_revision="local-unverified")
    a.profile_repository.save(profile)
    # No capability evaluation persisted for this profile.
    revision = support.mission_revision(ds, profile=profile)
    support.provision_lifecycle_roles(a)
    a.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    with pytest.raises(MissionValidationError):
        a.mission_manager.validate_mission(support.MISSION_ID, 0, actor_token=support.OPERATOR_ACTOR_TOKEN)
