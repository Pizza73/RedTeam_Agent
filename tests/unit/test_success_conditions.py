"""Typed / registered success condition validation (start-time validation 1)."""

from __future__ import annotations

import pytest

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.testing import build_evidence_retention_policy
from redteam_agent.errors import MissionValidationError
from redteam_agent.mission.models import HostPrivilegeCondition, SessionEstablishedCondition
from redteam_agent.mission.validation import MissionValidationPolicy, validate_mission_revision
from redteam_agent.semantics import SemanticCatalog


def _policy(ds: DigestService, catalog: SemanticCatalog | None = None) -> MissionValidationPolicy:
    kwargs = {
        "max_recovery_window_seconds": 7 * 24 * 3600,
        "evidence_retention_policy": build_evidence_retention_policy(ds),
    }
    if catalog is not None:
        kwargs["semantic_catalog"] = catalog
    return MissionValidationPolicy(**kwargs)


def test_registered_condition_validates() -> None:
    ds = DigestService()
    profile = support.make_profile(ds)
    condition = SessionEstablishedCondition(
        condition_id="c1", description="establish", selector_type="exact_session", selector_value="sess-1"
    )
    revision = support.mission_revision(ds, profile=profile, success_conditions=(condition,))
    validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds))


def test_host_privilege_condition_validates_with_default_catalog() -> None:
    ds = DigestService()
    profile = support.make_profile(ds)
    condition = HostPrivilegeCondition(
        condition_id="c1", description="root", host_ref="h1", required_privilege="linux_uid0"
    )
    revision = support.mission_revision(ds, profile=profile, success_conditions=(condition,))
    validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds))


def test_unregistered_condition_kind_rejected() -> None:
    ds = DigestService()
    profile = support.make_profile(ds)
    # Restrict the catalog so host_privilege is not a supported condition kind.
    restricted = SemanticCatalog(
        catalog_revision="restricted",
        fact_types=frozenset({"finding"}),
        selector_types=frozenset({"active_session"}),
        privilege_levels=frozenset({"linux_uid0"}),
        condition_kinds=frozenset({"session_established"}),
        finding_fact_types=frozenset({"finding"}),
        registered_entity_refs=frozenset({"entity:host-1"}),
    )
    condition = HostPrivilegeCondition(
        condition_id="c1", description="root", host_ref="h1", required_privilege="linux_uid0"
    )
    revision = support.mission_revision(ds, profile=profile, success_conditions=(condition,))
    with pytest.raises(MissionValidationError):
        validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds, restricted))


def test_duplicate_condition_id_rejected() -> None:
    ds = DigestService()
    profile = support.make_profile(ds)
    c1 = SessionEstablishedCondition(
        condition_id="dup", description="a", selector_type="active_session", selector_value="any"
    )
    c2 = SessionEstablishedCondition(
        condition_id="dup", description="b", selector_type="active_session", selector_value="any"
    )
    revision = support.mission_revision(ds, profile=profile, success_conditions=(c1, c2))
    with pytest.raises(MissionValidationError):
        validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds))
