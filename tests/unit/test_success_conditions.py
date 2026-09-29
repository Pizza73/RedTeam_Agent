"""Typed success-condition rule/proof/source validation."""

from __future__ import annotations

from dataclasses import replace

import pytest
from pydantic import ValidationError

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.testing import build_evidence_retention_policy
from redteam_agent.errors import MissionValidationError
from redteam_agent.mission.models import (
    ActiveSessionSelector,
    ADPrincipalContextCondition,
    ExactSessionSelector,
    SessionExistsCondition,
)
from redteam_agent.mission.validation import MissionValidationPolicy, validate_mission_revision
from redteam_agent.semantics import (
    SESSION_EXISTS_RULE_ID,
    SESSION_GOAL_SOURCE_CAPABILITY_ID,
    EmptySessionGoalSource,
    SessionStateProof,
    default_semantic_catalog,
)


def _policy(ds: DigestService, catalog=None) -> MissionValidationPolicy:
    return MissionValidationPolicy(
        max_recovery_window_seconds=7 * 24 * 3600,
        evidence_retention_policy=build_evidence_retention_policy(ds),
        semantic_catalog=catalog if catalog is not None else default_semantic_catalog(),
    )


def _validate(condition: SessionExistsCondition, *, catalog=None) -> None:
    ds = DigestService()
    profile = support.make_profile(ds)
    revision = support.mission_revision(ds, profile=profile, success_conditions=(condition,))
    validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds, catalog))


def test_registered_exact_session_condition_validates() -> None:
    _validate(
        SessionExistsCondition(
            condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
        )
    )


def test_registered_active_session_condition_validates() -> None:
    _validate(
        SessionExistsCondition(
            condition_id="c1", session_selector=ActiveSessionSelector(host_ref="host-1")
        )
    )


def test_registered_ad_principal_context_condition_validates() -> None:
    _validate(ADPrincipalContextCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1"),
        principal_ref="root", required_group_sid="S-1-5-21-512",
    ))  # type: ignore[arg-type]


def test_ad_group_requirement_without_source_contract_is_rejected() -> None:
    with pytest.raises(MissionValidationError, match="group source"):
        _validate(ADPrincipalContextCondition(
            condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1"),
            principal_ref="root",
        ))  # type: ignore[arg-type]


def test_missing_concrete_rule_rejected() -> None:
    catalog = replace(default_semantic_catalog(), session_exists_rule=None)
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="rule is not registered"):
        _validate(condition, catalog=catalog)


def test_duplicate_condition_id_rejected() -> None:
    ds = DigestService()
    profile = support.make_profile(ds)
    first = SessionExistsCondition(
        condition_id="dup", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    second = SessionExistsCondition(
        condition_id="dup", session_selector=ActiveSessionSelector(host_ref="host-1")
    )
    revision = support.mission_revision(ds, profile=profile, success_conditions=(first, second))
    with pytest.raises(MissionValidationError, match="duplicate"):
        validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds))


def test_unregistered_host_reference_rejected() -> None:
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ActiveSessionSelector(host_ref="unregistered-host")
    )
    with pytest.raises(MissionValidationError, match="unregistered host"):
        _validate(condition)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("principal_ref", "unknown-principal", "unregistered principal"),
        ("provider_id", "unknown-provider", "unregistered provider"),
    ],
)
def test_unregistered_active_selector_references_rejected(field: str, value: str, message: str) -> None:
    selector = ActiveSessionSelector(host_ref="host-1", **{field: value})
    condition = SessionExistsCondition(condition_id="c1", session_selector=selector)
    with pytest.raises(MissionValidationError, match=message):
        _validate(condition)


@pytest.mark.parametrize("field", ["principal_ref", "provider_id"])
def test_empty_optional_selector_reference_rejected(field: str) -> None:
    with pytest.raises(ValidationError):
        ActiveSessionSelector(host_ref="host-1", **{field: ""})


def test_rule_binds_closed_proof_model_and_concrete_source() -> None:
    catalog = default_semantic_catalog()
    rule = catalog.session_exists_rule
    assert rule is not None
    assert rule.proof_schema is SessionStateProof
    assert rule.source.capability_id == "session-manager-current-active-v1"
    assert rule.source.list_current_sessions() == ()


def test_source_capability_id_mismatch_rejected() -> None:
    class WrongSource:
        capability_id = "wrong-source"

        def get_current_session(self, session_id: str):
            del session_id
            return None

        def list_current_sessions(self):
            return ()

    catalog = default_semantic_catalog()
    assert catalog.session_exists_rule is not None
    catalog = replace(
        catalog,
        session_exists_rule=replace(catalog.session_exists_rule, source=WrongSource()),
    )
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="not implemented"):
        _validate(condition, catalog=catalog)


def test_self_consistent_unregistered_source_id_rejected() -> None:
    class UnknownSource:
        capability_id = "unknown-source"

        def get_current_session(self, session_id: str):
            del session_id
            return None

        def list_current_sessions(self):
            return ()

    catalog = default_semantic_catalog()
    assert catalog.session_exists_rule is not None
    altered = replace(
        catalog.session_exists_rule,
        source=UnknownSource(),
        source_capability_id="unknown-source",  # type: ignore[arg-type]
    )
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="source capability id"):
        _validate(condition, catalog=replace(catalog, session_exists_rule=altered))


def test_unregistered_rule_id_rejected() -> None:
    catalog = default_semantic_catalog()
    assert catalog.session_exists_rule is not None
    altered = replace(
        catalog.session_exists_rule,
        rule_id="unknown-rule",  # type: ignore[arg-type]
    )
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="rule id"):
        _validate(condition, catalog=replace(catalog, session_exists_rule=altered))


def test_unregistered_catalog_revision_rejected() -> None:
    catalog = replace(default_semantic_catalog(), catalog_revision="unknown-catalog")
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="catalog revision"):
        _validate(condition, catalog=catalog)


def test_foreign_rule_object_with_registered_ids_rejected() -> None:
    class ForeignRule:
        rule_id = SESSION_EXISTS_RULE_ID
        source_capability_id = SESSION_GOAL_SOURCE_CAPABILITY_ID
        proof_schema = SessionStateProof
        source = EmptySessionGoalSource()

        def validate_static(self, condition, catalog):
            del condition, catalog

    catalog = replace(default_semantic_catalog(), session_exists_rule=ForeignRule())  # type: ignore[arg-type]
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="rule is not registered"):
        _validate(condition, catalog=catalog)


def test_noncallable_source_method_rejected() -> None:
    catalog = default_semantic_catalog()
    assert catalog.session_exists_rule is not None
    source = EmptySessionGoalSource()
    source.get_current_session = None  # type: ignore[assignment]
    rule = replace(catalog.session_exists_rule, source=source)
    condition = SessionExistsCondition(
        condition_id="c1", session_selector=ExactSessionSelector(session_ref="sess-1")
    )
    with pytest.raises(MissionValidationError, match="methods are not callable"):
        _validate(condition, catalog=replace(catalog, session_exists_rule=rule))
