"""Mission validation failure paths (SystemDesign §21)."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.testing import build_evidence_retention_policy
from redteam_agent.errors import MissionValidationError
from redteam_agent.mission.models import MissionRevision
from redteam_agent.mission.validation import MissionValidationPolicy, validate_mission_revision
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.policy.scope_models import NetworkScopeRule


def _ds() -> DigestService:
    return DigestService()


def _policy(ds: DigestService) -> MissionValidationPolicy:
    return MissionValidationPolicy(
        max_recovery_window_seconds=7 * 24 * 3600,
        evidence_retention_policy=build_evidence_retention_policy(ds),
    )


def _redigest(revision: MissionRevision, ds: DigestService) -> MissionRevision:
    payload = revision.model_dump(mode="python")
    payload.pop("mission_revision_digest", None)
    return revision.model_copy(update={"mission_revision_digest": ds.compute("mission_revision_digest", payload)})


def _validate(ds: DigestService, revision: MissionRevision, *, profile=None) -> None:
    profile = profile if profile is not None else support.make_profile(ds)
    validate_mission_revision(revision, digest_service=ds, profile=profile, policy=_policy(ds))


def test_valid_revision_passes() -> None:
    ds = _ds()
    _validate(ds, support.mission_revision(ds, profile=support.make_profile(ds)))


def test_time_window_invariant_violation_rejected() -> None:
    ds = _ds()
    base = support.mission_revision(ds, profile=support.make_profile(ds))
    bad = _redigest(base.model_copy(update={"valid_until": base.valid_from - timedelta(hours=1)}), ds)
    with pytest.raises(MissionValidationError):
        _validate(ds, bad)


def test_recovery_window_too_long_rejected() -> None:
    ds = _ds()
    base = support.mission_revision(ds, profile=support.make_profile(ds))
    recovery = base.valid_until + timedelta(days=8)
    bad = _redigest(base.model_copy(update={"recovery_until": recovery, "evidence_retention_until": recovery + timedelta(days=1)}), ds)
    with pytest.raises(MissionValidationError):
        _validate(ds, bad)


def test_evidence_retention_too_long_rejected() -> None:
    ds = _ds()
    base = support.mission_revision(ds, profile=support.make_profile(ds))
    evidence = base.recovery_until + timedelta(days=40)
    bad = _redigest(base.model_copy(update={"evidence_retention_until": evidence}), ds)
    with pytest.raises(MissionValidationError):
        _validate(ds, bad)


def test_profile_missing_rejected() -> None:
    ds = _ds()
    with pytest.raises(MissionValidationError):
        validate_mission_revision(
            support.mission_revision(ds, profile=support.make_profile(ds)),
            digest_service=ds, profile=None, policy=_policy(ds),
        )


def test_digest_tamper_rejected() -> None:
    ds = _ds()
    base = support.mission_revision(ds, profile=support.make_profile(ds))
    # Change a field without re-computing the digest.
    tampered = base.model_copy(update={"max_iterations": base.max_iterations + 1})
    with pytest.raises(MissionValidationError):
        _validate(ds, tampered)


def test_uninterpretable_scope_rejected() -> None:
    ds = _ds()
    base = support.mission_revision(
        ds, profile=support.make_profile(ds),
        allowed_scope=(NetworkScopeRule(type="network", cidrs=("not-an-ip",), ports=None, protocols=None),),
    )
    with pytest.raises(MissionValidationError):
        _validate(ds, base)


def test_uninterpretable_data_pattern_rejected() -> None:
    ds = _ds()
    policy = DataAccessPolicy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="weird", operations=frozenset({"read"})),),
        prohibited=(),
    )
    base = support.mission_revision(ds, profile=support.make_profile(ds), data_access_policy=policy)
    with pytest.raises(MissionValidationError):
        _validate(ds, base)
