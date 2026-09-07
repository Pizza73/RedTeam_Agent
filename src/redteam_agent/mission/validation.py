"""Mission validation (SystemDesign §21).

A revision that fails any check cannot progress to VALIDATED; validation fails
closed with :class:`MissionValidationError`. This is where uninterpretable scope
rules and data-access patterns are rejected up front rather than being silently
ignored later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    DataAccessPatternError,
    DigestIntegrityError,
    MissionValidationError,
    ScopeEvaluationError,
)
from redteam_agent.llm.profile import AgentModelProfile
from redteam_agent.mission.models import (
    EvidenceRetentionPolicy,
    FindingConfirmedCondition,
    HostPrivilegeCondition,
    MissionRevision,
    SessionEstablishedCondition,
)
from redteam_agent.policy.data_access import validate_policy_patterns
from redteam_agent.policy.scope_engine import assert_scope_rules_interpretable
from redteam_agent.semantics import SemanticCatalog, default_semantic_catalog


@dataclass(frozen=True)
class MissionValidationPolicy:
    max_recovery_window_seconds: int
    evidence_retention_policy: EvidenceRetentionPolicy
    semantic_catalog: SemanticCatalog = field(default_factory=default_semantic_catalog)


def _validate_success_condition(condition: object, catalog: SemanticCatalog) -> None:
    kind = getattr(condition, "condition_kind", None)
    if kind not in catalog.condition_kinds:
        raise MissionValidationError(f"unregistered success condition kind: {kind}")
    if isinstance(condition, SessionEstablishedCondition):
        if condition.selector_type not in catalog.selector_types:
            raise MissionValidationError("unregistered session selector type")
    elif isinstance(condition, HostPrivilegeCondition):
        if condition.required_privilege not in catalog.privilege_levels:
            raise MissionValidationError("unregistered privilege level")
    elif isinstance(condition, FindingConfirmedCondition):
        if condition.fact_type not in catalog.fact_types:
            raise MissionValidationError("unregistered fact type")
    else:  # pragma: no cover - discriminated union is exhaustive
        raise MissionValidationError("unknown success condition type")


def _revision_digest_payload(revision: MissionRevision) -> dict[str, object]:
    payload = revision.model_dump(mode="python")
    payload.pop("mission_revision_digest", None)
    return payload


def validate_mission_revision(
    revision: MissionRevision,
    *,
    digest_service: DigestService,
    profile: AgentModelProfile | None,
    policy: MissionValidationPolicy,
) -> None:
    """Validate a mission revision; raise on the first structural failure."""
    # Integrity of the revision record itself (fail closed as a validation error).
    try:
        digest_service.verify(
            "mission_revision_digest", _revision_digest_payload(revision), revision.mission_revision_digest
        )
    except DigestIntegrityError as exc:
        raise MissionValidationError("mission revision digest mismatch") from exc

    condition_ids = [condition.condition_id for condition in revision.success_conditions]
    if len(condition_ids) != len(set(condition_ids)):
        raise MissionValidationError("duplicate condition_id within mission revision")
    for condition in revision.success_conditions:
        _validate_success_condition(condition, policy.semantic_catalog)

    if not (
        revision.valid_from
        < revision.valid_until
        <= revision.recovery_until
        <= revision.evidence_retention_until
    ):
        raise MissionValidationError("mission time window invariant violated")

    recovery_window = (revision.recovery_until - revision.valid_until).total_seconds()
    if recovery_window > policy.max_recovery_window_seconds:
        raise MissionValidationError("recovery window exceeds system policy maximum")

    max_retention = policy.evidence_retention_policy.max_evidence_retention_seconds
    if (revision.evidence_retention_until - revision.recovery_until).total_seconds() > max_retention:
        raise MissionValidationError("evidence retention exceeds policy maximum (from recovery_until)")
    if (revision.evidence_retention_until - revision.valid_until).total_seconds() > max_retention:
        raise MissionValidationError("evidence retention exceeds policy maximum (from valid_until)")

    if profile is None:
        raise MissionValidationError("llm profile is not registered")
    if profile.profile_revision != revision.llm_profile_revision:
        raise MissionValidationError("llm profile revision mismatch")
    if profile.profile_digest != revision.llm_profile_digest:
        raise MissionValidationError("llm profile digest mismatch")
    if not profile.is_usable():
        raise MissionValidationError("llm profile capability check has not passed")

    try:
        assert_scope_rules_interpretable(revision.allowed_execution_scope)
        assert_scope_rules_interpretable(revision.prohibited_execution_scope)
    except ScopeEvaluationError as exc:
        raise MissionValidationError(f"uninterpretable execution scope rule: {exc}") from exc

    try:
        validate_policy_patterns(revision.data_access_policy)
    except DataAccessPatternError as exc:
        raise MissionValidationError(f"uninterpretable data access pattern: {exc}") from exc


def revision_digest_matches(revision: MissionRevision, digest_service: DigestService) -> bool:
    try:
        digest_service.verify(
            "mission_revision_digest", _revision_digest_payload(revision), revision.mission_revision_digest
        )
    except DigestIntegrityError:
        return False
    return True
