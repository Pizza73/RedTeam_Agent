"""Mission validation (SystemDesign §21).

A revision that fails any check cannot progress to VALIDATED; validation fails
closed with :class:`MissionValidationError`. This is where uninterpretable scope
rules and data-access patterns are rejected up front rather than being silently
ignored later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    DataAccessPatternError,
    DigestIntegrityError,
    LLMCapabilityError,
    MissionValidationError,
    ScopeEvaluationError,
)
from redteam_agent.llm.profile import AgentModelProfile, LocalLLMProfile
from redteam_agent.mission.models import (
    ADPrincipalContextCondition,
    EvidenceRetentionPolicy,
    MissionRevision,
    SessionExistsCondition,
)
from redteam_agent.policy.data_access import validate_policy_patterns
from redteam_agent.policy.scope_engine import assert_scope_rules_interpretable
from redteam_agent.semantics import (
    SEMANTIC_CATALOG_REVISION,
    SESSION_EXISTS_RULE_ID,
    SESSION_GOAL_SOURCE_CAPABILITY_ID,
    EmptySessionGoalSource,
    RepositorySessionGoalSource,
    SemanticCatalog,
    SessionExistsGoalRule,
    SessionStateProof,
    default_semantic_catalog,
)


class LLMCapabilityVerifier(Protocol):
    """Verifies that a local LLM profile has a passed capability result bound to its
    ``profile_digest`` covering every schema the mission actually uses (Phase 2)."""

    def verify_mission_capability(self, profile: LocalLLMProfile, revision: MissionRevision) -> None:
        """Raise :class:`LLMCapabilityError` if capability is not proven."""
        ...


@dataclass(frozen=True)
class MissionValidationPolicy:
    max_recovery_window_seconds: int
    evidence_retention_policy: EvidenceRetentionPolicy
    semantic_catalog: SemanticCatalog = field(default_factory=default_semantic_catalog)
    # Phase 0A-1 kernels accept only the deterministic mock profile. A Phase 2
    # kernel sets ``allowed_profile_types={"vllm"}`` and a ``capability_verifier``
    # so real-LLM missions require a passed capability result and mock profiles
    # are rejected. This is one validation path, parameterized — not an alternate
    # authorization route.
    allowed_profile_types: frozenset[str] = frozenset({"mock"})
    capability_verifier: LLMCapabilityVerifier | None = None


def _validate_success_condition(condition: object, catalog: SemanticCatalog) -> None:
    if catalog.catalog_revision != SEMANTIC_CATALOG_REVISION:
        raise MissionValidationError("semantic catalog revision is not registered")
    if not isinstance(condition, (SessionExistsCondition, ADPrincipalContextCondition)):
        raise MissionValidationError("success condition type has no implemented Phase 0A rule")
    if isinstance(condition, ADPrincipalContextCondition) and (
        condition.required_group_sid is None
        or condition.required_group_sid not in catalog.registered_ad_group_sids
    ):
        raise MissionValidationError("AD principal context requires a registered group source")
    rule = catalog.session_exists_rule
    if rule is None or type(rule) is not SessionExistsGoalRule:
        raise MissionValidationError("session condition rule is not registered")
    if rule.proof_schema is not SessionStateProof:
        raise MissionValidationError("session condition proof schema is not the registered closed model")
    if rule.rule_id != SESSION_EXISTS_RULE_ID:
        raise MissionValidationError("session condition rule id is not registered")
    if rule.source_capability_id != SESSION_GOAL_SOURCE_CAPABILITY_ID:
        raise MissionValidationError("session condition source capability id is not registered")
    if type(rule.source) not in (EmptySessionGoalSource, RepositorySessionGoalSource):
        raise MissionValidationError("session condition source capability is not implemented")
    if not callable(rule.source.get_current_session) or not callable(rule.source.list_current_sessions):
        raise MissionValidationError("session condition source capability methods are not callable")
    if rule.source.capability_id != SESSION_GOAL_SOURCE_CAPABILITY_ID:
        raise MissionValidationError("session condition source capability binding mismatch")
    selector = condition.session_selector
    rule.validate_static(
        SessionExistsCondition(condition_id=condition.condition_id, session_selector=selector),
        catalog,
    )
    if (
        isinstance(condition, ADPrincipalContextCondition)
        and condition.principal_ref not in catalog.registered_principal_refs
    ):
        raise MissionValidationError("AD principal context references an unregistered principal")


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
    if profile.profile_type not in policy.allowed_profile_types:
        raise MissionValidationError("llm profile type is not permitted for this mission")
    if not profile.is_usable():
        raise MissionValidationError("llm profile is not usable")
    # A local LLM profile never self-attests capability with a bare boolean. Its
    # fitness for a real mission is proven only by a passed capability result bound
    # to its profile_digest and covering every schema the mission uses.
    if isinstance(profile, LocalLLMProfile):
        if policy.capability_verifier is None:
            raise MissionValidationError("local LLM profile requires a capability verifier")
        try:
            policy.capability_verifier.verify_mission_capability(profile, revision)
        except LLMCapabilityError as exc:
            raise MissionValidationError(f"local LLM capability not proven: {exc}") from exc

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
