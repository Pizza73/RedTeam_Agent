"""Mission configuration, lifecycle state and read model (SystemDesign §21).

Three concerns are kept separate and never substituted for one another:

* ``MissionRevision`` — immutable authorization configuration (scope, goals,
  approval policy, validity window). Changing configuration is what bumps
  ``mission_revision``.
* ``MissionState`` — the OCC lifecycle record carrying ``mission_state_version``
  (concurrency) and ``authorization_epoch`` (short-lived-authorization
  generation). A lifecycle change bumps ``mission_state_version``; a revocation
  boundary additionally bumps ``authorization_epoch``.
* ``Mission`` — a read model that joins the two for convenience.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.data_access import DataAccessPolicy
from redteam_agent.policy.risk_policy import RiskLevel, SideEffect
from redteam_agent.policy.scope_models import ExecutionScopeRule

MissionLifecycleState = Literal[
    "DRAFT",
    "VALIDATED",
    "RUNNING",
    "PAUSED",
    "FINALIZING",
    "WAITING_HUMAN_REVIEW",
    "COMPLETED",
    "COMPLETED_WITH_UNRESOLVED_ITEMS",
    "FAILED",
    "ABORTED",
]


# Legal lifecycle edges (SystemDesign §21.1 diagram). Shared by the mission
# manager and the state repository so both validate transitions in the write path.
LEGAL_LIFECYCLE_EDGES: frozenset[tuple[MissionLifecycleState, MissionLifecycleState]] = frozenset(
    {
        ("DRAFT", "VALIDATED"),
        ("VALIDATED", "RUNNING"),
        ("RUNNING", "PAUSED"),
        ("PAUSED", "RUNNING"),
        ("RUNNING", "FINALIZING"),
        ("PAUSED", "FINALIZING"),
        ("FINALIZING", "COMPLETED"),
        ("FINALIZING", "ABORTED"),
        ("FINALIZING", "FAILED"),
        ("FINALIZING", "WAITING_HUMAN_REVIEW"),
        ("WAITING_HUMAN_REVIEW", "FINALIZING"),
        ("WAITING_HUMAN_REVIEW", "COMPLETED_WITH_UNRESOLVED_ITEMS"),
    }
)

# Transitions that additionally rotate the authorization epoch.
EPOCH_ROTATING_EDGES: frozenset[tuple[MissionLifecycleState, MissionLifecycleState]] = frozenset(
    {
        ("RUNNING", "PAUSED"),
        ("PAUSED", "RUNNING"),
        ("RUNNING", "FINALIZING"),
        ("PAUSED", "FINALIZING"),
    }
)


class SessionEstablishedCondition(StrictImmutableBoundaryModel):
    condition_kind: Literal["session_established"] = "session_established"
    condition_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    selector_type: Literal["exact_session", "active_session"]
    selector_value: str = Field(min_length=1)


class HostPrivilegeCondition(StrictImmutableBoundaryModel):
    condition_kind: Literal["host_privilege"] = "host_privilege"
    condition_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    host_ref: str = Field(min_length=1)
    required_privilege: Literal["linux_uid0", "windows_system", "windows_high_integrity"]


class FindingConfirmedCondition(StrictImmutableBoundaryModel):
    condition_kind: Literal["finding_confirmed"] = "finding_confirmed"
    condition_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    fact_type: Literal["identity", "service", "relationship", "finding", "execution_outcome"]
    canonical_entity_ref: str = Field(min_length=1)


SuccessCondition = Annotated[
    SessionEstablishedCondition | HostPrivilegeCondition | FindingConfirmedCondition,
    Field(discriminator="condition_kind"),
]


class ApprovalPolicy(StrictImmutableBoundaryModel):
    require_for_risk: frozenset[RiskLevel]
    require_for_side_effect: frozenset[SideEffect]
    approval_ttl_seconds: int = Field(gt=0)
    count_approval_wait_in_runtime: bool


class EvidenceRetentionPolicy(StrictImmutableBoundaryModel):
    policy_revision: str = Field(min_length=1)
    max_evidence_retention_seconds: int = Field(gt=0)
    allow_local_reingestion_after_recovery: Literal[True] = True
    require_erasure_at_expiry: Literal[True] = True
    policy_digest: str = Field(min_length=1)


class MissionRevision(StrictImmutableBoundaryModel):
    """Immutable mission authorization configuration (digest-bound)."""

    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    llm_profile_revision: str = Field(min_length=1)
    llm_profile_digest: str = Field(min_length=1)
    description: str
    authorization_reference: str = Field(min_length=1)
    authorized_by: str = Field(min_length=1)
    valid_from: datetime
    valid_until: datetime
    recovery_until: datetime
    evidence_retention_until: datetime
    allowed_execution_scope: tuple[ExecutionScopeRule, ...] = Field(min_length=1)
    prohibited_execution_scope: tuple[ExecutionScopeRule, ...]
    data_access_policy: DataAccessPolicy
    objectives: tuple[str, ...]
    success_conditions: tuple[SuccessCondition, ...] = Field(min_length=1)
    success_mode: Literal["all", "any"] = "all"
    max_iterations: int = Field(gt=0)
    max_runtime_minutes: int = Field(gt=0)
    approval_policy: ApprovalPolicy
    mission_revision_digest: str = Field(min_length=1)


class MissionState(StrictImmutableBoundaryModel):
    """OCC lifecycle record. Only the Mission Manager may mutate this."""

    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    mission_state_version: int = Field(ge=0)
    authorization_epoch: int = Field(ge=0)
    state: MissionLifecycleState


class MissionLifecycleEvent(StrictImmutableBoundaryModel):
    """Append-only mission-owned lifecycle history, co-committed with state.

    This is the mission manager's own event stream (not a new independent
    service). Tamper-evident hash chaining and TPM witnessing are a later phase.
    """

    mission_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    from_state: MissionLifecycleState
    to_state: MissionLifecycleState
    mission_state_version: int = Field(ge=0)
    authorization_epoch: int = Field(ge=0)
    actor: str = Field(min_length=1)
    reason: str
    occurred_at: datetime


class Mission(StrictImmutableBoundaryModel):
    """Read model joining revision configuration and lifecycle state (§21)."""

    mission_id: str
    mission_revision: int = Field(ge=1)
    mission_state_version: int = Field(ge=0)
    authorization_epoch: int = Field(ge=0)
    state: MissionLifecycleState
    llm_profile_revision: str
    llm_profile_digest: str
    description: str
    authorization_reference: str
    authorized_by: str
    valid_from: datetime
    valid_until: datetime
    recovery_until: datetime
    evidence_retention_until: datetime
    allowed_execution_scope: tuple[ExecutionScopeRule, ...] = Field(min_length=1)
    prohibited_execution_scope: tuple[ExecutionScopeRule, ...]
    data_access_policy: DataAccessPolicy
    objectives: tuple[str, ...]
    success_conditions: tuple[SuccessCondition, ...] = Field(min_length=1)
    success_mode: Literal["all", "any"]
    max_iterations: int = Field(gt=0)
    max_runtime_minutes: int = Field(gt=0)
    approval_policy: ApprovalPolicy


def compute_mission_revision_digest(revision_fields: dict[str, object], digest_service: DigestService) -> str:
    return digest_service.compute("mission_revision_digest", revision_fields)


def join_mission(revision: MissionRevision, state: MissionState) -> Mission:
    """Build the read model, requiring revision and state to agree."""
    if revision.mission_id != state.mission_id or revision.mission_revision != state.mission_revision:
        raise ValueError("mission revision and state identity mismatch")
    return Mission(
        mission_id=revision.mission_id,
        mission_revision=revision.mission_revision,
        mission_state_version=state.mission_state_version,
        authorization_epoch=state.authorization_epoch,
        state=state.state,
        llm_profile_revision=revision.llm_profile_revision,
        llm_profile_digest=revision.llm_profile_digest,
        description=revision.description,
        authorization_reference=revision.authorization_reference,
        authorized_by=revision.authorized_by,
        valid_from=revision.valid_from,
        valid_until=revision.valid_until,
        recovery_until=revision.recovery_until,
        evidence_retention_until=revision.evidence_retention_until,
        allowed_execution_scope=revision.allowed_execution_scope,
        prohibited_execution_scope=revision.prohibited_execution_scope,
        data_access_policy=revision.data_access_policy,
        objectives=revision.objectives,
        success_conditions=revision.success_conditions,
        success_mode=revision.success_mode,
        max_iterations=revision.max_iterations,
        max_runtime_minutes=revision.max_runtime_minutes,
        approval_policy=revision.approval_policy,
    )
