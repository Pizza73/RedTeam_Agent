"""Object-integrity verification for stored security artifacts (D, B-06/H-03).

Every stored model belongs to a known security family. Digest-bearing families
recompute and verify their object-integrity digest on write and read. The risk
policy verifies its dedicated policy digests. Families without a content digest
(state/OCC records, capability snapshots, profiles, assignments) are integrity-
checked by exact id/row-key binding at the repository. An unregistered model
type fails closed rather than being trusted.
"""

from __future__ import annotations

from pydantic import BaseModel

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.approval.models import ApprovalRecord, ApprovalRequest
from redteam_agent.auth.models import MissionRoleAssignment
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.context.models import ContextDataAccessGrant, ContextResourceIndexRecord
from redteam_agent.errors import RepositoryIntegrityError
from redteam_agent.execution.models import (
    CancelAttempt,
    DispatchClaim,
    ExecutionRecord,
    ExecutionRecoveryAuthority,
    ExecutionResult,
    ExecutionResultProjection,
    LocalResultBinding,
    MissionExecutionBudget,
    ProviderTaskBinding,
    RawControlMetadataRecord,
    ResultCollectionAuthority,
    ResultCollectionStateRecord,
    ResultIngestionStateRecord,
)
from redteam_agent.llm.attestation import ServerAttestation
from redteam_agent.llm.profile import LocalLLMProfile, MockAgentProfile
from redteam_agent.mission.models import MissionLifecycleEvent, MissionRevision, MissionState
from redteam_agent.policy.models import PolicyDecision
from redteam_agent.policy.risk_policy import EffectiveRiskPolicy, verify_risk_policy_digests
from redteam_agent.quality.models import QualityReport, QualityRunRecord
from redteam_agent.sandbox.models import SandboxCapabilities
from redteam_agent.session.models import SessionSecurityContextSnapshot
from redteam_agent.tools.availability import AvailableToolSnapshot
from redteam_agent.tools.registry import ToolRegistryRevision

# family -> (digest field, catalog digest name)
_OBJECT_INTEGRITY: dict[str, tuple[str, str]] = {
    MissionRevision.__name__: ("mission_revision_digest", "mission_revision_digest"),
    PolicyDecision.__name__: ("decision_digest", "decision_digest"),
    ContextDataAccessGrant.__name__: ("grant_digest", "grant_digest"),
    ApprovalRequest.__name__: ("request_digest", "request_digest"),
    ApprovalRecord.__name__: ("record_digest", "record_digest"),
    AvailableToolSnapshot.__name__: ("snapshot_digest", "snapshot_digest"),
    ToolRegistryRevision.__name__: ("registry_digest", "registry_digest"),
    LocalLLMProfile.__name__: ("profile_digest", "profile_digest"),
    MockAgentProfile.__name__: ("profile_digest", "profile_digest"),
    ServerAttestation.__name__: ("attestation_digest", "llm_server_attestation_digest"),
    SandboxCapabilities.__name__: ("sandbox_binding_digest", "sandbox_binding_digest"),
    # Phase 0B execution-safety families.
    ExecutionRecord.__name__: ("record_digest", "execution_record_digest"),
    DispatchClaim.__name__: ("record_digest", "dispatch_claim_digest"),
    ResultCollectionStateRecord.__name__: ("record_digest", "result_collection_state_digest"),
    ResultIngestionStateRecord.__name__: ("record_digest", "result_ingestion_state_digest"),
    RawControlMetadataRecord.__name__: ("record_digest", "raw_control_metadata_digest"),
    ExecutionResultProjection.__name__: ("projection_digest", "execution_result_projection_digest"),
    MissionExecutionBudget.__name__: ("record_digest", "mission_execution_budget_digest"),
    CancelAttempt.__name__: ("record_digest", "cancel_attempt_digest"),
    ExecutionRecoveryAuthority.__name__: ("authority_digest", "execution_recovery_authority_digest"),
    ProviderTaskBinding.__name__: ("binding_digest", "result_task_binding_digest"),
    LocalResultBinding.__name__: ("binding_digest", "result_task_binding_digest"),
    # Phase 2 D11 durable quality evidence.
    QualityRunRecord.__name__: ("run_digest", "agent_quality_run_digest"),
    QualityReport.__name__: ("report_digest", "agent_quality_report_digest"),
}

# Families integrity-checked by id/row-key binding at the repository (no content
# digest field). Listed explicitly so an unknown type cannot pass silently.
_ID_BOUND_FAMILIES: frozenset[str] = frozenset(
    {
        MissionState.__name__,
        SessionSecurityContextSnapshot.__name__,
        AdapterCapabilities.__name__,
        ContextResourceIndexRecord.__name__,
        MissionRoleAssignment.__name__,
        MissionLifecycleEvent.__name__,
        # Phase 0B records whose integrity is enforced by id/row-key binding
        # (no self content digest field).
        ResultCollectionAuthority.__name__,
        ExecutionResult.__name__,
    }
)


def verify_object_integrity(model: BaseModel, digest_service: DigestService) -> None:
    """Verify the integrity of a stored security artifact, failing closed."""
    name = type(model).__name__
    mapping = _OBJECT_INTEGRITY.get(name)
    if mapping is not None:
        digest_field, digest_name = mapping
        payload = model.model_dump(mode="python")
        expected = payload.pop(digest_field)
        if not isinstance(expected, str):
            raise RepositoryIntegrityError(f"{name}: missing integrity digest field")
        digest_service.verify(digest_name, payload, expected)
        return
    if isinstance(model, EffectiveRiskPolicy):
        verify_risk_policy_digests(model, digest_service)
        return
    if name in _ID_BOUND_FAMILIES:
        return  # integrity enforced by repository id/row-key binding
    raise RepositoryIntegrityError(f"unregistered security family for storage: {name}")
