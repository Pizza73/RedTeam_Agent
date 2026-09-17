"""Strict evidence and result models for read-only AD configuration assessment.

These models deliberately contain configuration counts and opaque object references
only.  They cannot carry Kerberos tickets, password material, certificate private
keys, payloads, or arbitrary command output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel

ADAssessmentCategory = Literal[
    "privileged_access_configuration",
    "kerberos_service_account_configuration",
    "kerberos_preauth_configuration",
    "adcs_esc_configuration",
    "delegation_configuration",
]

ADAssessmentStatus = Literal[
    "misconfiguration_detected",
    "no_misconfiguration_detected",
    "indeterminate",
]


class PrivilegedAccessEvidence(StrictImmutableBoundaryModel):
    unexpected_tier_zero_membership_count: int = Field(ge=0)
    stale_privileged_account_count: int = Field(ge=0)
    excessive_delegated_admin_count: int = Field(ge=0)


class KerberosServiceAccountEvidence(StrictImmutableBoundaryModel):
    service_account_with_spn_count: int = Field(ge=0)
    weak_encryption_service_account_count: int = Field(ge=0)
    stale_password_service_account_count: int = Field(ge=0)
    unmanaged_service_account_count: int = Field(ge=0)

    @model_validator(mode="after")
    def _subsets_do_not_exceed_total(self) -> KerberosServiceAccountEvidence:
        total = self.service_account_with_spn_count
        if any(
            count > total
            for count in (
                self.weak_encryption_service_account_count,
                self.stale_password_service_account_count,
                self.unmanaged_service_account_count,
            )
        ):
            raise ValueError("Kerberos service-account risk count exceeds the SPN account total")
        return self


class KerberosPreauthEvidence(StrictImmutableBoundaryModel):
    preauthentication_disabled_account_count: int = Field(ge=0)


ADCSExposureId = Literal["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8"]


class ADCSExposureCount(StrictImmutableBoundaryModel):
    esc_id: ADCSExposureId
    affected_object_count: int = Field(ge=0)


class ADCSEvidence(StrictImmutableBoundaryModel):
    exposure_counts: tuple[ADCSExposureCount, ...] = Field(max_length=8)

    @model_validator(mode="after")
    def _unique_exposure_ids(self) -> ADCSEvidence:
        ids = [item.esc_id for item in self.exposure_counts]
        if len(ids) != len(set(ids)):
            raise ValueError("AD CS exposure identifiers must be unique")
        return self


class DelegationEvidence(StrictImmutableBoundaryModel):
    unconstrained_delegation_account_count: int = Field(ge=0)
    broad_constrained_delegation_account_count: int = Field(ge=0)
    protocol_transition_account_count: int = Field(ge=0)
    risky_rbcd_acl_count: int = Field(ge=0)


class ADAssessmentSnapshot(StrictImmutableBoundaryModel):
    """Trusted collector output or explicitly-labelled simulator fixture."""

    snapshot_id: str = Field(min_length=1, max_length=200)
    domain_ref: str = Field(min_length=1, max_length=256)
    source_type: Literal["simulator", "verified_directory_export", "verified_ldap_snapshot"]
    source_artifact_ids: tuple[str, ...] = Field(max_length=32)
    collected_at: datetime
    privileged_access: PrivilegedAccessEvidence | None = None
    kerberos_service_accounts: KerberosServiceAccountEvidence | None = None
    kerberos_preauth: KerberosPreauthEvidence | None = None
    adcs: ADCSEvidence | None = None
    delegation: DelegationEvidence | None = None

    @model_validator(mode="after")
    def _unique_artifact_references(self) -> ADAssessmentSnapshot:
        if len(self.source_artifact_ids) != len(set(self.source_artifact_ids)):
            raise ValueError("source artifact references must be unique")
        if self.source_type != "simulator":
            if not self.source_artifact_ids:
                raise ValueError("verified AD evidence requires a source artifact reference")
            if self.adcs is not None:
                expected = {f"ESC{index}" for index in range(1, 9)}
                actual = {item.esc_id for item in self.adcs.exposure_counts}
                if actual != expected:
                    raise ValueError("verified AD CS evidence requires complete ESC1-ESC8 coverage")
        return self


class ADAssessmentFinding(StrictImmutableBoundaryModel):
    rule_id: str = Field(pattern=r"^AD-[A-Z0-9-]+$")
    category: ADAssessmentCategory
    severity: Literal["low", "medium", "high", "critical"]
    title: str = Field(min_length=1, max_length=200)
    affected_object_count: int = Field(gt=0)
    evidence_artifact_ids: tuple[str, ...]


class ADAssessmentCheckResult(StrictImmutableBoundaryModel):
    operation_id: str = Field(pattern=r"^ad\.audit\.[a-z0-9_.-]+$")
    category: ADAssessmentCategory
    status: ADAssessmentStatus
    reason_codes: tuple[str, ...]
    finding_rule_ids: tuple[str, ...]


class ADAssessmentResult(StrictImmutableBoundaryModel):
    result_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    domain_ref: str = Field(min_length=1)
    evidence_source_type: Literal["simulator", "verified_directory_export", "verified_ldap_snapshot"]
    decision_authority: Literal["deterministic_verifier"] = "deterministic_verifier"
    evaluated_at: datetime
    checks: tuple[ADAssessmentCheckResult, ...]
    findings: tuple[ADAssessmentFinding, ...]


class ADAssessmentCategoryConsensus(StrictImmutableBoundaryModel):
    operation_id: str = Field(pattern=r"^ad\.audit\.[a-z0-9_.-]+$")
    category: ADAssessmentCategory
    llm_status: ADAssessmentStatus
    verifier_status: ADAssessmentStatus
    consensus: Literal["agreed", "disagreed"]
    verified_rule_ids: tuple[str, ...]

    @model_validator(mode="after")
    def _consensus_matches_statuses(self) -> ADAssessmentCategoryConsensus:
        expected = "agreed" if self.llm_status == self.verifier_status else "disagreed"
        if self.consensus != expected:
            raise ValueError("consensus does not match the LLM and verifier statuses")
        return self


class ADAssessmentConsensusResult(StrictImmutableBoundaryModel):
    result_id: str = Field(min_length=1)
    snapshot_id: str = Field(min_length=1)
    domain_ref: str = Field(min_length=1)
    evidence_source_type: Literal["simulator", "verified_directory_export", "verified_ldap_snapshot"]
    evaluation_mode: Literal["local_llm_plus_deterministic_verifier"] = "local_llm_plus_deterministic_verifier"
    status: Literal["completed", "blocked"]
    decision_authority: Literal["deterministic_verifier"] = "deterministic_verifier"
    output_schema: Literal["planner_output"] = "planner_output"
    evaluated_at: datetime
    category_results: tuple[ADAssessmentCategoryConsensus, ...] = Field(min_length=5, max_length=5)
    findings: tuple[ADAssessmentFinding, ...]

    @model_validator(mode="after")
    def _complete_closed_catalog(self) -> ADAssessmentConsensusResult:
        from redteam_agent.ad_assessment.catalog import AD_ASSESSMENT_OPERATIONS

        expected_pairs = {(item.operation_id, item.category) for item in AD_ASSESSMENT_OPERATIONS}
        actual_pairs = {(item.operation_id, item.category) for item in self.category_results}
        if actual_pairs != expected_pairs or len(actual_pairs) != len(self.category_results):
            raise ValueError("consensus result must cover each closed-catalog category exactly once")
        can_complete = all(
            item.consensus == "agreed" and item.verifier_status != "indeterminate" for item in self.category_results
        )
        if (self.status == "completed") != can_complete:
            raise ValueError("evaluation status does not match consensus and evidence completeness")
        return self


__all__ = [
    "ADAssessmentCategory",
    "ADAssessmentCategoryConsensus",
    "ADAssessmentCheckResult",
    "ADAssessmentConsensusResult",
    "ADAssessmentFinding",
    "ADAssessmentResult",
    "ADAssessmentSnapshot",
    "ADAssessmentStatus",
    "ADCSEvidence",
    "ADCSExposureCount",
    "DelegationEvidence",
    "KerberosPreauthEvidence",
    "KerberosServiceAccountEvidence",
    "PrivilegedAccessEvidence",
]
