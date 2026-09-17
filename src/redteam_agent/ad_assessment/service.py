"""Deterministic AD configuration verifier; LLM output is never evidence."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from redteam_agent.ad_assessment.catalog import AD_ASSESSMENT_OPERATIONS
from redteam_agent.ad_assessment.models import (
    ADAssessmentCheckResult,
    ADAssessmentFinding,
    ADAssessmentResult,
    ADAssessmentSnapshot,
)

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ADAssessmentVerifier:
    """Convert normalized trusted evidence into repeatable configuration findings."""

    def __init__(self, *, clock: Clock = _utc_now) -> None:
        self._clock = clock

    def evaluate(self, snapshot: ADAssessmentSnapshot) -> ADAssessmentResult:
        findings: list[ADAssessmentFinding] = []
        checks: list[ADAssessmentCheckResult] = []
        for operation in AD_ASSESSMENT_OPERATIONS:
            evidence = getattr(snapshot, operation.evidence_field)
            category_findings = [] if evidence is None else self._findings_for(operation.operation_id, snapshot)
            findings.extend(category_findings)
            if evidence is None:
                status = "indeterminate"
                reason_codes = ("EVIDENCE_NOT_COLLECTED",)
            elif category_findings:
                status = "misconfiguration_detected"
                reason_codes = ("DETERMINISTIC_RULE_MATCH",)
            else:
                status = "no_misconfiguration_detected"
                reason_codes = ("NO_RULE_MATCH",)
            checks.append(
                ADAssessmentCheckResult(
                    operation_id=operation.operation_id,
                    category=operation.category,  # type: ignore[arg-type]
                    status=status,  # type: ignore[arg-type]
                    reason_codes=reason_codes,
                    finding_rule_ids=tuple(item.rule_id for item in category_findings),
                )
            )
        return ADAssessmentResult(
            result_id=f"ad-assessment-{snapshot.snapshot_id}",
            snapshot_id=snapshot.snapshot_id,
            domain_ref=snapshot.domain_ref,
            evidence_source_type=snapshot.source_type,
            evaluated_at=self._clock(),
            checks=tuple(checks),
            findings=tuple(findings),
        )

    def _findings_for(self, operation_id: str, snapshot: ADAssessmentSnapshot) -> list[ADAssessmentFinding]:
        refs = snapshot.source_artifact_ids
        if operation_id == "ad.audit.privileged_access":
            assert snapshot.privileged_access is not None
            privileged = snapshot.privileged_access
            return self._positive_findings(
                (
                    (
                        "AD-PRIV-TIER0",
                        "high",
                        "Unexpected tier-zero membership",
                        privileged.unexpected_tier_zero_membership_count,
                    ),
                    (
                        "AD-PRIV-STALE",
                        "high",
                        "Stale privileged account",
                        privileged.stale_privileged_account_count,
                    ),
                    (
                        "AD-PRIV-DELEGATED",
                        "medium",
                        "Excessive delegated administration",
                        privileged.excessive_delegated_admin_count,
                    ),
                ),
                category="privileged_access_configuration",
                evidence_refs=refs,
            )
        if operation_id == "ad.audit.kerberos_service_accounts":
            assert snapshot.kerberos_service_accounts is not None
            service_accounts = snapshot.kerberos_service_accounts
            return self._positive_findings(
                (
                    (
                        "AD-KRB-WEAK-ENC",
                        "high",
                        "Service account permits weak Kerberos encryption",
                        service_accounts.weak_encryption_service_account_count,
                    ),
                    (
                        "AD-KRB-STALE-PWD",
                        "medium",
                        "Service account password is stale",
                        service_accounts.stale_password_service_account_count,
                    ),
                    (
                        "AD-KRB-UNMANAGED",
                        "medium",
                        "SPN account is not managed",
                        service_accounts.unmanaged_service_account_count,
                    ),
                ),
                category="kerberos_service_account_configuration",
                evidence_refs=refs,
            )
        if operation_id == "ad.audit.kerberos_preauth":
            assert snapshot.kerberos_preauth is not None
            return self._positive_findings(
                (
                    (
                        "AD-KRB-PREAUTH",
                        "high",
                        "Kerberos preauthentication is disabled",
                        snapshot.kerberos_preauth.preauthentication_disabled_account_count,
                    ),
                ),
                category="kerberos_preauth_configuration",
                evidence_refs=refs,
            )
        if operation_id == "ad.audit.adcs_esc":
            assert snapshot.adcs is not None
            return self._positive_findings(
                tuple(
                    (
                        f"AD-ADCS-{item.esc_id}",
                        "high" if item.esc_id in {"ESC1", "ESC4", "ESC6", "ESC7", "ESC8"} else "medium",
                        f"AD CS {item.esc_id} configuration exposure",
                        item.affected_object_count,
                    )
                    for item in snapshot.adcs.exposure_counts
                ),
                category="adcs_esc_configuration",
                evidence_refs=refs,
            )
        if operation_id == "ad.audit.delegation":
            assert snapshot.delegation is not None
            delegation = snapshot.delegation
            return self._positive_findings(
                (
                    (
                        "AD-DELEG-UNCONSTRAINED",
                        "high",
                        "Unconstrained delegation is configured",
                        delegation.unconstrained_delegation_account_count,
                    ),
                    (
                        "AD-DELEG-BROAD",
                        "medium",
                        "Constrained delegation scope is broad",
                        delegation.broad_constrained_delegation_account_count,
                    ),
                    (
                        "AD-DELEG-PROTOCOL",
                        "medium",
                        "Protocol transition is enabled",
                        delegation.protocol_transition_account_count,
                    ),
                    (
                        "AD-DELEG-RBCD",
                        "high",
                        "RBCD ACL grants risky control",
                        delegation.risky_rbcd_acl_count,
                    ),
                ),
                category="delegation_configuration",
                evidence_refs=refs,
            )
        raise ValueError("unregistered AD assessment operation")

    @staticmethod
    def _positive_findings(
        rules: tuple[tuple[str, str, str, int], ...],
        *,
        category: str,
        evidence_refs: tuple[str, ...],
    ) -> list[ADAssessmentFinding]:
        return [
            ADAssessmentFinding(
                rule_id=rule_id,
                category=category,  # type: ignore[arg-type]
                severity=severity,  # type: ignore[arg-type]
                title=title,
                affected_object_count=count,
                evidence_artifact_ids=evidence_refs,
            )
            for rule_id, severity, title, count in rules
            if count > 0
        ]


__all__ = ["ADAssessmentVerifier"]
