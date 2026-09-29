"""Closed catalog of read-only AD configuration assessment operations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from redteam_agent.ad_assessment.models import ADAssessmentCategory
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.contracts.catalog import parameter_schema_digest
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.tools.models import ToolDefinition

AD_ASSESSMENT_ADAPTER_ID = "local-ad-assessment-readonly"
AD_ASSESSMENT_CATALOG_REVISION = "ad-assessment-readonly-v1"


@dataclass(frozen=True)
class ADAssessmentOperation:
    operation_id: str
    category: ADAssessmentCategory
    title: str
    description: str
    evidence_field: str


AD_ASSESSMENT_OPERATIONS: tuple[ADAssessmentOperation, ...] = (
    ADAssessmentOperation(
        operation_id="ad.audit.privileged_access",
        category="privileged_access_configuration",
        title="Privileged access configuration",
        description="Inspect tier-zero membership, stale privileged identities, and delegated administration metadata.",
        evidence_field="privileged_access",
    ),
    ADAssessmentOperation(
        operation_id="ad.audit.kerberos_service_accounts",
        category="kerberos_service_account_configuration",
        title="Kerberos service-account configuration",
        description=(
            "Inspect SPN account encryption, password-age, and managed-identity metadata without requesting tickets."
        ),
        evidence_field="kerberos_service_accounts",
    ),
    ADAssessmentOperation(
        operation_id="ad.audit.kerberos_preauth",
        category="kerberos_preauth_configuration",
        title="Kerberos preauthentication configuration",
        description="Inspect the preauthentication-required account setting without requesting AS-REP material.",
        evidence_field="kerberos_preauth",
    ),
    ADAssessmentOperation(
        operation_id="ad.audit.adcs_esc",
        category="adcs_esc_configuration",
        title="AD CS ESC configuration",
        description=(
            "Inspect normalized certificate-template, CA, ACL, and enrollment endpoint configuration for ESC1-ESC8."
        ),
        evidence_field="adcs",
    ),
    ADAssessmentOperation(
        operation_id="ad.audit.delegation",
        category="delegation_configuration",
        title="Kerberos delegation configuration",
        description="Inspect unconstrained, constrained, protocol-transition, and RBCD configuration metadata.",
        evidence_field="delegation",
    ),
)

AD_ASSESSMENT_PARAMETER_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "host_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
    },
    "required": ["host_ids", "timeout_seconds"],
    "additionalProperties": False,
}


def operation_ids() -> frozenset[str]:
    return frozenset(item.operation_id for item in AD_ASSESSMENT_OPERATIONS)


def catalog_view(*, live_collector_attached: bool = False) -> dict[str, object]:
    """Public capability view; no execution authority or target values are included."""

    prohibited = [
        "Kerberos ticket acquisition or export",
        "password or hash cracking",
        "certificate enrollment or authentication",
        "delegation impersonation",
        "directory modification",
        "arbitrary command execution",
    ]
    return {
        "catalogRevision": AD_ASSESSMENT_CATALOG_REVISION,
        "mode": "read_only_configuration_assessment",
        "plannerRole": "select_next_registered_inspection",
        "evaluationRole": "classify_all_five_then_verify_consensus",
        "decisionAuthority": "deterministic_verifier",
        "liveCollectorStatus": "attached" if live_collector_attached else "not_attached",
        "simulatorStatus": "ready",
        "prohibitedActions": prohibited,
        "operations": [
            {
                "id": item.operation_id,
                "category": item.category,
                "title": item.title,
                "description": item.description,
                "readOnly": True,
                "llmSelectable": True,
                "evidenceField": item.evidence_field,
            }
            for item in AD_ASSESSMENT_OPERATIONS
        ],
    }


def build_ad_assessment_tool_definitions(
    *,
    registry_revision: int,
    action_contract_refs: Mapping[str, ActionContractReference],
    output_publication_rule_id: str,
    evidence_rule_ids: tuple[str, ...],
    digest_service: DigestService,
) -> tuple[ToolDefinition, ...]:
    """Create registry definitions that the existing finite Planner may select."""

    if set(action_contract_refs) != operation_ids():
        raise ValueError("AD assessment action contract references must cover the closed catalog")
    schema_digest = parameter_schema_digest(AD_ASSESSMENT_PARAMETER_SCHEMA)
    return tuple(
        ToolDefinition(
            tool_ref=ToolRef(tool_id=item.operation_id, registry_revision=registry_revision),
            display_name=item.title,
            version="1.0.0",
            description=item.description,
            adapter="local",
            adapter_id=AD_ASSESSMENT_ADAPTER_ID,
            provider_tool_name=item.operation_id,
            provider_definition_revision=AD_ASSESSMENT_CATALOG_REVISION,
            provider_schema_digest=schema_digest,
            minimum_risk_level="read",
            approval_rule="policy",
            side_effect="read_only",
            idempotency="idempotent",
            parameter_schema=AD_ASSESSMENT_PARAMETER_SCHEMA,
            output_publication_rule_id=output_publication_rule_id,
            evidence_rule_ids=evidence_rule_ids,
            action_contract_ref=action_contract_refs[item.operation_id],
            target_mode="required",
            target_extractor_id="host_target_v1",
            default_timeout_seconds=30,
            max_timeout_seconds=60,
            max_output_bytes=1024 * 1024,
            secret_argument_paths=(),
            requires_session=False,
            supported_os=frozenset({"windows"}),
            supported_architectures=frozenset({"x86_64", "amd64"}),
            required_adapter_capabilities=frozenset(
                {"local.ad_assessment.read_snapshot", f"operation.{item.operation_id}"}
            ),
            required_session_capabilities=frozenset(),
            required_data_access_types=frozenset(),
            required_target_binding_modes=frozenset({"provider_attested"}),
            allows_redirects=False,
            sandbox_requirement=None,
        )
        for item in AD_ASSESSMENT_OPERATIONS
    )


__all__ = [
    "AD_ASSESSMENT_ADAPTER_ID",
    "AD_ASSESSMENT_CATALOG_REVISION",
    "AD_ASSESSMENT_OPERATIONS",
    "AD_ASSESSMENT_PARAMETER_SCHEMA",
    "ADAssessmentOperation",
    "build_ad_assessment_tool_definitions",
    "catalog_view",
    "operation_ids",
]
