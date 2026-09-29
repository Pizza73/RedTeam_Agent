from __future__ import annotations

import pytest

from redteam_agent.adapters.ad_mcp_catalog import (
    approved_ad_mcp_schemas,
    build_ad_mcp_tool_definitions,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.common import ActionContractReference
from redteam_agent.tools.parameter_schema import validate_schema_is_supported
from redteam_agent.tools.target_extractors import (
    DEFAULT_TARGET_EXTRACTOR_REGISTRY,
    TargetExtractionInput,
)


def test_builds_provider_task_registry_entry_from_exact_schema() -> None:
    operation = "adcs.certipy.cert"
    contract = ActionContractReference(contract_id="adcs-cert", revision="1", digest="d")
    definitions = build_ad_mcp_tool_definitions(
        operation_ids=(operation,),
        risk_levels={operation: "read"},
        registry_revision=7,
        action_contract_refs={operation: contract},
        output_publication_rule_id="ad-mcp-public-v1",
        evidence_rule_ids=("adcs-evidence-v1",),
        digest_service=DigestService(),
    )
    assert len(definitions) == 1
    definition = definitions[0]
    assert definition.result_delivery_mode == "provider_task"
    assert definition.sandbox_requirement is None
    assert definition.provider_schema_digest
    assert approved_ad_mcp_schemas((operation,))[operation]["additionalProperties"] is False
    validate_schema_is_supported(definition.parameter_schema)


def test_ad_mcp_target_extractor_reads_only_nested_targets() -> None:
    targets = DEFAULT_TARGET_EXTRACTOR_REGISTRY.extract(
        "ad_mcp_targets_v1",
        TargetExtractionInput(
            requested_targets=(),
            arguments={
                "call": {
                    "targets": ["192.0.2.10"],
                    "parameters": {},
                    "dry_run": False,
                }
            },
            session_id=None,
        ),
    )
    assert [target.canonical_value for target in targets] == ["192.0.2.10"]


def test_unclassified_operation_cannot_enter_registry() -> None:
    operation = "recon.nmap.smb_security_mode"
    contract = ActionContractReference(contract_id="nmap", revision="1", digest="d")
    with pytest.raises(ValueError, match="unclassified"):
        build_ad_mcp_tool_definitions(
            operation_ids=(operation,),
            risk_levels={operation: "low"},
            registry_revision=7,
            action_contract_refs={operation: contract},
            output_publication_rule_id="ad-mcp-public-v1",
            evidence_rule_ids=("smb-evidence-v1",),
            digest_service=DigestService(),
        )
