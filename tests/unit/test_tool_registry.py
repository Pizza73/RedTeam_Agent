"""Tool Registry validation and digest tests (incl. action-contract binding)."""

from __future__ import annotations

from dataclasses import replace

import pytest

import support
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.contracts.catalog import ActionContractCatalog
from redteam_agent.errors import ToolRegistryValidationError
from redteam_agent.tools.registry import build_tool_registry


def _ds() -> DigestService:
    return DigestService()


def _build_invalid_tool(tool) -> None:
    """Build a registry with a tool expected to fail structural validation.

    Uses an empty contract catalog; structural (_validate_tool) checks run before
    the contract check, so the intended error is raised.
    """
    build_tool_registry(
        registry_revision=1,
        tools=(tool,),
        digest_service=_ds(),
        contract_catalog=support.empty_contract_catalog(),
        rule_catalog=support.rule_catalog_for((tool,)),
    )


def test_valid_registry_builds_with_digest() -> None:
    ds = _ds()
    registry, _tools, _catalog = support.build_registered_registry(ds, (support.network_tool(),))
    assert len(registry.registry_digest) == 64


def test_duplicate_tool_id_rejected() -> None:
    ds = _ds()
    tool = support.rebind_contract(support.network_tool())
    catalog = support.contract_catalog_for((support.network_tool(),))
    with pytest.raises(ToolRegistryValidationError):
        build_tool_registry(
            registry_revision=1, tools=(tool, tool), digest_service=ds, contract_catalog=catalog,
            rule_catalog=support.rule_catalog_for((tool,)),
        )


def test_registry_revision_mismatch_rejected() -> None:
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(support.network_tool(registry_revision=2))


def test_required_target_without_extractor_rejected() -> None:
    tool = support.network_tool().model_copy(update={"target_extractor_id": None})
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_dynamic_tool_with_none_binding_mode_rejected() -> None:
    tool = support.network_tool().model_copy(update={"required_target_binding_modes": frozenset({"none"})})
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_unregistered_extractor_rejected() -> None:
    tool = support.network_tool().model_copy(update={"target_extractor_id": "not_registered_v1"})
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_high_risk_local_without_sandbox_rejected() -> None:
    tool = support.network_tool(minimum_risk="high").model_copy(
        update={"adapter": "local", "sandbox_requirement": None}
    )
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_invalid_secret_path_rejected() -> None:
    tool = support.network_tool(secret_paths=("no-leading-slash",))
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_no_extractor_cannot_register_target_fields() -> None:
    tool = support.network_tool().model_copy(
        update={
            "target_mode": "none",
            "target_extractor_id": None,
            "required_target_binding_modes": frozenset({"none"}),
        }
    )
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_resource_fields_must_equal_declared_data_access_types() -> None:
    schema = {
        "type": "object",
        "properties": {
            "artifact_ids": {"type": "array", "items": {"type": "string"}},
            "report_ids": {"type": "array", "items": {"type": "string"}},
        },
        "additionalProperties": False,
    }
    tool = support.network_tool().model_copy(
        update={
            "target_mode": "none",
            "target_extractor_id": "artifact_target_v1",
            "required_target_binding_modes": frozenset({"none"}),
            "required_data_access_types": frozenset({"artifact"}),
            "parameter_schema": schema,
        }
    )
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool)


def test_secret_path_requires_closed_secret_reference_schema() -> None:
    tool = support.network_tool(secret_paths=("/credential",))
    schema = thaw(tool.parameter_schema)
    schema["properties"]["credential"] = {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }
    with pytest.raises(ToolRegistryValidationError):
        _build_invalid_tool(tool.model_copy(update={"parameter_schema": schema}))


def test_phase0a_contract_rejects_unevaluated_predicates() -> None:
    definition = replace(support.contract_for(support.network_tool()), preconditions=("unregistered=true",))
    with pytest.raises(ToolRegistryValidationError):
        ActionContractCatalog((definition,))


def test_unregistered_action_contract_rejected() -> None:
    ds = _ds()
    tool = support.rebind_contract(support.network_tool())
    with pytest.raises(ToolRegistryValidationError):
        build_tool_registry(
            registry_revision=1, tools=(tool,), digest_service=ds,
            contract_catalog=support.empty_contract_catalog(), rule_catalog=support.rule_catalog_for((tool,)),
        )


def test_action_contract_parameter_schema_mismatch_rejected() -> None:
    ds = _ds()
    base = support.network_tool()
    catalog = support.contract_catalog_for((base,))
    # Rebind the ref to the (matching) contract, then tamper the parameter schema
    # so the registered contract's schema digest no longer matches the tool.
    tampered = support.rebind_contract(base).model_copy(update={"parameter_schema": {"type": "object", "x": 1}})
    with pytest.raises(ToolRegistryValidationError):
        build_tool_registry(
            registry_revision=1, tools=(tampered,), digest_service=ds, contract_catalog=catalog,
            rule_catalog=support.rule_catalog_for((base,)),
        )
