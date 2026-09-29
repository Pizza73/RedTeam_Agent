"""Build trusted Tool Registry entries from the installed AD MCP package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from redteam_agent.adapters.ad_mcp_adapter import AD_MCP_ADAPTER_ID, AD_MCP_CATALOG_REVISION
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.tools.models import RiskLevel, ToolDefinition


def approved_ad_mcp_schemas(
    operation_ids: Sequence[str],
) -> dict[str, dict[str, object]]:
    """Load exact schemas lazily so the core package can run without the extra."""
    try:
        from ad_mcp.catalog import BY_NAME, input_schema
    except ImportError as exc:
        raise RuntimeError("the independent ad-mcp package is not installed") from exc
    schemas: dict[str, dict[str, object]] = {}
    for operation_id in operation_ids:
        tool = BY_NAME.get(operation_id)
        if tool is None:
            raise ValueError("AD MCP operation is not present in the pinned catalog")
        schemas[operation_id] = input_schema(tool)
    return schemas


def build_ad_mcp_tool_definitions(
    *,
    operation_ids: Sequence[str],
    risk_levels: Mapping[str, RiskLevel],
    registry_revision: int,
    action_contract_refs: Mapping[str, ActionContractReference],
    output_publication_rule_id: str,
    evidence_rule_ids: tuple[str, ...],
    digest_service: DigestService,
    adapter_id: str = AD_MCP_ADAPTER_ID,
) -> tuple[ToolDefinition, ...]:
    """Create entries only for explicitly enabled and risk-mapped operations."""
    if not operation_ids or len(operation_ids) != len(set(operation_ids)):
        raise ValueError("AD MCP operation IDs must be a non-empty unique sequence")
    requested = set(operation_ids)
    if set(risk_levels) != requested or set(action_contract_refs) != requested:
        raise ValueError("AD MCP risk and action-contract mappings must be exact")
    try:
        from ad_mcp.catalog import BY_NAME, input_schema
        from ad_mcp.models import ParameterKind, Risk
    except ImportError as exc:
        raise RuntimeError("the independent ad-mcp package is not installed") from exc
    definitions: list[ToolDefinition] = []
    for operation_id in operation_ids:
        provider = BY_NAME.get(operation_id)
        if provider is None:
            raise ValueError("AD MCP operation is not present in the pinned catalog")
        if provider.risk is Risk.UNCLASSIFIED:
            raise ValueError("AD MCP unclassified operation cannot enter the Tool Registry")
        schema = input_schema(provider)
        kernel_schema = _kernel_schema(schema)
        provider_schema_digest = digest_service.compute(
            "mcp_approved_tool_schema_digest",
            {"name": operation_id, "input_schema": schema},
        )
        has_secret = any(item.kind is ParameterKind.SECRET for item in provider.parameters)
        has_resource = any(item.kind is ParameterKind.RESOURCE for item in provider.parameters)
        capability = f"mcp.tool:{operation_id}:{AD_MCP_CATALOG_REVISION}"
        definitions.append(
            ToolDefinition(
                tool_ref=ToolRef(tool_id=operation_id, registry_revision=registry_revision),
                display_name=operation_id,
                version=provider.supported_version,
                description=provider.description,
                adapter="mcp",
                adapter_id=adapter_id,
                provider_tool_name=operation_id,
                provider_definition_revision=AD_MCP_CATALOG_REVISION,
                provider_schema_digest=provider_schema_digest,
                minimum_risk_level=risk_levels[operation_id],
                approval_rule="always" if provider.risk is Risk.INTRUSIVE else "policy",
                side_effect="state_change" if provider.risk is Risk.INTRUSIVE else "read_only",
                idempotency="non_idempotent",
                parameter_schema=kernel_schema,
                output_publication_rule_id=output_publication_rule_id,
                evidence_rule_ids=evidence_rule_ids,
                action_contract_ref=action_contract_refs[operation_id],
                target_mode="required" if provider.network_target_required else "none",
                target_extractor_id=(
                    "ad_mcp_targets_v1"
                    if provider.network_target_required
                    else "ad_mcp_offline_v1"
                ),
                default_timeout_seconds=provider.default_timeout_seconds,
                max_timeout_seconds=provider.default_timeout_seconds,
                max_output_bytes=provider.max_output_bytes,
                secret_argument_paths=(
                    ("/call/parameters/credential",) if has_secret else ()
                ),
                requires_session=False,
                supported_os=frozenset({"windows"}),
                supported_architectures=frozenset({"x86_64", "amd64"}),
                required_adapter_capabilities=frozenset(
                    {"server.initialize", "tools.list", "tools.call", capability}
                ),
                required_session_capabilities=frozenset(),
                required_data_access_types=frozenset(
                    {
                        *({"secret_reference"} if has_secret else set()),
                        *({"local_artifact"} if has_resource else set()),
                    }
                ),
                required_target_binding_modes=(
                    frozenset({"exact_ip_enforced"})
                    if provider.network_target_required
                    else frozenset({"none"})
                ),
                sandbox_requirement=None,
                result_delivery_mode="provider_task",
            )
        )
    return tuple(definitions)


def _kernel_schema(value: object) -> dict[str, object]:
    """Project the MCP schema into the authorization kernel's safe v1 subset."""
    if not isinstance(value, dict):
        raise ValueError("AD MCP schema node is invalid")
    raw_type = value.get("type")
    if isinstance(raw_type, list):
        non_null = [item for item in raw_type if item != "null"]
        if len(non_null) != 1:
            raise ValueError("AD MCP nullable schema has no single concrete type")
        raw_type = non_null[0]
    if not isinstance(raw_type, str):
        raise ValueError("AD MCP schema type is invalid")
    result: dict[str, object] = {"type": raw_type}
    for key in ("const", "enum", "minimum", "maximum", "minItems"):
        if key in value:
            result[key] = value[key]
    if raw_type == "object":
        properties = value.get("properties", {})
        if not isinstance(properties, dict):
            raise ValueError("AD MCP object properties are invalid")
        result["properties"] = {
            str(name): _kernel_schema(schema) for name, schema in properties.items()
        }
        required = value.get("required", [])
        if not isinstance(required, list):
            raise ValueError("AD MCP required fields are invalid")
        result["required"] = required
        result["additionalProperties"] = False
    elif raw_type == "array":
        result["items"] = _kernel_schema(value.get("items"))
    return result


__all__ = ["approved_ad_mcp_schemas", "build_ad_mcp_tool_definitions"]
