"""Tool Registry revision, validation and digest (SystemDesign §20).

A ``ToolRegistryRevision`` is an immutable, validated set of tool definitions
pinned to a revision number. Validation enforces the registry's structural
safety rules (timeouts, target-mode/binding-mode coherence, registered target
extractors, secret-path grammar, sandbox requirements for high-risk
local/MCP tools). The registry digest is order-independent over the tools.
"""

from __future__ import annotations

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.contracts.catalog import ActionContractCatalog, RuleCatalog, parameter_schema_digest
from redteam_agent.errors import ParameterSchemaError, SecretArgumentBindingError, ToolRegistryValidationError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.tools.models import ToolDefinition
from redteam_agent.tools.parameter_schema import validate_schema_is_supported
from redteam_agent.tools.secret_argument_path import parse_json_pointer
from redteam_agent.tools.target_extractors import (
    DEFAULT_TARGET_EXTRACTOR_REGISTRY,
    TrustedTargetExtractorRegistry,
)


def _validate_contract(tool: ToolDefinition, catalog: ActionContractCatalog, rules: RuleCatalog) -> None:
    ref = tool.action_contract_ref
    definition = catalog.get(ref.contract_id)
    tid = tool.tool_ref.tool_id
    if definition is None:
        raise ToolRegistryValidationError(f"tool {tid}: unregistered action contract {ref.contract_id!r}")
    if definition.revision != ref.revision or definition.definition_digest != ref.digest:
        raise ToolRegistryValidationError(f"tool {tid}: action contract revision/digest mismatch")
    if definition.tool_id != tid or definition.registry_revision != tool.tool_ref.registry_revision:
        raise ToolRegistryValidationError(f"tool {tid}: action contract is bound to a different ToolRef")
    if definition.parameter_schema_digest != parameter_schema_digest(tool.parameter_schema):
        raise ToolRegistryValidationError(f"tool {tid}: action contract parameter schema digest mismatch")
    if definition.target_extractor_id != tool.target_extractor_id:
        raise ToolRegistryValidationError(f"tool {tid}: action contract target extractor mismatch")
    if tuple(definition.evidence_rule_ids) != tuple(tool.evidence_rule_ids):
        raise ToolRegistryValidationError(f"tool {tid}: action contract evidence rules mismatch")
    if definition.output_publication_rule_id != tool.output_publication_rule_id:
        raise ToolRegistryValidationError(f"tool {tid}: action contract publication rule mismatch")
    if definition.minimum_risk_level != tool.minimum_risk_level or definition.side_effect != tool.side_effect:
        raise ToolRegistryValidationError(f"tool {tid}: action contract risk/side-effect mismatch")
    # The contract's referenced rules must exist in the registered rule catalog.
    if not rules.has_publication(definition.output_publication_rule_id):
        raise ToolRegistryValidationError(f"tool {tid}: contract publication rule not registered")
    if not all(rules.has_evidence(rule_id) for rule_id in definition.evidence_rule_ids):
        raise ToolRegistryValidationError(f"tool {tid}: contract evidence rule not registered")
    if not rules.has_outcome(definition.outcome_rule_id):
        raise ToolRegistryValidationError(f"tool {tid}: contract outcome rule not registered")


class ToolRegistryRevision(StrictImmutableBoundaryModel):
    registry_revision: int = Field(ge=1)
    tools: tuple[ToolDefinition, ...]
    registry_digest: str = Field(min_length=1)

    def by_ref(self, tool_id: str, registry_revision: int) -> ToolDefinition | None:
        for tool in self.tools:
            if tool.tool_ref.tool_id == tool_id and tool.tool_ref.registry_revision == registry_revision:
                return tool
        return None


def _validate_tool(
    tool: ToolDefinition, revision: int, extractors: TrustedTargetExtractorRegistry, rules: RuleCatalog
) -> None:
    if tool.tool_ref.registry_revision != revision:
        raise ToolRegistryValidationError(
            f"tool {tool.tool_ref.tool_id} pins registry_revision {tool.tool_ref.registry_revision}, "
            f"not {revision}"
        )
    if tool.default_timeout_seconds > tool.max_timeout_seconds:
        raise ToolRegistryValidationError(f"tool {tool.tool_ref.tool_id}: default timeout exceeds max timeout")
    try:
        validate_schema_is_supported(tool.parameter_schema)
    except ParameterSchemaError as exc:
        raise ToolRegistryValidationError(f"tool {tool.tool_ref.tool_id}: unsupported parameter schema") from exc
    if not rules.has_publication(tool.output_publication_rule_id):
        raise ToolRegistryValidationError(
            f"tool {tool.tool_ref.tool_id}: unregistered publication rule {tool.output_publication_rule_id!r}"
        )
    if not all(rules.has_evidence(rule_id) for rule_id in tool.evidence_rule_ids):
        raise ToolRegistryValidationError(f"tool {tool.tool_ref.tool_id}: unregistered evidence rule")

    if tool.target_mode == "none":
        if tool.required_target_binding_modes != frozenset({"none"}):
            raise ToolRegistryValidationError(
                f"tool {tool.tool_ref.tool_id}: target_mode=none requires binding modes == {{'none'}}"
            )
    else:
        if not tool.required_target_binding_modes:
            raise ToolRegistryValidationError(
                f"tool {tool.tool_ref.tool_id}: dynamic-target tool needs at least one binding mode"
            )
        if "none" in tool.required_target_binding_modes:
            raise ToolRegistryValidationError(
                f"tool {tool.tool_ref.tool_id}: dynamic-target tool must not include 'none' binding mode"
            )

    if tool.target_mode == "required" and tool.target_extractor_id is None:
        raise ToolRegistryValidationError(
            f"tool {tool.tool_ref.tool_id}: target_mode=required needs a target extractor"
        )
    if tool.target_extractor_id is not None and not extractors.is_registered(tool.target_extractor_id):
        raise ToolRegistryValidationError(
            f"tool {tool.tool_ref.tool_id}: unregistered target extractor {tool.target_extractor_id!r}"
        )

    for path in tool.secret_argument_paths:
        try:
            parse_json_pointer(path)
        except SecretArgumentBindingError as exc:
            raise ToolRegistryValidationError(
                f"tool {tool.tool_ref.tool_id}: invalid secret argument path {path!r}: {exc}"
            ) from exc

    if tool.minimum_risk_level == "high" and tool.adapter in ("local", "mcp") and tool.sandbox_requirement is None:
        raise ToolRegistryValidationError(
            f"tool {tool.tool_ref.tool_id}: high-risk {tool.adapter} tool requires a sandbox requirement"
        )


def _tool_payload(tool: ToolDefinition) -> dict[str, object]:
    return tool.model_dump(mode="python")


def validate_tool_registry(
    registry: ToolRegistryRevision,
    *,
    digest_service: DigestService,
    contract_catalog: ActionContractCatalog,
    rule_catalog: RuleCatalog,
    extractors: TrustedTargetExtractorRegistry | None = None,
) -> None:
    """Re-run the full registry validation (used by build *and* every load/save).

    A structurally invalid registry with a correctly recomputed ``registry_digest``
    is not treated as registered (R13): every entry point validates domain rules,
    contract binding and rule existence, then re-verifies the registry digest over
    the canonically-ordered tools.
    """
    resolver = extractors if extractors is not None else DEFAULT_TARGET_EXTRACTOR_REGISTRY
    seen: set[str] = set()
    for tool in registry.tools:
        if tool.tool_ref.tool_id in seen:
            raise ToolRegistryValidationError(f"duplicate tool_id in revision: {tool.tool_ref.tool_id}")
        seen.add(tool.tool_ref.tool_id)
        _validate_tool(tool, registry.registry_revision, resolver, rule_catalog)
        _validate_contract(tool, contract_catalog, rule_catalog)

    ordered = tuple(sorted(registry.tools, key=lambda t: (t.tool_ref.tool_id, t.tool_ref.registry_revision)))
    if tuple(registry.tools) != ordered:
        raise ToolRegistryValidationError("registry tools are not in canonical order")
    payload = {
        "registry_revision": registry.registry_revision,
        "tools": [_tool_payload(tool) for tool in ordered],
    }
    expected = digest_service.compute("registry_digest", payload)
    if registry.registry_digest != expected:
        raise ToolRegistryValidationError("registry digest does not match its validated content")


def build_tool_registry(
    *,
    registry_revision: int,
    tools: tuple[ToolDefinition, ...],
    digest_service: DigestService,
    contract_catalog: ActionContractCatalog,
    rule_catalog: RuleCatalog,
    extractors: TrustedTargetExtractorRegistry | None = None,
) -> ToolRegistryRevision:
    """Validate the tools and construct a digest-bound registry revision."""
    ordered = tuple(sorted(tools, key=lambda t: (t.tool_ref.tool_id, t.tool_ref.registry_revision)))
    payload = {
        "registry_revision": registry_revision,
        "tools": [_tool_payload(tool) for tool in ordered],
    }
    digest = digest_service.compute("registry_digest", payload)
    registry = ToolRegistryRevision(registry_revision=registry_revision, tools=ordered, registry_digest=digest)
    validate_tool_registry(
        registry, digest_service=digest_service, contract_catalog=contract_catalog,
        rule_catalog=rule_catalog, extractors=extractors,
    )
    return registry
