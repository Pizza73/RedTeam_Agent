"""Trusted registry construction and JSON Schema validation."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical import sha256_digest
from redteam_agent.errors import TargetExtractorResolutionError
from redteam_agent.json_schema import JsonSchemaDefinitionError, validate_json_schema_definition
from redteam_agent.models.tools import ToolDefinition, ToolRegistryRevision

from .target_extractors import TrustedTargetExtractorRegistry


def registry_payload(
    tools: tuple[ToolDefinition, ...], registry_revision: int
) -> dict[str, object]:
    return {
        "schema_version": "tool-registry-v1",
        "registry_revision": registry_revision,
        "tools": [tool.model_dump(mode="python") for tool in tools],
    }


def build_registry_revision(
    *,
    registry_revision: int,
    tools: tuple[ToolDefinition, ...],
    created_at: datetime,
    extractors: TrustedTargetExtractorRegistry,
) -> ToolRegistryRevision:
    ordered = tuple(
        sorted(tools, key=lambda item: (item.tool_ref.tool_id, item.tool_ref.registry_revision))
    )
    for tool in ordered:
        if tool.target_extractor_id is not None:
            extractors.resolve(tool.target_extractor_id)
        try:
            validate_json_schema_definition(tool.parameter_schema.to_dict())
        except JsonSchemaDefinitionError as exc:
            raise TargetExtractorResolutionError("tool parameter schema is invalid") from exc
    digest = sha256_digest(registry_payload(ordered, registry_revision))
    return ToolRegistryRevision(
        registry_revision=registry_revision,
        registry_digest=digest,
        schema_version="tool-registry-v1",
        tools=ordered,
        created_at=created_at,
    )
