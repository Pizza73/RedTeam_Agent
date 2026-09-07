"""Tool definition model and trusted target-extractor id type (SystemDesign §20)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from redteam_agent.canonical.json_boundary import CanonicalJsonObject
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import ActionContractReference, ToolRef
from redteam_agent.policy.target_binding import TargetBindingMode
from redteam_agent.sandbox.models import SandboxRequirement

TargetExtractorId = Literal[
    "network_target_v1",
    "session_target_v1",
    "host_target_v1",
    "artifact_target_v1",
]

AdapterType = Literal["c2", "mcp", "local"]
RiskLevel = Literal["read", "low", "medium", "high"]
SideEffect = Literal["read_only", "state_change", "destructive"]


class ToolDefinition(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    display_name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str
    adapter: AdapterType
    adapter_id: str = Field(min_length=1)
    provider_tool_name: str = Field(min_length=1)
    provider_definition_revision: str | None
    provider_schema_digest: str = Field(min_length=1)
    minimum_risk_level: RiskLevel
    approval_rule: Literal["policy", "always"]
    side_effect: SideEffect
    idempotency: Literal["idempotent", "provider_deduplicated", "non_idempotent"]
    parameter_schema: CanonicalJsonObject
    output_publication_rule_id: str = Field(min_length=1)
    evidence_rule_ids: tuple[str, ...]
    action_contract_ref: ActionContractReference
    target_mode: Literal["required", "optional", "none"]
    target_extractor_id: TargetExtractorId | None
    default_timeout_seconds: int = Field(gt=0)
    max_timeout_seconds: int = Field(gt=0)
    max_output_bytes: int = Field(gt=0)
    secret_argument_paths: tuple[str, ...]
    requires_session: bool
    supported_os: frozenset[Literal["windows", "linux", "macos", "other"]]
    supported_architectures: frozenset[str]
    required_adapter_capabilities: frozenset[str]
    required_session_capabilities: frozenset[str]
    required_data_access_types: frozenset[str]
    required_target_binding_modes: frozenset[TargetBindingMode]
    allows_redirects: Literal[False] = False
    sandbox_requirement: SandboxRequirement | None
