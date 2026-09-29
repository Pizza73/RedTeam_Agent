"""Adapter capability snapshot model (SystemDesign §13)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.target_binding import TargetBindingMode


class AdapterCapabilities(StrictImmutableBoundaryModel):
    adapter_id: str = Field(min_length=1)
    adapter_type: Literal["c2", "mcp", "local"]
    execution_location: Literal["local_process", "managed_remote", "untrusted_remote"]
    capability_revision: str = Field(min_length=1)
    capabilities: frozenset[str]
    supported_os: frozenset[str]
    supported_architectures: frozenset[str]
    reconciliation: bool
    cancellation: bool
    provider_deduplication: bool
    result_streaming: bool
    result_resume: bool
    durable_result_collection: bool
    result_delivery_mode: Literal["provider_task", "local_result"]
    target_binding_modes: frozenset[TargetBindingMode]
    redirect_disable_enforcement: bool
    policy_intercepted_redirect: bool
    max_output_bytes: int = Field(gt=0)
    provider_tool_catalog_digest: str | None
    observed_at: datetime
