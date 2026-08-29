"""Versioned agent profiles used by Phase 0A mock validation."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .base import StrictImmutableBoundaryModel
from .common import UtcDatetime


class MockAgentProfile(StrictImmutableBoundaryModel):
    profile_type: Literal["mock"] = "mock"
    profile_revision: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    planner_fixture_revision: str = Field(min_length=1)
    analyzer_fixture_revision: str = Field(min_length=1)


class LocalLLMProfile(StrictImmutableBoundaryModel):
    profile_type: Literal["local_llm"] = "local_llm"
    profile_revision: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    wire_api: Literal["chat_completions"]
    structured_output_mode: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    model_hash: str = Field(min_length=1)
    chat_template_digest: str | None = None


class LLMCapabilityResult(StrictImmutableBoundaryModel):
    capability_result_id: str = Field(min_length=1)
    profile_revision: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    status: Literal["PASSED", "FAILED", "NOT_REQUIRED"]
    result_digest: str = Field(min_length=1)
    checked_at: UtcDatetime

