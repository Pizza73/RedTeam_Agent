"""Strict models shared by the registry, runner, and MCP boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Risk(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"
    UNCLASSIFIED = "unclassified"


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    OUTCOME_UNKNOWN = "outcome_unknown"


class ParameterKind(StrEnum):
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    ENUM = "enum"
    RESOURCE = "resource"
    SECRET = "secret"


class ParameterSpec(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    kind: ParameterKind
    flag: str | None = None
    required: bool = False
    choices: tuple[str, ...] = ()
    pattern: str | None = None
    minimum: int | None = None
    maximum: int | None = None
    sensitive: bool = False


class ToolDefinition(StrictModel):
    operation_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    mcp_name: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    category: str
    binary_id: str
    supported_version: str
    argv_prefix: tuple[str, ...]
    parameters: tuple[ParameterSpec, ...] = ()
    risk: Risk
    classification_note: str | None = None
    description: str
    parser_id: str
    detection_ids: tuple[str, ...] = ()
    default_timeout_seconds: int = Field(ge=1, le=86_400)
    max_output_bytes: int = Field(ge=1, le=1_073_741_824)
    network_target_required: bool = True
    remote_windows: bool = False


class SecretReference(StrictModel):
    secret_version_id: str = Field(min_length=1, max_length=256)
    secret_version: str = Field(min_length=1, max_length=256)
    principal_ref: str = Field(min_length=1, max_length=256)
    credential_type: Literal["password", "ntlm_hash", "aes_key", "private_key"]


class ProjectAuthorization(StrictModel):
    client_id: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    mission_id: str = Field(min_length=1, max_length=256)
    execution_id: str = Field(min_length=1, max_length=256)
    approval_id: str | None = Field(default=None, max_length=256)
    catalog_revision: str
    token: SecretStr


class ToolCall(StrictModel):
    targets: tuple[str, ...] = Field(default=(), max_length=64)
    domain: str | None = Field(default=None, max_length=253)
    username: str | None = Field(default=None, max_length=256)
    parameters: dict[str, object] = Field(default_factory=dict)
    dry_run: bool = False

    @field_validator("targets")
    @classmethod
    def unique_targets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("targets must be unique")
        return value


class CommandPlan(StrictModel):
    operation_id: str
    executable: str
    redacted_argv: tuple[str, ...]
    targets: tuple[str, ...]
    risk: Risk
    timeout_seconds: int
    max_output_bytes: int


class DetectionFinding(StrictModel):
    detection_id: str
    target: str | None
    status: Literal["observed", "not_observed", "unknown"]
    summary: str


class PublicResult(StrictModel):
    schema_version: Literal["ad-mcp-result-v1"] = "ad-mcp-result-v1"
    operation_id: str
    status: JobState
    exit_code: int | None
    parser_id: str
    findings: tuple[DetectionFinding, ...]
    coverage: tuple[str, ...]
    limitations: tuple[str, ...]
    raw_result_ref: str
    stdout_bytes: int
    stderr_bytes: int
    completed_at: datetime


class JobView(StrictModel):
    job_id: str
    execution_id: str
    operation_id: str
    state: JobState
    created_at: datetime
    updated_at: datetime
    result: PublicResult | None = None
    error_code: str | None = None


def utc_now() -> datetime:
    return datetime.now(UTC)


SafeString = Annotated[str, Field(min_length=1, max_length=4096)]
