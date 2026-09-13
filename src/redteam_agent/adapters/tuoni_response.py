"""Strict, content-free response projection for the Tuoni 0.16.1 contract.

Provider JSON is untrusted.  Duplicate keys, unknown top-level control fields,
coercion, inconsistent agent identities, and unknown status values all fail
closed before a provider response can become application control metadata.
Command result content stays inside the Tuoni response model and is never
copied into the neutral task observation.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Literal, cast

from pydantic import Field, TypeAdapter, ValidationError, field_validator

from redteam_agent.adapters.c2 import C2SessionObservation
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import AuthorizationKernelError, C2AdapterContractError
from redteam_agent.models.base import StrictImmutableBoundaryModel

type TuoniAgentStatus = Literal["ACTIVE", "INACTIVE", "BLOCKED"]
type TuoniCommandStatus = Literal[
    "CREATED", "SENT", "ONGOING", "CANCELED", "FAILED", "COMPLETE"
]
type TuoniNormalizedTaskStatus = Literal[
    "queued", "running", "succeeded", "failed", "cancelled"
]
type TuoniExecUnitType = Literal[
    "SHELLCODE_NATIVE", "NATIVE_LIB", "DOTNET_DLL", "DOTNET_EXE"
]

_PERMISSION_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{0,127}$"

_ARCHITECTURE_MAP = {
    "X86": "x86",
    "X64": "x86_64",
    "ARM32": "arm32",
    "ARM64": "arm64",
}
_OS_MAP: dict[str, Literal["windows", "linux", "macos", "other"]] = {
    "WINDOWS": "windows",
    "LINUX": "linux",
    "MAC": "macos",
    "BSD": "other",
}
_TASK_STATUS_MAP: dict[TuoniCommandStatus, TuoniNormalizedTaskStatus] = {
    "CREATED": "queued",
    "SENT": "running",
    "ONGOING": "running",
    "CANCELED": "cancelled",
    "FAILED": "failed",
    "COMPLETE": "succeeded",
}


def _canonical_uuid(value: str, *, label: str) -> str:
    from uuid import UUID

    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not a UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{label} is not canonical")
    return value


class TuoniAgentResponseV0161(StrictImmutableBoundaryModel):
    """OpenAPI 0.16.1 AgentResponse top-level control shape."""

    guid: str
    first_registration_time: datetime = Field(alias="firstRegistrationTime")
    last_callback_time: datetime = Field(alias="lastCallbackTime")
    next_callback: CanonicalJsonObject = Field(alias="nextCallback")
    metadata: CanonicalJsonObject
    active: bool
    status: TuoniAgentStatus
    recent_listeners: tuple[CanonicalJsonObject, ...] = Field(alias="recentListeners")
    available_command_templates: tuple[str, ...] = Field(
        alias="availableCommandTemplates"
    )

    @field_validator("guid")
    @classmethod
    def _guid_is_canonical(cls, value: str) -> str:
        return _canonical_uuid(value, label="agent guid")

    @field_validator("available_command_templates")
    @classmethod
    def _template_ids_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _canonical_uuid(value, label="command template id")
        if len(values) != len(set(values)):
            raise ValueError("command template ids are not unique")
        return values


class TuoniCommandResponseV0161(StrictImmutableBoundaryModel):
    """OpenAPI 0.16.1 CommandResponse with result kept as untrusted content."""

    id: int = Field(gt=0)
    command_template_id: str = Field(alias="commandTemplateId")
    command_template_name: str | None = Field(alias="commandTemplateName")
    configuration: CanonicalJsonObject
    exec_conf: CanonicalJsonObject = Field(alias="execConf")
    agent_guid: str = Field(alias="agentGuid")
    created: datetime
    sent: datetime | None
    send_format: Literal[
        "SHELLCODE",
        "EXEC_UNIT_SHELLCODE_NATIVE",
        "EXEC_UNIT_NATIVE_LIB",
        "EXEC_UNIT_DOTNET_DLL",
        "EXEC_UNIT_DOTNET_EXE",
        "COMMAND_CONTROL",
        "EXTERNAL",
        "NATIVE",
        "GENERIC",
    ] | None = Field(alias="sendFormat")
    sends: tuple[CanonicalJsonObject, ...]
    status: TuoniCommandStatus
    command_updates: tuple[CanonicalJsonObject, ...] = Field(alias="commandUpdates")
    result: TuoniCompositeCommandResultResponseV0161 | None

    @field_validator("command_template_id", "agent_guid")
    @classmethod
    def _ids_are_canonical(cls, value: str) -> str:
        return _canonical_uuid(value, label="Tuoni response id")


class TuoniCompositeCommandResultResponseV0161(StrictImmutableBoundaryModel):
    """Typed result envelope; individual child payloads remain untrusted JSON."""

    status: str = Field(min_length=1)
    error_message: str | None = Field(alias="errorMessage")
    received: datetime
    child_results: tuple[CanonicalJsonObject, ...] = Field(alias="childResults")


class TuoniCommandTemplateResponseV0161(StrictImmutableBoundaryModel):
    """OpenAPI 0.16.1 CommandTemplateResponse control shape."""

    id: str
    name: str = Field(min_length=1)
    plugin_id: str = Field(alias="pluginId", min_length=1)
    scope: str = Field(min_length=1)
    qualified_name: str = Field(alias="qualifiedName", min_length=1)
    fully_qualified_name: str = Field(alias="fullyQualifiedName", min_length=1)
    description: str
    status: Literal["ENABLED", "DISABLED", "ARCHIVED"]
    supported_exec_unit_types: tuple[TuoniExecUnitType, ...] = Field(
        alias="supportedExecUnitTypes"
    )
    example_configurations: tuple[CanonicalJsonObject, ...] = Field(
        alias="exampleConfigurations"
    )
    configuration_schema: CanonicalJsonObject = Field(alias="configurationSchema")
    update_schema: CanonicalJsonObject | None = Field(alias="updateSchema")
    is_user_creatable: bool = Field(alias="isUserCreatable")
    is_alias: bool = Field(alias="isAlias")

    @field_validator("id")
    @classmethod
    def _id_is_canonical(cls, value: str) -> str:
        return _canonical_uuid(value, label="command template id")


class TuoniPermissionResponseV0161(StrictImmutableBoundaryModel):
    """Permission metadata returned by the v0.16.1 discovery/user APIs."""

    label: str = Field(min_length=1, max_length=256)
    code: str = Field(pattern=_PERMISSION_CODE_PATTERN)
    description: str
    mandatory: bool


class TuoniCurrentUserResponseV0161(StrictImmutableBoundaryModel):
    """Authenticated v2 user shape used for least-privilege verification."""

    user_guid: str = Field(alias="userGuid")
    username: str = Field(min_length=1, max_length=128)
    enabled: bool
    permissions: tuple[TuoniPermissionResponseV0161, ...]
    create_event: CanonicalJsonObject = Field(alias="createEvent")
    last_update_event: CanonicalJsonObject = Field(alias="lastUpdateEvent")

    @field_validator("user_guid")
    @classmethod
    def _user_guid_is_canonical(cls, value: str) -> str:
        return _canonical_uuid(value, label="user guid")

    @field_validator("permissions")
    @classmethod
    def _permission_codes_are_unique(
        cls,
        values: tuple[TuoniPermissionResponseV0161, ...],
    ) -> tuple[TuoniPermissionResponseV0161, ...]:
        codes = [item.code for item in values]
        if len(codes) != len(set(codes)):
            raise ValueError("current user permission codes are not unique")
        return values


class TuoniServiceAccountObservation(StrictImmutableBoundaryModel):
    """Content-minimal service-account control metadata."""

    user_guid: str
    username: str
    enabled: bool
    permission_codes: frozenset[str]


class TuoniTaskObservation(StrictImmutableBoundaryModel):
    """Neutral control projection; raw command results are intentionally absent."""

    provider_task_id: str = Field(min_length=1)
    provider_session_id: str = Field(min_length=1)
    provider_status: TuoniCommandStatus
    normalized_status: TuoniNormalizedTaskStatus
    result_available: bool
    observed_at: datetime


_AGENT_LIST_ADAPTER = TypeAdapter(tuple[TuoniAgentResponseV0161, ...])
_COMMAND_TEMPLATE_LIST_ADAPTER = TypeAdapter(
    tuple[TuoniCommandTemplateResponseV0161, ...]
)
_PERMISSION_LIST_ADAPTER = TypeAdapter(tuple[TuoniPermissionResponseV0161, ...])


def _decode_model[ModelT: StrictImmutableBoundaryModel](
    model_type: type[ModelT], raw: str | bytes
) -> ModelT:
    try:
        parse_json_no_duplicate_keys(raw)
        return model_type.model_validate_json(raw)
    except (AuthorizationKernelError, ValidationError, ValueError, TypeError) as exc:
        raise C2AdapterContractError("Tuoni response violated its pinned contract") from exc


def decode_active_agents_v0161(
    raw: str | bytes, *, observed_at: datetime
) -> tuple[C2SessionObservation, ...]:
    """Decode active-agent JSON using a caller-supplied trusted observation time."""
    try:
        parse_json_no_duplicate_keys(raw)
        agents = _AGENT_LIST_ADAPTER.validate_json(raw)
        return tuple(_normalize_agent(item, observed_at=observed_at) for item in agents)
    except (AuthorizationKernelError, ValidationError, ValueError, TypeError) as exc:
        raise C2AdapterContractError("Tuoni agent response violated its pinned contract") from exc


def decode_agent_v0161(
    raw: str | bytes, *, observed_at: datetime
) -> C2SessionObservation:
    agent = _decode_model(TuoniAgentResponseV0161, raw)
    try:
        return _normalize_agent(agent, observed_at=observed_at)
    except (ValueError, TypeError) as exc:
        raise C2AdapterContractError("Tuoni agent response violated its pinned contract") from exc


def decode_command_v0161(
    raw: str | bytes, *, observed_at: datetime
) -> tuple[TuoniCommandResponseV0161, TuoniTaskObservation]:
    command = _decode_model(TuoniCommandResponseV0161, raw)
    observation = TuoniTaskObservation(
        provider_task_id=str(command.id),
        provider_session_id=command.agent_guid,
        provider_status=command.status,
        normalized_status=_TASK_STATUS_MAP[command.status],
        result_available=command.result is not None,
        observed_at=observed_at,
    )
    return command, observation


def decode_command_templates_v0161(
    raw: str | bytes, *, approved_names: tuple[str, ...]
) -> frozenset[str]:
    """Return only enabled, user-creatable templates in the approved catalog."""
    try:
        parse_json_no_duplicate_keys(raw)
        templates = _COMMAND_TEMPLATE_LIST_ADAPTER.validate_json(raw)
        ids = [item.id for item in templates]
        names = [item.name for item in templates]
        if len(ids) != len(set(ids)) or len(names) != len(set(names)):
            raise ValueError("Tuoni command template identities are not unique")
        approved = set(approved_names)
        return frozenset(
            item.name
            for item in templates
            if item.name in approved
            and item.status == "ENABLED"
            and item.is_user_creatable
        )
    except (AuthorizationKernelError, ValidationError, ValueError, TypeError) as exc:
        raise C2AdapterContractError(
            "Tuoni command template response violated its pinned contract"
        ) from exc


def decode_current_user_v0161(raw: str | bytes) -> TuoniServiceAccountObservation:
    """Strictly project the authenticated account without audit-event payloads."""

    user = _decode_model(TuoniCurrentUserResponseV0161, raw)
    return TuoniServiceAccountObservation(
        user_guid=user.user_guid,
        username=user.username,
        enabled=user.enabled,
        permission_codes=frozenset(item.code for item in user.permissions),
    )


def decode_permissions_v0161(
    raw: str | bytes,
) -> tuple[TuoniPermissionResponseV0161, ...]:
    """Decode the permission catalog and reject ambiguous duplicate codes."""

    try:
        parse_json_no_duplicate_keys(raw)
        permissions = _PERMISSION_LIST_ADAPTER.validate_json(raw)
        codes = [item.code for item in permissions]
        if len(codes) != len(set(codes)):
            raise ValueError("Tuoni permission catalog contains duplicate codes")
        return permissions
    except (AuthorizationKernelError, ValidationError, ValueError, TypeError) as exc:
        raise C2AdapterContractError(
            "Tuoni permission response violated its pinned contract"
        ) from exc


def _metadata_value(
    metadata: Mapping[str, object], key: str, expected: type[str]
) -> str | None:
    if key not in metadata:
        raise ValueError("required Tuoni metadata field is missing")
    value = metadata[key]
    if value is None:
        return None
    if type(value) is not expected:
        raise TypeError("Tuoni metadata field has the wrong type")
    return value


def _normalize_agent(
    agent: TuoniAgentResponseV0161, *, observed_at: datetime
) -> C2SessionObservation:
    metadata = cast(Mapping[str, object], agent.metadata)
    metadata_guid = _metadata_value(metadata, "guid", str)
    if metadata_guid != agent.guid:
        raise ValueError("Tuoni agent metadata identity mismatch")
    hostname = _metadata_value(metadata, "hostname", str)
    username = _metadata_value(metadata, "username", str)
    provider_os = _metadata_value(metadata, "os", str)
    provider_arch = _metadata_value(metadata, "osArch", str)
    if provider_os is not None and provider_os not in _OS_MAP:
        raise ValueError("unknown Tuoni operating system")
    if provider_arch is not None and provider_arch not in _ARCHITECTURE_MAP:
        raise ValueError("unknown Tuoni architecture")

    if agent.status == "ACTIVE" and agent.active:
        status: Literal["active", "stale", "terminated", "unknown"] = "active"
    elif agent.status == "INACTIVE" and not agent.active:
        status = "stale"
    elif agent.status == "BLOCKED" and not agent.active:
        status = "terminated"
    else:
        status = "unknown"

    return C2SessionObservation(
        provider_session_id=agent.guid,
        provider_status=status,
        host=hostname,
        os="other" if provider_os is None else _OS_MAP[provider_os],
        architecture=(
            None if provider_arch is None else _ARCHITECTURE_MAP[provider_arch]
        ),
        current_principal=username,
        # AgentResponse carries template UUIDs, not approved command names.  Do
        # not promote those opaque IDs into application capabilities.
        capabilities=frozenset(),
        observed_at=observed_at,
    )


__all__ = [
    "TuoniAgentResponseV0161",
    "TuoniAgentStatus",
    "TuoniCommandResponseV0161",
    "TuoniCommandStatus",
    "TuoniCommandTemplateResponseV0161",
    "TuoniCompositeCommandResultResponseV0161",
    "TuoniCurrentUserResponseV0161",
    "TuoniExecUnitType",
    "TuoniNormalizedTaskStatus",
    "TuoniPermissionResponseV0161",
    "TuoniServiceAccountObservation",
    "TuoniTaskObservation",
    "decode_active_agents_v0161",
    "decode_agent_v0161",
    "decode_command_templates_v0161",
    "decode_command_v0161",
    "decode_current_user_v0161",
    "decode_permissions_v0161",
]
