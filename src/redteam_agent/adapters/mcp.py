"""Pinned MCP 2026-07-28 configuration and fail-closed foundation.

The production server is intentionally unresolved.  This module fixes the
protocol and trust semantics that can be established offline while keeping all
provider operations unavailable until a server, transport identity, sandbox,
and live discovery evidence are approved.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal, NoReturn, Protocol
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MCPAdapterUnavailableError
from redteam_agent.execution.adapter import (
    AdapterIdentity,
    CancelOutcome,
    ExecutionAdapter,
    ExecutionRequest,
    ReconciliationResult,
    TaskHandle,
)
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.models import (
    AdapterCollectionControl,
    CollectionCancellation,
    CollectionResumeCursor,
    ResultTaskBinding,
)
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import RawResultSink
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.target_binding import TargetBindingMode

MCP_PROTOCOL_REVISION: Literal["2026-07-28"] = "2026-07-28"
MCP_SPEC_COMMIT: Literal[
    "5f5440bb26a62e2cf3440b92da5a667efa03b267"
] = "5f5440bb26a62e2cf3440b92da5a667efa03b267"
MCP_SCHEMA_SHA256: Literal[
    "ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203"
] = "ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203"
MCP_CLIENT_NAME = "redteam-agent"
MCP_CLIENT_VERSION = "phase5-offline-v1"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTITY_VALUE_PATTERN = r"^[\x20-\x7e]{1,2048}$"
_SERVER_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_REVISION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"
_STDIO_IDENTITY_TYPES = frozenset(
    {
        "executable_path",
        "executable_sha256",
        "command_configuration_digest",
        "package_version",
    }
)
_REMOTE_IDENTITY_TYPES = frozenset(
    {
        "configured_url",
        "tls_certificate_sha256",
        "spki_sha256",
        "oauth_resource",
        "mtls_peer_sha256",
    }
)
_REMOTE_PROOF_TYPES = frozenset(
    {
        "tls_certificate_sha256",
        "spki_sha256",
        "mtls_peer_sha256",
    }
)

type MCPTransportType = Literal["stdio", "streamable_http"]
type MCPExecutionLocation = Literal[
    "local_process", "managed_remote", "untrusted_remote"
]
type MCPTransportIdentityType = Literal[
    "executable_path",
    "executable_sha256",
    "command_configuration_digest",
    "package_version",
    "configured_url",
    "tls_certificate_sha256",
    "spki_sha256",
    "oauth_resource",
    "mtls_peer_sha256",
]


class MCPServerCapabilities(StrictImmutableBoundaryModel):
    tools: bool
    tools_list_changed_subscription: bool
    cancellation: bool
    task_extension: bool
    reconciliation: bool


class MCPTransportIdentity(StrictImmutableBoundaryModel):
    transport_type: MCPTransportType
    identity_type: MCPTransportIdentityType
    identity_value: str = Field(pattern=_IDENTITY_VALUE_PATTERN)

    @model_validator(mode="after")
    def _identity_matches_transport(self) -> MCPTransportIdentity:
        allowed = (
            _STDIO_IDENTITY_TYPES
            if self.transport_type == "stdio"
            else _REMOTE_IDENTITY_TYPES
        )
        if self.identity_type not in allowed:
            raise ValueError("MCP identity type is invalid for the transport")
        if self.identity_value != self.identity_value.strip():
            raise ValueError("MCP transport identity must be canonical")
        if self.identity_type in {
            "executable_sha256",
            "command_configuration_digest",
            "tls_certificate_sha256",
            "spki_sha256",
            "mtls_peer_sha256",
        } and re.fullmatch(_SHA256_PATTERN, self.identity_value) is None:
            raise ValueError("MCP digest transport identity is invalid")
        if self.identity_type == "executable_path":
            path = PurePosixPath(self.identity_value)
            if (
                not path.is_absolute()
                or ".." in path.parts
                or str(path) != self.identity_value
            ):
                raise ValueError("MCP executable path must be absolute and canonical")
        if self.identity_type == "configured_url":
            parsed = urlsplit(self.identity_value)
            if (
                parsed.scheme != "https"
                or parsed.hostname is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError("remote MCP URL must be an HTTPS origin/path")
        return self


class RemoteMCPEnforcementCapabilities(StrictImmutableBoundaryModel):
    scope_enforcement: bool
    authentication_authorization: bool
    audit: bool
    network_egress_enforcement: bool
    sandbox_process_isolation: bool
    stable_transport_identity: bool

    def complete(self) -> bool:
        return all(self.model_dump(mode="python").values())


class MCPTrustPolicy(StrictImmutableBoundaryModel):
    adapter_id: str = Field(pattern=_SERVER_ID_PATTERN)
    execution_location: MCPExecutionLocation
    allow_state_change: bool = False
    allow_destructive: bool = False
    allow_high_risk: bool = False
    allow_secret_resolution: bool = False
    remote_enforcement: RemoteMCPEnforcementCapabilities | None = None

    @model_validator(mode="after")
    def _trust_is_fail_closed(self) -> MCPTrustPolicy:
        unsafe_allowed = any(
            (
                self.allow_state_change,
                self.allow_destructive,
                self.allow_high_risk,
                self.allow_secret_resolution,
            )
        )
        if self.execution_location == "local_process":
            if self.remote_enforcement is not None:
                raise ValueError("local MCP must not claim remote enforcement")
        elif self.execution_location == "untrusted_remote":
            if unsafe_allowed:
                raise ValueError("untrusted remote MCP cannot enable unsafe operations")
            if self.remote_enforcement is not None:
                raise ValueError("untrusted remote MCP cannot self-attest enforcement")
        elif unsafe_allowed and (
            self.remote_enforcement is None or not self.remote_enforcement.complete()
        ):
            raise ValueError("managed remote unsafe operations require full enforcement")
        return self


def compute_mcp_trust_policy_digest(
    policies: tuple[MCPTrustPolicy, ...], digest_service: DigestService
) -> str:
    ordered = sorted(policies, key=lambda item: item.adapter_id)
    if len({item.adapter_id for item in ordered}) != len(ordered):
        raise ValueError("MCP trust policy adapter IDs must be unique")
    return digest_service.compute(
        "remote_mcp_trust_policy_digest",
        {"policies": [item.model_dump(mode="python") for item in ordered]},
    )


class MCPServerConfig(StrictImmutableBoundaryModel):
    server_id: str = Field(pattern=_SERVER_ID_PATTERN)
    expected_server_name: str = Field(min_length=1, max_length=256)
    expected_server_version: str = Field(min_length=1, max_length=128)
    protocol_revision: Literal["2026-07-28"] = MCP_PROTOCOL_REVISION
    transport: MCPTransportType
    execution_location: MCPExecutionLocation
    configured_transport_identities: tuple[MCPTransportIdentity, ...]
    tool_list_revision: str = Field(pattern=_REVISION_PATTERN)
    required_capabilities: MCPServerCapabilities
    target_binding_modes: frozenset[TargetBindingMode] = frozenset({"none"})
    secret_delivery_mode: Literal["disabled", "ephemeral_meta_v1"] = "disabled"  # noqa: S105
    task_extension_id: str | None = Field(default=None, max_length=256)
    task_extension_version: str | None = Field(default=None, max_length=128)
    task_implementation_mode: Literal["native", "custom", "disabled"] = "disabled"
    client_task_capability_digest: str | None = Field(
        default=None, pattern=_SHA256_PATTERN
    )
    config_digest: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _configuration_is_complete(self) -> MCPServerConfig:
        if (self.execution_location == "local_process") != (
            self.transport == "stdio"
        ):
            raise ValueError("local MCP must use stdio and remote MCP must use HTTP")
        if any(
            item.transport_type != self.transport
            for item in self.configured_transport_identities
        ):
            raise ValueError("MCP transport identity type does not match configuration")
        types = {item.identity_type for item in self.configured_transport_identities}
        if len(types) != len(self.configured_transport_identities):
            raise ValueError("MCP transport identity types must be unique")
        if self.transport == "stdio":
            if types != _STDIO_IDENTITY_TYPES:
                raise ValueError("stdio MCP requires the complete executable identity set")
        elif "configured_url" not in types or not types.intersection(
            _REMOTE_PROOF_TYPES
        ):
            raise ValueError("remote MCP requires URL and cryptographic identity")
        if not self.target_binding_modes:
            raise ValueError("MCP target binding modes must not be empty")
        if "none" in self.target_binding_modes and len(self.target_binding_modes) != 1:
            raise ValueError("MCP none target binding cannot be combined with enforcement")
        if (
            self.secret_delivery_mode == "ephemeral_meta_v1"  # noqa: S105
            and self.execution_location != "local_process"
        ):
            raise ValueError("ephemeral MCP secrets are restricted to a local process")
        tasks_configured = self.task_implementation_mode != "disabled"
        if tasks_configured != self.required_capabilities.task_extension:
            raise ValueError("MCP task mode and required capability disagree")
        if tasks_configured:
            if not all(
                (
                    self.task_extension_id,
                    self.task_extension_version,
                    self.client_task_capability_digest,
                )
            ):
                raise ValueError("enabled MCP tasks require extension and client evidence")
        elif any(
            (
                self.task_extension_id,
                self.task_extension_version,
                self.client_task_capability_digest,
                self.required_capabilities.reconciliation,
            )
        ):
            raise ValueError("disabled MCP tasks cannot expose task capability")
        return self


def finalize_mcp_server_config(
    config: MCPServerConfig, digest_service: DigestService
) -> MCPServerConfig:
    payload = config.model_dump(mode="python")
    payload["config_digest"] = "0" * 64
    digest = digest_service.compute("mcp_server_config_digest", payload)
    return config.model_copy(update={"config_digest": digest})


class MCPFoundationProfile(StrictImmutableBoundaryModel):
    adapter_id: str = Field(default="mcp-primary", pattern=_SERVER_ID_PATTERN)
    provider_product: str | None = Field(default=None, max_length=256)
    server_config: MCPServerConfig | None = None
    trust_policy: MCPTrustPolicy | None = None
    profile_digest: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _bindings_agree(self) -> MCPFoundationProfile:
        if self.trust_policy is not None and self.trust_policy.adapter_id != self.adapter_id:
            raise ValueError("MCP trust policy is bound to another adapter")
        if (
            self.trust_policy is not None
            and self.server_config is not None
            and self.trust_policy.execution_location
            != self.server_config.execution_location
        ):
            raise ValueError("MCP trust policy execution location mismatch")
        return self

    def configuration_blockers(self) -> tuple[str, ...]:
        blockers: list[str] = []
        if self.provider_product is None:
            blockers.append("mcp_server_product_unresolved")
        if self.server_config is None:
            blockers.append("mcp_server_config_unresolved")
        if self.trust_policy is None:
            blockers.append("mcp_trust_policy_unresolved")
        return tuple(blockers)


def build_mcp_foundation_profile(
    *,
    digest_service: DigestService,
    adapter_id: str = "mcp-primary",
    provider_product: str | None = None,
    server_config: MCPServerConfig | None = None,
    trust_policy: MCPTrustPolicy | None = None,
) -> MCPFoundationProfile:
    if provider_product is not None and (
        not provider_product.strip() or provider_product != provider_product.strip()
    ):
        raise ValueError("MCP provider product must be canonical")
    if server_config is not None:
        digest_service.verify(
            "mcp_server_config_digest",
            server_config.model_dump(mode="python"),
            server_config.config_digest,
        )
    fields = {
        "adapter_id": adapter_id,
        "provider_product": provider_product,
        "server_config": (
            None if server_config is None else server_config.model_dump(mode="python")
        ),
        "trust_policy": (
            None if trust_policy is None else trust_policy.model_dump(mode="python")
        ),
    }
    digest = digest_service.compute("mcp_provider_profile_digest", fields)
    return MCPFoundationProfile(
        adapter_id=adapter_id,
        provider_product=provider_product,
        server_config=server_config,
        trust_policy=trust_policy,
        profile_digest=digest,
    )


class MCPLogicalServerInfo(StrictImmutableBoundaryModel):
    server_name: str = Field(min_length=1, max_length=256)
    server_version: str = Field(min_length=1, max_length=128)
    server_info_digest: str = Field(pattern=_SHA256_PATTERN)


class MCPDiscoverResult(StrictImmutableBoundaryModel):
    discover_result_id: str = Field(min_length=1)
    server_id: str = Field(pattern=_SERVER_ID_PATTERN)
    logical_server_info: MCPLogicalServerInfo
    verified_transport_identities: tuple[MCPTransportIdentity, ...]
    reported_protocol_revision: Literal["2026-07-28"] = MCP_PROTOCOL_REVISION
    transport: MCPTransportType
    reported_capabilities: MCPServerCapabilities
    remote_enforcement_capabilities: RemoteMCPEnforcementCapabilities | None
    tool_list_revision: str = Field(min_length=1)
    task_extension_id: str | None
    task_extension_version: str | None
    task_implementation_mode: Literal["native", "custom", "disabled"]
    client_sdk_name: Literal["redteam-agent-low-level"] = "redteam-agent-low-level"
    client_sdk_version: Literal["phase5-offline-v1"] = "phase5-offline-v1"
    discover_digest: str = Field(pattern=_SHA256_PATTERN)
    verified_at: datetime


class MCPAdapterProtocol(ExecutionAdapter, Protocol):
    def get_capabilities(self) -> AdapterCapabilities: ...

    def discover(self) -> MCPDiscoverResult: ...


class MCPAdapterFoundation:
    """Non-operational MCP placeholder used until a live provider is approved."""

    def __init__(
        self, profile: MCPFoundationProfile, digest_service: DigestService
    ) -> None:
        payload = profile.model_dump(mode="python")
        expected = str(payload.pop("profile_digest"))
        digest_service.verify("mcp_provider_profile_digest", payload, expected)
        self._profile = profile

    @property
    def profile(self) -> MCPFoundationProfile:
        return self._profile

    def activation_blockers(self) -> tuple[str, ...]:
        return (
            *self._profile.configuration_blockers(),
            "mcp_transport_unconfigured",
            "mcp_sandbox_attestation_unverified",
            "mcp_live_discovery_unverified",
            "mcp_approved_tool_catalog_empty",
        )

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id=self._profile.adapter_id,
            adapter_identity_digest=self._profile.profile_digest,
            provider_identity_digest="mcp-provider-unresolved",
            result_delivery_mode="local_result",
        )

    @staticmethod
    def _unavailable() -> NoReturn:
        raise MCPAdapterUnavailableError(
            "MCP adapter is unavailable until provider, transport, sandbox, and "
            "live discovery identities are approved"
        )

    def get_capabilities(self) -> AdapterCapabilities:
        self._unavailable()

    def discover(self) -> MCPDiscoverResult:
        self._unavailable()

    def submit(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle:
        del request, secret_bindings, result_capture, idempotency_key
        self._unavailable()

    def reconcile(
        self, execution_id: str, task_binding: ResultTaskBinding | None
    ) -> ReconciliationResult:
        del execution_id, task_binding
        self._unavailable()

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome:
        del execution_id, provider_task_id
        self._unavailable()

    def collect_result(
        self,
        execution_id: str,
        task_binding: ResultTaskBinding,
        sink: RawResultSink,
        resume: CollectionResumeCursor | None = None,
        cancellation: CollectionCancellation | None = None,
    ) -> AdapterCollectionControl:
        del execution_id, task_binding, sink, resume, cancellation
        self._unavailable()

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl:
        del execution_id, task_binding
        self._unavailable()


__all__ = [
    "MCP_CLIENT_NAME",
    "MCP_CLIENT_VERSION",
    "MCP_PROTOCOL_REVISION",
    "MCP_SCHEMA_SHA256",
    "MCP_SPEC_COMMIT",
    "MCPAdapterFoundation",
    "MCPAdapterProtocol",
    "MCPDiscoverResult",
    "MCPExecutionLocation",
    "MCPFoundationProfile",
    "MCPLogicalServerInfo",
    "MCPServerCapabilities",
    "MCPServerConfig",
    "MCPTransportIdentity",
    "MCPTransportIdentityType",
    "MCPTransportType",
    "MCPTrustPolicy",
    "RemoteMCPEnforcementCapabilities",
    "build_mcp_foundation_profile",
    "compute_mcp_trust_policy_digest",
    "finalize_mcp_server_config",
]
