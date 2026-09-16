"""Private, bounded transport boundary for the pinned MCP adapter."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, NoReturn, Protocol

from pydantic import Field, model_validator

from redteam_agent.adapters.mcp import (
    MCPExecutionLocation,
    MCPTransportIdentity,
    MCPTransportType,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class MCPTransportAttestation(StrictImmutableBoundaryModel):
    evidence_kind: Literal["test_server", "live"]
    production_eligible: bool
    adapter_profile_digest: str = Field(pattern=_SHA256_PATTERN)
    server_config_digest: str = Field(pattern=_SHA256_PATTERN)
    contract_digest: str = Field(pattern=_SHA256_PATTERN)
    server_id: str = Field(min_length=1)
    protocol_revision: Literal["2026-07-28"] = "2026-07-28"
    transport: MCPTransportType
    execution_location: MCPExecutionLocation
    verified_transport_identities: tuple[MCPTransportIdentity, ...]
    sandbox_verified: bool
    redirects_disabled: bool
    attested_at: datetime
    attestation_digest: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def _provenance_is_not_promotable(self) -> MCPTransportAttestation:
        if self.evidence_kind == "test_server" and self.production_eligible:
            raise ValueError("MCP test-server evidence cannot authorize production")
        if self.evidence_kind == "live" and not self.production_eligible:
            raise ValueError("live MCP attestation must state its eligibility")
        if any(
            item.transport_type != self.transport
            for item in self.verified_transport_identities
        ):
            raise ValueError("MCP attested identities use the wrong transport")
        if not self.redirects_disabled:
            raise ValueError("MCP transport must disable automatic redirects")
        if self.attested_at.tzinfo is None:
            raise ValueError("MCP attestation time must be timezone-aware")
        return self


def finalize_mcp_transport_attestation(
    attestation: MCPTransportAttestation, digest_service: DigestService
) -> MCPTransportAttestation:
    digest = digest_service.compute(
        "mcp_transport_attestation_digest",
        attestation.model_dump(mode="python"),
    )
    return attestation.model_copy(update={"attestation_digest": digest})


class MCPTransportResponse:
    """Ephemeral JSON-RPC response with content hidden from diagnostics."""

    __slots__ = ("_body",)

    def __init__(self, body: bytes) -> None:
        if type(body) is not bytes:
            raise TypeError("MCP response body must be bytes")
        self._body = body

    @property
    def body(self) -> bytes:
        return self._body

    def __repr__(self) -> str:
        return "<MCPTransportResponse body=<redacted>>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("MCPTransportResponse is not serializable")


class MCPTransport(Protocol):
    @property
    def attestation(self) -> MCPTransportAttestation: ...

    def request(
        self,
        request: bytes,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> MCPTransportResponse: ...


__all__ = [
    "MCPTransport",
    "MCPTransportAttestation",
    "MCPTransportResponse",
    "finalize_mcp_transport_attestation",
]
