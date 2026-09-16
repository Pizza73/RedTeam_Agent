"""Private transport boundary for the pinned Sliver RPC allowlist."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, NoReturn, Protocol

from pydantic import Field, field_validator

from redteam_agent.adapters.sliver_contract import SliverWireRequest
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class SliverTransportAttestation(StrictImmutableBoundaryModel):
    evidence_kind: Literal["test_double", "live"]
    production_eligible: bool
    channel_type: Literal["grpc_mtls_direct"] = "grpc_mtls_direct"
    adapter_profile_digest: str = Field(pattern=_SHA256_PATTERN)
    contract_digest: str = Field(pattern=_SHA256_PATTERN)
    provider_version: Literal["1.7.3"] = "1.7.3"
    provider_source_commit: Literal[
        "3bbaf805104dcc4a75414ee0084e8de50702cad4"
    ] = "3bbaf805104dcc4a75414ee0084e8de50702cad4"
    operator_name: Literal["joe"] = "joe"
    operator_config_secret_version_id: str = Field(min_length=1, max_length=512)
    operator_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    server_address: str = Field(min_length=1, max_length=255)
    server_port: int = Field(ge=1, le=65535)
    server_tls_name: str = Field(min_length=1, max_length=255)
    ca_certificate_sha256: str = Field(pattern=_SHA256_PATTERN)
    operator_certificate_sha256: str = Field(pattern=_SHA256_PATTERN)
    implant_transport: Literal["http"] = "http"
    server_identity_verified: bool
    operator_identity_verified: bool
    http_beacon_verified: bool
    attested_at: datetime
    attestation_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("attested_at")
    @classmethod
    def _time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Sliver attestation time must be timezone-aware")
        return value

    @field_validator("server_address", "server_tls_name")
    @classmethod
    def _server_text_is_canonical(cls, value: str) -> str:
        if value != value.strip() or any(character in value for character in "/@:#"):
            raise ValueError("Sliver server identity must be canonical")
        return value

    def model_post_init(self, __context: object) -> None:
        del __context
        if self.evidence_kind == "test_double" and self.production_eligible:
            raise ValueError("Sliver test-double evidence cannot authorize production")
        if self.production_eligible and not all(
            (
                self.server_identity_verified,
                self.operator_identity_verified,
                self.http_beacon_verified,
            )
        ):
            raise ValueError("Sliver production evidence must verify every live identity")


def finalize_sliver_transport_attestation(
    attestation: SliverTransportAttestation, digest_service: DigestService
) -> SliverTransportAttestation:
    digest = digest_service.compute(
        "sliver_transport_attestation_digest",
        attestation.model_dump(mode="python"),
    )
    return attestation.model_copy(update={"attestation_digest": digest})


class SliverTransportResponse:
    """Ephemeral normalized RPC response hidden from diagnostics."""

    __slots__ = ("_body",)

    def __init__(self, body: bytes) -> None:
        if type(body) is not bytes:
            raise TypeError("Sliver response body must be bytes")
        self._body = body

    @property
    def body(self) -> bytes:
        return self._body

    def __repr__(self) -> str:
        return "<SliverTransportResponse body=<redacted>>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("SliverTransportResponse is not serializable")


class SliverTransport(Protocol):
    """Transport converts the closed request into the pinned protobuf RPC."""

    @property
    def attestation(self) -> SliverTransportAttestation: ...

    def request(
        self,
        request: SliverWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> SliverTransportResponse: ...


__all__ = [
    "SliverTransport",
    "SliverTransportAttestation",
    "SliverTransportResponse",
    "finalize_sliver_transport_attestation",
]
