"""Private process-transport boundary for the pinned Tuoni adapter.

The wire request contains no endpoint, credential, JWT, proxy, redirect, or
DNS option.  Those choices belong to the composition-owned transport and are
bound by an immutable attestation before :class:`TuoniAdapter` can be built.
The concrete Ubuntu one-shot process transport is implemented separately so
this module remains free of subprocess, credential-file, and network details.
Unit and integration tests can use an in-memory implementation of this exact
protocol without contacting a provider.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, NoReturn, Protocol

from pydantic import Field, field_validator

from redteam_agent.adapters.tuoni_contract import TuoniWireRequest
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CONTAINER_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"


class TuoniTransportAttestation(StrictImmutableBoundaryModel):
    """Deployment identity consumed only by the trusted adapter composition."""

    channel_type: Literal["process_isolated_https_loopback"] = (
        "process_isolated_https_loopback"
    )
    control_vm_operating_system: Literal["ubuntu_24_04_lts"] = "ubuntu_24_04_lts"
    control_vm_architecture: Literal["x86_64"] = "x86_64"
    adapter_placement: Literal["same_control_vm_loopback"] = (
        "same_control_vm_loopback"
    )
    adapter_profile_digest: str = Field(pattern=_SHA256_PATTERN)
    contract_digest: str = Field(pattern=_SHA256_PATTERN)
    server_version: str = Field(min_length=1)
    openapi_sha256: str = Field(pattern=_SHA256_PATTERN)
    container_image_digest: str = Field(pattern=_CONTAINER_DIGEST_PATTERN)
    source_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    api_origin: Literal["https://127.0.0.1:8443"] = "https://127.0.0.1:8443"
    tls_certificate_sha256: str = Field(pattern=_SHA256_PATTERN)
    credential_secret_version_id: str = Field(
        min_length=1,
        max_length=512,
        pattern=r"^[\x21-\x7e]+$",
    )
    credential_delivery: Literal["systemd_load_credential_encrypted"] = (
        "systemd_load_credential_encrypted"
    )
    vcenter_port_group_name: str = Field(min_length=1, max_length=256)
    process_isolated: Literal[True] = True
    redirects_disabled: Literal[True] = True
    proxy_disabled: Literal[True] = True
    dns_resolution_disabled: Literal[True] = True
    server_identity_verified: Literal[True] = True
    vcenter_isolation_verified: Literal[True] = True
    attested_at: datetime
    attestation_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "server_version", "credential_secret_version_id", "vcenter_port_group_name"
    )
    @classmethod
    def _nonblank_canonical_text(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("transport attestation text must be canonical")
        return value

    @field_validator("attested_at")
    @classmethod
    def _attested_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("transport attestation time must be timezone-aware")
        return value


def finalize_tuoni_transport_attestation(
    attestation: TuoniTransportAttestation, digest_service: DigestService
) -> TuoniTransportAttestation:
    payload = attestation.model_dump(mode="python")
    payload["attestation_digest"] = "pending"
    digest = digest_service.compute("tuoni_transport_attestation_digest", payload)
    return attestation.model_copy(update={"attestation_digest": digest})


class TuoniTransportResponse:
    """Ephemeral response envelope whose body is redacted from repr/serialization."""

    __slots__ = ("_body", "_content_type", "_status_code")

    def __init__(self, *, status_code: int, content_type: str, body: bytes) -> None:
        if status_code < 100 or status_code > 599:
            raise ValueError("transport response status is invalid")
        if (
            not content_type
            or len(content_type) > 256
            or content_type != content_type.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in content_type)
        ):
            raise ValueError("transport response content type is invalid")
        if type(body) is not bytes:
            raise TypeError("transport response body must be bytes")
        self._status_code = status_code
        self._content_type = content_type
        self._body = body

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def content_type(self) -> str:
        return self._content_type

    @property
    def body(self) -> bytes:
        return self._body

    def __repr__(self) -> str:
        return (
            "<TuoniTransportResponse "
            f"status={self._status_code} content_type={self._content_type!r} body=<redacted>>"
        )

    def __reduce__(self) -> NoReturn:
        raise TypeError("TuoniTransportResponse is not serializable")


class TuoniTransport(Protocol):
    """Composition-owned fixed transport; callers cannot select a destination."""

    @property
    def attestation(self) -> TuoniTransportAttestation: ...

    def request(
        self,
        request: TuoniWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> TuoniTransportResponse: ...


__all__ = [
    "TuoniTransport",
    "TuoniTransportAttestation",
    "TuoniTransportResponse",
    "finalize_tuoni_transport_attestation",
]
