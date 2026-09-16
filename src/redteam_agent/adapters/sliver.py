"""Fail-closed foundation for the pinned Sliver C2 provider.

The foundation records the approved HTTP implant transport and the exact
upstream release without reading an operator configuration or opening a
network connection.  The operator configuration contains long-lived mTLS and
bearer credentials and therefore remains a secret reference owned by the
trusted deployment composition.
"""

from __future__ import annotations

from typing import Literal, NoReturn

from pydantic import Field, model_validator

from redteam_agent.adapters.c2 import C2SessionObservation
from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.execution.adapter import (
    AdapterIdentity,
    CancelOutcome,
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

SLIVER_VERSION_PIN = "1.7.3"
SLIVER_SOURCE_TAG_PIN = "v1.7.3"
SLIVER_SOURCE_COMMIT_PIN = "3bbaf805104dcc4a75414ee0084e8de50702cad4"
SLIVER_OPERATOR_NAME: Literal["joe"] = "joe"
SLIVER_OPERATOR_CONFIG_LOCATION_HINT: Literal["downloads"] = "downloads"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"


class SliverProviderPin(StrictImmutableBoundaryModel):
    product: Literal["sliver"] = "sliver"
    version: Literal["1.7.3"] = "1.7.3"
    source_tag: Literal["v1.7.3"] = "v1.7.3"
    source_commit: str = Field(
        default=SLIVER_SOURCE_COMMIT_PIN, pattern=_GIT_COMMIT_PATTERN
    )


class SliverConnectionPolicy(StrictImmutableBoundaryModel):
    operator_channel: Literal["grpc_mtls_direct"] = "grpc_mtls_direct"
    operator_name: Literal["joe"] = SLIVER_OPERATOR_NAME
    operator_config_location_hint: Literal["downloads"] = (
        SLIVER_OPERATOR_CONFIG_LOCATION_HINT
    )
    operator_config_secret_version_id: str | None = Field(
        default=None, max_length=512, pattern=r"^[\x21-\x7e]+$"
    )
    operator_config_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    server_address: str | None = Field(default=None, max_length=255)
    server_port: int | None = Field(default=None, ge=1, le=65535)
    server_tls_name: str | None = Field(default=None, max_length=255)
    ca_certificate_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    operator_certificate_sha256: str | None = Field(
        default=None, pattern=_SHA256_PATTERN
    )
    redirects_allowed: Literal[False] = False
    proxy_allowed: Literal[False] = False

    @model_validator(mode="after")
    def _complete_server_tuple(self) -> SliverConnectionPolicy:
        values = (self.server_address, self.server_port, self.server_tls_name)
        if any(value is not None for value in values) and not all(
            value is not None for value in values
        ):
            raise ValueError("Sliver server address, port, and TLS name are atomic")
        for value in (self.server_address, self.server_tls_name):
            if value is not None and (
                value != value.strip()
                or not value
                or any(character in value for character in "/@:#")
            ):
                raise ValueError("Sliver server identity must be canonical")
        return self


class SliverTargetPolicy(StrictImmutableBoundaryModel):
    target_operating_system: Literal["windows"] = "windows"
    target_architecture: Literal["x86_64"] = "x86_64"
    implant_transport: Literal["http"] = "http"
    existing_beacon_required_for_activation: Literal[True] = True
    listener_management_allowed: Literal[False] = False
    implant_generation_allowed: Literal[False] = False
    arbitrary_command_allowed: Literal[False] = False
    upload_allowed: Literal[False] = False
    injection_allowed: Literal[False] = False
    port_forward_allowed: Literal[False] = False


class SliverFoundationProfile(StrictImmutableBoundaryModel):
    adapter_id: Literal["sliver-c2"] = "sliver-c2"
    provider: SliverProviderPin
    connection: SliverConnectionPolicy
    target: SliverTargetPolicy
    profile_digest: str = Field(pattern=_SHA256_PATTERN)

    def configuration_blockers(self) -> tuple[str, ...]:
        blockers: list[str] = []
        connection = self.connection
        if connection.operator_config_secret_version_id is None:
            blockers.append("operator_config_secret_reference_unresolved")
        if connection.operator_config_sha256 is None:
            blockers.append("operator_config_digest_unresolved")
        if connection.server_address is None:
            blockers.append("operator_server_endpoint_unresolved")
        if connection.ca_certificate_sha256 is None:
            blockers.append("operator_ca_certificate_unresolved")
        if connection.operator_certificate_sha256 is None:
            blockers.append("operator_certificate_unresolved")
        return tuple(blockers)


def build_sliver_foundation_profile(
    *,
    digest_service: DigestService,
    provider: SliverProviderPin | None = None,
    connection: SliverConnectionPolicy | None = None,
    target: SliverTargetPolicy | None = None,
) -> SliverFoundationProfile:
    provider_value = provider or SliverProviderPin()
    connection_value = connection or SliverConnectionPolicy()
    target_value = target or SliverTargetPolicy()
    payload = {
        "adapter_id": "sliver-c2",
        "provider": provider_value.model_dump(mode="python"),
        "connection": connection_value.model_dump(mode="python"),
        "target": target_value.model_dump(mode="python"),
    }
    digest = digest_service.compute("sliver_provider_profile_digest", payload)
    return SliverFoundationProfile(**payload, profile_digest=digest)  # type: ignore[arg-type]


class SliverAdapterFoundation:
    """Provider-neutral placeholder that never reads credentials or connects."""

    def __init__(
        self, profile: SliverFoundationProfile, digest_service: DigestService
    ) -> None:
        payload = profile.model_dump(mode="python")
        expected = str(payload.pop("profile_digest"))
        digest_service.verify("sliver_provider_profile_digest", payload, expected)
        self._profile = profile

    @property
    def profile(self) -> SliverFoundationProfile:
        return self._profile

    def activation_blockers(self) -> tuple[str, ...]:
        return (
            *self._profile.configuration_blockers(),
            "grpc_mtls_transport_unconfigured",
            "live_provider_attestation_unverified",
            "http_beacon_unavailable",
        )

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id="sliver-c2",
            adapter_identity_digest=self._profile.profile_digest,
            provider_identity_digest="sliver-provider-unresolved",
            result_delivery_mode="provider_task",
        )

    def _unavailable(self) -> NoReturn:
        raise C2AdapterUnavailableError(
            "Sliver adapter is unavailable until the operator config, direct gRPC/mTLS "
            "transport, live provider attestation, and HTTP Beacon are verified"
        )

    def get_capabilities(self) -> AdapterCapabilities:
        self._unavailable()

    def list_sessions(self) -> tuple[C2SessionObservation, ...]:
        self._unavailable()

    def get_session(self, provider_session_id: str) -> C2SessionObservation:
        del provider_session_id
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
    "SLIVER_OPERATOR_CONFIG_LOCATION_HINT",
    "SLIVER_OPERATOR_NAME",
    "SLIVER_SOURCE_COMMIT_PIN",
    "SLIVER_SOURCE_TAG_PIN",
    "SLIVER_VERSION_PIN",
    "SliverAdapterFoundation",
    "SliverConnectionPolicy",
    "SliverFoundationProfile",
    "SliverProviderPin",
    "SliverTargetPolicy",
    "build_sliver_foundation_profile",
]
