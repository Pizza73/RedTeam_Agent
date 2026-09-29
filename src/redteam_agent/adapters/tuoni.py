"""Version-pinned, non-networking Tuoni C2 adapter foundation.

This module records the approved lab boundary and the immutable Tuoni 0.16.1
artifact identities that can be established without Control VM access.
``TuoniAdapterFoundation`` structurally implements the C2 adapter surface, but
every provider operation fails before transport or secret access.  It remains
unavailable until the deployment-specific identities are captured and the
authenticated, process-isolated transport is qualified in the isolated lab.
"""

from __future__ import annotations

from typing import Literal, NoReturn
from urllib.parse import urlsplit

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

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CONTAINER_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"

TUONI_VERSION_PIN = "0.16.1"
TUONI_SOURCE_COMMIT_PIN = "7d9a2057b309481c530f7c7a71b4ad2f8c5a615e"
# The OpenAPI document is served by the installed Tuoni server at /docs/api;
# it is not published in the source release.  Never substitute a synthetic
# digest for the deployment artifact that must be captured during activation.
TUONI_OPENAPI_SHA256_PIN: None = None
TUONI_SERVER_IMAGE_DIGEST_PIN = (
    "sha256:e1e24a1f0fcee7ce8728f1d7fd0790da116651505c6ad88afe58daf1067d6e95"
)


class TuoniProviderPin(StrictImmutableBoundaryModel):
    """Immutable provider identity inputs; ``None`` means explicitly unresolved."""

    product: Literal["tuoni"] = "tuoni"
    edition: Literal["commercial"] = "commercial"
    server_version: str | None = None
    openapi_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    container_image_digest: str | None = Field(
        default=None, pattern=_CONTAINER_DIGEST_PATTERN
    )
    source_commit: str | None = Field(default=None, pattern=_GIT_COMMIT_PATTERN)

    @model_validator(mode="after")
    def _immutable_artifact_identity(self) -> TuoniProviderPin:
        if self.server_version is not None and not self.server_version.strip():
            raise ValueError("server_version must be non-empty when present")
        for label, value in (
            ("container_image_digest", self.container_image_digest),
            ("source_commit", self.source_commit),
        ):
            if value is not None and not value.strip():
                raise ValueError(f"{label} must be non-empty when present")
        return self


class TuoniLabIsolationPolicy(StrictImmutableBoundaryModel):
    topology: Literal["colocated_control_vm_disposable_target"] = (
        "colocated_control_vm_disposable_target"
    )
    control_vm_operating_system: Literal["ubuntu_24_04_lts"] = "ubuntu_24_04_lts"
    control_vm_architecture: Literal["x86_64"] = "x86_64"
    adapter_placement: Literal["same_control_vm_loopback"] = (
        "same_control_vm_loopback"
    )
    vcenter_isolated_port_group: Literal[True] = True
    vcenter_port_group_name: str | None = Field(default=None, max_length=256)
    physical_uplink_allowed: Literal[False] = False
    default_gateway_allowed: Literal[False] = False
    internet_egress_allowed: Literal[False] = False
    corporate_lan_egress_allowed: Literal[False] = False
    disposable_target_required: Literal[True] = True
    validation_target_operating_systems: tuple[
        Literal["windows_server"], Literal["windows_11"]
    ] = ("windows_server", "windows_11")
    target_implementation_owner: Literal["external_to_project"] = "external_to_project"
    tuoni_agent_provisioning: Literal["manually_preinstalled"] = "manually_preinstalled"
    target_listener_protocol: Literal["https"] = "https"
    target_listener_port: Literal[8444] = 8444

    @model_validator(mode="after")
    def _port_group_name_if_present(self) -> TuoniLabIsolationPolicy:
        name = self.vcenter_port_group_name
        if name is not None and not name.strip():
            raise ValueError("vcenter_port_group_name must be non-empty when present")
        return self


class TuoniConnectionPolicy(StrictImmutableBoundaryModel):
    api_origin: str = "https://127.0.0.1:8443"
    tls_certificate_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    redirects_allowed: Literal[False] = False
    proxy_allowed: Literal[False] = False
    dns_resolution_allowed: Literal[False] = False

    @model_validator(mode="after")
    def _approved_loopback_origin_only(self) -> TuoniConnectionPolicy:
        parsed = urlsplit(self.api_origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "127.0.0.1"
            or parsed.port != 8443
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Tuoni API origin must be the approved HTTPS loopback endpoint")
        return self


class TuoniAuthenticationPolicy(StrictImmutableBoundaryModel):
    mode: Literal["username_password_to_short_lived_jwt"] = (
        "username_password_to_short_lived_jwt"
    )
    credential_secret_version_id: str | None = Field(
        default=None,
        max_length=512,
        pattern=r"^[\x21-\x7e]+$",
    )
    credential_delivery: Literal["systemd_load_credential_encrypted"] = (
        "systemd_load_credential_encrypted"
    )
    jwt_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    jwt_storage: Literal["memory_only"] = "memory_only"
    administrator_account_allowed: Literal[False] = False

    @model_validator(mode="after")
    def _secret_reference_if_present(self) -> TuoniAuthenticationPolicy:
        reference = self.credential_secret_version_id
        if reference is not None and not reference.strip():
            raise ValueError("credential_secret_version_id must be non-empty when present")
        return self


class TuoniFoundationProfile(StrictImmutableBoundaryModel):
    adapter_id: Literal["tuoni-c2"] = "tuoni-c2"
    provider: TuoniProviderPin
    connection: TuoniConnectionPolicy
    authentication: TuoniAuthenticationPolicy
    isolation: TuoniLabIsolationPolicy
    profile_digest: str = Field(pattern=_SHA256_PATTERN)

    def configuration_blockers(self) -> tuple[str, ...]:
        blockers: list[str] = []
        if self.provider.server_version is None:
            blockers.append("provider_version_unresolved")
        if self.provider.openapi_sha256 is None:
            blockers.append("openapi_digest_unresolved")
        if self.provider.container_image_digest is None:
            blockers.append("container_image_digest_unresolved")
        if self.provider.source_commit is None:
            blockers.append("source_commit_unresolved")
        if self.connection.tls_certificate_sha256 is None:
            blockers.append("tls_certificate_unresolved")
        if self.authentication.credential_secret_version_id is None:
            blockers.append("credential_secret_reference_unresolved")
        if self.isolation.vcenter_port_group_name is None:
            blockers.append("vcenter_port_group_unresolved")
        return tuple(blockers)


def build_tuoni_foundation_profile(
    *,
    digest_service: DigestService,
    provider: TuoniProviderPin | None = None,
    connection: TuoniConnectionPolicy | None = None,
    authentication: TuoniAuthenticationPolicy | None = None,
    isolation: TuoniLabIsolationPolicy | None = None,
) -> TuoniFoundationProfile:
    provider_value = provider or TuoniProviderPin(
        server_version=TUONI_VERSION_PIN,
        openapi_sha256=None,
        container_image_digest=TUONI_SERVER_IMAGE_DIGEST_PIN,
        source_commit=TUONI_SOURCE_COMMIT_PIN,
    )
    connection_value = connection or TuoniConnectionPolicy()
    authentication_value = authentication or TuoniAuthenticationPolicy()
    isolation_value = isolation or TuoniLabIsolationPolicy()
    fields = {
        "adapter_id": "tuoni-c2",
        "provider": provider_value,
        "connection": connection_value,
        "authentication": authentication_value,
        "isolation": isolation_value,
    }
    digest_payload = {
        "adapter_id": "tuoni-c2",
        "provider": provider_value.model_dump(mode="python"),
        "connection": connection_value.model_dump(mode="python"),
        "authentication": authentication_value.model_dump(mode="python"),
        "isolation": isolation_value.model_dump(mode="python"),
    }
    digest = digest_service.compute("tuoni_provider_profile_digest", digest_payload)
    return TuoniFoundationProfile(**fields, profile_digest=digest)  # type: ignore[arg-type]


class TuoniAdapterFoundation:
    """Non-operational C2Adapter placeholder with no transport dependency."""

    def __init__(self, profile: TuoniFoundationProfile, digest_service: DigestService) -> None:
        payload = profile.model_dump(mode="python")
        expected = str(payload.pop("profile_digest"))
        digest_service.verify("tuoni_provider_profile_digest", payload, expected)
        self._profile = profile

    @property
    def profile(self) -> TuoniFoundationProfile:
        return self._profile

    def activation_blockers(self) -> tuple[str, ...]:
        return (
            *self._profile.configuration_blockers(),
            "authenticated_process_transport_unconfigured",
            "live_provider_attestation_unverified",
        )

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id=self._profile.adapter_id,
            adapter_identity_digest=self._profile.profile_digest,
            provider_identity_digest="tuoni-provider-unresolved",
            result_delivery_mode="provider_task",
        )

    def _unavailable(self) -> NoReturn:
        raise C2AdapterUnavailableError(
            "Tuoni adapter is unavailable until deployment identities, authenticated "
            "transport, and live provider attestation are complete"
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
    "TUONI_OPENAPI_SHA256_PIN",
    "TUONI_SERVER_IMAGE_DIGEST_PIN",
    "TUONI_SOURCE_COMMIT_PIN",
    "TUONI_VERSION_PIN",
    "TuoniAdapterFoundation",
    "TuoniAuthenticationPolicy",
    "TuoniConnectionPolicy",
    "TuoniFoundationProfile",
    "TuoniLabIsolationPolicy",
    "TuoniProviderPin",
    "build_tuoni_foundation_profile",
]
