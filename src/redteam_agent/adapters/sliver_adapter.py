"""Read/control-only Sliver v1.7.7 adapter over an attested transport."""

from __future__ import annotations

from typing import Literal

from redteam_agent.adapters.c2 import C2SessionObservation
from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.adapters.sliver import (
    SLIVER_SOURCE_COMMIT_PIN,
    SLIVER_VERSION_PIN,
    SliverFoundationProfile,
)
from redteam_agent.adapters.sliver_contract import SliverRpcContractV177, SliverWireRequest
from redteam_agent.adapters.sliver_response import (
    SliverBeaconTaskRecord,
    decode_beacon,
    decode_beacon_task,
    decode_beacon_tasks,
    decode_beacons,
    decode_sessions,
    decode_version,
    endpoint_observation,
)
from redteam_agent.adapters.sliver_transport import (
    SliverTransport,
    SliverTransportAttestation,
    SliverTransportResponse,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterContractError, C2AdapterUnavailableError, ResultCollectionError
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
    LocalResultBinding,
    ResultTaskBinding,
)
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import RawResultSink
from redteam_agent.runtime.clock import Clock

SLIVER_CONTROL_TIMEOUT_SECONDS = 30
SLIVER_CONTROL_MAX_BYTES = 4 * 1024 * 1024


class SliverAdapter:
    """C2 inventory plus existing Beacon Task read/cancel; no task submission."""

    def __init__(
        self,
        *,
        profile: SliverFoundationProfile,
        contract: SliverRpcContractV177,
        transport: SliverTransport,
        clock: Clock,
        digest_service: DigestService,
    ) -> None:
        self._verify_profile(profile, digest_service)
        if profile.configuration_blockers():
            raise C2AdapterUnavailableError(
                "Sliver adapter profile has unresolved deployment identities"
            )
        contract_digest = contract.contract_digest(digest_service)
        self._verify_attestation(
            profile=profile,
            contract_digest=contract_digest,
            attestation=transport.attestation,
            digest_service=digest_service,
        )
        self._profile = profile
        self._contract = contract
        self._transport = transport
        self._clock = clock
        self._contract_digest = contract_digest
        self._provider_identity_digest = transport.attestation.attestation_digest
        self._adapter_identity_digest = digest_service.compute(
            "sliver_adapter_identity_digest",
            {
                "profile_digest": profile.profile_digest,
                "contract_digest": contract_digest,
                "transport_attestation_digest": transport.attestation.attestation_digest,
            },
        )

    @staticmethod
    def _verify_profile(
        profile: SliverFoundationProfile, digest_service: DigestService
    ) -> None:
        payload = profile.model_dump(mode="python")
        expected = str(payload.pop("profile_digest"))
        digest_service.verify("sliver_provider_profile_digest", payload, expected)

    @staticmethod
    def _verify_attestation(
        *,
        profile: SliverFoundationProfile,
        contract_digest: str,
        attestation: SliverTransportAttestation,
        digest_service: DigestService,
    ) -> None:
        digest_service.verify(
            "sliver_transport_attestation_digest",
            attestation.model_dump(mode="python"),
            attestation.attestation_digest,
        )
        connection = profile.connection
        if (
            attestation.adapter_profile_digest != profile.profile_digest
            or attestation.contract_digest != contract_digest
            or attestation.provider_version != SLIVER_VERSION_PIN
            or attestation.provider_source_commit != SLIVER_SOURCE_COMMIT_PIN
            or attestation.operator_name != connection.operator_name
            or attestation.operator_config_secret_version_id
            != connection.operator_config_secret_version_id
            or attestation.operator_config_sha256 != connection.operator_config_sha256
            or attestation.server_address != connection.server_address
            or attestation.server_port != connection.server_port
            or attestation.server_tls_name != connection.server_tls_name
            or attestation.ca_certificate_sha256 != connection.ca_certificate_sha256
            or attestation.operator_certificate_sha256
            != connection.operator_certificate_sha256
            or attestation.implant_transport != profile.target.implant_transport
        ):
            raise C2AdapterUnavailableError(
                "Sliver transport attestation does not match the fixed profile"
            )

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id="sliver-c2",
            adapter_identity_digest=self._adapter_identity_digest,
            provider_identity_digest=self._provider_identity_digest,
            result_delivery_mode="provider_task",
        )

    def get_capabilities(self) -> AdapterCapabilities:
        self._verify_live_version()
        return AdapterCapabilities(
            adapter_id="sliver-c2",
            adapter_type="c2",
            execution_location="managed_remote",
            capability_revision="sliver-capabilities-1.7.7-read-control-v1",
            capabilities=frozenset(
                {
                    "session.list",
                    "session.get",
                    "beacon.task.list",
                    "beacon.task.get",
                    "beacon.task.cancel",
                    "task.reconcile-by-id",
                }
            ),
            supported_os=frozenset({"windows"}),
            supported_architectures=frozenset({"x86_64"}),
            reconciliation=True,
            cancellation=True,
            provider_deduplication=False,
            result_streaming=False,
            result_resume=False,
            durable_result_collection=False,
            result_delivery_mode="provider_task",
            target_binding_modes=frozenset({"none"}),
            redirect_disable_enforcement=True,
            policy_intercepted_redirect=False,
            max_output_bytes=SLIVER_CONTROL_MAX_BYTES,
            provider_tool_catalog_digest=self._contract_digest,
            observed_at=self._clock.now(),
        )

    def list_sessions(self) -> tuple[C2SessionObservation, ...]:
        observed_at = self._clock.now()
        sessions = decode_sessions(self._request(self._contract.list_sessions()).body)
        beacons = decode_beacons(self._request(self._contract.list_beacons()).body)
        combined = (
            *(endpoint_observation(item, kind="session", observed_at=observed_at) for item in sessions.sessions),
            *(endpoint_observation(item, kind="beacon", observed_at=observed_at) for item in beacons.beacons),
        )
        identifiers = tuple(item.provider_session_id for item in combined)
        if len(set(identifiers)) != len(identifiers):
            raise C2AdapterContractError("Sliver endpoint identities are ambiguous")
        return tuple(self._enforce_target(item) for item in combined)

    def get_session(self, provider_session_id: str) -> C2SessionObservation:
        kind, separator, raw_id = provider_session_id.partition(":")
        if not separator or kind not in {"session", "beacon"} or not raw_id:
            raise C2AdapterContractError("Sliver provider session ID is invalid")
        observed_at = self._clock.now()
        if kind == "beacon":
            response = decode_beacon(self._request(self._contract.get_beacon(raw_id)).body)
            if response.beacon.id != raw_id:
                raise C2AdapterContractError("Sliver returned a different Beacon identity")
            return self._enforce_target(
                endpoint_observation(response.beacon, kind="beacon", observed_at=observed_at)
            )
        sessions = decode_sessions(self._request(self._contract.list_sessions()).body)
        matches = tuple(item for item in sessions.sessions if item.id == raw_id)
        if len(matches) != 1:
            raise C2AdapterUnavailableError("Sliver Session is not present in live inventory")
        return self._enforce_target(
            endpoint_observation(matches[0], kind="session", observed_at=observed_at)
        )

    def list_beacon_tasks(self, provider_session_id: str) -> tuple[SliverBeaconTaskRecord, ...]:
        kind, separator, beacon_id = provider_session_id.partition(":")
        if not separator or kind != "beacon" or not beacon_id:
            raise C2AdapterContractError("Sliver Beacon provider session ID is invalid")
        response = decode_beacon_tasks(
            self._request(self._contract.list_beacon_tasks(beacon_id)).body
        )
        if response.beacon_id != beacon_id:
            raise C2AdapterContractError("Sliver returned tasks for a different Beacon")
        return response.tasks

    def get_beacon_task(self, provider_task_id: str) -> SliverBeaconTaskRecord:
        response = decode_beacon_task(
            self._request(self._contract.get_beacon_task_content(provider_task_id)).body
        )
        if response.task.id != provider_task_id:
            raise C2AdapterContractError("Sliver returned a different Beacon Task")
        return response.task

    def submit(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle:
        del request, secret_bindings, result_capture, idempotency_key
        raise C2AdapterUnavailableError(
            "Sliver command submission is outside the approved read/control contract"
        )

    def reconcile(
        self, execution_id: str, task_binding: ResultTaskBinding | None
    ) -> ReconciliationResult:
        if task_binding is None or isinstance(task_binding, LocalResultBinding):
            return ReconciliationResult(
                execution_id=execution_id,
                status="UNSUPPORTED",
                task_binding=None,
                provider_status=None,
                provider_task_id=None,
                observed_at=self._clock.now(),
            )
        task = self.get_beacon_task(task_binding.provider_task_id)
        if task.state in {"pending", "sent"}:
            status: Literal["FOUND_RUNNING", "FOUND_TERMINAL"] = "FOUND_RUNNING"
            provider_status: Literal["succeeded", "cancelled"] | None = None
            terminal_binding = None
        else:
            status = "FOUND_TERMINAL"
            provider_status = "succeeded" if task.state == "completed" else "cancelled"
            terminal_binding = task_binding
        return ReconciliationResult(
            execution_id=execution_id,
            status=status,
            task_binding=terminal_binding,
            provider_status=provider_status,
            provider_task_id=task.id,
            observed_at=self._clock.now(),
        )

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome:
        response = decode_beacon_task(
            self._request(self._contract.cancel_beacon_task(provider_task_id)).body
        )
        if response.task.id != provider_task_id:
            raise C2AdapterContractError("Sliver cancelled a different Beacon Task")
        return CancelOutcome(
            execution_id=execution_id,
            provider_task_id=provider_task_id,
            result="CONFIRMED" if response.task.state == "canceled" else "UNKNOWN",
            observed_at=self._clock.now(),
        )

    def collect_result(
        self,
        execution_id: str,
        task_binding: ResultTaskBinding,
        sink: RawResultSink,
        resume: CollectionResumeCursor | None = None,
        cancellation: CollectionCancellation | None = None,
    ) -> AdapterCollectionControl:
        del execution_id, task_binding, sink, resume, cancellation
        raise ResultCollectionError(
            "Sliver result collection is outside the approved read/control contract"
        )

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl:
        del execution_id, task_binding
        raise ResultCollectionError(
            "Sliver result control is outside the approved read/control contract"
        )

    def _verify_live_version(self) -> None:
        version = decode_version(self._request(self._contract.get_version()).body)
        if (
            version.semantic_version() != SLIVER_VERSION_PIN
            or version.dirty
            or not SLIVER_SOURCE_COMMIT_PIN.startswith(version.commit)
        ):
            raise C2AdapterUnavailableError(
                "Sliver live version does not match the pinned clean release"
            )

    def _enforce_target(self, observation: C2SessionObservation) -> C2SessionObservation:
        if (
            observation.os != self._profile.target.target_operating_system
            or observation.architecture != self._profile.target.target_architecture
        ):
            return observation.model_copy(
                update={"provider_status": "unknown", "capabilities": frozenset()}
            )
        return observation

    def _request(self, request: SliverWireRequest) -> SliverTransportResponse:
        return self._transport.request(
            request,
            timeout_seconds=SLIVER_CONTROL_TIMEOUT_SECONDS,
            max_response_bytes=SLIVER_CONTROL_MAX_BYTES,
        )


__all__ = [
    "SLIVER_CONTROL_MAX_BYTES",
    "SLIVER_CONTROL_TIMEOUT_SECONDS",
    "SliverAdapter",
]
