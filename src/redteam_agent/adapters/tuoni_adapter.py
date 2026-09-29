"""Tuoni 0.16.1 C2 adapter over an attested private transport.

The adapter contains provider semantics but no HTTP implementation, endpoint
selection, credential access, or Control VM management logic.  Those remain in
the composition-owned process transport.  This split allows every operation to
be exercised offline while keeping production activation blocked until a live
transport attestation exactly matches the immutable provider profile.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import ValidationError

from redteam_agent.adapters.c2 import C2SessionObservation
from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.adapters.tuoni import (
    TUONI_SERVER_IMAGE_DIGEST_PIN,
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
    TuoniFoundationProfile,
)
from redteam_agent.adapters.tuoni_contract import (
    TuoniApiContractV0161,
    TuoniCommandArguments,
    TuoniWireRequest,
)
from redteam_agent.adapters.tuoni_response import (
    TuoniCommandResponseV0161,
    TuoniTaskObservation,
    decode_active_agents_v0161,
    decode_agent_v0161,
    decode_command_templates_v0161,
    decode_command_v0161,
    decode_current_user_v0161,
    decode_permissions_v0161,
)
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransport,
    TuoniTransportAttestation,
    TuoniTransportResponse,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import (
    C2AdapterContractError,
    C2AdapterTransportError,
    C2AdapterUnavailableError,
    ResultCollectionError,
)
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
    ProviderTaskBinding,
    ResultTaskBinding,
)
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import RawResultSink
from redteam_agent.runtime.clock import Clock

TUONI_CONTROL_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
TUONI_RESULT_RESPONSE_MAX_BYTES = 16 * 1024 * 1024
TUONI_RESULT_CHUNK_BYTES = 64 * 1024
TUONI_CONTROL_TIMEOUT_SECONDS = 30
TUONI_RESULT_TIMEOUT_SECONDS = 120

type _TerminalStatus = Literal["succeeded", "failed", "cancelled"]
_REQUIRED_SERVICE_ACCOUNT_PERMISSIONS = frozenset(
    {"VIEW_RESOURCES", "SEND_COMMANDS"}
)
_SUPPORTED_WINDOWS_TARGET_ARCHITECTURES = frozenset({"x86_64", "arm64"})


def _terminal_status(task: TuoniTaskObservation) -> _TerminalStatus | None:
    if task.normalized_status == "succeeded":
        return "succeeded"
    if task.normalized_status == "failed":
        return "failed"
    if task.normalized_status == "cancelled":
        return "cancelled"
    return None


class TuoniAdapter:
    """ExecutionAdapter/C2Adapter implementation for an exact attested release."""

    def __init__(
        self,
        *,
        profile: TuoniFoundationProfile,
        contract: TuoniApiContractV0161,
        transport: TuoniTransport,
        clock: Clock,
        digest_service: DigestService,
    ) -> None:
        self._verify_profile(profile, digest_service)
        blockers = profile.configuration_blockers()
        if blockers:
            raise C2AdapterUnavailableError(
                "Tuoni adapter profile has unresolved deployment identities"
            )
        contract_digest = contract.contract_digest(digest_service)
        attestation = transport.attestation
        self._verify_attestation(
            profile=profile,
            contract_digest=contract_digest,
            attestation=attestation,
            digest_service=digest_service,
        )
        self._profile = profile
        self._contract = contract
        self._transport = transport
        self._clock = clock
        self._contract_digest = contract_digest
        self._provider_identity_digest = attestation.attestation_digest
        self._adapter_identity_digest = digest_service.compute(
            "tuoni_adapter_identity_digest",
            {
                "profile_digest": profile.profile_digest,
                "contract_digest": contract_digest,
                "transport_attestation_digest": attestation.attestation_digest,
            },
        )

    @staticmethod
    def _verify_profile(
        profile: TuoniFoundationProfile, digest_service: DigestService
    ) -> None:
        payload = profile.model_dump(mode="python")
        expected = str(payload.pop("profile_digest"))
        digest_service.verify("tuoni_provider_profile_digest", payload, expected)

    @staticmethod
    def _verify_attestation(
        *,
        profile: TuoniFoundationProfile,
        contract_digest: str,
        attestation: TuoniTransportAttestation,
        digest_service: DigestService,
    ) -> None:
        digest_service.verify(
            "tuoni_transport_attestation_digest",
            attestation.model_dump(mode="python"),
            attestation.attestation_digest,
        )
        provider = profile.provider
        connection = profile.connection
        authentication = profile.authentication
        isolation = profile.isolation
        if (
            attestation.adapter_profile_digest != profile.profile_digest
            or attestation.contract_digest != contract_digest
            or attestation.server_version != TUONI_VERSION_PIN
            or attestation.server_version != provider.server_version
            or attestation.openapi_sha256 != provider.openapi_sha256
            or attestation.container_image_digest != TUONI_SERVER_IMAGE_DIGEST_PIN
            or attestation.container_image_digest != provider.container_image_digest
            or attestation.source_commit != TUONI_SOURCE_COMMIT_PIN
            or attestation.source_commit != provider.source_commit
            or attestation.api_origin != connection.api_origin
            or attestation.tls_certificate_sha256
            != connection.tls_certificate_sha256
            or attestation.credential_secret_version_id
            != authentication.credential_secret_version_id
            or attestation.credential_delivery != authentication.credential_delivery
            or attestation.vcenter_port_group_name
            != isolation.vcenter_port_group_name
            or attestation.control_vm_operating_system
            != isolation.control_vm_operating_system
            or attestation.control_vm_architecture
            != isolation.control_vm_architecture
            or attestation.adapter_placement != isolation.adapter_placement
        ):
            raise C2AdapterUnavailableError(
                "Tuoni transport attestation does not match the fixed provider profile"
            )

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id="tuoni-c2",
            adapter_identity_digest=self._adapter_identity_digest,
            provider_identity_digest=self._provider_identity_digest,
            result_delivery_mode="provider_task",
        )

    def get_capabilities(self) -> AdapterCapabilities:
        expected_openapi_sha256 = self._profile.provider.openapi_sha256
        if expected_openapi_sha256 is None:  # guarded by configuration blockers
            raise C2AdapterUnavailableError("Tuoni OpenAPI digest is unresolved")
        openapi_response = self._request(self._contract.openapi())
        self._contract.verify_openapi_artifact(
            openapi_response.body,
            expected_sha256=expected_openapi_sha256,
        )
        self._verify_service_account_permissions(include_catalog=True)
        return AdapterCapabilities(
            adapter_id="tuoni-c2",
            adapter_type="c2",
            execution_location="managed_remote",
            capability_revision="tuoni-capabilities-0.16.1-v1",
            capabilities=frozenset(
                {
                    "session.list",
                    "session.get",
                    "task.submit",
                    "task.get",
                    "task.cancel",
                    "task.reconcile-by-id",
                    "result.collect",
                }
            ),
            supported_os=frozenset({"windows"}),
            supported_architectures=_SUPPORTED_WINDOWS_TARGET_ARCHITECTURES,
            reconciliation=True,
            cancellation=True,
            provider_deduplication=False,
            result_streaming=True,
            result_resume=False,
            durable_result_collection=True,
            result_delivery_mode="provider_task",
            target_binding_modes=frozenset({"none"}),
            redirect_disable_enforcement=True,
            policy_intercepted_redirect=False,
            max_output_bytes=TUONI_RESULT_RESPONSE_MAX_BYTES,
            provider_tool_catalog_digest=self._contract_digest,
            observed_at=self._clock.now(),
        )

    def list_sessions(self) -> tuple[C2SessionObservation, ...]:
        observed_at = self._clock.now()
        response = self._request(self._contract.list_active_agents())
        observations = decode_active_agents_v0161(
            response.body, observed_at=observed_at
        )
        return tuple(self._with_live_capabilities(item) for item in observations)

    def get_session(self, provider_session_id: str) -> C2SessionObservation:
        observed_at = self._clock.now()
        response = self._request(self._contract.get_agent(provider_session_id))
        observation = decode_agent_v0161(response.body, observed_at=observed_at)
        if observation.provider_session_id != provider_session_id:
            raise C2AdapterContractError("Tuoni returned a different agent identity")
        return self._with_live_capabilities(observation)

    def _with_live_capabilities(
        self, observation: C2SessionObservation
    ) -> C2SessionObservation:
        response = self._request(
            self._contract.list_agent_command_templates(
                observation.provider_session_id
            )
        )
        available = decode_command_templates_v0161(
            response.body,
            approved_names=self._contract.approved_command_templates,
        )
        return observation.model_copy(update={"capabilities": available})

    def submit(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle:
        if secret_bindings:
            raise C2AdapterContractError(
                "the approved Tuoni command contract accepts no execution secrets"
            )
        if result_capture.mode != "provider_task" or result_capture.sink is not None:
            raise C2AdapterContractError("Tuoni submit requires provider-task capture")
        if idempotency_key != request.idempotency_key:
            raise C2AdapterContractError("Tuoni submit idempotency binding mismatch")

        wire_request = self._contract.submit_command(request)
        try:
            arguments = TuoniCommandArguments.model_validate(thaw(request.arguments))
        except (C2AdapterContractError, ValidationError) as exc:
            raise C2AdapterContractError(
                "execution arguments violate the Tuoni contract"
            ) from exc
        self._verify_service_account_permissions(include_catalog=False)
        self._verify_eligible_target_session(arguments.provider_session_id)
        template_response = self._request(
            self._contract.list_agent_command_templates(
                arguments.provider_session_id
            )
        )
        available = decode_command_templates_v0161(
            template_response.body,
            approved_names=self._contract.approved_command_templates,
        )
        if request.provider_tool_name not in available:
            raise C2AdapterContractError(
                "approved Tuoni command template is not currently available"
            )
        response = self._request(
            wire_request, timeout_seconds=request.timeout_seconds
        )
        command, task = decode_command_v0161(
            response.body, observed_at=self._clock.now()
        )
        self._verify_submitted_command(
            request=request, expected_session_id=arguments.provider_session_id,
            command=command, task=task,
        )
        identity = self.identity()
        return TaskHandle(
            task_id=request.task_id,
            result_delivery_mode="provider_task",
            provider_task_id=task.provider_task_id,
            adapter_identity_digest=identity.adapter_identity_digest,
            provider_identity_digest=identity.provider_identity_digest,
        )

    def _verify_eligible_target_session(self, provider_session_id: str) -> None:
        response = self._request(self._contract.get_agent(provider_session_id))
        observation = decode_agent_v0161(
            response.body,
            observed_at=self._clock.now(),
        )
        if observation.provider_session_id != provider_session_id:
            raise C2AdapterContractError("Tuoni target session identity mismatch")
        if (
            observation.provider_status != "active"
            or observation.os != "windows"
            or observation.architecture
            not in _SUPPORTED_WINDOWS_TARGET_ARCHITECTURES
        ):
            raise C2AdapterUnavailableError(
                "Tuoni target session is not an active supported Windows target"
            )

    def _verify_service_account_permissions(self, *, include_catalog: bool) -> None:
        user_response = self._request(self._contract.current_user())
        user = decode_current_user_v0161(user_response.body)
        if not user.enabled:
            raise C2AdapterUnavailableError("Tuoni service account is disabled")
        if user.permission_codes != _REQUIRED_SERVICE_ACCOUNT_PERMISSIONS:
            raise C2AdapterUnavailableError(
                "Tuoni service account is not bound to the exact least-privilege set"
            )
        if not include_catalog:
            return
        catalog_response = self._request(self._contract.permissions())
        catalog = decode_permissions_v0161(catalog_response.body)
        catalog_codes = frozenset(item.code for item in catalog)
        mandatory_codes = frozenset(item.code for item in catalog if item.mandatory)
        if (
            not _REQUIRED_SERVICE_ACCOUNT_PERMISSIONS.issubset(catalog_codes)
            or not mandatory_codes.issubset(user.permission_codes)
        ):
            raise C2AdapterUnavailableError(
                "Tuoni permission catalog is incompatible with the service account"
            )

    @staticmethod
    def _verify_submitted_command(
        *,
        request: ExecutionRequest,
        expected_session_id: str,
        command: TuoniCommandResponseV0161,
        task: TuoniTaskObservation,
    ) -> None:
        if task.provider_session_id != expected_session_id:
            raise C2AdapterContractError("Tuoni submit response agent identity mismatch")
        if (
            command.command_template_name is not None
            and command.command_template_name != request.provider_tool_name
        ):
            raise C2AdapterContractError("Tuoni submit response command template mismatch")

    def reconcile(
        self, execution_id: str, task_binding: ResultTaskBinding | None
    ) -> ReconciliationResult:
        observed_at = self._clock.now()
        if task_binding is None:
            # Tuoni 0.16.1 has no idempotency-key lookup. An unacknowledged
            # submit can therefore never be proven absent or safely re-sent.
            return ReconciliationResult(
                execution_id=execution_id,
                status="UNSUPPORTED",
                task_binding=None,
                provider_status=None,
                provider_task_id=None,
                observed_at=observed_at,
            )
        binding = self._require_provider_binding(execution_id, task_binding)
        command_request = self._contract.get_command(binding.provider_task_id)
        try:
            response = self._request(
                command_request,
                accepted_status_codes=frozenset({200, 404}),
            )
            if response.status_code == 404:
                return ReconciliationResult(
                    execution_id=execution_id,
                    status="NOT_FOUND_UNCERTAIN",
                    task_binding=None,
                    provider_status=None,
                    provider_task_id=binding.provider_task_id,
                    observed_at=observed_at,
                )
            _, task = decode_command_v0161(
                response.body, observed_at=observed_at
            )
            self._verify_task_id(binding.provider_task_id, task)
        except (C2AdapterContractError, C2AdapterTransportError):
            return ReconciliationResult(
                execution_id=execution_id,
                status="UNKNOWN",
                task_binding=None,
                provider_status=None,
                provider_task_id=binding.provider_task_id,
                observed_at=observed_at,
            )
        terminal_status = _terminal_status(task)
        if terminal_status is not None:
            return ReconciliationResult(
                execution_id=execution_id,
                status="FOUND_TERMINAL",
                task_binding=binding,
                provider_status=terminal_status,
                provider_task_id=binding.provider_task_id,
                observed_at=observed_at,
            )
        return ReconciliationResult(
            execution_id=execution_id,
            status="FOUND_RUNNING",
            task_binding=None,
            provider_status=None,
            provider_task_id=binding.provider_task_id,
            observed_at=observed_at,
        )

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome:
        observed_at = self._clock.now()
        result: Literal["ACKNOWLEDGED", "CONFIRMED", "UNKNOWN", "FAILED"]
        stop_request = self._contract.stop_command(provider_task_id)
        try:
            response = self._request(stop_request)
            _, task = decode_command_v0161(response.body, observed_at=observed_at)
            self._verify_task_id(provider_task_id, task)
        except (C2AdapterContractError, C2AdapterTransportError):
            result = "UNKNOWN"
        else:
            if task.normalized_status == "cancelled":
                result = "CONFIRMED"
            elif task.normalized_status in {"queued", "running"}:
                result = "ACKNOWLEDGED"
            else:
                result = "FAILED"
        return CancelOutcome(
            execution_id=execution_id,
            provider_task_id=provider_task_id,
            result=result,
            observed_at=observed_at,
        )

    def collect_result(
        self,
        execution_id: str,
        task_binding: ResultTaskBinding,
        sink: RawResultSink,
        resume: CollectionResumeCursor | None = None,
        cancellation: CollectionCancellation | None = None,
    ) -> AdapterCollectionControl:
        binding = self._require_provider_binding(execution_id, task_binding)
        self._verify_collection_controls(
            execution_id=execution_id,
            binding=binding,
            sink=sink,
            resume=resume,
            cancellation=cancellation,
        )
        try:
            response = self._request(
                self._contract.get_command(binding.provider_task_id),
                timeout_seconds=TUONI_RESULT_TIMEOUT_SECONDS,
                max_body_bytes=TUONI_RESULT_RESPONSE_MAX_BYTES,
            )
            command, task = decode_command_v0161(
                response.body, observed_at=self._clock.now()
            )
            self._verify_task_id(binding.provider_task_id, task)
            control = self._terminal_control(command, task)
            for chunk in self._chunks(response.body, TUONI_RESULT_CHUNK_BYTES):
                sink.write_stdout(chunk)
            return control
        except (C2AdapterContractError, C2AdapterTransportError) as exc:
            raise ResultCollectionError(
                "Tuoni result collection failed at the pinned provider boundary"
            ) from exc

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl:
        binding = self._require_provider_binding(execution_id, task_binding)
        try:
            response = self._request(self._contract.get_command(binding.provider_task_id))
            command, task = decode_command_v0161(
                response.body, observed_at=self._clock.now()
            )
            self._verify_task_id(binding.provider_task_id, task)
            return self._terminal_control(command, task)
        except (C2AdapterContractError, C2AdapterTransportError) as exc:
            raise ResultCollectionError(
                "Tuoni control read failed at the pinned provider boundary"
            ) from exc

    def _require_provider_binding(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> ProviderTaskBinding:
        if isinstance(task_binding, LocalResultBinding):
            raise C2AdapterContractError("Tuoni accepts only provider task bindings")
        identity = self.identity()
        if (
            task_binding.execution_id != execution_id
            or task_binding.adapter_identity_digest
            != identity.adapter_identity_digest
            or task_binding.provider_identity_digest
            != identity.provider_identity_digest
        ):
            raise C2AdapterContractError("Tuoni task binding identity mismatch")
        return task_binding

    @staticmethod
    def _verify_task_id(
        provider_task_id: str, task: TuoniTaskObservation
    ) -> None:
        if task.provider_task_id != provider_task_id:
            raise C2AdapterContractError("Tuoni command identity mismatch")

    @staticmethod
    def _terminal_control(
        command: TuoniCommandResponseV0161, task: TuoniTaskObservation
    ) -> AdapterCollectionControl:
        terminal_status = _terminal_status(task)
        if terminal_status is None:
            raise C2AdapterContractError("Tuoni command result is not terminal")
        finished_at = (
            command.result.received
            if command.result is not None
            else command.sent or command.created
        )
        return AdapterCollectionControl(
            provider_status=terminal_status,
            exit_code=None,
            timed_out=False,
            started_at=command.created,
            finished_at=finished_at,
            status_normalization_rule_id="status-normalization-v1",
        )

    @staticmethod
    def _verify_collection_controls(
        *,
        execution_id: str,
        binding: ProviderTaskBinding,
        sink: RawResultSink,
        resume: CollectionResumeCursor | None,
        cancellation: CollectionCancellation | None,
    ) -> None:
        if resume is not None and (
            resume.execution_id != execution_id
            or resume.collection_id != f"collection-{execution_id}"
            or resume.sink_id != sink.sink_id
            or resume.task_binding_digest != binding.binding_digest
            or resume.result_delivery_mode != "provider_task"
            or resume.last_committed_chunk_sequence != 0
            or resume.receipt_id is not None
        ):
            raise ResultCollectionError("Tuoni result resume cursor is wrongly bound")
        if cancellation is not None:
            if (
                cancellation.execution_id != execution_id
                or cancellation.collection_id != f"collection-{execution_id}"
                or cancellation.sink_id != sink.sink_id
                or cancellation.task_binding_digest != binding.binding_digest
            ):
                raise ResultCollectionError("Tuoni result cancellation is wrongly bound")
            raise ResultCollectionError("Tuoni result collection was cancelled before read")

    def _request(
        self,
        request: TuoniWireRequest,
        *,
        timeout_seconds: int = TUONI_CONTROL_TIMEOUT_SECONDS,
        max_body_bytes: int = TUONI_CONTROL_RESPONSE_MAX_BYTES,
        accepted_status_codes: frozenset[int] | None = None,
    ) -> TuoniTransportResponse:
        if timeout_seconds < 1:
            raise C2AdapterContractError("Tuoni request timeout must be positive")
        response = self._transport.request(
            request,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_body_bytes,
        )
        allowed = request.expected_status_codes if accepted_status_codes is None else accepted_status_codes
        if response.status_code not in allowed:
            raise C2AdapterTransportError("Tuoni returned an unexpected HTTP status")
        if len(response.body) > max_body_bytes:
            raise C2AdapterTransportError("Tuoni response exceeded the fixed size limit")
        if response.status_code in request.expected_status_codes:
            media_type = response.content_type.partition(";")[0].strip().lower()
            if media_type != "application/json":
                raise C2AdapterTransportError("Tuoni returned an unexpected media type")
        return response

    @staticmethod
    def _chunks(value: bytes, size: int) -> Iterable[bytes]:
        for offset in range(0, len(value), size):
            yield value[offset : offset + size]


__all__ = [
    "TUONI_CONTROL_RESPONSE_MAX_BYTES",
    "TUONI_CONTROL_TIMEOUT_SECONDS",
    "TUONI_RESULT_CHUNK_BYTES",
    "TUONI_RESULT_RESPONSE_MAX_BYTES",
    "TUONI_RESULT_TIMEOUT_SECONDS",
    "TuoniAdapter",
]
