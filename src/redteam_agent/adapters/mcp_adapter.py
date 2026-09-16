"""Provider-neutral MCP 2026-07-28 adapter over an attested transport."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.adapters.mcp import (
    MCPDiscoverResult,
    MCPFoundationProfile,
    MCPServerCapabilities,
)
from redteam_agent.adapters.mcp_contract import (
    MCPApiContractV20260728,
    MCPWireRequest,
    mcp_tool_capability_id,
)
from redteam_agent.adapters.mcp_response import (
    MCPToolCatalogObservation,
    decode_mcp_call_response,
    decode_mcp_discover_response,
    decode_mcp_tool_list_changed_notification,
    decode_mcp_tools_list_response,
)
from redteam_agent.adapters.mcp_transport import (
    MCPTransport,
    MCPTransportAttestation,
    MCPTransportResponse,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import (
    MCPAdapterUnavailableError,
    MCPContractError,
    MCPProtocolRevisionMismatchError,
    MCPTaskCapabilityError,
    MCPTransportError,
    MCPTransportIdentityMismatchError,
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
    ResultTaskBinding,
)
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import RawResultSink
from redteam_agent.policy.target_binding import build_target_dispatch_binding
from redteam_agent.runtime.clock import Clock

MCP_CONTROL_TIMEOUT_SECONDS = 30
MCP_CALL_RESPONSE_MAX_BYTES = 16 * 1024 * 1024
MCP_CONTROL_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
MCP_RESULT_CHUNK_BYTES = 64 * 1024


class MCPAdapter:
    """Stateless, local-result MCP adapter with Tasks deliberately disabled."""

    def __init__(
        self,
        *,
        profile: MCPFoundationProfile,
        contract: MCPApiContractV20260728,
        transport: MCPTransport,
        clock: Clock,
        digest_service: DigestService,
    ) -> None:
        self._verify_profile(profile, digest_service)
        if profile.configuration_blockers():
            raise MCPAdapterUnavailableError("MCP profile has unresolved identities")
        if contract.adapter_id != profile.adapter_id:
            raise MCPAdapterUnavailableError("MCP contract is bound to another adapter")
        config = profile.server_config
        trust_policy = profile.trust_policy
        assert config is not None and trust_policy is not None
        if config.task_implementation_mode != "disabled":
            raise MCPTaskCapabilityError(
                "offline MCP adapter does not implement the Tasks extension"
            )
        if (
            trust_policy.adapter_id != profile.adapter_id
            or trust_policy.execution_location != config.execution_location
        ):
            raise MCPAdapterUnavailableError("MCP trust policy binding mismatch")
        digest_service.verify(
            "mcp_server_config_digest",
            config.model_dump(mode="python"),
            config.config_digest,
        )
        contract_digest = contract.contract_digest()
        attestation = transport.attestation
        self._verify_attestation(
            profile=profile,
            contract_digest=contract_digest,
            attestation=attestation,
            digest_service=digest_service,
        )
        self._profile = profile
        self._config = config
        self._trust_policy = trust_policy
        self._contract = contract
        self._transport = transport
        self._clock = clock
        self._digest_service = digest_service
        self._contract_digest = contract_digest
        self._provider_identity_digest = attestation.attestation_digest
        self._adapter_identity_digest = digest_service.compute(
            "mcp_adapter_identity_digest",
            {
                "profile_digest": profile.profile_digest,
                "server_config_digest": config.config_digest,
                "contract_digest": contract_digest,
                "transport_attestation_digest": attestation.attestation_digest,
            },
        )

    @staticmethod
    def _verify_profile(
        profile: MCPFoundationProfile, digest_service: DigestService
    ) -> None:
        payload = profile.model_dump(mode="python")
        expected = str(payload.pop("profile_digest"))
        digest_service.verify("mcp_provider_profile_digest", payload, expected)

    @staticmethod
    def _verify_attestation(
        *,
        profile: MCPFoundationProfile,
        contract_digest: str,
        attestation: MCPTransportAttestation,
        digest_service: DigestService,
    ) -> None:
        digest_service.verify(
            "mcp_transport_attestation_digest",
            attestation.model_dump(mode="python"),
            attestation.attestation_digest,
        )
        config = profile.server_config
        assert config is not None
        if attestation.protocol_revision != config.protocol_revision:
            raise MCPProtocolRevisionMismatchError(
                "MCP transport attested the wrong protocol revision"
            )
        if (
            attestation.transport != config.transport
            or attestation.execution_location != config.execution_location
            or attestation.verified_transport_identities
            != config.configured_transport_identities
        ):
            raise MCPTransportIdentityMismatchError(
                "MCP transport identity attestation mismatch"
            )
        if (
            attestation.adapter_profile_digest != profile.profile_digest
            or attestation.server_config_digest != config.config_digest
            or attestation.contract_digest != contract_digest
            or attestation.server_id != config.server_id
            or not attestation.sandbox_verified
            or not attestation.redirects_disabled
        ):
            raise MCPAdapterUnavailableError("MCP transport attestation mismatch")

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id=self._profile.adapter_id,
            adapter_identity_digest=self._adapter_identity_digest,
            provider_identity_digest=self._provider_identity_digest,
            result_delivery_mode="local_result",
        )

    def discover(self) -> MCPDiscoverResult:
        request = self._contract.discover()
        response = self._request(request)
        discovered = decode_mcp_discover_response(
            response.body,
            expected_request_id=request.request_id,
            config=self._config,
            remote_enforcement_capabilities=self._trust_policy.remote_enforcement,
            verified_transport_identities=(
                self._transport.attestation.verified_transport_identities
            ),
            verified_at=self._clock.now(),
            digest_service=self._digest_service,
        )
        self._verify_required_capabilities(discovered.reported_capabilities)
        return discovered

    def observe_tool_catalog(self) -> MCPToolCatalogObservation:
        request = self._contract.tools_list()
        response = self._request(request)
        return decode_mcp_tools_list_response(
            response.body,
            expected_request_id=request.request_id,
            approved_tools=self._contract.approved_tools,
            tool_list_revision=self._config.tool_list_revision,
            digest_service=self._digest_service,
        )

    def observe_tools_list_changed(
        self,
        notification: str | bytes,
        *,
        expected_subscription_id: str | int,
    ) -> MCPToolCatalogObservation:
        """Validate a subscription signal, then refresh candidates only."""
        decode_mcp_tool_list_changed_notification(
            notification, expected_subscription_id=expected_subscription_id
        )
        return self.observe_tool_catalog()

    def _qualify(self) -> tuple[MCPDiscoverResult, MCPToolCatalogObservation]:
        discovered = self.discover()
        catalog = self.observe_tool_catalog()
        return discovered, catalog

    def _verify_required_capabilities(
        self, reported: MCPServerCapabilities
    ) -> None:
        required = self._config.required_capabilities
        for field in (
            "tools",
            "tools_list_changed_subscription",
            "cancellation",
            "task_extension",
            "reconciliation",
        ):
            if getattr(required, field) and not getattr(reported, field):
                raise MCPAdapterUnavailableError(
                    "MCP server is missing a required capability"
                )
        if required.task_extension or required.reconciliation:
            raise MCPTaskCapabilityError("MCP Tasks are disabled in this adapter")

    def get_capabilities(self) -> AdapterCapabilities:
        discovered, catalog = self._qualify()
        capabilities = {"server.discover", "tools.list", "tools.call"}
        approved_by_name = {item.name: item for item in self._contract.approved_tools}
        capabilities.update(
            mcp_tool_capability_id(
                name=name,
                tool_list_revision=self._config.tool_list_revision,
                input_schema_digest=approved_by_name[name].input_schema_digest,
            )
            for name in catalog.approved_tool_names
        )
        if discovered.reported_capabilities.tools_list_changed_subscription:
            capabilities.add("tools.list_changed.observe_only")
        return AdapterCapabilities(
            adapter_id=self._profile.adapter_id,
            adapter_type="mcp",
            execution_location=self._config.execution_location,
            capability_revision="mcp-capabilities-2026-07-28-v1",
            capabilities=frozenset(capabilities),
            supported_os=frozenset(),
            supported_architectures=frozenset(),
            reconciliation=False,
            cancellation=False,
            provider_deduplication=False,
            result_streaming=True,
            result_resume=False,
            durable_result_collection=True,
            result_delivery_mode="local_result",
            target_binding_modes=self._config.target_binding_modes,
            redirect_disable_enforcement=True,
            policy_intercepted_redirect=False,
            max_output_bytes=MCP_CALL_RESPONSE_MAX_BYTES,
            provider_tool_catalog_digest=catalog.live_catalog_digest,
            observed_at=self._clock.now(),
        )

    def submit(
        self,
        request: ExecutionRequest,
        secret_bindings: tuple[EphemeralSecretBinding, ...],
        result_capture: DispatchResultCapture,
        idempotency_key: str,
    ) -> TaskHandle:
        if (
            result_capture.mode != "local_result"
            or result_capture.sink is None
            or request.result_delivery_mode != "local_result"
        ):
            raise MCPContractError("MCP call requires local-result capture")
        if idempotency_key != request.idempotency_key:
            raise MCPContractError("MCP idempotency binding mismatch")
        wire_request = self._contract.tools_call(request)
        self._verify_target_bindings(request)
        self._contract.validate_secret_bindings(request, secret_bindings)
        if secret_bindings and (
            self._config.secret_delivery_mode != "ephemeral_meta_v1"  # noqa: S105
            or not self._trust_policy.allow_secret_resolution
            or self._config.execution_location != "local_process"
        ):
            raise MCPContractError(
                "MCP execution secrets are not enabled for this local server"
            )
        _, catalog = self._qualify()
        if request.provider_tool_name not in catalog.approved_tool_names:
            raise MCPContractError(
                "MCP live tool schema does not match the approved definition"
            )
        started_at = self._clock.now()
        call_bytes = self._contract.tools_call_wire_bytes(request, secret_bindings)
        response = self._request_bytes(
            call_bytes,
            timeout_seconds=request.timeout_seconds,
            max_response_bytes=MCP_CALL_RESPONSE_MAX_BYTES,
        )
        control = decode_mcp_call_response(
            response.body, expected_request_id=wire_request.request_id
        )
        for chunk in self._chunks(response.body, MCP_RESULT_CHUNK_BYTES):
            result_capture.sink.write_stdout(chunk)
        result_capture.commit_control_metadata(
            AdapterCollectionControl(
                provider_status="failed" if control.is_error else "succeeded",
                exit_code=None,
                timed_out=False,
                started_at=started_at,
                finished_at=self._clock.now(),
                status_normalization_rule_id="mcp-call-result-v1",
            )
        )
        identity = self.identity()
        return TaskHandle(
            task_id=request.task_id,
            result_delivery_mode="local_result",
            provider_task_id=None,
            adapter_identity_digest=identity.adapter_identity_digest,
            provider_identity_digest=identity.provider_identity_digest,
        )

    def _verify_target_bindings(self, request: ExecutionRequest) -> None:
        arguments = thaw(request.arguments)
        raw_destinations = arguments.get("destinations")
        bindings = request.target_dispatch_bindings
        if raw_destinations is None:
            if bindings:
                raise MCPContractError(
                    "MCP target bindings exist without destination arguments"
                )
            return
        if (
            not isinstance(raw_destinations, list)
            or not raw_destinations
            or any(type(item) is not str for item in raw_destinations)
        ):
            raise MCPContractError("MCP destination arguments are invalid")
        if not bindings or "exact_ip_enforced" not in self._config.target_binding_modes:
            raise MCPContractError("MCP network call has no enforced target binding")

        canonical_arguments: list[str] = []
        for destination in raw_destinations:
            try:
                canonical_arguments.append(str(ipaddress.ip_address(destination)))
            except ValueError as exc:
                raise MCPContractError(
                    "MCP destination must be a canonical IP address"
                ) from exc
        if len(canonical_arguments) != len(set(canonical_arguments)):
            raise MCPContractError("MCP destination arguments contain duplicates")

        authorized: list[str] = []
        for binding in bindings:
            target = binding.normalized_target
            expected = build_target_dispatch_binding(
                normalized_target=target,
                binding_mode=binding.binding_mode,
                connection_addresses=binding.connection_addresses,
                digest_service=self._digest_service,
            )
            if expected != binding:
                raise MCPContractError("MCP target binding digest is invalid")
            if (
                binding.binding_mode != "exact_ip_enforced"
                or binding.redirect_mode != "disabled"
                or target.type != "ip"
                or len(binding.connection_addresses) != 1
                or binding.connection_addresses[0] != target.canonical_value
            ):
                raise MCPContractError("MCP target binding is not an exact IP")
            try:
                authorized.append(str(ipaddress.ip_address(target.canonical_value)))
            except ValueError as exc:  # pragma: no cover - NormalizedTarget invariant
                raise MCPContractError("MCP authorized target is invalid") from exc
            if "port" in arguments and target.port != arguments["port"]:
                raise MCPContractError("MCP target port binding mismatch")
            if "protocol" in arguments and target.protocol != arguments["protocol"]:
                raise MCPContractError("MCP target protocol binding mismatch")
        if sorted(canonical_arguments) != sorted(authorized):
            raise MCPContractError("MCP destination does not match authorization")

    def reconcile(
        self, execution_id: str, task_binding: ResultTaskBinding | None
    ) -> ReconciliationResult:
        del task_binding
        return ReconciliationResult(
            execution_id=execution_id,
            status="UNSUPPORTED",
            task_binding=None,
            provider_status=None,
            provider_task_id=None,
            observed_at=self._clock.now(),
        )

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome:
        return CancelOutcome(
            execution_id=execution_id,
            provider_task_id=provider_task_id,
            result="FAILED",
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
            "MCP local-result calls have no provider result collection API"
        )

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl:
        del execution_id, task_binding
        raise ResultCollectionError(
            "MCP local-result calls have no provider task control API"
        )

    def _request(
        self,
        request: MCPWireRequest,
        *,
        timeout_seconds: int = MCP_CONTROL_TIMEOUT_SECONDS,
        max_response_bytes: int = MCP_CONTROL_RESPONSE_MAX_BYTES,
    ) -> MCPTransportResponse:
        return self._request_bytes(
            request.to_wire_bytes(),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )

    def _request_bytes(
        self,
        request: bytes,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> MCPTransportResponse:
        if timeout_seconds < 1 or timeout_seconds > 300:
            raise MCPContractError("MCP request timeout is outside policy")
        try:
            response = self._transport.request(
                request,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        except MCPAdapterUnavailableError:
            raise
        except MCPTransportError:
            raise
        except Exception:
            raise MCPTransportError("MCP transport failed at the private boundary") from None
        if len(response.body) > max_response_bytes:
            raise MCPTransportError("MCP response exceeded the fixed size limit")
        return response

    @staticmethod
    def _chunks(value: bytes, size: int) -> Iterable[bytes]:
        for offset in range(0, len(value), size):
            yield value[offset : offset + size]


__all__ = [
    "MCP_CALL_RESPONSE_MAX_BYTES",
    "MCP_CONTROL_RESPONSE_MAX_BYTES",
    "MCP_CONTROL_TIMEOUT_SECONDS",
    "MCP_RESULT_CHUNK_BYTES",
    "MCPAdapter",
]
