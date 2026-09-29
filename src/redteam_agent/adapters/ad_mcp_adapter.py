"""Provider-job adapter for the official-SDK AD MCP server."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import MCPContractError, ResultCollectionError
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
from redteam_agent.policy.target_binding import build_target_dispatch_binding
from redteam_agent.runtime.clock import Clock

AD_MCP_CATALOG_REVISION = "ad-mcp-catalog-v1"
AD_MCP_ADAPTER_ID = "mcp-ad-local"
AD_MCP_RESULT_MAX_BYTES = 16 * 1024 * 1024


class AdMcpClientPort(Protocol):
    def list_tools(self, *, timeout_seconds: float = 15) -> dict[str, dict[str, object]]: ...

    def call_tool(
        self,
        name: str,
        arguments: dict[str, object],
        authorization: dict[str, object],
        secret_bindings: tuple[dict[str, str], ...] = (),
        *,
        timeout_seconds: float = 30,
    ) -> dict[str, object]: ...

    def encode_secret(
        self, *, argument_name: str, secret_version_id: str, material: bytes
    ) -> dict[str, str]: ...


class _BindingStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS ad_mcp_bindings (
                    execution_id TEXT PRIMARY KEY,
                    provider_task_id TEXT NOT NULL UNIQUE,
                    actor_id TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    approval_id TEXT
                )"""
            )
        os.chmod(self._path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def create(
        self,
        *,
        execution_id: str,
        provider_task_id: str,
        actor_id: str,
        mission_id: str,
        approval_id: str | None,
    ) -> None:
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO ad_mcp_bindings VALUES (?, ?, ?, ?, ?)",
                    (execution_id, provider_task_id, actor_id, mission_id, approval_id),
                )
            except sqlite3.IntegrityError as exc:
                raise MCPContractError("AD MCP execution is already bound") from exc

    def get(self, execution_id: str, provider_task_id: str) -> sqlite3.Row:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ad_mcp_bindings WHERE execution_id=? AND provider_task_id=?",
                (execution_id, provider_task_id),
            ).fetchone()
        if row is None:
            raise MCPContractError("AD MCP task binding is unknown")
        return cast(sqlite3.Row, row)


class AdMcpAdapter:
    """Connect the authorization kernel to one persistent local AD MCP server."""

    def __init__(
        self,
        *,
        client: AdMcpClientPort,
        approved_tool_schemas: Mapping[str, Mapping[str, object]],
        state_db: Path,
        clock: Clock,
        digest_service: DigestService,
        adapter_id: str = AD_MCP_ADAPTER_ID,
        adapter_identity_digest: str,
        provider_identity_digest: str,
    ) -> None:
        if not approved_tool_schemas:
            raise MCPContractError("AD MCP approved tool catalog is empty")
        self._client = client
        self._approved = {
            name: dict(schema) for name, schema in approved_tool_schemas.items()
        }
        self._store = _BindingStore(state_db)
        self._clock = clock
        self._digest_service = digest_service
        self._adapter_id = adapter_id
        self._adapter_identity_digest = adapter_identity_digest
        self._provider_identity_digest = provider_identity_digest
        self._verify_catalog()

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(
            adapter_id=self._adapter_id,
            adapter_identity_digest=self._adapter_identity_digest,
            provider_identity_digest=self._provider_identity_digest,
            result_delivery_mode="provider_task",
        )

    def get_capabilities(self) -> AdapterCapabilities:
        self._verify_catalog()
        capabilities = {
            "server.initialize",
            "tools.list",
            "tools.call",
            "provider_task",
            "provider_task.cancel",
            "provider_task.reconcile",
        }
        capabilities.update(f"mcp.tool:{name}:{AD_MCP_CATALOG_REVISION}" for name in self._approved)
        return AdapterCapabilities(
            adapter_id=self._adapter_id,
            adapter_type="mcp",
            execution_location="local_process",
            capability_revision="ad-mcp-capabilities-v1",
            capabilities=frozenset(capabilities),
            supported_os=frozenset({"windows", "linux"}),
            supported_architectures=frozenset({"x86_64", "amd64"}),
            reconciliation=True,
            cancellation=True,
            provider_deduplication=True,
            result_streaming=False,
            result_resume=False,
            durable_result_collection=True,
            result_delivery_mode="provider_task",
            target_binding_modes=frozenset({"exact_ip_enforced"}),
            redirect_disable_enforcement=False,
            policy_intercepted_redirect=False,
            max_output_bytes=AD_MCP_RESULT_MAX_BYTES,
            provider_tool_catalog_digest=_digest(self._approved),
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
            request.adapter_id != self._adapter_id
            or request.result_delivery_mode != "provider_task"
            or result_capture.mode != "provider_task"
            or result_capture.sink is not None
            or idempotency_key != request.idempotency_key
        ):
            raise MCPContractError("AD MCP submit binding is invalid")
        if request.mission_id is None or request.actor_id is None:
            raise MCPContractError("AD MCP authorization context is missing")
        if request.provider_tool_name not in self._approved:
            raise MCPContractError("AD MCP operation is not approved")
        arguments = thaw(request.arguments)
        self._verify_targets(arguments, request)
        encoded_secrets = self._encode_secrets(secret_bindings)
        response = self._client.call_tool(
            request.provider_tool_name,
            cast(dict[str, object], arguments),
            self._authorization(request),
            encoded_secrets,
            timeout_seconds=min(float(request.timeout_seconds), 30.0),
        )
        job = _require_job_response(response, request.execution_id)
        provider_task_id = str(job["job_id"])
        self._store.create(
            execution_id=request.execution_id,
            provider_task_id=provider_task_id,
            actor_id=request.actor_id,
            mission_id=request.mission_id,
            approval_id=request.approval_id,
        )
        identity = self.identity()
        return TaskHandle(
            task_id=request.task_id,
            result_delivery_mode="provider_task",
            provider_task_id=provider_task_id,
            adapter_identity_digest=identity.adapter_identity_digest,
            provider_identity_digest=identity.provider_identity_digest,
        )

    def reconcile(
        self, execution_id: str, task_binding: ResultTaskBinding | None
    ) -> ReconciliationResult:
        if not isinstance(task_binding, ProviderTaskBinding):
            return ReconciliationResult(
                execution_id=execution_id,
                status="UNKNOWN",
                task_binding=None,
                provider_status=None,
                provider_task_id=None,
                observed_at=self._clock.now(),
            )
        binding = self._require_binding(execution_id, task_binding)
        try:
            job = self._get_job(execution_id, binding.provider_task_id)
        except Exception:
            return ReconciliationResult(
                execution_id=execution_id,
                status="UNKNOWN",
                task_binding=None,
                provider_status=None,
                provider_task_id=binding.provider_task_id,
                observed_at=self._clock.now(),
            )
        terminal = _provider_status(str(job["state"]))
        return ReconciliationResult(
            execution_id=execution_id,
            status="FOUND_TERMINAL" if terminal is not None else "FOUND_RUNNING",
            task_binding=binding if terminal is not None else None,
            provider_status=terminal,
            provider_task_id=binding.provider_task_id,
            observed_at=self._clock.now(),
        )

    def cancel(self, execution_id: str, provider_task_id: str) -> CancelOutcome:
        row = self._store.get(execution_id, provider_task_id)
        response = self._client.call_tool(
            "job.cancel",
            {"job_id": provider_task_id},
            self._authorization_from_row(row),
        )
        state = str(response.get("state", ""))
        result: Literal["ACKNOWLEDGED", "CONFIRMED", "UNKNOWN", "FAILED"]
        if state == "cancelled":
            result = "CONFIRMED"
        elif state in {"queued", "running"}:
            result = "ACKNOWLEDGED"
        elif state == "outcome_unknown":
            result = "UNKNOWN"
        else:
            result = "FAILED"
        return CancelOutcome(
            execution_id=execution_id,
            provider_task_id=provider_task_id,
            result=result,
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
        if resume is not None:
            raise ResultCollectionError("AD MCP result resume is not supported")
        if cancellation is not None:
            raise ResultCollectionError("AD MCP collection was cancelled before read")
        binding = self._require_binding(execution_id, task_binding)
        job = self._get_job(execution_id, binding.provider_task_id)
        control = self._control(job)
        result = job.get("result")
        if not isinstance(result, dict):
            raise ResultCollectionError("AD MCP terminal result is missing")
        payload = canonical_dumps(result)
        if len(payload) > AD_MCP_RESULT_MAX_BYTES:
            raise ResultCollectionError("AD MCP public result exceeded its bound")
        sink.write_stdout(payload)
        return control

    def get_task_control(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> AdapterCollectionControl:
        binding = self._require_binding(execution_id, task_binding)
        return self._control(self._get_job(execution_id, binding.provider_task_id))

    def _verify_catalog(self) -> None:
        live = self._client.list_tools()
        for name, expected in self._approved.items():
            if live.get(name) != expected:
                raise MCPContractError("AD MCP live catalog does not match the approved schema")

    def _require_binding(
        self, execution_id: str, task_binding: ResultTaskBinding
    ) -> ProviderTaskBinding:
        if isinstance(task_binding, LocalResultBinding):
            raise MCPContractError("AD MCP requires a provider task binding")
        identity = self.identity()
        if (
            task_binding.execution_id != execution_id
            or task_binding.adapter_identity_digest != identity.adapter_identity_digest
            or task_binding.provider_identity_digest != identity.provider_identity_digest
        ):
            raise MCPContractError("AD MCP task identity mismatch")
        self._store.get(execution_id, task_binding.provider_task_id)
        return task_binding

    def _get_job(self, execution_id: str, provider_task_id: str) -> dict[str, object]:
        row = self._store.get(execution_id, provider_task_id)
        return self._client.call_tool(
            "job.get_status",
            {"job_id": provider_task_id},
            self._authorization_from_row(row),
        )

    def _authorization(self, request: ExecutionRequest) -> dict[str, object]:
        assert request.actor_id is not None and request.mission_id is not None
        return {
            "actor_id": request.actor_id,
            "mission_id": request.mission_id,
            "execution_id": request.execution_id,
            "approval_id": request.approval_id,
            "catalog_revision": AD_MCP_CATALOG_REVISION,
        }

    @staticmethod
    def _authorization_from_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "actor_id": row["actor_id"],
            "mission_id": row["mission_id"],
            "execution_id": row["execution_id"],
            "approval_id": row["approval_id"],
            "catalog_revision": AD_MCP_CATALOG_REVISION,
        }

    def _encode_secrets(
        self, secret_bindings: tuple[EphemeralSecretBinding, ...]
    ) -> tuple[dict[str, str], ...]:
        encoded: list[dict[str, str]] = []
        for binding in secret_bindings:
            name = binding.secret_argument_path.rsplit("/", maxsplit=1)[-1]
            if not name or name == binding.secret_argument_path:
                raise MCPContractError("AD MCP secret argument path is invalid")
            encoded.append(
                self._client.encode_secret(
                    argument_name=name,
                    secret_version_id=binding.secret_version_id,
                    material=binding.consume(),
                )
            )
        return tuple(encoded)

    def _verify_targets(self, arguments: dict[str, Any], request: ExecutionRequest) -> None:
        call = arguments.get("call")
        if not isinstance(call, dict):
            raise MCPContractError("AD MCP call envelope is invalid")
        targets = call.get("targets")
        if not isinstance(targets, list) or any(type(value) is not str for value in targets):
            raise MCPContractError("AD MCP targets are invalid")
        authorized: list[str] = []
        for binding in request.target_dispatch_bindings:
            expected = build_target_dispatch_binding(
                normalized_target=binding.normalized_target,
                binding_mode=binding.binding_mode,
                connection_addresses=binding.connection_addresses,
                digest_service=self._digest_service,
            )
            if expected != binding:
                raise MCPContractError("AD MCP target binding digest is invalid")
            target = binding.normalized_target
            if (
                binding.binding_mode != "exact_ip_enforced"
                or binding.redirect_mode != "disabled"
                or target.type != "ip"
                or len(binding.connection_addresses) != 1
            ):
                raise MCPContractError("AD MCP target binding is not an exact IP")
            authorized.append(str(ipaddress.ip_address(target.canonical_value)))
        if sorted(cast(list[str], targets)) != sorted(authorized):
            raise MCPContractError("AD MCP targets do not match authorization")

    @staticmethod
    def _control(job: dict[str, object]) -> AdapterCollectionControl:
        state = str(job.get("state", ""))
        status = _provider_status(state)
        if status is None:
            raise ResultCollectionError("AD MCP job is not terminal")
        try:
            started_at = datetime.fromisoformat(str(job["created_at"]))
            finished_at = datetime.fromisoformat(str(job["updated_at"]))
        except (KeyError, ValueError) as exc:
            raise ResultCollectionError("AD MCP job timestamps are invalid") from exc
        result = job.get("result")
        exit_code = result.get("exit_code") if isinstance(result, dict) else None
        if exit_code is not None and type(exit_code) is not int:
            raise ResultCollectionError("AD MCP exit code is invalid")
        return AdapterCollectionControl(
            provider_status=status,
            exit_code=exit_code,
            timed_out=state == "timed_out",
            started_at=started_at,
            finished_at=finished_at,
            status_normalization_rule_id="ad-mcp-job-v1",
        )


def _require_job_response(response: dict[str, object], execution_id: str) -> dict[str, object]:
    if response.get("result_type") != "job" or not isinstance(response.get("job"), dict):
        raise MCPContractError("AD MCP did not return a provider job")
    job = cast(dict[str, object], response["job"])
    if (
        job.get("execution_id") != execution_id
        or not isinstance(job.get("job_id"), str)
        or job.get("state") not in {"queued", "running"}
    ):
        raise MCPContractError("AD MCP provider job binding is invalid")
    return job


def _provider_status(
    state: str,
) -> Literal["succeeded", "failed", "cancelled"] | None:
    if state == "succeeded":
        return "succeeded"
    if state == "cancelled":
        return "cancelled"
    if state in {"failed", "timed_out"}:
        return "failed"
    return None


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_dumps(value)).hexdigest()


__all__ = [
    "AD_MCP_ADAPTER_ID",
    "AD_MCP_CATALOG_REVISION",
    "AdMcpAdapter",
    "AdMcpClientPort",
]
