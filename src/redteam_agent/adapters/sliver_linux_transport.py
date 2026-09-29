"""One-shot Linux process transport for Sliver operator gRPC/mTLS."""

from __future__ import annotations

import base64
import binascii
import platform
import subprocess
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.adapters.sliver_contract import SliverOperation, SliverWireRequest
from redteam_agent.adapters.sliver_transport import (
    SliverTransportAttestation,
    SliverTransportResponse,
)
from redteam_agent.errors import C2AdapterTransportError
from redteam_agent.models.base import StrictImmutableBoundaryModel

SLIVER_OPERATOR_CONFIG_FILE = (
    "/run/credentials/redteam-agent.service/sliver-operator.cfg"
)
SLIVER_WORKER_MODULE = "redteam_agent.adapters.sliver_worker"
SLIVER_WORKER_PROTOCOL_REVISION = "sliver-worker-ipc-v1"
SLIVER_WORKER_MAX_INPUT_BYTES = 2 * 1024 * 1024
SLIVER_WORKER_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class SliverWorkerRequest(StrictImmutableBoundaryModel):
    protocol_revision: Literal["sliver-worker-ipc-v1"] = "sliver-worker-ipc-v1"
    transport_attestation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: SliverOperation
    request: SliverWireRequest
    operator_name: Literal["joe"] = "joe"
    operator_config_secret_version_id: str = Field(min_length=1, max_length=512)
    operator_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    server_address: str = Field(min_length=1, max_length=255)
    server_port: int = Field(ge=1, le=65535)
    server_tls_name: str = Field(min_length=1, max_length=255)
    ca_certificate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operator_certificate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    timeout_seconds: int = Field(ge=1, le=300)
    max_response_bytes: int = Field(ge=1, le=SLIVER_WORKER_MAX_RESPONSE_BYTES)

    @model_validator(mode="after")
    def _operation_matches_request(self) -> SliverWorkerRequest:
        if self.operation != self.request.operation:
            raise ValueError("Sliver worker operation does not match request")
        return self


class SliverWorkerResponse(StrictImmutableBoundaryModel):
    protocol_revision: Literal["sliver-worker-ipc-v1"] = "sliver-worker-ipc-v1"
    transport_attestation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: SliverOperation
    body_base64: str = Field(max_length=6 * 1024 * 1024)


class SliverLinuxProcessTransport:
    """Run each approved RPC in a fresh process with no secret return path."""

    def __init__(self, attestation: SliverTransportAttestation) -> None:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise C2AdapterTransportError("Sliver worker requires Linux x86_64")
        if attestation.channel_type != "grpc_mtls_direct":
            raise C2AdapterTransportError("Sliver attestation uses another channel")
        self._attestation = attestation

    @property
    def attestation(self) -> SliverTransportAttestation:
        return self._attestation

    def request(
        self,
        request: SliverWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> SliverTransportResponse:
        if timeout_seconds < 1 or timeout_seconds > 300:
            raise C2AdapterTransportError("Sliver worker timeout is outside policy")
        if max_response_bytes < 1 or max_response_bytes > SLIVER_WORKER_MAX_RESPONSE_BYTES:
            raise C2AdapterTransportError("Sliver worker response limit is outside policy")
        attestation = self._attestation
        worker_request = SliverWorkerRequest(
            transport_attestation_digest=attestation.attestation_digest,
            operation=request.operation,
            request=request,
            operator_config_secret_version_id=attestation.operator_config_secret_version_id,
            operator_config_sha256=attestation.operator_config_sha256,
            server_address=attestation.server_address,
            server_port=attestation.server_port,
            server_tls_name=attestation.server_tls_name,
            ca_certificate_sha256=attestation.ca_certificate_sha256,
            operator_certificate_sha256=attestation.operator_certificate_sha256,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        encoded = worker_request.model_dump_json().encode("utf-8")
        if len(encoded) > SLIVER_WORKER_MAX_INPUT_BYTES:
            raise C2AdapterTransportError("Sliver worker request exceeded the IPC limit")
        executable = Path(sys.executable)
        if not executable.is_absolute():
            raise C2AdapterTransportError("Sliver worker Python is not absolute")
        try:
            completed = subprocess.run(  # noqa: S603 - fixed interpreter/module, no shell
                [str(executable), "-I", "-m", SLIVER_WORKER_MODULE],
                input=encoded,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout_seconds + 5,
                cwd="/",
                env={"PYTHONUTF8": "1"},
                close_fds=True,
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise C2AdapterTransportError("Sliver worker process failed") from exc
        if completed.returncode != 0:
            raise C2AdapterTransportError("Sliver worker rejected the provider request")
        if len(completed.stdout) > 6 * 1024 * 1024:
            raise C2AdapterTransportError("Sliver worker IPC response exceeded the limit")
        try:
            response = SliverWorkerResponse.from_untrusted_json(completed.stdout)
            body = base64.b64decode(response.body_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise C2AdapterTransportError("Sliver worker returned an invalid response") from exc
        except Exception as exc:
            raise C2AdapterTransportError("Sliver worker response validation failed") from exc
        if (
            response.transport_attestation_digest != attestation.attestation_digest
            or response.operation != request.operation
            or len(body) > max_response_bytes
        ):
            raise C2AdapterTransportError("Sliver worker response binding mismatch")
        return SliverTransportResponse(body)


__all__ = [
    "SLIVER_OPERATOR_CONFIG_FILE",
    "SLIVER_WORKER_MAX_INPUT_BYTES",
    "SLIVER_WORKER_MAX_RESPONSE_BYTES",
    "SLIVER_WORKER_MODULE",
    "SLIVER_WORKER_PROTOCOL_REVISION",
    "SliverLinuxProcessTransport",
    "SliverWorkerRequest",
    "SliverWorkerResponse",
]
