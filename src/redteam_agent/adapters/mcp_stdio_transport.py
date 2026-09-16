"""Bounded one-shot stdio process transport for an attested local MCP server."""

from __future__ import annotations

import hashlib
import os
import resource
import selectors
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path

from redteam_agent.adapters.mcp import MCPTransportIdentity
from redteam_agent.adapters.mcp_transport import (
    MCPTransportAttestation,
    MCPTransportResponse,
)
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.errors import MCPTransportError, MCPTransportIdentityMismatchError

MCP_STDIO_REQUEST_MAX_BYTES = 1024 * 1024
_FIXED_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONUNBUFFERED": "1",
}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise MCPTransportIdentityMismatchError(
            "MCP executable identity cannot be measured"
        ) from exc
    return digest.hexdigest()


def _command_digest(argv: tuple[str, ...]) -> str:
    return hashlib.sha256(
        canonical_dumps(
            {
                "argv": list(argv),
                "environment": _FIXED_ENVIRONMENT,
                "working_directory": "/",
                "shell": False,
                "one_request_per_process": True,
            }
        )
    ).hexdigest()


def inspect_mcp_stdio_identities(
    *, argv: tuple[str, ...], package_version: str
) -> tuple[MCPTransportIdentity, ...]:
    """Measure the complete identity tuple required by ``MCPServerConfig``."""

    if not argv or not package_version:
        raise MCPTransportIdentityMismatchError("MCP stdio command identity is incomplete")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise MCPTransportIdentityMismatchError("MCP stdio executable must be absolute")
    try:
        resolved = executable.resolve(strict=True)
    except OSError as exc:
        raise MCPTransportIdentityMismatchError("MCP stdio executable does not exist") from exc
    if str(resolved) != argv[0] or not resolved.is_file():
        raise MCPTransportIdentityMismatchError(
            "MCP stdio executable path must be resolved and canonical"
        )
    return (
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="executable_path",
            identity_value=str(resolved),
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="executable_sha256",
            identity_value=_file_sha256(resolved),
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="command_configuration_digest",
            identity_value=_command_digest(argv),
        ),
        MCPTransportIdentity(
            transport_type="stdio",
            identity_type="package_version",
            identity_value=package_version,
        ),
    )


class MCPStdioProcessTransport:
    """Launch an exact executable without a shell for one JSON-RPC request.

    Process output, elapsed time, address space, file size, CPU, and inherited
    descriptors are bounded.  The fixed command (including target allowlist) is
    covered by the transport identity digest; request values cannot change it.
    """

    def __init__(
        self,
        *,
        argv: tuple[str, ...],
        package_version: str,
        attestation: MCPTransportAttestation,
    ) -> None:
        if (
            attestation.transport != "stdio"
            or attestation.execution_location != "local_process"
        ):
            raise MCPTransportIdentityMismatchError(
                "MCP stdio transport received a non-local attestation"
            )
        measured = inspect_mcp_stdio_identities(
            argv=argv, package_version=package_version
        )
        if measured != attestation.verified_transport_identities:
            raise MCPTransportIdentityMismatchError(
                "MCP stdio runtime identity does not match attestation"
            )
        self._argv = argv
        self._package_version = package_version
        self._verified_identities = measured
        self._attestation = attestation

    @property
    def attestation(self) -> MCPTransportAttestation:
        return self._attestation

    def request(
        self,
        request: bytes,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> MCPTransportResponse:
        if (
            type(request) is not bytes
            or not request
            or len(request) > MCP_STDIO_REQUEST_MAX_BYTES
            or timeout_seconds < 1
            or timeout_seconds > 300
            or max_response_bytes < 1
        ):
            raise MCPTransportError("MCP stdio request bounds are invalid")
        process: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        try:
            self._verify_runtime_identity()
            process = subprocess.Popen(  # noqa: S603 - exact attested argv, shell disabled
                self._argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd="/",
                env=dict(_FIXED_ENVIRONMENT),
                close_fds=True,
                start_new_session=True,
                preexec_fn=lambda: _set_process_limits(max_response_bytes, timeout_seconds),
            )
            # A post-spawn measurement closes replacement between the preflight
            # check and exec.  Replacement after exec cannot change this process
            # image; it only invalidates subsequent requests.
            self._verify_runtime_identity()
            if process.stdin is None or process.stdout is None:  # pragma: no cover
                raise MCPTransportError("MCP stdio pipes are unavailable")
            deadline = time.monotonic() + timeout_seconds
            payload = request + b"\n"
            written = 0
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            output = bytearray()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MCPTransportError("MCP stdio request timed out")
                events = selector.select(min(remaining, 0.25))
                for key, _ in events:
                    if key.data == "stdin":
                        try:
                            written += os.write(key.fd, payload[written:])
                        except BlockingIOError:
                            continue
                        except (BrokenPipeError, OSError) as exc:
                            raise MCPTransportError(
                                "MCP stdio request delivery failed"
                            ) from exc
                        if written == len(payload):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                        continue
                    chunk = os.read(
                        key.fd,
                        min(64 * 1024, max_response_bytes - len(output) + 1),
                    )
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > max_response_bytes:
                        raise MCPTransportError(
                            "MCP stdio response exceeded its fixed bound"
                        )
            return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
            if return_code != 0 or not output:
                raise MCPTransportError("MCP stdio server failed without trusted diagnostics")
            return MCPTransportResponse(bytes(output))
        except MCPTransportError:
            if process is not None and process.poll() is None:
                _terminate_process_group(process)
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            if process is not None and process.poll() is None:
                _terminate_process_group(process)
            raise MCPTransportError("MCP stdio transport failed") from exc
        finally:
            selector.close()
            if process is not None and process.poll() is None:
                _terminate_process_group(process)

    def _verify_runtime_identity(self) -> None:
        measured = inspect_mcp_stdio_identities(
            argv=self._argv, package_version=self._package_version
        )
        if measured != self._verified_identities:
            raise MCPTransportIdentityMismatchError(
                "MCP stdio runtime identity changed after attestation"
            )


def _set_process_limits(max_response_bytes: int, timeout_seconds: int) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    file_size = max_response_bytes + 4096
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))
    address_space = 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    cpu_seconds = max(2, timeout_seconds + 1)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=2)


__all__ = [
    "MCP_STDIO_REQUEST_MAX_BYTES",
    "MCPStdioProcessTransport",
    "inspect_mcp_stdio_identities",
]
