"""One-shot stdio MCP server exposing a closed read-only Impacket surface."""

from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, NoReturn, cast

from redteam_agent.adapters.mcp import MCP_PROTOCOL_REVISION
from redteam_agent.adapters.mcp_contract import MCP_EPHEMERAL_SECRET_META_KEY
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.json_boundary import parse_json_no_duplicate_keys
from redteam_agent.errors import MCPContractError, ParameterSchemaError
from redteam_agent.mcp_servers.impacket_backend import (
    FortraImpacketBackend,
    ImpacketBackend,
    ImpacketBackendError,
    ImpacketCredential,
    validate_ntlm_hash,
)
from redteam_agent.mcp_servers.impacket_catalog import (
    IMPACKET_MCP_SERVER_NAME,
    IMPACKET_MCP_SERVER_VERSION,
    IMPACKET_TOOL_METADATA,
    IMPACKET_TOOL_SCHEMAS,
)
from redteam_agent.tools.parameter_schema import validate_arguments

IMPACKET_MCP_MAX_REQUEST_BYTES = 1024 * 1024
IMPACKET_MCP_MAX_TARGETS = 16
_CORE_META = {
    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_REVISION,
    "io.modelcontextprotocol/clientInfo": {
        "name": "redteam-agent",
        "version": "phase5-offline-v1",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}


class _SecretEnvelope:
    __slots__ = ("argument_path", "material", "secret_version_id")

    def __init__(
        self, *, argument_path: str, secret_version_id: str, material: bytearray
    ) -> None:
        self.argument_path = argument_path
        self.secret_version_id = secret_version_id
        self.material = material

    def zeroize(self) -> None:
        for index in range(len(self.material)):
            self.material[index] = 0

    def __repr__(self) -> str:
        return "<_SecretEnvelope material=<redacted>>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("MCP secret envelope is not serializable")


@dataclass(frozen=True)
class ImpacketServerPolicy:
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    max_targets: int = IMPACKET_MCP_MAX_TARGETS

    @classmethod
    def from_strings(cls, values: Sequence[str]) -> ImpacketServerPolicy:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for value in values:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise ValueError("invalid Impacket MCP target allowlist") from exc
        return cls(allowed_networks=tuple(networks))

    def authorize(self, destinations: object) -> tuple[str, ...]:
        if (
            not isinstance(destinations, list)
            or not destinations
            or len(destinations) > self.max_targets
            or not self.allowed_networks
        ):
            raise MCPContractError("Impacket MCP target set is not authorized")
        canonical: list[str] = []
        for raw in destinations:
            if type(raw) is not str:
                raise MCPContractError("Impacket MCP target must be an IP address")
            try:
                address = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise MCPContractError("Impacket MCP target must be an IP address") from exc
            if raw != str(address):
                raise MCPContractError("Impacket MCP target must be canonical")
            if not any(address in network for network in self.allowed_networks):
                raise MCPContractError("Impacket MCP target is outside the fixed allowlist")
            canonical.append(raw)
        if len(canonical) != len(set(canonical)):
            raise MCPContractError("Impacket MCP target set contains duplicates")
        return tuple(canonical)

    def audit_hook(self, event: str, args: tuple[object, ...]) -> None:
        """Deny Python socket connects outside fixed lab CIDRs and ports.

        The hook is installed only in the one-shot server process.  It is an
        additional application-level control; Production still requires an
        independent OS/vCenter egress policy and attestation.
        """

        if event != "socket.connect":
            return
        address = args[1] if len(args) > 1 else None
        if not isinstance(address, tuple) or len(address) < 2:
            raise PermissionError("Impacket MCP egress denied")
        host, port = address[0], address[1]
        if type(host) is not str or type(port) is not int or port not in {135, 445}:
            raise PermissionError("Impacket MCP egress denied")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise PermissionError("Impacket MCP egress denied") from exc
        if not any(ip in network for network in self.allowed_networks):
            raise PermissionError("Impacket MCP egress denied")


class ImpacketMCPServer:
    """Strict JSON-RPC handler with no arbitrary Impacket dispatch path."""

    def __init__(self, *, policy: ImpacketServerPolicy, backend: ImpacketBackend) -> None:
        self._policy = policy
        self._backend = backend

    def handle(self, request_bytes: bytes) -> bytes:
        request = self._parse_request(request_bytes)
        request_id = request["id"]
        method = request["method"]
        params = request["params"]
        secrets = self._validate_meta(params, allow_secrets=method == "tools/call")
        try:
            if method == "server/discover":
                self._require_exact_keys(params, {"_meta"})
                result = self._discover()
            elif method == "tools/list":
                self._require_exact_keys(params, {"_meta"})
                result = self._tools_list()
            elif method == "tools/call":
                self._require_exact_keys(params, {"name", "arguments", "_meta"})
                result = self._tools_call(params, secrets)
            else:
                raise MCPContractError("Impacket MCP method is not implemented")
        finally:
            for secret in secrets:
                secret.zeroize()
        return canonical_dumps({"jsonrpc": "2.0", "id": request_id, "result": result})

    @staticmethod
    def _parse_request(request_bytes: bytes) -> dict[str, Any]:
        if not request_bytes or len(request_bytes) > IMPACKET_MCP_MAX_REQUEST_BYTES:
            raise MCPContractError("Impacket MCP request size is invalid")
        try:
            request = parse_json_no_duplicate_keys(request_bytes)
        except Exception as exc:
            raise MCPContractError("Impacket MCP request is malformed") from exc
        if not isinstance(request, dict) or set(request) != {
            "jsonrpc",
            "id",
            "method",
            "params",
        }:
            raise MCPContractError("Impacket MCP request envelope is invalid")
        if (
            request["jsonrpc"] != "2.0"
            or type(request["id"]) is not int
            or request["id"] < 1
            or type(request["method"]) is not str
            or not isinstance(request["params"], dict)
        ):
            raise MCPContractError("Impacket MCP request binding is invalid")
        return request

    @staticmethod
    def _require_exact_keys(value: dict[str, Any], expected: set[str]) -> None:
        if set(value) != expected:
            raise MCPContractError("Impacket MCP parameters are not exact")

    @staticmethod
    def _validate_meta(
        params: dict[str, Any], *, allow_secrets: bool
    ) -> tuple[_SecretEnvelope, ...]:
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            raise MCPContractError("Impacket MCP metadata is missing")
        allowed_keys = set(_CORE_META)
        if allow_secrets:
            allowed_keys.add(MCP_EPHEMERAL_SECRET_META_KEY)
        if set(meta) - allowed_keys or any(meta.get(key) != value for key, value in _CORE_META.items()):
            raise MCPContractError("Impacket MCP metadata is invalid")
        raw_secrets = meta.get(MCP_EPHEMERAL_SECRET_META_KEY, [])
        if not allow_secrets and raw_secrets:
            raise MCPContractError("Impacket MCP control requests cannot carry secrets")
        if not isinstance(raw_secrets, list) or len(raw_secrets) > 1:
            raise MCPContractError("Impacket MCP secret binding count is invalid")
        secrets: list[_SecretEnvelope] = []
        try:
            for raw in raw_secrets:
                if not isinstance(raw, dict) or set(raw) != {
                    "argumentPath",
                    "secretVersionId",
                    "encoding",
                    "material",
                }:
                    raise MCPContractError("Impacket MCP secret envelope is invalid")
                if (
                    raw["argumentPath"] != "/credential"
                    or type(raw["secretVersionId"]) is not str
                    or not raw["secretVersionId"]
                    or raw["encoding"] != "base64"
                    or type(raw["material"]) is not str
                ):
                    raise MCPContractError("Impacket MCP secret binding is invalid")
                try:
                    material = bytearray(base64.b64decode(raw["material"], validate=True))
                except (ValueError, binascii.Error) as exc:
                    raise MCPContractError("Impacket MCP secret encoding is invalid") from exc
                if not material or len(material) > 64 * 1024:
                    for index in range(len(material)):
                        material[index] = 0
                    raise MCPContractError("Impacket MCP secret size is invalid")
                secrets.append(
                    _SecretEnvelope(
                        argument_path=raw["argumentPath"],
                        secret_version_id=raw["secretVersionId"],
                        material=material,
                    )
                )
        except Exception:
            for secret in secrets:
                secret.zeroize()
            raise
        return tuple(secrets)

    @staticmethod
    def _discover() -> dict[str, object]:
        return {
            "resultType": "complete",
            "supportedVersions": [MCP_PROTOCOL_REVISION],
            "capabilities": {"tools": {"listChanged": False}},
            "ttlMs": 0,
            "cacheScope": "private",
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": IMPACKET_MCP_SERVER_NAME,
                    "version": IMPACKET_MCP_SERVER_VERSION,
                }
            },
        }

    @staticmethod
    def _tools_list() -> dict[str, object]:
        tools = []
        for name in sorted(IMPACKET_TOOL_SCHEMAS):
            title, description = IMPACKET_TOOL_METADATA[name]
            tools.append(
                {
                    "name": name,
                    "title": title,
                    "description": description,
                    "inputSchema": IMPACKET_TOOL_SCHEMAS[name],
                }
            )
        return {
            "resultType": "complete",
            "tools": tools,
            "ttlMs": 0,
            "cacheScope": "private",
        }

    def _tools_call(
        self, params: dict[str, Any], secrets: tuple[_SecretEnvelope, ...]
    ) -> dict[str, object]:
        name = params["name"]
        arguments = params["arguments"]
        if type(name) is not str or name not in IMPACKET_TOOL_SCHEMAS or not isinstance(arguments, dict):
            raise MCPContractError("Impacket MCP tool call is not approved")
        try:
            validate_arguments(IMPACKET_TOOL_SCHEMAS[name], arguments)
        except ParameterSchemaError as exc:
            raise MCPContractError("Impacket MCP tool arguments are invalid") from exc
        destinations = self._policy.authorize(arguments["destinations"])
        credential = self._credential(arguments, secrets)
        results: list[dict[str, object]] = []
        failed = False
        for target in destinations:
            try:
                results.append(
                    {
                        "target": target,
                        "status": "ok",
                        "result": self._dispatch(name, target, arguments, credential),
                    }
                )
            except ImpacketBackendError as exc:
                failed = True
                results.append({"target": target, "status": "error", "error_code": exc.code})
        payload = canonical_dumps(
            {
                "tool": name,
                "result_count": len(results),
                "results": results,
            }
        ).decode("utf-8")
        return {
            "resultType": "complete",
            "content": [{"type": "text", "text": payload}],
            "isError": failed,
        }

    @staticmethod
    def _credential(
        arguments: dict[str, Any], secrets: tuple[_SecretEnvelope, ...]
    ) -> ImpacketCredential | None:
        reference = arguments.get("credential")
        if reference is None:
            if secrets:
                raise MCPContractError("Impacket MCP tool does not accept a credential")
            return None
        if len(secrets) != 1 or not isinstance(reference, dict):
            raise MCPContractError("Impacket MCP credential binding is missing")
        envelope = secrets[0]
        if envelope.secret_version_id != reference.get("secret_version_id"):
            raise MCPContractError("Impacket MCP credential version does not match")
        try:
            decoded = parse_json_no_duplicate_keys(bytes(envelope.material))
        except Exception as exc:
            raise MCPContractError("Impacket MCP credential material is malformed") from exc
        credential_type = reference.get("credential_type")
        if credential_type == "password":
            expected = {"username", "password", "domain"}
        elif credential_type == "ntlm_hash":
            expected = {"username", "lmhash", "nthash", "domain"}
        else:  # schema validation should make this unreachable
            raise MCPContractError("Impacket MCP credential type is unsupported")
        if not isinstance(decoded, dict) or set(decoded) != expected:
            raise MCPContractError("Impacket MCP credential material shape is invalid")
        if any(type(decoded[key]) is not str for key in expected):
            raise MCPContractError("Impacket MCP credential values are invalid")
        username = cast(str, decoded["username"])
        domain = cast(str, decoded["domain"])
        if (
            not username
            or len(username) > 256
            or len(domain) > 256
        ):
            raise MCPContractError("Impacket MCP credential identity is invalid")
        if credential_type == "password":
            password = cast(str, decoded["password"])
            if not password or len(password) > 4096:
                raise MCPContractError("Impacket MCP password credential is invalid")
            return ImpacketCredential(
                credential_type=credential_type,
                username=username,
                password=password,
                domain=domain,
            )
        lmhash = cast(str, decoded["lmhash"])
        nthash = cast(str, decoded["nthash"])
        if not validate_ntlm_hash(lmhash) or not validate_ntlm_hash(nthash):
            raise MCPContractError("Impacket MCP NTLM credential is invalid")
        return ImpacketCredential(
            credential_type=credential_type,
            username=username,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
        )

    def _dispatch(
        self,
        name: str,
        target: str,
        arguments: dict[str, Any],
        credential: ImpacketCredential | None,
    ) -> dict[str, object]:
        port = arguments["port"]
        timeout = arguments["timeout_seconds"]
        if name == "impacket.smb.negotiate":
            return self._backend.smb_negotiate(target, port, timeout)
        if name == "impacket.rpc.endpoint_map":
            return self._backend.rpc_endpoint_map(target, port, timeout)
        if credential is None:  # pragma: no cover - credential contract above
            raise MCPContractError("Impacket MCP credential is unavailable")
        if name == "impacket.smb.authenticate":
            return self._backend.smb_authenticate(target, port, timeout, credential)
        if name == "impacket.smb.list_shares":
            return self._backend.smb_list_shares(target, port, timeout, credential)
        raise MCPContractError("Impacket MCP tool dispatch is closed")


def _error_response(request_id: int | None, code: str) -> bytes:
    return canonical_dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32600, "message": code},
        }
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Fortra Impacket MCP server")
    parser.add_argument(
        "--allow-target",
        action="append",
        default=[],
        help="Allowed IP or CIDR; repeat for additional isolated-lab ranges",
    )
    parser.add_argument("--version", action="version", version=IMPACKET_MCP_SERVER_VERSION)
    args = parser.parse_args(argv)
    try:
        policy = ImpacketServerPolicy.from_strings(args.allow_target)
    except ValueError:
        return 2
    sys.addaudithook(policy.audit_hook)
    raw = sys.stdin.buffer.readline(IMPACKET_MCP_MAX_REQUEST_BYTES + 2)
    if len(raw) > IMPACKET_MCP_MAX_REQUEST_BYTES + 1:
        sys.stdout.buffer.write(_error_response(None, "REQUEST_TOO_LARGE") + b"\n")
        return 1
    server = ImpacketMCPServer(policy=policy, backend=FortraImpacketBackend())
    try:
        response = server.handle(raw)
    except Exception:
        response = _error_response(None, "INVALID_OR_FAILED_REQUEST")
    sys.stdout.buffer.write(response + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())


__all__ = [
    "IMPACKET_MCP_MAX_REQUEST_BYTES",
    "IMPACKET_MCP_MAX_TARGETS",
    "ImpacketMCPServer",
    "ImpacketServerPolicy",
    "main",
]
