"""Dependency-free HTTP server with explicit and local-interface origin gates."""

from __future__ import annotations

import argparse
import fcntl
import json
import mimetypes
import os
import re
import socket
import struct
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from redteam_agent.ad_assessment.models import ADAssessmentSnapshot
from redteam_agent.errors import AuthorizationKernelError
from redteam_agent.ui.auth import (
    DEFAULT_SESSION_TTL_SECONDS,
    OperatorSessionAuthenticator,
    UIAuthenticationError,
    read_operator_token,
)
from redteam_agent.ui.control_plane import (
    UIActionBlockedError,
    UIConflictError,
    UIControlPlane,
    UIControlPlaneError,
)
from redteam_agent.ui.models import (
    ADAssessmentCollectionInput,
    ADAssessmentRecommendationInput,
    ApprovalDecisionInput,
    CandidateSelectionInput,
    MissionCreateInput,
    MissionDraftInput,
    MissionTransitionInput,
    OperatorLoginInput,
    ProviderPolicyDraftInput,
    VllmCandidateInput,
    VllmCandidateVersionInput,
    VllmConfigInput,
)

_MAX_REQUEST_BYTES = 1_048_576
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
_SESSION_COOKIE = "redteam_operator_session"
DIRECT_EXTERNAL_BIND_HOST = "0.0.0.0"  # noqa: S104 - explicit direct-access mode with origin gates
_RFC1918_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
_SIOCGIFADDR = 0x8915


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: object
    headers: tuple[tuple[str, str], ...] = ()


class UIRouter:
    def __init__(
        self,
        control_plane: UIControlPlane,
        authenticator: OperatorSessionAuthenticator | None = None,
    ) -> None:
        self._control_plane = control_plane
        self._authenticator = authenticator

    def dispatch(
        self,
        *,
        method: str,
        path: str,
        body: bytes = b"",
        session_id: str | None = None,
    ) -> ApiResponse:
        if method == "GET" and path == "/api/v1/health":
            return ApiResponse(HTTPStatus.OK, self._control_plane.health())
        if method == "GET" and path == "/api/v1/session":
            if self._authenticator is None:
                return ApiResponse(
                    HTTPStatus.OK,
                    {"authenticated": True, "principalId": "local-development", "expiresAt": None},
                )
            session = self._authenticator.authenticate(session_id)
            if session is None:
                return ApiResponse(
                    HTTPStatus.OK,
                    {"authenticated": False, "principalId": None, "expiresAt": None},
                )
            return ApiResponse(
                HTTPStatus.OK,
                {
                    "authenticated": True,
                    "principalId": session.principal_id,
                    "expiresAt": session.expires_at.isoformat(),
                },
            )
        if method == "POST" and path == "/api/v1/session":
            if self._authenticator is None:
                raise UIAuthenticationError("operator authentication is managed externally")
            credentials = OperatorLoginInput.from_untrusted_json(body)
            issued_id, session = self._authenticator.login(credentials.token)
            cookie = (
                f"{_SESSION_COOKIE}={issued_id}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={self._authenticator.session_ttl_seconds}"
            )
            return ApiResponse(
                HTTPStatus.OK,
                {
                    "authenticated": True,
                    "principalId": session.principal_id,
                    "expiresAt": session.expires_at.isoformat(),
                },
                headers=(("Set-Cookie", cookie),),
            )
        if method == "DELETE" and path == "/api/v1/session":
            if self._authenticator is not None:
                self._authenticator.logout(session_id)
            return ApiResponse(
                HTTPStatus.OK,
                {"authenticated": False, "principalId": None, "expiresAt": None},
                headers=(
                    (
                        "Set-Cookie",
                        f"{_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                    ),
                ),
            )
        if self._authenticator is not None and self._authenticator.authenticate(session_id) is None:
            raise UIAuthenticationError("operator session is required")
        if method == "GET" and path == "/api/v1/dashboard":
            return ApiResponse(HTTPStatus.OK, self._control_plane.dashboard())
        if method == "GET" and path == "/api/v1/phases":
            return ApiResponse(HTTPStatus.OK, self._control_plane.phases())
        if method == "GET" and path == "/api/v1/activity":
            return ApiResponse(HTTPStatus.OK, self._control_plane.activity())
        if method == "GET" and path == "/api/v1/interventions":
            return ApiResponse(HTTPStatus.OK, self._control_plane.interventions())
        if method == "GET" and path == "/api/v1/knowledge":
            return ApiResponse(HTTPStatus.OK, self._control_plane.knowledge())
        if method == "GET" and path == "/api/v1/providers":
            return ApiResponse(HTTPStatus.OK, self._control_plane.provider_status())
        if method == "GET" and path == "/api/v1/readiness":
            return ApiResponse(HTTPStatus.OK, self._control_plane.readiness())
        if method == "GET" and path == "/api/v1/ad-assessment/catalog":
            return ApiResponse(HTTPStatus.OK, self._control_plane.ad_assessment_catalog())
        if method == "GET" and path == "/api/v1/vllm/config":
            return ApiResponse(HTTPStatus.OK, self._control_plane.vllm_configuration())
        if method == "GET" and path == "/api/v1/vllm/settings":
            return ApiResponse(HTTPStatus.OK, self._control_plane.vllm_settings())
        if method == "POST" and path == "/api/v1/mission-drafts":
            mission_draft = MissionDraftInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.CREATED, self._control_plane.save_mission_draft(mission_draft))
        if method == "POST" and path == "/api/v1/missions":
            create_request = MissionCreateInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.CREATED,
                self._control_plane.create_mission(draft_id=create_request.draftId),
            )
        if method == "POST" and path == "/api/v1/provider-policy-drafts":
            provider_draft = ProviderPolicyDraftInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.CREATED, self._control_plane.save_provider_policy_draft(provider_draft))
        if method == "POST" and path == "/api/v1/vllm/capability":
            config = VllmConfigInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.OK, self._control_plane.check_vllm(config))
        if method == "POST" and path == "/api/v1/vllm/candidate":
            candidate_request = VllmCandidateInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.CREATED,
                self._control_plane.stage_vllm_candidate(candidate_request),
            )
        if method == "POST" and path == "/api/v1/vllm/candidate/test":
            candidate_version = VllmCandidateVersionInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.OK,
                self._control_plane.test_vllm_candidate(expected_version=candidate_version.version),
            )
        if method == "POST" and path == "/api/v1/vllm/candidate/activate":
            candidate_version = VllmCandidateVersionInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.OK,
                self._control_plane.activate_vllm_candidate(expected_version=candidate_version.version),
            )
        if method == "POST" and path == "/api/v1/ad-assessment/evaluate":
            snapshot = ADAssessmentSnapshot.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.OK, self._control_plane.evaluate_ad_assessment(snapshot))
        if method == "POST" and path == "/api/v1/ad-assessment/evaluate-with-llm":
            snapshot = ADAssessmentSnapshot.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.OK,
                self._control_plane.evaluate_ad_assessment_with_llm(snapshot),
            )
        if method == "POST" and path == "/api/v1/ad-assessment/collect-and-evaluate":
            ADAssessmentCollectionInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.OK,
                self._control_plane.collect_and_evaluate_ad_assessment(),
            )
        if method == "POST" and path == "/api/v1/ad-assessment/recommendation":
            ADAssessmentRecommendationInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.OK, self._control_plane.recommend_ad_assessment())
        match = re.fullmatch(r"/api/v1/interventions/([^/]+)/decision", path)
        if method == "POST" and match is not None:
            request_id = unquote(match.group(1))
            if _SAFE_ID.fullmatch(request_id) is None:
                return ApiResponse(HTTPStatus.BAD_REQUEST, {"error": "invalid request", "code": "INVALID_ID"})
            decision = ApprovalDecisionInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.OK,
                self._control_plane.submit_approval(
                    approval_request_id=request_id,
                    presentation_digest=decision.presentationDigest,
                    verdict=decision.decision,
                ),
            )
        match = re.fullmatch(r"/api/v1/missions/([^/]+)/transitions", path)
        if method == "POST" and match is not None:
            mission_id = unquote(match.group(1))
            if _SAFE_ID.fullmatch(mission_id) is None:
                return ApiResponse(HTTPStatus.BAD_REQUEST, {"error": "invalid request", "code": "INVALID_ID"})
            transition_request = MissionTransitionInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.OK,
                self._control_plane.transition_mission(
                    mission_id=mission_id,
                    expected_version=transition_request.expectedVersion,
                    action=transition_request.action,
                ),
            )
        match = re.fullmatch(r"/api/v1/interventions/([^/]+)/selection", path)
        if method == "POST" and match is not None:
            CandidateSelectionInput.from_untrusted_json(body)
            return ApiResponse(
                HTTPStatus.CONFLICT,
                {"error": "planning choices are not available in the current runtime", "code": "UNAVAILABLE"},
            )
        return ApiResponse(HTTPStatus.NOT_FOUND, {"error": "resource not found", "code": "NOT_FOUND"})


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _host_name(host_header: str) -> str:
    if host_header.startswith("["):
        end = host_header.find("]")
        return host_header[: end + 1] if end >= 0 else ""
    return host_header.split(":", 1)[0]


def validate_direct_ui_origins(origins: tuple[str, ...]) -> tuple[str, ...]:
    """Validate explicitly allowlisted exact HTTP origins across IPv4."""
    if len(set(origins)) != len(origins):
        raise ValueError("UI allowed origins must be unique")
    validated: list[str] = []
    for origin in origins:
        if not origin or origin != origin.strip() or len(origin) > 200:
            raise ValueError("UI allowed origin is not canonical")
        parsed = urlsplit(origin)
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("UI allowed origin port is invalid") from None
        if (
            parsed.scheme != "http"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.hostname is None
            or port is None
        ):
            raise ValueError("direct UI origin must be an exact HTTP origin with an explicit port")
        try:
            address = IPv4Address(parsed.hostname)
        except ValueError:
            raise ValueError("direct UI origin host must be a literal IPv4 address") from None
        canonical = f"http://{address}:{port}"
        if origin != canonical:
            raise ValueError("UI allowed origin is not canonical")
        validated.append(canonical)
    return tuple(validated)


def _ipv4_origin_for_host(host: str, *, expected_port: int) -> tuple[str, IPv4Address] | None:
    parsed = urlsplit(f"http://{host}")
    try:
        port = parsed.port
    except ValueError:
        return None
    if parsed.hostname is None or port is None or (expected_port != 0 and port != expected_port):
        return None
    try:
        address = IPv4Address(parsed.hostname)
    except ValueError:
        return None
    origin = f"http://{address}:{port}"
    return (origin, address) if host == origin.removeprefix("http://") else None


def _rfc1918_origin_for_host(host: str, *, expected_port: int) -> str | None:
    parsed = _ipv4_origin_for_host(host, expected_port=expected_port)
    if parsed is None:
        return None
    origin, address = parsed
    if not any(address in network for network in _RFC1918_NETWORKS):
        return None
    return origin


def discover_local_ipv4_addresses() -> frozenset[IPv4Address]:
    """Return IPv4 addresses assigned to Linux interfaces at server startup."""
    addresses: set[IPv4Address] = set()
    try:
        interfaces = socket.if_nameindex()
    except OSError as exc:
        raise ValueError("local IPv4 interfaces are unavailable") from exc
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in interfaces:
            encoded_name = os.fsencode(name)
            if not encoded_name or len(encoded_name) > 15:
                continue
            try:
                response = fcntl.ioctl(probe.fileno(), _SIOCGIFADDR, struct.pack("256s", encoded_name))
            except OSError:
                continue
            addresses.add(IPv4Address(response[20:24]))
    if not addresses:
        raise ValueError("no local IPv4 interface address is available")
    return frozenset(addresses)


def _local_ipv4_origin_for_host(
    host: str,
    *,
    expected_port: int,
    local_addresses: frozenset[IPv4Address],
) -> str | None:
    parsed = _ipv4_origin_for_host(host, expected_port=expected_port)
    if parsed is None:
        return None
    origin, address = parsed
    return origin if address in local_addresses else None


def build_handler(
    *,
    router: UIRouter,
    static_root: Path | None,
    allowed_origins: tuple[str, ...] = (),
    allow_rfc1918_same_origin: bool = False,
    allow_local_ipv4_same_origin: bool = False,
    local_ipv4_addresses: frozenset[IPv4Address] = frozenset(),
    bind_port: int = 0,
) -> type[BaseHTTPRequestHandler]:
    root = static_root.resolve() if static_root is not None else None
    external_origins = {
        urlsplit(origin).netloc: origin for origin in validate_direct_ui_origins(allowed_origins)
    }

    def external_origin_for_host(host: str) -> str | None:
        configured = external_origins.get(host)
        if configured is not None:
            return configured
        if allow_rfc1918_same_origin:
            return _rfc1918_origin_for_host(host, expected_port=bind_port)
        if allow_local_ipv4_same_origin:
            return _local_ipv4_origin_for_host(
                host,
                expected_port=bind_port,
                local_addresses=local_ipv4_addresses,
            )
        return None

    class OperatorUIHandler(BaseHTTPRequestHandler):
        server_version = "RedTeamAgentUI/1"

        def version_string(self) -> str:
            return self.server_version

        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            if not self._host_allowed():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid host", "code": "INVALID_HOST"})
                return
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                self._handle_api("GET", path)
                return
            self._serve_static(path, send_body=True)

        def do_HEAD(self) -> None:
            if not self._host_allowed():
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
                return
            self._serve_static(path, send_body=False)

        def do_POST(self) -> None:
            if not self._host_allowed():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid host", "code": "INVALID_HOST"})
                return
            if not self._mutation_allowed():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "same-origin proof required", "code": "CSRF"})
                return
            path = urlsplit(self.path).path
            self._handle_api("POST", path)

        def do_DELETE(self) -> None:
            if not self._host_allowed():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid host", "code": "INVALID_HOST"})
                return
            if not self._mutation_allowed():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "same-origin proof required", "code": "CSRF"})
                return
            path = urlsplit(self.path).path
            self._handle_api("DELETE", path)

        def do_OPTIONS(self) -> None:
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "cross-origin access denied", "code": "CORS"})

        def _host_allowed(self) -> bool:
            host = self.headers.get("Host", "")
            return _host_name(host) in _ALLOWED_HOSTS or external_origin_for_host(host) is not None

        def _mutation_allowed(self) -> bool:
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin", "")
            if self.headers.get("X-RedTeam-UI") != "1":
                return False
            external_origin = external_origin_for_host(host)
            if external_origin is not None:
                return origin == external_origin
            return _host_name(host) in _ALLOWED_HOSTS and origin == f"http://{host}"

        def _read_json_body(self) -> bytes | None:
            if self.headers.get_content_type() != "application/json":
                self._send_json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    {"error": "application/json required", "code": "CONTENT_TYPE"},
                )
                return None
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._send_json(HTTPStatus.LENGTH_REQUIRED, {"error": "content length required", "code": "LENGTH"})
                return None
            try:
                length = int(raw_length)
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid content length", "code": "LENGTH"})
                return None
            if length < 0 or length > _MAX_REQUEST_BYTES:
                self._send_json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": "request body is too large", "code": "BODY_TOO_LARGE"},
                )
                return None
            return self.rfile.read(length)

        def _handle_api(self, method: str, path: str) -> None:
            body = b""
            if method == "POST":
                loaded = self._read_json_body()
                if loaded is None:
                    return
                body = loaded
            try:
                response = router.dispatch(
                    method=method,
                    path=path,
                    body=body,
                    session_id=self._session_id(),
                )
            except UIAuthenticationError:
                response = ApiResponse(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "operator authentication required", "code": "UNAUTHENTICATED"},
                )
            except UIActionBlockedError as exc:
                response = ApiResponse(
                    HTTPStatus.CONFLICT,
                    {
                        "error": exc.user_message,
                        "code": exc.code,
                        "resolution": exc.resolution,
                    },
                )
            except UIConflictError:
                response = ApiResponse(
                    HTTPStatus.CONFLICT,
                    {"error": "operator action is stale or unavailable", "code": "CONFLICT"},
                )
            except (UIControlPlaneError, AuthorizationKernelError):
                response = ApiResponse(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"error": "control plane is unavailable", "code": "CONTROL_PLANE_UNAVAILABLE"},
                )
            except (TypeError, ValueError):
                response = ApiResponse(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "request failed strict validation", "code": "INVALID_REQUEST"},
                )
            self._send_json(response.status, response.body, headers=response.headers)

        def _session_id(self) -> str | None:
            raw = self.headers.get("Cookie")
            if raw is None or len(raw) > 4096:
                return None
            try:
                cookies = SimpleCookie()
                cookies.load(raw)
            except CookieError:
                return None
            morsel = cookies.get(_SESSION_COOKIE)
            return None if morsel is None else morsel.value

        def _send_json(
            self,
            status: int,
            body: object,
            *,
            headers: tuple[tuple[str, str], ...] = (),
        ) -> None:
            payload = _json_bytes(body)
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Vary", "Cookie")
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def _serve_static(self, path: str, *, send_body: bool) -> None:
            if root is None or not root.is_dir():
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "frontend build is unavailable", "code": "FRONTEND_NOT_BUILT"},
                )
                return
            relative = unquote(path).lstrip("/") or "index.html"
            candidate = (root / relative).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "static resource not found", "code": "NOT_FOUND"},
                )
                return
            if not candidate.is_file():
                if Path(relative).suffix:
                    self._send_json(
                        HTTPStatus.NOT_FOUND,
                        {"error": "static asset not found", "code": "NOT_FOUND"},
                    )
                    return
                candidate = root / "index.html"
            payload = candidate.read_bytes()
            media_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            content_type = f"{media_type}; charset=utf-8" if media_type.startswith("text/") else media_type
            cache_control = "no-store" if candidate.name == "index.html" else "public, max-age=31536000, immutable"
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", cache_control)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if send_body:
                self.wfile.write(payload)

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            )

    return OperatorUIHandler


def build_server(
    *,
    control_plane: UIControlPlane,
    host: str,
    port: int,
    static_root: Path | None,
    authenticator: OperatorSessionAuthenticator | None = None,
    allowed_origins: tuple[str, ...] = (),
    allow_rfc1918_same_origin: bool = False,
    allow_local_ipv4_same_origin: bool = False,
    local_ipv4_addresses: frozenset[IPv4Address] | None = None,
) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "localhost", DIRECT_EXTERNAL_BIND_HOST}:
        raise ValueError("operator UI bind address is not allowed")
    validated_origins = validate_direct_ui_origins(allowed_origins)
    same_origin_mode_count = int(allow_rfc1918_same_origin) + int(allow_local_ipv4_same_origin)
    if host == DIRECT_EXTERNAL_BIND_HOST and not validated_origins and same_origin_mode_count == 0:
        raise ValueError("direct external UI bind requires an exact origin or a same-origin mode")
    if same_origin_mode_count > 1:
        raise ValueError("only one dynamic UI same-origin mode may be enabled")
    if validated_origins and same_origin_mode_count:
        raise ValueError("exact UI origins cannot be combined with a dynamic same-origin mode")
    if (
        host == DIRECT_EXTERNAL_BIND_HOST
        and port != 0
        and any(urlsplit(origin).port != port for origin in validated_origins)
    ):
        raise ValueError("direct external UI origin port must match the bind port")
    resolved_local_addresses = local_ipv4_addresses
    if allow_local_ipv4_same_origin and resolved_local_addresses is None:
        resolved_local_addresses = discover_local_ipv4_addresses()
    return ThreadingHTTPServer(
        (host, port),
        build_handler(
            router=UIRouter(control_plane, authenticator=authenticator),
            static_root=static_root,
            allowed_origins=validated_origins,
            allow_rfc1918_same_origin=allow_rfc1918_same_origin,
            allow_local_ipv4_same_origin=allow_local_ipv4_same_origin,
            local_ipv4_addresses=resolved_local_addresses or frozenset(),
            bind_port=port,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local RedTeam Agent operator UI")
    parser.add_argument("--database", required=True, help="Provisioned RedTeam Agent SQLite database")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        choices=("127.0.0.1", "localhost", DIRECT_EXTERNAL_BIND_HOST),
    )
    parser.add_argument("--port", default=18000, type=int)
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        help="Exact IPv4 HTTP origin allowed for direct external access; repeat for multiple URLs",
    )
    parser.add_argument(
        "--allow-rfc1918-same-origin",
        action="store_true",
        help="Allow the requested canonical RFC1918 Host when the browser Origin exactly matches it",
    )
    parser.add_argument(
        "--allow-local-ipv4-same-origin",
        action="store_true",
        help="Allow a Host assigned to this server when the browser Origin exactly matches it",
    )
    parser.add_argument("--static-dir", default="frontend/dist", help="Built frontend directory")
    parser.add_argument("--api-only", action="store_true", help="Serve only the JSON API")
    parser.add_argument(
        "--operator-token-file",
        type=Path,
        help="Owner-private operator token file; required unless unsafe development mode is explicit",
    )
    parser.add_argument("--operator-principal", default="redteam-operator")
    parser.add_argument("--operator-session-ttl", type=int, default=DEFAULT_SESSION_TTL_SECONDS)
    parser.add_argument("--unsafe-disable-auth", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--vllm-base-url", help="Enable the trusted Phase 2 vLLM gateway at this URL")
    parser.add_argument("--vllm-model", default="gemma-4-31B-it")
    parser.add_argument("--vllm-api-key-file", type=Path)
    parser.add_argument("--vllm-manifest", type=Path)
    parser.add_argument("--vllm-public-key", type=Path)
    parser.add_argument("--vllm-manifest-key-id", default="llm001-gemma4-2026")
    parser.add_argument("--vllm-tokenizer-directory", type=Path)
    parser.add_argument("--vllm-profile-revision", default="gemma-4-31b-it-vllm-0.25.1-r2")
    parser.add_argument("--vllm-max-context-tokens", type=int, default=131072)
    parser.add_argument("--vllm-max-output-tokens", type=int, default=1024)
    parser.add_argument("--vllm-structured-output-mode", choices=("native", "tool_output"), default="native")
    parser.add_argument("--vllm-attestation-timeout", type=int, default=60)
    parser.add_argument("--vllm-capability-deadline", type=int, default=900)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.unsafe_disable_auth and args.operator_token_file is not None:
        parser.error("--unsafe-disable-auth cannot be combined with --operator-token-file")
    if not args.unsafe_disable_auth and args.operator_token_file is None:
        parser.error("--operator-token-file is required")
    authenticator = None
    if args.operator_token_file is not None:
        try:
            authenticator = OperatorSessionAuthenticator(
                principal_id=args.operator_principal,
                operator_token=read_operator_token(args.operator_token_file),
                session_ttl_seconds=args.operator_session_ttl,
            )
        except (UIAuthenticationError, ValueError) as exc:
            parser.error(f"invalid operator authentication configuration: {type(exc).__name__}")
    vllm_port = None
    vllm_public_config = None
    if args.vllm_base_url is not None:
        required = {
            "--vllm-api-key-file": args.vllm_api_key_file,
            "--vllm-manifest": args.vllm_manifest,
            "--vllm-public-key": args.vllm_public_key,
            "--vllm-tokenizer-directory": args.vllm_tokenizer_directory,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            parser.error(f"{', '.join(missing)} required when --vllm-base-url is set")
        from redteam_agent.ui.vllm_capability import (
            Phase2VllmCapabilityPort,
            Phase2VllmCapabilitySettings,
        )

        try:
            settings = Phase2VllmCapabilitySettings(
                database_path=Path(args.database),
                base_url=args.vllm_base_url,
                model=args.vllm_model,
                api_key_file=args.vllm_api_key_file,
                manifest_path=args.vllm_manifest,
                public_key_path=args.vllm_public_key,
                manifest_key_id=args.vllm_manifest_key_id,
                tokenizer_directory=args.vllm_tokenizer_directory,
                profile_revision=args.vllm_profile_revision,
                max_context_tokens=args.vllm_max_context_tokens,
                max_output_tokens=args.vllm_max_output_tokens,
                structured_output_mode=args.vllm_structured_output_mode,
                attestation_timeout_seconds=args.vllm_attestation_timeout,
                capability_deadline_seconds=args.vllm_capability_deadline,
            )
            vllm_port = Phase2VllmCapabilityPort(settings=settings)
            vllm_public_config = vllm_port.public_config
        except (AuthorizationKernelError, OSError, ValueError) as exc:
            parser.error(f"invalid trusted vLLM configuration: {type(exc).__name__}")
    control_plane = UIControlPlane(
        database_path=args.database,
        vllm_capability_port=vllm_port,
        vllm_public_config=vllm_public_config,
    )
    static_root = None if args.api_only else Path(args.static_dir)
    try:
        server = build_server(
            control_plane=control_plane,
            host=args.host,
            port=args.port,
            static_root=static_root,
            authenticator=authenticator,
            allowed_origins=tuple(args.allowed_origin),
            allow_rfc1918_same_origin=args.allow_rfc1918_same_origin,
            allow_local_ipv4_same_origin=args.allow_local_ipv4_same_origin,
        )
    except ValueError as exc:
        parser.error(f"invalid UI network configuration: {exc}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if vllm_port is not None:
            vllm_port.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
