"""Dependency-free localhost HTTP server for the operator console."""

from __future__ import annotations

import argparse
import json
import mimetypes
import re
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from redteam_agent.errors import AuthorizationKernelError
from redteam_agent.ui.control_plane import UIConflictError, UIControlPlane, UIControlPlaneError
from redteam_agent.ui.models import (
    ApprovalDecisionInput,
    CandidateSelectionInput,
    MissionDraftInput,
    ProviderPolicyDraftInput,
    VllmConfigInput,
)

_MAX_REQUEST_BYTES = 1_048_576
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,200}$")
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: object


class UIRouter:
    def __init__(self, control_plane: UIControlPlane) -> None:
        self._control_plane = control_plane

    def dispatch(self, *, method: str, path: str, body: bytes = b"") -> ApiResponse:
        if method == "GET" and path == "/api/v1/health":
            return ApiResponse(HTTPStatus.OK, self._control_plane.health())
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
        if method == "POST" and path == "/api/v1/mission-drafts":
            mission_draft = MissionDraftInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.CREATED, self._control_plane.save_mission_draft(mission_draft))
        if method == "POST" and path == "/api/v1/provider-policy-drafts":
            provider_draft = ProviderPolicyDraftInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.CREATED, self._control_plane.save_provider_policy_draft(provider_draft))
        if method == "POST" and path == "/api/v1/vllm/capability":
            config = VllmConfigInput.from_untrusted_json(body)
            return ApiResponse(HTTPStatus.OK, self._control_plane.check_vllm(config))
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


def build_handler(*, router: UIRouter, static_root: Path | None) -> type[BaseHTTPRequestHandler]:
    root = static_root.resolve() if static_root is not None else None

    class OperatorUIHandler(BaseHTTPRequestHandler):
        server_version = "RedTeamAgentUI/1"

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

        def do_OPTIONS(self) -> None:
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "cross-origin access denied", "code": "CORS"})

        def _host_allowed(self) -> bool:
            host = self.headers.get("Host", "")
            return _host_name(host) in _ALLOWED_HOSTS

        def _mutation_allowed(self) -> bool:
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin", "")
            return self.headers.get("X-RedTeam-UI") == "1" and origin == f"http://{host}"

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
                response = router.dispatch(method=method, path=path, body=body)
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
            self._send_json(response.status, response.body)

        def _send_json(self, status: int, body: object) -> None:
            payload = _json_bytes(body)
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
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
            cache_control = (
                "no-store" if candidate.name == "index.html" else "public, max-age=31536000, immutable"
            )
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
    *, control_plane: UIControlPlane, host: str, port: int, static_root: Path | None
) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("operator UI may bind only to loopback")
    return ThreadingHTTPServer((host, port), build_handler(router=UIRouter(control_plane), static_root=static_root))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local RedTeam Agent operator UI")
    parser.add_argument("--database", required=True, help="Provisioned RedTeam Agent SQLite database")
    parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    parser.add_argument("--port", default=18000, type=int)
    parser.add_argument("--static-dir", default="frontend/dist", help="Built frontend directory")
    parser.add_argument("--api-only", action="store_true", help="Serve only the JSON API")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    control_plane = UIControlPlane(database_path=args.database)
    static_root = None if args.api_only else Path(args.static_dir)
    server = build_server(control_plane=control_plane, host=args.host, port=args.port, static_root=static_root)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
