"""Stateful Tuoni 0.16.1 transport double for offline Phase 4 acceptance.

This module lives under ``tests`` so it cannot be imported by the packaged
application.  It implements only the pinned relative requests and labels
itself non-production; it contains no socket, credential, payload, or implant
behavior.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import ClassVar

from redteam_agent.adapters.tuoni_contract import TuoniWireRequest
from redteam_agent.adapters.tuoni_transport import (
    TuoniTransportAttestation,
    TuoniTransportResponse,
)
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import C2AdapterTransportError

AGENT_ID = "33d17e49-44ca-4204-bfc2-2b8c34f40f96"
TEMPLATE_ID = "a4c85e2b-53e1-4f82-889f-7cc17c7674cc"
TEMPLATE_NAME = "ps"
USER_ID = "d288f64b-0bb5-4168-90ad-5a0c46049444"
OPENAPI_DOCUMENT = {"openapi": "3.0.0"}
OPENAPI_DIGEST = sha256(
    json.dumps(OPENAPI_DOCUMENT, separators=(",", ":")).encode("utf-8")
).hexdigest()


def _permission(code: str, *, mandatory: bool = False) -> dict[str, object]:
    return {
        "label": code.replace("_", " ").title(),
        "code": code,
        "description": f"Offline metadata for {code}",
        "mandatory": mandatory,
    }


def _permissions() -> list[dict[str, object]]:
    return [
        _permission("VIEW_RESOURCES", mandatory=True),
        _permission("SEND_COMMANDS"),
        _permission("MANAGE_USERS"),
    ]


def _current_user() -> dict[str, object]:
    return {
        "userGuid": USER_ID,
        "username": "red-agent-service",
        "enabled": True,
        "permissions": [
            _permission("VIEW_RESOURCES", mandatory=True),
            _permission("SEND_COMMANDS"),
        ],
        "createEvent": {},
        "lastUpdateEvent": {},
    }


def _agent() -> dict[str, object]:
    return {
        "guid": AGENT_ID,
        "firstRegistrationTime": "2026-09-13T02:00:00Z",
        "lastCallbackTime": "2026-09-13T02:59:58Z",
        "nextCallback": {
            "expectedTime": "2026-09-13T03:00:02Z",
            "randomMs": 0,
        },
        "metadata": {
            "guid": AGENT_ID,
            "hostname": "offline-windows-target",
            "username": "LAB\\operator",
            "os": "WINDOWS",
            "osArch": "X64",
        },
        "active": True,
        "status": "ACTIVE",
        "recentListeners": [],
        "availableCommandTemplates": [TEMPLATE_ID],
    }


def _template() -> dict[str, object]:
    return {
        "id": TEMPLATE_ID,
        "name": TEMPLATE_NAME,
        "pluginId": "tuoni.process",
        "scope": "agent",
        "qualifiedName": f"agent:{TEMPLATE_NAME}",
        "fullyQualifiedName": f"tuoni.process:agent:{TEMPLATE_NAME}",
        "description": "Offline process-list test double",
        "status": "ENABLED",
        "supportedExecUnitTypes": ["SHELLCODE_NATIVE"],
        "exampleConfigurations": [],
        "configurationSchema": {
            "type": "object",
            "properties": {
                "includeSystem": {"type": "boolean"},
            },
            "required": ["includeSystem"],
            "additionalProperties": False,
        },
        "updateSchema": None,
        "isUserCreatable": True,
        "isAlias": False,
    }


class StatefulTuoniTransportDouble:
    """Exact-path state machine used only by offline tests."""

    evidence_kind: ClassVar[str] = "test_double"
    is_production: ClassVar[bool] = False

    def __init__(self, attestation: TuoniTransportAttestation) -> None:
        self._attestation = attestation
        self.requests: list[TuoniWireRequest] = []
        self._commands: dict[int, dict[str, object]] = {}
        self._next_command_id = 1
        self._failures: dict[str, C2AdapterTransportError] = {}

    @property
    def attestation(self) -> TuoniTransportAttestation:
        return self._attestation

    def fail_once(self, operation: str) -> None:
        self._failures[operation] = C2AdapterTransportError(
            "offline Tuoni transport failure"
        )

    def mark_running(self, command_id: int) -> None:
        command = self._require_command(command_id)
        command["status"] = "ONGOING"
        command["sent"] = "2026-09-13T03:00:01Z"
        command["sendFormat"] = "GENERIC"

    def complete(self, command_id: int, *, output: str) -> None:
        command = self._require_command(command_id)
        command["status"] = "COMPLETE"
        command["sent"] = "2026-09-13T03:00:01Z"
        command["sendFormat"] = "GENERIC"
        command["result"] = {
            "status": "COMPLETE",
            "errorMessage": None,
            "received": "2026-09-13T03:00:03Z",
            "childResults": [
                {"type": "text", "name": "stdout", "value": output}
            ],
        }

    def request(
        self,
        request: TuoniWireRequest,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
    ) -> TuoniTransportResponse:
        if timeout_seconds < 1 or max_response_bytes < 1:
            raise AssertionError("adapter sent an unbounded test-double request")
        self.requests.append(request)
        failure = self._failures.pop(request.operation, None)
        if failure is not None:
            raise failure

        status_code = 200
        if request.operation == "openapi":
            self._require_request(request, "GET", "/docs/api")
            payload: object = OPENAPI_DOCUMENT
        elif request.operation == "current_user":
            self._require_request(request, "GET", "/api/v2/users/me")
            payload = _current_user()
        elif request.operation == "permissions":
            self._require_request(request, "GET", "/api/v1/permissions")
            payload = _permissions()
        elif request.operation == "list_active_agents":
            self._require_request(request, "GET", "/api/v1/agents/active")
            payload = [_agent()]
        elif request.operation == "get_agent":
            self._require_request(request, "GET", f"/api/v1/agents/{AGENT_ID}")
            payload = _agent()
        elif request.operation == "list_agent_command_templates":
            self._require_request(
                request,
                "GET",
                f"/api/v1/agents/{AGENT_ID}/command-templates",
            )
            payload = [_template()]
        elif request.operation == "submit_command":
            self._require_request(
                request,
                "POST",
                f"/api/v1/agents/{AGENT_ID}/commands",
            )
            body = None if request.json_body is None else thaw(request.json_body)
            if not isinstance(body, dict) or set(body) != {"template", "configuration"}:
                raise AssertionError("adapter submitted an unexpected Tuoni body")
            if body["template"] != TEMPLATE_NAME:
                raise AssertionError("adapter submitted an unapproved template")
            if body["configuration"] != {"includeSystem": False}:
                raise AssertionError(
                    "adapter submitted configuration outside the approved fixture"
                )
            command_id = self._next_command_id
            self._next_command_id += 1
            command = self._new_command(command_id, body["configuration"])
            self._commands[command_id] = command
            payload = command
        elif request.operation in {"get_command", "stop_command"}:
            command_id = self._command_id(request.relative_path)
            command = self._require_command(command_id)
            if request.operation == "get_command":
                self._require_request(
                    request,
                    "GET",
                    f"/api/v1/commands/{command_id}",
                )
            else:
                self._require_request(
                    request,
                    "PUT",
                    f"/api/v1/commands/{command_id}/stop",
                )
                command["status"] = "CANCELED"
            payload = command
        else:
            raise AssertionError(
                f"operation {request.operation!r} is outside the scenario double"
            )
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(encoded) > max_response_bytes:
            raise C2AdapterTransportError("offline Tuoni response exceeded limit")
        return TuoniTransportResponse(
            status_code=status_code,
            content_type="application/json",
            body=encoded,
        )

    @staticmethod
    def _require_request(
        request: TuoniWireRequest,
        method: str,
        path: str,
    ) -> None:
        if request.method != method or request.relative_path != path:
            raise AssertionError("adapter request escaped the pinned Tuoni contract")

    @staticmethod
    def _command_id(path: str) -> int:
        parts = path.removesuffix("/stop").split("/")
        if len(parts) != 5 or parts[1:4] != ["api", "v1", "commands"]:
            raise AssertionError("adapter used an invalid command path")
        return int(parts[4])

    def _require_command(self, command_id: int) -> dict[str, object]:
        command = self._commands.get(command_id)
        if command is None:
            raise AssertionError("scenario referenced an unknown command")
        return command

    @staticmethod
    def _new_command(command_id: int, configuration: object) -> dict[str, object]:
        return {
            "id": command_id,
            "commandTemplateId": TEMPLATE_ID,
            "commandTemplateName": TEMPLATE_NAME,
            "configuration": configuration,
            "execConf": {},
            "agentGuid": AGENT_ID,
            "created": "2026-09-13T03:00:00Z",
            "sent": None,
            "sendFormat": None,
            "sends": [],
            "status": "CREATED",
            "commandUpdates": [],
            "result": None,
        }


__all__ = [
    "AGENT_ID",
    "OPENAPI_DIGEST",
    "TEMPLATE_ID",
    "TEMPLATE_NAME",
    "StatefulTuoniTransportDouble",
]
