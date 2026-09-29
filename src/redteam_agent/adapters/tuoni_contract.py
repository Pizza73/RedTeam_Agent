"""Pinned, transport-free REST request contract for Tuoni 0.16.1.

The contract builds only relative paths and JSON request bodies documented by
Tuoni 0.16.1.  It deliberately owns no endpoint, authentication header, TLS
configuration, socket, or retry logic.  The process-isolated transport may
consume these requests only after the remaining live-environment identities are
attested.  Until then, :mod:`redteam_agent.adapters.tuoni` remains unavailable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from hashlib import sha256
from hmac import compare_digest
from typing import Literal
from uuid import UUID

from pydantic import Field, ValidationError, field_validator, model_validator

from redteam_agent.adapters.tuoni import (
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject, thaw
from redteam_agent.errors import C2AdapterContractError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.models.base import StrictImmutableBoundaryModel

TUONI_API_CONTRACT_REVISION = "tuoni-rest-0.16.1-v1"

_TEMPLATE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

type TuoniOperation = Literal[
    "openapi",
    "current_user",
    "permissions",
    "list_active_agents",
    "get_agent",
    "list_agent_command_templates",
    "submit_command",
    "get_command",
    "stop_command",
]


class TuoniWireRequest(StrictImmutableBoundaryModel):
    """Secret-free request description for a composition-owned transport."""

    contract_revision: Literal["tuoni-rest-0.16.1-v1"] = "tuoni-rest-0.16.1-v1"
    operation: TuoniOperation
    method: Literal["GET", "POST", "PUT"]
    relative_path: str = Field(pattern=r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+$")
    json_body: CanonicalJsonObject | None = None
    expected_status_codes: frozenset[int]

    @model_validator(mode="after")
    def _method_body_contract(self) -> TuoniWireRequest:
        if self.method == "GET" and self.json_body is not None:
            raise ValueError("GET requests must not carry a JSON body")
        if not self.expected_status_codes or any(
            status < 200 or status >= 300 for status in self.expected_status_codes
        ):
            raise ValueError("expected statuses must be a non-empty 2xx set")
        return self


class TuoniCommandArguments(StrictImmutableBoundaryModel):
    """Closed ExecutionRequest argument shape for JSON-only command submission."""

    provider_session_id: str = Field(min_length=1)
    configuration: CanonicalJsonObject

    @field_validator("provider_session_id")
    @classmethod
    def _canonical_session_id(cls, value: str) -> str:
        return _require_canonical_uuid(value)


def _require_canonical_uuid(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise C2AdapterContractError("provider session id is not a UUID") from exc
    canonical = str(parsed)
    if canonical != value:
        raise C2AdapterContractError("provider session id is not canonical")
    return canonical


def _require_command_id(value: str) -> str:
    if not value.isascii() or not value.isdecimal():
        raise C2AdapterContractError("provider task id is not a decimal command id")
    command_id = int(value)
    if command_id < 1 or str(command_id) != value:
        raise C2AdapterContractError("provider task id is not canonical")
    return value


def _require_template_name(value: str) -> str:
    if _TEMPLATE_PATTERN.fullmatch(value) is None:
        raise C2AdapterContractError("provider command template name is invalid")
    return value


class TuoniApiContractV0161:
    """Exact endpoint and submission projection for the pinned Tuoni release.

    The allowlist comes from the trusted Tool Registry composition.  An empty
    allowlist is valid and makes every command submission fail closed while
    read-only/control request construction remains testable offline.
    """

    def __init__(self, *, approved_command_templates: Iterable[str] = ()) -> None:
        templates = tuple(sorted({_require_template_name(item) for item in approved_command_templates}))
        self._approved_command_templates = templates

    @property
    def approved_command_templates(self) -> tuple[str, ...]:
        return self._approved_command_templates

    def contract_digest(self, digest_service: DigestService) -> str:
        return digest_service.compute(
            "tuoni_api_contract_digest",
            {
                "contract_revision": TUONI_API_CONTRACT_REVISION,
                "provider_version": TUONI_VERSION_PIN,
                "source_commit": TUONI_SOURCE_COMMIT_PIN,
                "openapi_validation": "live_artifact_sha256_required",
                "approved_command_templates": list(self._approved_command_templates),
                "request_mode": "json_only_no_exec_conf_no_files",
                "endpoints": {
                    "openapi": "GET /docs/api",
                    "current_user": "GET /api/v2/users/me",
                    "permissions": "GET /api/v1/permissions",
                    "list_active_agents": "GET /api/v1/agents/active",
                    "get_agent": "GET /api/v1/agents/{agent_guid}",
                    "list_agent_command_templates": (
                        "GET /api/v1/agents/{agent_guid}/command-templates"
                    ),
                    "submit_command": "POST /api/v1/agents/{agent_guid}/commands",
                    "get_command": "GET /api/v1/commands/{command_id}",
                    "stop_command": "PUT /api/v1/commands/{command_id}/stop",
                },
            },
        )

    @staticmethod
    def verify_openapi_artifact(
        raw_openapi: bytes, *, expected_sha256: str
    ) -> None:
        """Verify a live deployment artifact against its approved digest."""
        if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
            raise C2AdapterContractError("Tuoni OpenAPI digest is invalid")
        observed = sha256(raw_openapi).hexdigest()
        if not compare_digest(observed, expected_sha256):
            raise C2AdapterContractError("Tuoni OpenAPI artifact digest mismatch")

    def openapi(self) -> TuoniWireRequest:
        return self._get("openapi", "/docs/api")

    def current_user(self) -> TuoniWireRequest:
        return self._get("current_user", "/api/v2/users/me")

    def permissions(self) -> TuoniWireRequest:
        return self._get("permissions", "/api/v1/permissions")

    def list_active_agents(self) -> TuoniWireRequest:
        return self._get("list_active_agents", "/api/v1/agents/active")

    def get_agent(self, provider_session_id: str) -> TuoniWireRequest:
        session_id = _require_canonical_uuid(provider_session_id)
        return self._get("get_agent", f"/api/v1/agents/{session_id}")

    def list_agent_command_templates(self, provider_session_id: str) -> TuoniWireRequest:
        session_id = _require_canonical_uuid(provider_session_id)
        return self._get(
            "list_agent_command_templates",
            f"/api/v1/agents/{session_id}/command-templates",
        )

    def submit_command(self, request: ExecutionRequest) -> TuoniWireRequest:
        if request.adapter_id != "tuoni-c2" or request.result_delivery_mode != "provider_task":
            raise C2AdapterContractError("execution request is bound to a different adapter mode")
        template = _require_template_name(request.provider_tool_name)
        if template not in self._approved_command_templates:
            raise C2AdapterContractError("provider command template is not approved")
        try:
            arguments = TuoniCommandArguments.model_validate(thaw(request.arguments))
        except (C2AdapterContractError, ValidationError) as exc:
            raise C2AdapterContractError("execution arguments violate the Tuoni contract") from exc
        return TuoniWireRequest(
            operation="submit_command",
            method="POST",
            relative_path=f"/api/v1/agents/{arguments.provider_session_id}/commands",
            json_body={
                "template": template,
                "configuration": thaw(arguments.configuration),
            },
            expected_status_codes=frozenset({200}),
        )

    def get_command(self, provider_task_id: str) -> TuoniWireRequest:
        command_id = _require_command_id(provider_task_id)
        return self._get("get_command", f"/api/v1/commands/{command_id}")

    def stop_command(self, provider_task_id: str) -> TuoniWireRequest:
        command_id = _require_command_id(provider_task_id)
        return TuoniWireRequest(
            operation="stop_command",
            method="PUT",
            relative_path=f"/api/v1/commands/{command_id}/stop",
            expected_status_codes=frozenset({200}),
        )

    @staticmethod
    def _get(operation: TuoniOperation, path: str) -> TuoniWireRequest:
        return TuoniWireRequest(
            operation=operation,
            method="GET",
            relative_path=path,
            expected_status_codes=frozenset({200}),
        )


__all__ = [
    "TUONI_API_CONTRACT_REVISION",
    "TuoniApiContractV0161",
    "TuoniCommandArguments",
    "TuoniOperation",
    "TuoniWireRequest",
]
