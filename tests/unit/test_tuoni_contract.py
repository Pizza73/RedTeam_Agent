"""Offline contract tests for the pinned Tuoni 0.16.1 REST projection."""

from __future__ import annotations

from hashlib import sha256

import pytest
from pydantic import ValidationError

from redteam_agent.adapters.tuoni import (
    TUONI_SOURCE_COMMIT_PIN,
    TUONI_VERSION_PIN,
)
from redteam_agent.adapters.tuoni_contract import (
    TUONI_API_CONTRACT_REVISION,
    TuoniApiContractV0161,
)
from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import C2AdapterContractError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.models.common import ToolRef

SESSION_ID = "33d17e49-44ca-4204-bfc2-2b8c34f40f96"


def _execution_request(
    *,
    adapter_id: str = "tuoni-c2",
    provider_tool_name: str = "ps",
    result_delivery_mode: str = "provider_task",
    arguments: object | None = None,
) -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-1",
        task_id="task-1",
        tool_ref=ToolRef(tool_id="process-list", registry_revision=1),
        adapter_id=adapter_id,
        provider_tool_name=provider_tool_name,
        result_delivery_mode=result_delivery_mode,  # type: ignore[arg-type]
        idempotency_key="idempotency-1",
        timeout_seconds=60,
        arguments=(
            {
                "provider_session_id": SESSION_ID,
                "configuration": {"includeSystem": False},
            }
            if arguments is None
            else arguments
        ),
    )


def test_read_and_control_endpoints_are_exact_relative_paths() -> None:
    contract = TuoniApiContractV0161()

    assert (contract.openapi().method, contract.openapi().relative_path) == (
        "GET",
        "/docs/api",
    )
    assert contract.current_user().relative_path == "/api/v2/users/me"
    assert contract.permissions().relative_path == "/api/v1/permissions"
    assert contract.list_active_agents().relative_path == "/api/v1/agents/active"
    assert contract.get_agent(SESSION_ID).relative_path == f"/api/v1/agents/{SESSION_ID}"
    assert contract.list_agent_command_templates(SESSION_ID).relative_path == (
        f"/api/v1/agents/{SESSION_ID}/command-templates"
    )
    assert contract.get_command("42").relative_path == "/api/v1/commands/42"
    stop = contract.stop_command("42")
    assert (stop.method, stop.relative_path, stop.json_body) == (
        "PUT",
        "/api/v1/commands/42/stop",
        None,
    )


def test_submission_projects_only_closed_json_command_shape() -> None:
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))

    wire = contract.submit_command(_execution_request())

    assert wire.contract_revision == TUONI_API_CONTRACT_REVISION
    assert wire.method == "POST"
    assert wire.relative_path == f"/api/v1/agents/{SESSION_ID}/commands"
    assert wire.expected_status_codes == frozenset({200})
    assert thaw(wire.json_body) == {
        "template": "ps",
        "configuration": {"includeSystem": False},
    }
    assert set(type(wire).model_fields) == {
        "contract_revision",
        "operation",
        "method",
        "relative_path",
        "json_body",
        "expected_status_codes",
    }


@pytest.mark.parametrize(
    "provider_tool_name",
    ["spawn", "../commands", "ps/../../payloads", " ps"],
)
def test_submission_rejects_unapproved_or_noncanonical_templates(
    provider_tool_name: str,
) -> None:
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))

    with pytest.raises(C2AdapterContractError):
        contract.submit_command(
            _execution_request(provider_tool_name=provider_tool_name)
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {
            "provider_session_id": SESSION_ID,
            "configuration": {},
            "execConf": {"execType": "NEW"},
        },
        {
            "provider_session_id": SESSION_ID,
            "configuration": {},
            "files": ["payload.bin"],
        },
        {"provider_session_id": SESSION_ID},
    ],
)
def test_submission_rejects_exec_conf_files_and_incomplete_shapes(arguments: object) -> None:
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))

    with pytest.raises(C2AdapterContractError):
        contract.submit_command(_execution_request(arguments=arguments))


def test_submission_rejects_wrong_adapter_or_result_mode() -> None:
    contract = TuoniApiContractV0161(approved_command_templates=("ps",))

    with pytest.raises(C2AdapterContractError):
        contract.submit_command(_execution_request(adapter_id="other-c2"))
    with pytest.raises(C2AdapterContractError):
        contract.submit_command(_execution_request(result_delivery_mode="local_result"))


@pytest.mark.parametrize(
    "provider_session_id",
    [
        "33D17E49-44CA-4204-BFC2-2B8C34F40F96",
        "33d17e4944ca4204bfc22b8c34f40f96",
        "../commands/1",
        "not-a-uuid",
    ],
)
def test_session_paths_reject_noncanonical_or_injected_ids(provider_session_id: str) -> None:
    with pytest.raises(C2AdapterContractError):
        TuoniApiContractV0161().get_agent(provider_session_id)


@pytest.mark.parametrize("provider_task_id", ["0", "01", "-1", "1/stop", "abc"])
def test_command_paths_reject_noncanonical_or_injected_ids(provider_task_id: str) -> None:
    with pytest.raises(C2AdapterContractError):
        TuoniApiContractV0161().get_command(provider_task_id)


def test_contract_digest_binds_release_endpoints_and_approved_templates() -> None:
    digest_service = DigestService()
    first = TuoniApiContractV0161(approved_command_templates=("whoami", "ps"))
    reordered = TuoniApiContractV0161(approved_command_templates=("ps", "whoami"))
    changed = TuoniApiContractV0161(approved_command_templates=("ps",))

    assert TUONI_VERSION_PIN == "0.16.1"
    assert TUONI_SOURCE_COMMIT_PIN == "7d9a2057b309481c530f7c7a71b4ad2f8c5a615e"
    assert first.contract_digest(digest_service) == reordered.contract_digest(digest_service)
    assert first.contract_digest(digest_service) != changed.contract_digest(digest_service)
    assert "tuoni_api_contract_digest" in DEFAULT_DIGEST_CATALOG.names()


def test_openapi_artifact_verification_uses_the_live_approved_digest() -> None:
    artifact = b'{"info":{"version":"0.16.1"}}'
    expected = sha256(artifact).hexdigest()

    TuoniApiContractV0161.verify_openapi_artifact(
        artifact,
        expected_sha256=expected,
    )
    with pytest.raises(C2AdapterContractError):
        TuoniApiContractV0161.verify_openapi_artifact(
            artifact,
            expected_sha256="0" * 64,
        )


def test_wire_request_is_immutable() -> None:
    wire = TuoniApiContractV0161().list_active_agents()

    with pytest.raises(ValidationError):
        wire.relative_path = "/api/v1/payloads"  # type: ignore[misc]
