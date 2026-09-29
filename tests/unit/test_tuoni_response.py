"""Offline response-boundary tests for Tuoni 0.16.1."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from redteam_agent.adapters.tuoni_response import (
    decode_active_agents_v0161,
    decode_agent_v0161,
    decode_command_templates_v0161,
    decode_command_v0161,
    decode_current_user_v0161,
    decode_permissions_v0161,
)
from redteam_agent.errors import C2AdapterContractError

AGENT_ID = "33d17e49-44ca-4204-bfc2-2b8c34f40f96"
TEMPLATE_ID = "a4c85e2b-53e1-4f82-889f-7cc17c7674cc"
OBSERVED_AT = datetime(2026, 9, 12, 3, 0, tzinfo=UTC)


def _agent(*, status: str = "ACTIVE", active: bool = True) -> dict[str, object]:
    return {
        "guid": AGENT_ID,
        "firstRegistrationTime": "2026-09-12T01:00:00Z",
        "lastCallbackTime": "2026-09-12T02:59:58Z",
        "nextCallback": {"expectedTime": "2026-09-12T03:00:02Z", "randomMs": 0},
        "metadata": {
            "guid": AGENT_ID,
            "hostname": "target-lab-01",
            "username": "LAB\\operator",
            "os": "WINDOWS",
            "osArch": "X64",
        },
        "active": active,
        "status": status,
        "recentListeners": [],
        "availableCommandTemplates": [TEMPLATE_ID],
    }


def _command(*, status: str = "COMPLETE", result: object = None) -> dict[str, object]:
    return {
        "id": 42,
        "commandTemplateId": TEMPLATE_ID,
        "commandTemplateName": "ps",
        "configuration": {"includeSystem": False},
        "execConf": {"execType": "SELF"},
        "agentGuid": AGENT_ID,
        "created": "2026-09-12T02:59:00Z",
        "sent": "2026-09-12T02:59:01Z",
        "sendFormat": "GENERIC",
        "sends": [],
        "status": status,
        "commandUpdates": [],
        "result": result,
    }


def _template(
    *, name: str, status: str = "ENABLED", user_creatable: bool = True
) -> dict[str, object]:
    return {
        "id": TEMPLATE_ID,
        "name": name,
        "pluginId": "tuoni.process",
        "scope": "agent",
        "qualifiedName": f"agent:{name}",
        "fullyQualifiedName": f"tuoni.process:agent:{name}",
        "description": "Process listing",
        "status": status,
        "supportedExecUnitTypes": ["SHELLCODE_NATIVE"],
        "exampleConfigurations": [],
        "configurationSchema": {"type": "object"},
        "updateSchema": None,
        "isUserCreatable": user_creatable,
        "isAlias": False,
    }


def _permission(code: str, *, mandatory: bool = False) -> dict[str, object]:
    return {
        "label": code,
        "code": code,
        "description": code,
        "mandatory": mandatory,
    }


def _current_user() -> dict[str, object]:
    return {
        "userGuid": "d288f64b-0bb5-4168-90ad-5a0c46049444",
        "username": "red-agent-service",
        "enabled": True,
        "permissions": [
            _permission("VIEW_RESOURCES", mandatory=True),
            _permission("SEND_COMMANDS"),
        ],
        "createEvent": {},
        "lastUpdateEvent": {},
    }


def test_active_agent_is_projected_to_provider_neutral_observation() -> None:
    observation = decode_agent_v0161(json.dumps(_agent()), observed_at=OBSERVED_AT)

    assert observation.provider_session_id == AGENT_ID
    assert observation.provider_status == "active"
    assert observation.host == "target-lab-01"
    assert observation.os == "windows"
    assert observation.architecture == "x86_64"
    assert observation.current_principal == "LAB\\operator"
    assert observation.capabilities == frozenset()
    assert observation.observed_at == OBSERVED_AT


@pytest.mark.parametrize(
    "provider_status, active, expected",
    [
        ("ACTIVE", True, "active"),
        ("INACTIVE", False, "stale"),
        ("BLOCKED", False, "terminated"),
        ("ACTIVE", False, "unknown"),
    ],
)
def test_agent_status_mapping_fails_safe_on_inconsistent_state(
    provider_status: str, active: bool, expected: str
) -> None:
    raw = json.dumps(_agent(status=provider_status, active=active))

    assert decode_agent_v0161(raw, observed_at=OBSERVED_AT).provider_status == expected


def test_active_agent_list_uses_one_trusted_observation_time() -> None:
    raw = json.dumps([_agent(), _agent(status="INACTIVE", active=False)])

    observations = decode_active_agents_v0161(raw, observed_at=OBSERVED_AT)

    assert len(observations) == 2
    assert {item.observed_at for item in observations} == {OBSERVED_AT}


@pytest.mark.parametrize(
    "provider_status, normalized",
    [
        ("CREATED", "queued"),
        ("SENT", "running"),
        ("ONGOING", "running"),
        ("CANCELED", "cancelled"),
        ("FAILED", "failed"),
        ("COMPLETE", "succeeded"),
    ],
)
def test_command_status_is_normalized_without_copying_raw_result(
    provider_status: str, normalized: str
) -> None:
    raw = json.dumps(
        _command(
            status=provider_status,
            result={
                "status": "ok",
                "errorMessage": None,
                "received": "2026-09-12T03:00:00Z",
                "childResults": [{"value": "untrusted"}],
            },
        )
    )

    command, observation = decode_command_v0161(raw, observed_at=OBSERVED_AT)

    assert command.result is not None
    assert observation.provider_task_id == "42"
    assert observation.provider_session_id == AGENT_ID
    assert observation.provider_status == provider_status
    assert observation.normalized_status == normalized
    assert observation.result_available is True
    assert "result" not in type(observation).model_fields


def test_response_rejects_duplicate_keys_without_echoing_content() -> None:
    raw = json.dumps(_agent()).replace(
        '"guid": "33d17e49-44ca-4204-bfc2-2b8c34f40f96",',
        '"guid": "33d17e49-44ca-4204-bfc2-2b8c34f40f96", "guid": "secret",',
        1,
    )

    with pytest.raises(C2AdapterContractError) as caught:
        decode_agent_v0161(raw, observed_at=OBSERVED_AT)

    assert "secret" not in str(caught.value)


def test_response_rejects_unknown_top_level_control_field() -> None:
    value = _agent()
    value["providerOverride"] = "ACTIVE"

    with pytest.raises(C2AdapterContractError):
        decode_agent_v0161(json.dumps(value), observed_at=OBSERVED_AT)


def test_response_rejects_mismatched_nested_agent_identity() -> None:
    value = _agent()
    metadata = value["metadata"]
    assert isinstance(metadata, dict)
    metadata["guid"] = "589f1360-82b7-4473-9798-82e0e68142a4"

    with pytest.raises(C2AdapterContractError):
        decode_agent_v0161(json.dumps(value), observed_at=OBSERVED_AT)


def test_command_templates_intersect_live_state_with_approved_catalog() -> None:
    second = _template(name="whoami")
    second["id"] = "463258be-3ac0-4720-8b0c-d277de89c80e"
    disabled = _template(name="disabled", status="DISABLED")
    disabled["id"] = "532294a6-24cb-4859-ac10-6035b6f8e72f"
    internal = _template(name="internal", user_creatable=False)
    internal["id"] = "889aacbf-7cb0-414c-9fc4-bc5c713722fd"
    raw = json.dumps([_template(name="ps"), second, disabled, internal])

    available = decode_command_templates_v0161(
        raw, approved_names=("ps", "whoami", "disabled", "internal", "unseen")
    )

    assert available == frozenset({"ps", "whoami"})


def test_command_template_response_rejects_duplicate_names() -> None:
    duplicate = _template(name="ps")
    duplicate["id"] = "463258be-3ac0-4720-8b0c-d277de89c80e"

    with pytest.raises(C2AdapterContractError):
        decode_command_templates_v0161(
            json.dumps([_template(name="ps"), duplicate]),
            approved_names=("ps",),
        )


def test_current_user_is_projected_to_minimal_permission_control_metadata() -> None:
    user = decode_current_user_v0161(json.dumps(_current_user()))

    assert user.enabled is True
    assert user.username == "red-agent-service"
    assert user.permission_codes == frozenset({"VIEW_RESOURCES", "SEND_COMMANDS"})
    assert "create_event" not in type(user).model_fields


def test_permission_catalog_rejects_duplicate_codes() -> None:
    duplicate = _permission("VIEW_RESOURCES")

    with pytest.raises(C2AdapterContractError):
        decode_permissions_v0161(
            json.dumps(
                [
                    _permission("VIEW_RESOURCES", mandatory=True),
                    duplicate,
                ]
            )
        )


def test_current_user_rejects_unknown_or_lowercase_permission_codes() -> None:
    unknown = _current_user()
    unknown["providerOverride"] = True
    lowercase = _current_user()
    permissions = lowercase["permissions"]
    assert isinstance(permissions, list)
    assert isinstance(permissions[0], dict)
    permissions[0]["code"] = "view_resources"

    with pytest.raises(C2AdapterContractError):
        decode_current_user_v0161(json.dumps(unknown))
    with pytest.raises(C2AdapterContractError):
        decode_current_user_v0161(json.dumps(lowercase))
