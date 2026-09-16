"""Strict trust-boundary tests for operator UI inputs."""

from __future__ import annotations

import pytest

from redteam_agent.errors import (
    DuplicateJsonKeyError,
    PydanticBoundaryValidationError,
)
from redteam_agent.ui.models import MissionDraftInput, ProviderPolicyDraftInput

_MISSION = b"""{
  "name":"Lab Mission",
  "description":"Authorized isolated lab mission.",
  "authorizationReference":"AUTH-1",
  "validUntil":"2026-12-01T00:00:00Z",
  "targets":[{"id":"t1","type":"network","value":"10.0.0.0/24","port":445,"protocol":"tcp"}],
  "successType":"evidence",
  "successValue":"Confirmed evidence exists",
  "maxIterations":10,
  "maxRuntimeMinutes":60,
  "approvalRisk":"medium"
}"""


def test_mission_draft_accepts_typed_zoned_input() -> None:
    draft = MissionDraftInput.from_untrusted_json(_MISSION)
    assert draft.targets[0].port == 445
    assert draft.validUntil.utcoffset() is not None


def test_mission_draft_rejects_duplicate_and_unknown_fields() -> None:
    with pytest.raises(DuplicateJsonKeyError):
        MissionDraftInput.from_untrusted_json(_MISSION.replace(b'"name":"Lab Mission"', b'"name":"A","name":"Lab Mission"'))
    with pytest.raises(PydanticBoundaryValidationError):
        MissionDraftInput.from_untrusted_json(_MISSION.replace(b'"approvalRisk":"medium"', b'"approvalRisk":"medium","activate":true'))


def test_mission_draft_rejects_unzoned_expiry_and_non_network_port() -> None:
    with pytest.raises(PydanticBoundaryValidationError):
        MissionDraftInput.from_untrusted_json(_MISSION.replace(b"2026-12-01T00:00:00Z", b"2026-12-01T00:00:00"))
    with pytest.raises(PydanticBoundaryValidationError):
        MissionDraftInput.from_untrusted_json(_MISSION.replace(b'"type":"network"', b'"type":"host"'))


def test_provider_policy_is_closed_to_tuoni_and_impacket_allowlist() -> None:
    valid = b"""{
      "missionRevision":1,
      "c2":{"providerId":"tuoni","registryReference":"registry://c2/tuoni/latest-commercial"},
      "enabledMcpServers":["impacket_mcp"],
      "operations":[
        {"id":"impacket.smb.negotiate","source":"impacket_mcp","state":"allowed","arbitraryArguments":false},
        {"id":"impacket.smb.authenticate","source":"impacket_mcp","state":"approval_required","arbitraryArguments":false},
        {"id":"impacket.smb.list_shares","source":"impacket_mcp","state":"approval_required","arbitraryArguments":false},
        {"id":"impacket.rpc.endpoint_map","source":"impacket_mcp","state":"allowed","arbitraryArguments":false}
      ]
    }"""
    assert ProviderPolicyDraftInput.from_untrusted_json(valid).c2.providerId == "tuoni"
    with pytest.raises(PydanticBoundaryValidationError):
        ProviderPolicyDraftInput.from_untrusted_json(valid.replace(b"impacket_mcp", b"arbitrary_mcp", 1))
    with pytest.raises(PydanticBoundaryValidationError):
        ProviderPolicyDraftInput.from_untrusted_json(valid.replace(b"false", b"true"))
