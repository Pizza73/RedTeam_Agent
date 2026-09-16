"""Offline integration coverage for the local operator UI control plane."""

from __future__ import annotations

import http.client
import json
import threading

import pytest

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.policy.scope_models import IpTargetReference
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.storage.database import Database
from redteam_agent.ui.control_plane import UIControlPlane
from redteam_agent.ui.models import MissionDraftInput, ProviderPolicyDraftInput, VllmConfigInput
from redteam_agent.ui.server import build_server


def _mission_draft() -> MissionDraftInput:
    return MissionDraftInput.from_untrusted_json(b"""{
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
    }""")


def _provider_draft() -> ProviderPolicyDraftInput:
    return ProviderPolicyDraftInput.from_untrusted_json(b"""{
      "missionRevision":1,
      "c2":{"providerId":"tuoni","registryReference":"registry://c2/tuoni/latest-commercial"},
      "enabledMcpServers":["impacket_mcp"],
      "operations":[
        {"id":"impacket.smb.negotiate","source":"impacket_mcp","state":"allowed","arbitraryArguments":false},
        {"id":"impacket.smb.authenticate","source":"impacket_mcp","state":"approval_required","arbitraryArguments":false},
        {"id":"impacket.smb.list_shares","source":"impacket_mcp","state":"approval_required","arbitraryArguments":false},
        {"id":"impacket.rpc.endpoint_map","source":"impacket_mcp","state":"allowed","arbitraryArguments":false}
      ]
    }""")


def _vllm_config() -> VllmConfigInput:
    return VllmConfigInput(
        baseUrl="http://10.0.6.181:8100/v1",
        modelName="gemma-4-31B-it",
        wireApi="chat_completions",
        structuredOutputMode="native",
    )


def test_empty_provisioned_database_and_drafts_are_managed_without_activation(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)

    assert control.health()["status"] == "healthy"
    assert control.dashboard()["mission"] is None
    mission_result = control.save_mission_draft(_mission_draft())
    provider_result = control.save_provider_policy_draft(_provider_draft())

    database = Database(str(path), create_schema=False)
    try:
        assert len(database.get_all("ui_mission_draft")) == 1
        assert len(database.get_all("ui_provider_policy_draft")) == 1
        assert database.get_all("mission_states") == []
    finally:
        database.close()
    assert str(mission_result["draftId"]).startswith("mission-draft-")
    assert str(provider_result["draftId"]).startswith("provider-draft-")
    provider_status = control.provider_status()
    sliver_status = provider_status["sliver"]
    assert isinstance(sliver_status, dict)
    assert sliver_status == {
        "version": "1.7.7",
        "operator": "joe",
        "operatorConfigLocation": "downloads",
        "operatorAccess": "unconfigured",
        "implantTransport": "http",
        "beaconPresent": False,
    }
    latest = provider_status["latestDraft"]
    assert isinstance(latest, dict)
    assert latest["draft"]["c2"]["providerId"] == "tuoni"


def test_vllm_check_uses_attached_port_and_publishes_only_managed_configuration(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    calls: list[VllmConfigInput] = []

    def capability(config: VllmConfigInput) -> dict[str, object]:
        calls.append(config)
        return {
            "status": "passed",
            "summary": "Attested capability passed.",
            "latencyMs": 12,
            "checkedAt": support.T0.isoformat(),
            "checks": [{"name": "planner_output", "status": "passed", "detail": "10/10"}],
        }

    config = _vllm_config()
    control = UIControlPlane(
        database_path=str(path),
        vllm_capability_port=capability,
        vllm_public_config=config,
        clock=lambda: support.T0,
    )

    assert control.health()["vllmChecksEnabled"] is True
    assert control.vllm_configuration() == {
        "enabled": True,
        "config": config.model_dump(mode="json"),
    }
    assert control.check_vllm(config)["status"] == "passed"
    assert calls == [config]


def test_vllm_port_and_public_configuration_must_be_attached_together(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()

    with pytest.raises(ValueError, match="attached together"):
        UIControlPlane(database_path=str(path), vllm_public_config=_vllm_config())


def test_dashboard_projects_real_mission_state_and_lifecycle(tmp_path) -> None:
    path = tmp_path / "app.db"
    kernel = build_test_kernel(db_path=str(path), clock=ManualClock(support.T0))
    tool = support.network_tool()
    profile = support.make_profile(kernel.digest_service)
    revision = support.mission_revision(kernel.digest_service, profile=profile)
    support.seed_running_mission(kernel, tool=tool, revision=revision)
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)

    dashboard = control.dashboard()

    assert dashboard["mission"] == {
        "id": support.MISSION_ID,
        "title": "exercise",
        "state": "running",
        "revision": 1,
        "authorizationEpoch": 0,
        "authorizationReference": "AUTH-REF-1",
        "validUntil": revision.valid_until.isoformat(),
        "objectives": ["enumerate"],
        "scopes": ["network:10.0.0.0/8"],
    }
    assert len(dashboard["timeline"]) == 3
    assert control.phases()[0]["status"] == "current"
    kernel.database.close()


def test_approval_decision_uses_injected_owner_service_and_exact_presentation(tmp_path) -> None:
    path = tmp_path / "app.db"
    kernel = build_test_kernel(db_path=str(path), clock=ManualClock(support.T0))
    tool = support.network_tool(minimum_risk="high", approval_rule="always")
    profile = support.make_profile(kernel.digest_service)
    revision = support.mission_revision(
        kernel.digest_service,
        profile=profile,
        require_for_risk=frozenset({"high"}),
    )
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    proposal = support.make_proposal(
        tool=seeded.tool,
        arguments={"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
        requested_targets=(IpTargetReference(type="ip", address="10.1.2.3"),),
    )
    plan = support.make_plan(kernel, seeded=seeded, proposal=proposal)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "REQUIRE_APPROVAL"
    request = kernel.approval_service.issue_request(
        approval_request_id="approval-ui-1", decision_id=decision.decision_id, plan=plan
    )
    support.register_approver(kernel, token="ui-approver", principal_id="ui-operator")

    def submit(request_id: str, verdict: str) -> None:
        kernel.approval_service.submit_decision(
            approval_id="approval-record-ui-1",
            approval_request_id=request_id,
            actor_token="ui-approver",
            verdict=verdict,
        )

    control = UIControlPlane(
        database_path=str(path), approval_decision_port=submit, clock=lambda: support.T0
    )
    pending = control.interventions()[0]
    assert pending["actionable"] is True

    updated = control.submit_approval(
        approval_request_id="approval-ui-1",
        presentation_digest=request.presentation.presentation_digest,
        verdict="approved",
    )

    assert updated["state"] == "approved"
    assert kernel.record_repository.find_by_request("approval-ui-1").approver_id == "ui-operator"  # type: ignore[union-attr]
    kernel.database.close()


def test_http_server_requires_same_origin_proof_for_mutations(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    server = build_server(control_plane=control, host="127.0.0.1", port=0, static_root=None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    body = json.dumps(_mission_draft().model_dump(mode="json")).encode()
    try:
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("POST", "/api/v1/mission-drafts", body, {"Content-Type": "application/json"})
        assert connection.getresponse().status == 403
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        origin = f"http://{host}:{port}"
        connection.request(
            "POST",
            "/api/v1/mission-drafts",
            body,
            {"Content-Type": "application/json", "Origin": origin, "X-RedTeam-UI": "1"},
        )
        response = connection.getresponse()
        assert response.status == 201
        assert json.loads(response.read())["draftId"].startswith("mission-draft-")
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_server_falls_back_only_for_spa_routes(tmp_path) -> None:
    path = tmp_path / "app.db"
    static_root = tmp_path / "dist"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>operator</title>", encoding="utf-8")
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    server = build_server(control_plane=control, host="127.0.0.1", port=0, static_root=static_root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/settings/providers")
        response = connection.getresponse()
        assert response.status == 200
        assert b"operator" in response.read()
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/assets/missing.js")
        response = connection.getresponse()
        assert response.status == 404
        assert json.loads(response.read())["code"] == "NOT_FOUND"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
