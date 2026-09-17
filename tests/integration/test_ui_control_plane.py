"""Offline integration coverage for the local operator UI control plane."""

from __future__ import annotations

import http.client
import json
import threading

import pytest

import support
from redteam_agent.ad_assessment.collector import ADCollectorError
from redteam_agent.ad_assessment.models import ADAssessmentSnapshot
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import LLMCapabilityError
from redteam_agent.llm.profile import build_mock_agent_profile
from redteam_agent.policy.scope_models import IpTargetReference
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.storage.database import Database
from redteam_agent.ui.auth import OperatorSessionAuthenticator
from redteam_agent.ui.control_plane import UIActionBlockedError, UIConflictError, UIControlPlane
from redteam_agent.ui.mission_commands import MissionCommandOwner
from redteam_agent.ui.models import MissionDraftInput, ProviderPolicyDraftInput, VllmConfigInput
from redteam_agent.ui.server import UIRouter, build_server, validate_direct_ui_origins


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
        "identityAttested": False,
    }
    latest = provider_status["latestDraft"]
    assert isinstance(latest, dict)
    assert latest["draft"]["c2"]["providerId"] == "tuoni"


def test_ad_assessment_catalog_and_offline_verifier_are_available_without_live_ad(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    snapshot = ADAssessmentSnapshot.from_untrusted_json(b"""{
      "snapshot_id":"snapshot-ui-1",
      "domain_ref":"domain:intern.local",
      "source_type":"simulator",
      "source_artifact_ids":["artifact-directory-1"],
      "collected_at":"2026-01-01T00:00:00Z",
      "privileged_access":null,
      "kerberos_service_accounts":null,
      "kerberos_preauth":{"preauthentication_disabled_account_count":1},
      "adcs":null,
      "delegation":null
    }""")

    catalog = control.ad_assessment_catalog()
    result = control.evaluate_ad_assessment(snapshot)

    assert catalog["plannerRole"] == "select_next_registered_inspection"
    assert catalog["liveCollectorStatus"] == "not_attached"
    assert result["decision_authority"] == "deterministic_verifier"
    assert result["evidence_source_type"] == "simulator"
    assert result["findings"][0]["rule_id"] == "AD-KRB-PREAUTH"

    spoofed = snapshot.model_copy(update={"source_type": "verified_ldap_snapshot"})
    with pytest.raises(UIConflictError, match="trusted collector"):
        control.evaluate_ad_assessment(spoofed)


def test_ad_assessment_llm_recommendation_is_advisory_and_capability_gated(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    expected = {
        "operation_id": "ad.audit.kerberos_preauth",
        "category": "kerberos_preauth_configuration",
        "title": "Kerberos preauthentication configuration",
        "description": "Read-only inspection.",
        "output_schema": "planner_output",
        "authority": "recommendation_only",
        "candidate_count": 5,
        "generated_at": support.T0.isoformat(),
    }
    control = UIControlPlane(
        database_path=str(path),
        ad_assessment_reasoning_port=lambda: expected,
        clock=lambda: support.T0,
    )

    assert control.health()["adAssessmentReasoningEnabled"] is True
    assert control.recommend_ad_assessment() == expected

    def not_qualified() -> dict[str, object]:
        raise LLMCapabilityError("test capability is missing")

    blocked = UIControlPlane(
        database_path=str(path),
        ad_assessment_reasoning_port=not_qualified,
        clock=lambda: support.T0,
    )
    with pytest.raises(UIActionBlockedError) as caught:
        blocked.recommend_ad_assessment()
    assert caught.value.code == "AD_ASSESSMENT_LLM_CAPABILITY_REQUIRED"


def test_complete_ad_assessment_is_simulator_only_and_capability_gated(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    snapshot = ADAssessmentSnapshot.from_untrusted_json(b"""{
      "snapshot_id":"snapshot-consensus-ui-1",
      "domain_ref":"domain:simulated.local",
      "source_type":"simulator",
      "source_artifact_ids":["artifact-directory-1"],
      "collected_at":"2026-01-01T00:00:00Z",
      "privileged_access":{"unexpected_tier_zero_membership_count":0,"stale_privileged_account_count":0,"excessive_delegated_admin_count":0},
      "kerberos_service_accounts":{"service_account_with_spn_count":0,"weak_encryption_service_account_count":0,"stale_password_service_account_count":0,"unmanaged_service_account_count":0},
      "kerberos_preauth":{"preauthentication_disabled_account_count":0},
      "adcs":{"exposure_counts":[]},
      "delegation":{"unconstrained_delegation_account_count":0,"broad_constrained_delegation_account_count":0,"protocol_transition_account_count":0,"risky_rbcd_acl_count":0}
    }""")
    expected = {"status": "completed", "category_results": ["all-five"]}
    control = UIControlPlane(
        database_path=str(path),
        ad_assessment_evaluation_port=lambda supplied: (expected if supplied == snapshot else {"status": "blocked"}),
        clock=lambda: support.T0,
    )

    assert control.health()["adAssessmentEvaluationEnabled"] is True
    assert control.evaluate_ad_assessment_with_llm(snapshot) == expected
    with pytest.raises(UIConflictError, match="trusted collector"):
        control.evaluate_ad_assessment_with_llm(
            snapshot.model_copy(update={"source_type": "verified_directory_export"})
        )

    def not_qualified(_snapshot: ADAssessmentSnapshot) -> dict[str, object]:
        raise LLMCapabilityError("test capability is missing")

    blocked = UIControlPlane(
        database_path=str(path),
        ad_assessment_evaluation_port=not_qualified,
        clock=lambda: support.T0,
    )
    with pytest.raises(UIActionBlockedError) as caught:
        blocked.evaluate_ad_assessment_with_llm(snapshot)
    assert caught.value.code == "AD_ASSESSMENT_LLM_CAPABILITY_REQUIRED"


def test_live_ad_collector_is_server_owned_and_reports_actionable_failures(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    expected = {"status": "completed", "evidence_source_type": "verified_ldap_snapshot"}
    control = UIControlPlane(
        database_path=str(path),
        ad_assessment_collector_port=lambda: expected,
        clock=lambda: support.T0,
    )

    assert control.health()["adAssessmentCollectorEnabled"] is True
    assert control.ad_assessment_catalog()["liveCollectorStatus"] == "attached"
    assert control.collect_and_evaluate_ad_assessment() == expected

    def unreachable() -> dict[str, object]:
        raise ADCollectorError(
            code="AD_COLLECTOR_LDAPS_UNREACHABLE",
            message="The configured domain controller LDAPS endpoint is unreachable or untrusted.",
            resolution="Provide the DC IP, allow TCP/636, and install its issuing CA certificate.",
        )

    blocked = UIControlPlane(
        database_path=str(path),
        ad_assessment_collector_port=unreachable,
        clock=lambda: support.T0,
    )
    with pytest.raises(UIActionBlockedError) as caught:
        blocked.collect_and_evaluate_ad_assessment()
    assert caught.value.code == "AD_COLLECTOR_LDAPS_UNREACHABLE"
    assert "TCP/636" in caught.value.resolution


def test_readiness_explains_each_unresolved_activation_requirement(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    control.save_mission_draft(_mission_draft())

    readiness = control.readiness()
    blocker_ids = {item["id"] for item in readiness["blockers"]}
    assert readiness["status"] == "blocked"
    assert readiness["blockerCount"] == len(readiness["blockers"])
    assert {
        "SUCCESS_CONDITION_UNSUPPORTED",
        "MISSION_NOT_CREATED",
        "PROVIDER_POLICY_DRAFT_MISSING",
        "LLM_GATEWAY_UNAVAILABLE",
        "SLIVER_IDENTITY_UNATTESTED",
        "TPM_KEY_PROVIDER_UNAVAILABLE",
    }.issubset(blocker_ids)
    unsupported = next(item for item in readiness["blockers"] if item["id"] == "SUCCESS_CONDITION_UNSUPPORTED")
    assert "Active session exists" in unsupported["resolution"]


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


def test_vllm_settings_routes_never_return_registered_api_key(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    calls: list[tuple[str, object]] = []

    class SettingsPort:
        def state(self) -> dict[str, object]:
            return {
                "enabled": True,
                "active": {"version": 1, "config": _vllm_config().model_dump(mode="json")},
                "candidate": None,
            }

        def public_state(self) -> dict[str, object]:
            return self.state()

        def stage(self, request: object) -> dict[str, object]:
            calls.append(("stage", request.apiKey.get_secret_value()))  # type: ignore[attr-defined]
            return self.state()

        def test_candidate(self, *, expected_version: int) -> dict[str, object]:
            calls.append(("test", expected_version))
            return {"settings": self.state(), "capability": {"status": "passed"}}

        def activate_candidate(self, *, expected_version: int) -> dict[str, object]:
            calls.append(("activate", expected_version))
            return {"activated": True, "settings": self.state(), "capability": {"status": "passed"}}

    settings = SettingsPort()
    control = UIControlPlane(
        database_path=str(path),
        vllm_capability_port=lambda config: {"status": "passed"},
        vllm_public_config=_vllm_config(),
        vllm_settings_port=settings,
    )
    router = UIRouter(control)

    staged = router.dispatch(
        method="POST",
        path="/api/v1/vllm/candidate",
        body=b'{"baseUrl":"http://10.0.6.182:8100/v1","apiKey":"one-shot-secret"}',
    )
    tested = router.dispatch(
        method="POST", path="/api/v1/vllm/candidate/test", body=b'{"version":2}'
    )
    activated = router.dispatch(
        method="POST", path="/api/v1/vllm/candidate/activate", body=b'{"version":2}'
    )

    assert staged.status == 201
    assert "one-shot-secret" not in json.dumps(staged.body)
    assert tested.status == 200
    assert activated.status == 200
    assert calls == [("stage", "one-shot-secret"), ("test", 2), ("activate", 2)]


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

    control = UIControlPlane(database_path=str(path), approval_decision_port=submit, clock=lambda: support.T0)
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


def test_http_server_direct_bind_enforces_explicit_non_rfc1918_origin_and_authentication(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    authenticator = OperatorSessionAuthenticator(
        principal_id="redteam-operator",
        operator_token=bytearray(b"a" * 32),
        clock=lambda: support.T0,
        token_factory=lambda: "s" * 32,
    )
    origin = "http://100.101.210.70:18000"
    server = build_server(
        control_plane=control,
        host="0.0.0.0",
        port=0,
        static_root=None,
        authenticator=authenticator,
        allowed_origins=(origin,),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = server.server_address
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/api/v1/health", headers={"Host": "100.101.210.71:18000"})
        assert connection.getresponse().status == 400
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/api/v1/dashboard", headers={"Host": "100.101.210.70:18000"})
        assert connection.getresponse().status == 401
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/session",
            json.dumps({"token": "a" * 32}),
            {
                "Content-Type": "application/json",
                "Host": "100.101.210.70:18000",
                "Origin": "http://100.101.210.71:18000",
                "X-RedTeam-UI": "1",
            },
        )
        assert connection.getresponse().status == 403
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/session",
            json.dumps({"token": "a" * 32}),
            {
                "Content-Type": "application/json",
                "Host": "100.101.210.70:18000",
                "Origin": origin,
                "X-RedTeam-UI": "1",
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        cookie = response.getheader("Set-Cookie") or ""
        assert "HttpOnly" in cookie
        session_cookie = cookie.split(";", 1)[0]
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "GET",
            "/api/v1/dashboard",
            headers={"Host": "100.101.210.70:18000", "Cookie": session_cookie},
        )
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_explicit_origin_accepts_all_ipv4_and_rejects_malformed_urls(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    with pytest.raises(ValueError, match="exact origin or RFC1918"):
        build_server(control_plane=control, host="0.0.0.0", port=18000, static_root=None)
    assert validate_direct_ui_origins(
        (
            "http://100.101.210.70:18000",
            "http://203.0.113.10:18000",
            "http://8.8.8.8:18000",
            "http://0.0.0.0:18000",
            "http://255.255.255.255:18000",
        )
    ) == (
        "http://100.101.210.70:18000",
        "http://203.0.113.10:18000",
        "http://8.8.8.8:18000",
        "http://0.0.0.0:18000",
        "http://255.255.255.255:18000",
    )
    for invalid_host in ("redteam-agent.example", "*", "999.1.1.1"):
        with pytest.raises(ValueError, match="literal IPv4"):
            validate_direct_ui_origins((f"http://{invalid_host}:18000",))
    for malformed in (
        "https://100.101.210.70:18000",
        "http://100.101.210.70",
        "http://100.101.210.70:18000/",
        "http://100.101.210.70:18000/dashboard",
        "http://user@100.101.210.70:18000",
        "http://100.101.210.70:18000?query=1",
        "http://100.101.210.70:18000#fragment",
    ):
        with pytest.raises(ValueError, match="exact HTTP origin"):
            validate_direct_ui_origins((malformed,))
    with pytest.raises(ValueError, match="must be unique"):
        validate_direct_ui_origins(("http://100.101.210.70:18000", "http://100.101.210.70:18000"))
    with pytest.raises(ValueError, match="port must match"):
        build_server(
            control_plane=control,
            host="0.0.0.0",
            port=18000,
            static_root=None,
            allowed_origins=("http://100.101.210.70:18001",),
        )


def test_http_server_can_derive_origin_from_the_requested_runtime_rfc1918_ip(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    server = build_server(
        control_plane=control,
        host="0.0.0.0",
        port=0,
        static_root=None,
        allow_rfc1918_same_origin=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = server.server_address
    body = json.dumps(_mission_draft().model_dump(mode="json")).encode()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/mission-drafts",
            body,
            {
                "Content-Type": "application/json",
                "Host": "10.20.30.40:18000",
                "Origin": "http://10.20.30.40:18000",
                "X-RedTeam-UI": "1",
            },
        )
        assert connection.getresponse().status == 201
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/mission-drafts",
            body,
            {
                "Content-Type": "application/json",
                "Host": "10.20.30.40:18000",
                "Origin": "http://10.20.30.41:18000",
                "X-RedTeam-UI": "1",
            },
        )
        assert connection.getresponse().status == 403
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", "/api/v1/health", headers={"Host": "100.101.210.70:18000"})
        assert connection.getresponse().status == 400
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


def test_http_server_exchanges_operator_token_for_httponly_session(tmp_path) -> None:
    path = tmp_path / "app.db"
    Database(str(path)).close()
    control = UIControlPlane(database_path=str(path), clock=lambda: support.T0)
    authenticator = OperatorSessionAuthenticator(
        principal_id="redteam-operator",
        operator_token=bytearray(b"a" * 32),
        clock=lambda: support.T0,
        token_factory=lambda: "s" * 32,
    )
    server = build_server(
        control_plane=control,
        host="127.0.0.1",
        port=0,
        static_root=None,
        authenticator=authenticator,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    origin = f"http://{host}:{port}"
    try:
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/api/v1/dashboard")
        response = connection.getresponse()
        assert response.status == 401
        assert json.loads(response.read())["code"] == "UNAUTHENTICATED"
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request(
            "POST",
            "/api/v1/session",
            json.dumps({"token": "a" * 32}),
            {
                "Content-Type": "application/json",
                "Origin": origin,
                "X-RedTeam-UI": "1",
            },
        )
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["principalId"] == "redteam-operator"
        cookie = response.getheader("Set-Cookie")
        assert cookie is not None and "HttpOnly" in cookie and "SameSite=Strict" in cookie
        session_cookie = cookie.split(";", 1)[0]
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/api/v1/dashboard", headers={"Cookie": session_cookie})
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["mission"] is None
        connection.close()

        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/api/v1/readiness", headers={"Cookie": session_cookie})
        response = connection.getresponse()
        assert response.status == 200
        readiness = json.loads(response.read())
        assert readiness["status"] == "blocked"
        assert readiness["blockerCount"] == len(readiness["blockers"])
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_ui_mission_owner_creates_validates_and_starts_reviewed_draft(tmp_path) -> None:
    path = tmp_path / "app.db"
    kernel = build_test_kernel(db_path=str(path), clock=ManualClock(support.T0))
    profile = build_mock_agent_profile(digest_service=kernel.digest_service)
    owner = MissionCommandOwner(kernel=kernel, profile=profile, execution_enabled=True)
    control = UIControlPlane(
        database_path=str(path),
        mission_command_port=owner,
        approval_decision_port=owner.submit_approval,
        clock=lambda: support.T0,
    )
    draft = _mission_draft().model_copy(update={"successType": "session_exists", "successValue": "sess-1"})
    saved = control.save_mission_draft(draft)

    created = control.create_mission(draft_id=str(saved["draftId"]))
    assert created["state"] == "DRAFT"
    assert control.create_mission(draft_id=str(saved["draftId"])) == created

    validated = control.transition_mission(
        mission_id=str(created["missionId"]),
        expected_version=0,
        action="validate",
    )
    assert validated["state"] == "VALIDATED"
    running = control.transition_mission(
        mission_id=str(created["missionId"]),
        expected_version=1,
        action="start",
    )
    assert running["state"] == "RUNNING"
    assert control.health()["missionActionsEnabled"] is True
    assert control.health()["missionExecutionEnabled"] is True
    kernel.database.close()


def test_ui_mission_owner_rejects_unimplemented_success_authority(tmp_path) -> None:
    path = tmp_path / "app.db"
    kernel = build_test_kernel(db_path=str(path), clock=ManualClock(support.T0))
    owner = MissionCommandOwner(
        kernel=kernel,
        profile=build_mock_agent_profile(digest_service=kernel.digest_service),
    )
    control = UIControlPlane(database_path=str(path), mission_command_port=owner, clock=lambda: support.T0)
    saved = control.save_mission_draft(_mission_draft())
    with pytest.raises(UIActionBlockedError) as caught:
        control.create_mission(draft_id=str(saved["draftId"]))
    assert caught.value.code == "MISSION_DRAFT_NOT_ACTIVATABLE"
    assert "Execution readiness" in caught.value.resolution
    kernel.database.close()


def test_ui_mission_owner_blocks_start_without_an_attached_execution_runtime(tmp_path) -> None:
    path = tmp_path / "app.db"
    kernel = build_test_kernel(db_path=str(path), clock=ManualClock(support.T0))
    owner = MissionCommandOwner(
        kernel=kernel,
        profile=build_mock_agent_profile(digest_service=kernel.digest_service),
    )
    control = UIControlPlane(database_path=str(path), mission_command_port=owner, clock=lambda: support.T0)
    saved = control.save_mission_draft(
        _mission_draft().model_copy(update={"successType": "session_exists", "successValue": "sess-1"})
    )
    created = control.create_mission(draft_id=str(saved["draftId"]))
    validated = control.transition_mission(mission_id=str(created["missionId"]), expected_version=0, action="validate")

    with pytest.raises(UIActionBlockedError) as caught:
        control.transition_mission(
            mission_id=str(created["missionId"]),
            expected_version=int(validated["missionStateVersion"]),
            action="start",
        )
    assert caught.value.code == "MISSION_VALIDATION_BLOCKED"
    assert "Execution readiness" in caught.value.resolution
    kernel.database.close()
