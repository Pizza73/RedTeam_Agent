"""Offline wiring test for the Kali-local authenticated control plane."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition import kali_product
from redteam_agent.composition.kali_product import KaliProductSettings
from redteam_agent.llm.profile import build_local_llm_profile


class _FakeVllmCapabilityPort:
    def __init__(self, *, settings: object) -> None:
        self.public_config = settings.public_config()  # type: ignore[attr-defined]
        self.profile = build_local_llm_profile(
            profile_revision="test-vllm-r1",
            structured_output_mode="native_json_schema",
            max_context_tokens=131_072,
            max_output_tokens=1_024,
            model_name="gemma-4-31B-it",
            model_hash="b" * 64,
            chat_template_digest="d" * 64,
            tokenizer_revision="c" * 64,
            runtime_version="0.25.1",
            digest_service=DigestService(),
        )

    def __call__(self, config: object) -> dict[str, object]:
        del config
        return {"status": "failed", "summary": "offline test", "checks": []}

    def recommend_ad_assessment(self) -> dict[str, object]:
        return {
            "operation_id": "ad.audit.kerberos_preauth",
            "category": "kerberos_preauth_configuration",
            "title": "Kerberos preauthentication configuration",
            "description": "Read-only test recommendation.",
            "output_schema": "planner_output",
            "authority": "recommendation_only",
            "candidate_count": 5,
            "generated_at": "2026-01-01T00:00:00Z",
        }

    def evaluate_ad_assessment_with_llm(self, snapshot: object) -> dict[str, object]:
        del snapshot
        return {"status": "completed", "category_results": []}


def _settings(tmp_path: Path) -> KaliProductSettings:
    token = tmp_path / "operator.token"
    token.write_bytes(b"a" * 32)
    token.chmod(0o600)
    static = tmp_path / "static"
    static.mkdir()
    return KaliProductSettings(
        databasePath=str(tmp_path / "product.db"),
        staticDirectory=str(static),
        operatorTokenFile=str(token),
        vllmApiKeyFile=str(tmp_path / "vllm.key"),
        vllmSettingsDirectory=str(tmp_path / "llm-settings"),
        vllmManifest=str(tmp_path / "manifest.json"),
        vllmPublicKey=str(tmp_path / "public.pem"),
        vllmTokenizerDirectory=str(tmp_path / "tokenizer"),
        impacketExecutable=str(tmp_path / "redteam-impacket-mcp"),
        approvedSessionRefs=(),
    )


def test_kali_product_wires_auth_and_persistent_owner_without_enabling_execution(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(kali_product, "Phase2VllmCapabilityPort", _FakeVllmCapabilityPort)
    settings = _settings(tmp_path)

    first = kali_product.build_kali_product_application(settings)
    assert first.control_plane.health()["missionExecutionEnabled"] is False
    assert first.control_plane.health()["adAssessmentReasoningEnabled"] is True
    assert first.control_plane.health()["adAssessmentEvaluationEnabled"] is True
    assert first.control_plane.provider_status()["runtime"]["productionEligible"] is False
    session_id, session = first.authenticator.login("a" * 32)
    assert first.authenticator.authenticate(session_id) == session
    first.close()

    second = kali_product.build_kali_product_application(settings)
    try:
        assert second.control_plane.health()["database"] == "connected"
        assert second.settings.productionEligible is False
    finally:
        second.close()


def test_kali_product_direct_bind_requires_exact_matching_origin(tmp_path: Path) -> None:
    base = _settings(tmp_path)
    with pytest.raises(ValueError, match="exact origin or RFC1918"):
        KaliProductSettings.model_validate({**base.model_dump(), "uiHost": "0.0.0.0"})
    with pytest.raises(ValueError, match="must match uiPort"):
        KaliProductSettings.model_validate(
            {
                **base.model_dump(),
                "uiHost": "0.0.0.0",
                "uiAllowedOrigins": ("http://10.0.1.109:18001",),
            }
        )

    settings = KaliProductSettings.model_validate(
        {
            **base.model_dump(),
            "uiHost": "0.0.0.0",
            "uiAllowedOrigins": ("http://10.0.1.109:18000",),
        }
    )
    assert settings.uiAllowedOrigins == ("http://10.0.1.109:18000",)

    dynamic = KaliProductSettings.model_validate(
        {
            **base.model_dump(),
            "uiHost": "0.0.0.0",
            "uiOriginPolicy": "rfc1918_same_origin",
            "uiAllowedOrigins": (),
        }
    )
    assert dynamic.uiOriginPolicy == "rfc1918_same_origin"
    assert dynamic.uiAllowedOrigins == ()


def test_kali_product_attaches_server_owned_ad_collector_when_enabled(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(kali_product, "Phase2VllmCapabilityPort", _FakeVllmCapabilityPort)
    credential = tmp_path / "ad-credential.json"
    credential.write_text(
        '{"domain":"intern.local","username":"collector","password":"test-secret"}',
        encoding="utf-8",
    )
    credential.chmod(0o600)
    settings = _settings(tmp_path).model_copy(
        update={
            "adCollectorEnabled": True,
            "adCollectorServerIp": "10.0.10.10",
            "adCollectorCredentialFile": str(credential),
            "adCollectorCertipyPython": "/usr/bin/python3",
        }
    )

    application = kali_product.build_kali_product_application(settings)
    try:
        assert application.ad_collector is not None
        assert application.control_plane.health()["adAssessmentCollectorEnabled"] is True
        assert application.control_plane.ad_assessment_catalog()["liveCollectorStatus"] == "attached"
    finally:
        application.close()
