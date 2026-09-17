from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

import support
from redteam_agent.storage.database import Database
from redteam_agent.ui.models import VllmCandidateInput, VllmConfigInput
from redteam_agent.ui.vllm_capability import Phase2VllmCapabilitySettings
from redteam_agent.ui.vllm_settings import VllmSettingsManager


@dataclass(frozen=True)
class _Profile:
    profile_digest: str = "profile-digest"


class _FakePort:
    def __init__(self, settings: Phase2VllmCapabilitySettings, *, activation_fails: bool = False) -> None:
        self.settings = settings
        self.public_config = settings.public_config()
        self.profile = _Profile()
        self.activation_fails = activation_fails
        self.persistence: list[bool] = []

    def evaluate_capability(
        self, config: VllmConfigInput, *, persist_results: bool
    ) -> dict[str, object]:
        assert config == self.public_config
        self.persistence.append(persist_results)
        status = "failed" if persist_results and self.activation_fails else "passed"
        return {
            "status": status,
            "summary": "test result",
            "latencyMs": 1,
            "checkedAt": support.T0.isoformat(),
            "checks": [{"name": "planner_output", "status": status, "detail": "bounded"}],
        }

    def __call__(self, config: VllmConfigInput) -> dict[str, object]:
        return self.evaluate_capability(config, persist_results=True)

    def recommend_ad_assessment(self) -> dict[str, object]:
        return {"source": self.public_config.baseUrl}

    def evaluate_ad_assessment_with_llm(self, snapshot: object) -> dict[str, object]:
        del snapshot
        return {"source": self.public_config.baseUrl}

    def close(self) -> None:
        return


def _template(tmp_path: Path) -> Phase2VllmCapabilitySettings:
    database = tmp_path / "app.db"
    Database(str(database)).close()
    key = tmp_path / "initial.key"
    key.write_text("initial-secret", encoding="ascii")
    key.chmod(0o600)
    return Phase2VllmCapabilitySettings(
        database_path=database,
        base_url="http://10.0.6.181:8100/v1",
        model="gemma-4-31B-it",
        api_key_file=key,
        manifest_path=tmp_path / "manifest.json",
        public_key_path=tmp_path / "public.pem",
        manifest_key_id="test-key",
        tokenizer_directory=tmp_path / "tokenizer",
    )


def _candidate(base_url: str = "http://10.0.6.182:8100/v1") -> VllmCandidateInput:
    return VllmCandidateInput(baseUrl=base_url, apiKey="replacement-secret")


def test_candidate_key_is_private_redacted_and_not_published_before_activation(tmp_path: Path) -> None:
    template = _template(tmp_path)
    created: list[_FakePort] = []

    def factory(*, settings: Phase2VllmCapabilitySettings) -> _FakePort:
        port = _FakePort(settings)
        created.append(port)
        return port

    manager = VllmSettingsManager(
        initial_port=_FakePort(template),
        settings_template=template,
        settings_directory=tmp_path / "managed",
        allowed_cidrs=("10.0.6.0/24",),
        port_factory=factory,
        clock=lambda: support.T0,
    )

    staged = manager.stage(_candidate())
    serialized = json.dumps(staged)
    assert "replacement-secret" not in serialized
    assert "candidate-" not in serialized
    assert staged["active"]["config"]["baseUrl"] == "http://10.0.6.181:8100/v1"  # type: ignore[index]
    candidate = staged["candidate"]
    assert isinstance(candidate, dict)
    assert candidate["apiKeyConfigured"] is True
    key_file = created[0].settings.api_key_file
    assert key_file.read_text(encoding="ascii") == "replacement-secret"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

    tested = manager.test_candidate(expected_version=int(candidate["version"]))
    assert tested["capability"]["status"] == "passed"  # type: ignore[index]
    assert created[0].persistence == [False]

    activated = manager.activate_candidate(expected_version=int(candidate["version"]))
    assert activated["activated"] is True
    assert created[0].persistence == [False, True]
    assert manager.public_config.baseUrl == "http://10.0.6.182:8100/v1"
    assert manager.public_state()["candidate"] is None
    assert (tmp_path / "managed" / "active.json").is_file()
    assert "replacement-secret" not in (tmp_path / "managed" / "active.json").read_text(encoding="utf-8")


def test_candidate_rejects_destination_outside_allowlist_without_leaving_a_secret(tmp_path: Path) -> None:
    template = _template(tmp_path)
    managed = tmp_path / "managed"
    manager = VllmSettingsManager(
        initial_port=_FakePort(template),
        settings_template=template,
        settings_directory=managed,
        allowed_cidrs=("10.0.6.0/24",),
        port_factory=lambda *, settings: _FakePort(settings),
    )

    with pytest.raises(ValueError, match="allowlist"):
        manager.stage(_candidate("http://10.0.7.10:8100/v1"))
    assert list(managed.glob("*.key")) == []


def test_failed_activation_keeps_previous_active_endpoint(tmp_path: Path) -> None:
    template = _template(tmp_path)
    candidate_port: _FakePort | None = None

    def factory(*, settings: Phase2VllmCapabilitySettings) -> _FakePort:
        nonlocal candidate_port
        candidate_port = _FakePort(settings, activation_fails=True)
        return candidate_port

    manager = VllmSettingsManager(
        initial_port=_FakePort(template),
        settings_template=template,
        settings_directory=tmp_path / "managed",
        allowed_cidrs=("10.0.6.0/24",),
        port_factory=factory,
        clock=lambda: support.T0,
    )
    state = manager.stage(_candidate())
    candidate = state["candidate"]
    assert isinstance(candidate, dict)
    version = int(candidate["version"])
    manager.test_candidate(expected_version=version)

    result = manager.activate_candidate(expected_version=version)

    assert result["activated"] is False
    assert manager.public_config.baseUrl == template.base_url
    assert manager.public_state()["candidate"] is not None
    assert candidate_port is not None and candidate_port.persistence == [False, True]


def test_activated_endpoint_and_private_key_are_reloaded_after_restart(tmp_path: Path) -> None:
    template = _template(tmp_path)
    managed = tmp_path / "managed"

    def factory(*, settings: Phase2VllmCapabilitySettings) -> _FakePort:
        return _FakePort(settings)

    first = VllmSettingsManager(
        initial_port=_FakePort(template),
        settings_template=template,
        settings_directory=managed,
        allowed_cidrs=("10.0.6.0/24",),
        port_factory=factory,
        clock=lambda: support.T0,
    )
    state = first.stage(_candidate())
    candidate = state["candidate"]
    assert isinstance(candidate, dict)
    version = int(candidate["version"])
    first.test_candidate(expected_version=version)
    assert first.activate_candidate(expected_version=version)["activated"] is True
    first.close()

    second = VllmSettingsManager(
        initial_port=_FakePort(template),
        settings_template=template,
        settings_directory=managed,
        allowed_cidrs=("10.0.6.0/24",),
        port_factory=factory,
        clock=lambda: support.T0,
    )

    assert second.public_config.baseUrl == "http://10.0.6.182:8100/v1"
    assert second.public_state()["active"]["version"] == version  # type: ignore[index]
    assert second.public_state()["candidate"] is None
