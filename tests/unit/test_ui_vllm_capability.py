"""Configuration boundary tests for the trusted UI/Phase 2 VLLM adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam_agent.storage.database import Database
from redteam_agent.ui.vllm_capability import Phase2VllmCapabilitySettings


def _settings(tmp_path: Path, **updates: object) -> Phase2VllmCapabilitySettings:
    database = tmp_path / "app.db"
    if not database.exists():
        Database(str(database)).close()
    values: dict[str, object] = {
        "database_path": database,
        "base_url": "http://10.0.6.181:8100/v1/",
        "model": "gemma-4-31B-it",
        "api_key_file": tmp_path / "vllm.key",
        "manifest_path": tmp_path / "model.manifest.json",
        "public_key_path": tmp_path / "attestation.pem",
        "manifest_key_id": "model-key-1",
        "tokenizer_directory": tmp_path / "tokenizer",
    }
    values.update(updates)
    return Phase2VllmCapabilitySettings(**values)  # type: ignore[arg-type]


def test_public_config_exposes_no_secret_or_artifact_paths(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    assert settings.public_config().model_dump(mode="json") == {
        "baseUrl": "http://10.0.6.181:8100/v1",
        "modelName": "gemma-4-31B-it",
        "wireApi": "chat_completions",
        "structuredOutputMode": "native",
    }


def test_tool_output_ui_mode_maps_to_the_fixed_profile_mode(tmp_path: Path) -> None:
    settings = _settings(tmp_path, structured_output_mode="tool_output")

    assert settings.profile_output_mode == "tool_output_json"


def test_relative_secret_or_artifact_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must be absolute"):
        _settings(tmp_path, api_key_file=Path("relative.key"))


def test_missing_application_database_is_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"

    with pytest.raises(ValueError, match="existing application database"):
        _settings(tmp_path, database_path=missing)
