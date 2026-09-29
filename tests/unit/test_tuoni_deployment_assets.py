"""Deployment assets stay aligned with the fixed runtime credential boundary."""

from __future__ import annotations

import json
from pathlib import Path

from redteam_agent.adapters.tuoni_linux_transport import TUONI_CREDENTIAL_FILE

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_systemd_drop_in_uses_only_the_encrypted_credential_store() -> None:
    drop_in = (
        REPOSITORY_ROOT
        / "deployment/systemd/redteam-agent.service.d/tuoni-credential.conf"
    ).read_text(encoding="utf-8")

    assert drop_in.splitlines() == [
        "[Service]",
        "LoadCredentialEncrypted=tuoni-credential.json:"
        "/etc/credstore.encrypted/redteam-agent-tuoni.credential",
    ]
    assert "LoadCredential=" not in drop_in
    assert TUONI_CREDENTIAL_FILE == (
        "/run/credentials/redteam-agent.service/tuoni-credential.json"
    )


def test_credential_schema_contains_no_value_or_permissive_extension_point() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "deployment/tuoni-credential.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert schema["additionalProperties"] is False
    assert schema["required"] == ["version_id", "username", "password"]
    serialized = json.dumps(schema).lower()
    assert '"default"' not in serialized
    assert '"example"' not in serialized
    assert '"value"' not in serialized
