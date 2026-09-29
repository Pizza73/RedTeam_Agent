"""Deployment assets preserve the Sliver operator config as a credential."""

from __future__ import annotations

import json
from pathlib import Path

from redteam_agent.adapters.sliver_linux_transport import SLIVER_OPERATOR_CONFIG_FILE

ROOT = Path(__file__).resolve().parents[2]


def test_systemd_loads_the_operator_config_out_of_band() -> None:
    dropin = (
        ROOT / "deployment/systemd/redteam-agent.service.d/sliver-operator.conf"
    ).read_text(encoding="utf-8")
    assert "LoadCredentialEncrypted=sliver-operator.cfg:" in dropin
    assert SLIVER_OPERATOR_CONFIG_FILE == (
        "/run/credentials/redteam-agent.service/sliver-operator.cfg"
    )


def test_operator_config_schema_is_exact_and_never_has_defaults() -> None:
    schema = json.loads(
        (ROOT / "deployment/sliver-operator-config.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["operator"] == {"const": "joe"}
    assert all("default" not in value for value in schema["properties"].values())
