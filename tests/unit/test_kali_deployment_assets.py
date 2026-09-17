from __future__ import annotations

import json
from pathlib import Path

from redteam_agent.composition.kali_product import KaliProductSettings

ROOT = Path(__file__).resolve().parents[2]


def test_kali_product_config_is_strict_and_contains_no_secret_values() -> None:
    raw = (ROOT / "deployment/kali/product.json").read_bytes()
    settings = KaliProductSettings.from_untrusted_json(raw)
    assert settings.productionEligible is False
    assert settings.uiHost == "0.0.0.0"
    assert settings.uiAllowedOrigins == ("http://10.0.1.109:18000",)
    assert settings.impacketAllowedTargets == ("10.0.10.212/32",)
    assert settings.vllmAllowedCidrs == ("10.0.6.0/24",)
    serialized = json.loads(raw)
    assert serialized.keys().isdisjoint({"apiKey", "operatorToken", "sliverToken", "password"})


def test_kali_systemd_unit_allows_only_configured_lan_and_service_dependencies() -> None:
    unit = (ROOT / "deployment/systemd/redteam-agent.service").read_text(encoding="utf-8")
    assert "User=redteam-agent" in unit
    assert "ExecStart=/opt/redteam-agent/venv/bin/redteam-product" in unit
    assert "LoadCredentialEncrypted=ui-operator.token:" in unit
    assert "LoadCredentialEncrypted=vllm-api.key:" in unit
    assert "LoadCredentialEncrypted=ad-collector-credential.json:" in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=10.0.1.0/24" in unit
    assert "IPAddressAllow=10.0.6.0/24" in unit
    assert "IPAddressAllow=10.0.10.212/32" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "CapabilityBoundingSet=\n" in unit
