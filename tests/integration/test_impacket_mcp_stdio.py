"""Credential-free process-level acceptance for the Impacket MCP stdio server."""

from __future__ import annotations

from pathlib import Path

import support
from redteam_agent.adapters.impacket_composition import build_impacket_mcp_adapter
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.runtime.clock import ManualClock


def test_real_one_shot_stdio_process_qualifies_discovery_and_tool_catalog() -> None:
    ds = DigestService()
    clock = ManualClock(support.T0)
    executable = str(
        (Path(__file__).parents[2] / ".venv/bin/redteam-impacket-mcp").resolve(
            strict=True
        )
    )
    adapter = build_impacket_mcp_adapter(
        executable_path=executable,
        allowed_targets=("10.20.30.0/24",),
        evidence_kind="test_server",
        production_eligible=False,
        sandbox_verified=True,
        clock=clock,
        digest_service=ds,
    )

    capabilities = adapter.get_capabilities()

    assert capabilities.adapter_id == "mcp-impacket-local"
    assert capabilities.target_binding_modes == frozenset({"exact_ip_enforced"})
    assert len(
        [item for item in capabilities.capabilities if item.startswith("mcp.tool:")]
    ) == 4
