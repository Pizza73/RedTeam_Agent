import os
import sys
from pathlib import Path

import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ad_mcp.auth import AUTH_META_KEY
from ad_mcp.catalog import CATALOG_REVISION


@pytest.mark.asyncio
async def test_official_sdk_stdio_list_and_authorized_dry_run(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    settings_path = tmp_path / "settings.yaml"
    settings_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "ad-mcp-settings-v1",
                "client_id": "redteam-agent",
                "workspace_root": str(tmp_path),
                "raw_root": str(raw),
                "state_db": str(tmp_path / "jobs.sqlite3"),
                "audit_log": str(tmp_path / "audit.jsonl"),
                "binary_paths": {},
                "enabled_operations": [],
                "transport": "stdio",
                "remote_transport": "disabled",
            }
        ),
        encoding="utf-8",
    )
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "ad-mcp-scope-v1",
                "cidrs": ["192.0.2.0/24"],
                "domains": ["lab.example"],
                "hosts": [],
            }
        ),
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["AD_MCP_PROJECT_TOKEN"] = "x" * 32
    source = str(Path(__file__).parents[1] / "src")
    environment["PYTHONPATH"] = source
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "ad_mcp.server",
            "--settings",
            str(settings_path),
            "--scope",
            str(scope_path),
        ],
        env=environment,
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        initialized = await session.initialize()
        assert initialized.server_info.name == "redteam-ad-mcp"
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        assert "recon.nmap.smb_security_mode" in names
        meta = {
            AUTH_META_KEY: {
                "client_id": "redteam-agent",
                "actor_id": "operator-1",
                "mission_id": "mission-1",
                "execution_id": "execution-1",
                "approval_id": None,
                "catalog_revision": CATALOG_REVISION,
                "token": "x" * 32,
            }
        }
        result = await session.call_tool(
            "recon.nmap.smb_security_mode",
            arguments={
                "call": {
                    "targets": ["192.0.2.10"],
                    "domain": None,
                    "username": None,
                    "parameters": {},
                    "dry_run": True,
                }
            },
            meta=meta,
        )
        assert result.is_error is False
        assert result.structured_content is not None
        assert result.structured_content["result_type"] == "dry_run"
        assert result.structured_content["executed"] is False
