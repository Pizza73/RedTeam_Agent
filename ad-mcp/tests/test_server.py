from pathlib import Path

from ad_mcp.config import ScopeConfig, Settings
from ad_mcp.scope import ScopePolicy
from ad_mcp.server import Runtime, build_server


def test_official_sdk_server_registers_catalog_and_management_tools(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    settings = Settings(
        schema_version="ad-mcp-settings-v1",
        client_id="redteam-agent",
        workspace_root=tmp_path,
        raw_root=raw,
        state_db=tmp_path / "jobs.sqlite3",
        audit_log=tmp_path / "audit.jsonl",
        binary_paths={},
        enabled_operations=(),
    )
    runtime = Runtime(
        settings,
        ScopePolicy(ScopeConfig(schema_version="ad-mcp-scope-v1", cidrs=("192.0.2.0/24",))),
        "x" * 32,
    )
    server = build_server(runtime)
    names = set(server._tool_manager._tools)
    assert "catalog.describe" in names
    assert "run_allowlisted_tool" in names
    assert "job.get_status" in names
    assert "recon.nmap.smb_security_mode" in names
    schema = server._tool_manager._tools["recon.nmap.smb_security_mode"].parameters
    assert schema["additionalProperties"] is False
    assert "call" in schema["properties"]
    call_schema = schema["properties"]["call"]
    assert call_schema["properties"]["parameters"]["additionalProperties"] is False
