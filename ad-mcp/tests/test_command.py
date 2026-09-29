import hashlib
from pathlib import Path

import pytest

from ad_mcp.catalog import BY_NAME, CATALOG_REVISION
from ad_mcp.command import CommandBuilder
from ad_mcp.config import ScopeConfig, Settings
from ad_mcp.errors import ValidationError
from ad_mcp.models import ProjectAuthorization, ToolCall
from ad_mcp.scope import ScopePolicy


def _settings(tmp_path: Path, binary: Path) -> Settings:
    return Settings(
        schema_version="ad-mcp-settings-v1",
        client_id="redteam-agent",
        workspace_root=tmp_path,
        raw_root=tmp_path / "raw",
        state_db=tmp_path / "state" / "jobs.sqlite3",
        audit_log=tmp_path / "audit" / "events.jsonl",
        binary_paths={"nmap": binary},
        binary_sha256={"nmap": hashlib.sha256(binary.read_bytes()).hexdigest()},
        enabled_operations=("recon.nmap.smb_security_mode",),
    )


def _auth(approval_id: str | None = None) -> ProjectAuthorization:
    return ProjectAuthorization(
        client_id="redteam-agent",
        actor_id="operator-1",
        mission_id="mission-1",
        execution_id="execution-1",
        approval_id=approval_id,
        catalog_revision=CATALOG_REVISION,
        token="x" * 32,
    )


def test_dry_run_builds_fixed_command_without_enabling_unclassified_risk(tmp_path: Path) -> None:
    binary = Path("/usr/bin/printf").resolve()
    builder = CommandBuilder(
        _settings(tmp_path, binary),
        ScopePolicy(ScopeConfig(schema_version="ad-mcp-scope-v1", cidrs=("192.0.2.0/24",))),
    )
    command = builder.build(
        BY_NAME["recon.nmap.smb_security_mode"],
        ToolCall(targets=("192.0.2.10",), dry_run=True),
        _auth(),
        (),
    )
    assert command.argv[-1] == "192.0.2.10"
    assert command.plan.risk.value == "unclassified"

    with pytest.raises(ValidationError, match="RISK_CLASSIFICATION_PENDING"):
        builder.build(
            BY_NAME["recon.nmap.smb_security_mode"],
            ToolCall(targets=("192.0.2.10",)),
            _auth(),
            (),
        )

def test_unknown_parameter_and_non_ip_target_are_rejected(tmp_path: Path) -> None:
    binary = Path("/usr/bin/printf").resolve()
    builder = CommandBuilder(
        _settings(tmp_path, binary),
        ScopePolicy(ScopeConfig(schema_version="ad-mcp-scope-v1", cidrs=("192.0.2.0/24",))),
    )
    with pytest.raises(ValidationError, match="UNKNOWN_PARAMETER"):
        builder.build(
            BY_NAME["recon.nmap.smb_security_mode"],
            ToolCall(targets=("192.0.2.10",), parameters={"argv": "--script=all"}, dry_run=True),
            _auth(),
            (),
        )
