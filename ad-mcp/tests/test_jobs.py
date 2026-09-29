import asyncio
import hashlib
from pathlib import Path

import pytest

from ad_mcp.audit import AuditLog
from ad_mcp.catalog import CATALOG_REVISION
from ad_mcp.command import BuiltCommand
from ad_mcp.jobs import JobManager, JobStore
from ad_mcp.models import CommandPlan, JobState, ProjectAuthorization, Risk, ToolDefinition
from ad_mcp.storage import RawStorage


def _auth(execution_id: str = "execution-1") -> ProjectAuthorization:
    return ProjectAuthorization(
        client_id="redteam-agent",
        actor_id="operator-1",
        mission_id="mission-1",
        execution_id=execution_id,
        approval_id=None,
        catalog_revision=CATALOG_REVISION,
        token="x" * 32,
    )


def _tool() -> ToolDefinition:
    return ToolDefinition(
        operation_id="test.provider.read",
        mcp_name="test.provider.read",
        category="test",
        binary_id="printf",
        supported_version="test",
        argv_prefix=(),
        risk=Risk.PASSIVE,
        description="test",
        parser_id="test-v1",
        default_timeout_seconds=5,
        max_output_bytes=1024,
        network_target_required=False,
    )


@pytest.mark.asyncio
async def test_job_output_is_private_and_public_result_is_structured(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    raw_root.mkdir(mode=0o700)
    manager = JobManager(
        JobStore(tmp_path / "jobs.sqlite3"),
        RawStorage(raw_root, 24),
        AuditLog(tmp_path / "audit.jsonl"),
        max_concurrent=1,
    )
    binary = str(Path("/usr/bin/printf").resolve())
    command = BuiltCommand(
        (binary, "provider-secret-output"),
        CommandPlan(
            operation_id="test.provider.read",
            executable=binary,
            redacted_argv=(binary, "<redacted>"),
            targets=(),
            risk=Risk.PASSIVE,
            timeout_seconds=5,
            max_output_bytes=1024,
        ),
    )
    auth = _auth()
    job = await manager.start(_tool(), command, auth)
    for _ in range(100):
        current = manager.get(job.job_id, auth)
        if current.state is not JobState.RUNNING:
            break
        await asyncio.sleep(0.01)
    assert current.state is JobState.SUCCEEDED
    assert current.result is not None
    assert "provider-secret-output" not in current.result.model_dump_json()
    raw_file = raw_root / job.job_id / "stdout.log"
    assert raw_file.read_text() == "provider-secret-output"
    assert raw_file.stat().st_mode & 0o777 == 0o600
    metadata = raw_root / job.job_id / "metadata.json"
    assert hashlib.sha256(raw_file.read_bytes()).hexdigest() in metadata.read_text()
    assert "provider-secret-output" not in (tmp_path / "audit.jsonl").read_text()
