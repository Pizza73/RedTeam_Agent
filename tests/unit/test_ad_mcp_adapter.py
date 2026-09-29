from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import ClassVar

import support
from redteam_agent.adapters.ad_mcp_adapter import AdMcpAdapter
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.models import ProviderTaskBinding
from redteam_agent.execution.sink import StreamingQuarantineSink
from redteam_agent.models.common import ToolRef
from redteam_agent.runtime.clock import ManualClock


class FakeAdMcpClient:
    schema: ClassVar[dict[str, object]] = {
        "type": "object",
        "additionalProperties": False,
    }

    def list_tools(self, *, timeout_seconds: float = 15) -> dict[str, dict[str, object]]:
        del timeout_seconds
        return {"adcs.certipy.cert": self.schema}

    def call_tool(
        self,
        name: str,
        arguments: dict[str, object],
        authorization: dict[str, object],
        secret_bindings: tuple[dict[str, str], ...] = (),
        *,
        timeout_seconds: float = 30,
    ) -> dict[str, object]:
        del arguments, secret_bindings, timeout_seconds
        assert authorization["mission_id"] == "mission-1"
        if name == "adcs.certipy.cert":
            return {
                "result_type": "job",
                "job": {
                    "job_id": "job-1",
                    "execution_id": "execution-1",
                    "state": "running",
                },
            }
        if name == "job.get_status":
            return {
                "job_id": "job-1",
                "execution_id": "execution-1",
                "operation_id": "adcs.certipy.cert",
                "state": "succeeded",
                "created_at": support.T0.isoformat(),
                "updated_at": (support.T0 + timedelta(seconds=1)).isoformat(),
                "result": {
                    "schema_version": "ad-mcp-result-v1",
                    "status": "succeeded",
                    "exit_code": 0,
                    "raw_result_ref": "job-1",
                },
            }
        if name == "job.cancel":
            return {"state": "cancelled"}
        raise AssertionError(name)

    def encode_secret(
        self, *, argument_name: str, secret_version_id: str, material: bytes
    ) -> dict[str, str]:
        del material
        return {
            "argumentName": argument_name,
            "secretVersionId": secret_version_id,
            "encoding": "base64",
            "material": "redacted-test-value",
        }


def _adapter(tmp_path: Path) -> AdMcpAdapter:
    return AdMcpAdapter(
        client=FakeAdMcpClient(),
        approved_tool_schemas={"adcs.certipy.cert": FakeAdMcpClient.schema},
        state_db=tmp_path / "bindings.sqlite3",
        clock=ManualClock(support.T0),
        digest_service=DigestService(),
        adapter_identity_digest="adapter-digest",
        provider_identity_digest="provider-digest",
    )


def _request() -> ExecutionRequest:
    return ExecutionRequest(
        execution_id="execution-1",
        task_id="task-1",
        tool_ref=ToolRef(tool_id="adcs.certipy.cert", registry_revision=1),
        adapter_id="mcp-ad-local",
        provider_tool_name="adcs.certipy.cert",
        result_delivery_mode="provider_task",
        idempotency_key="idem-1",
        timeout_seconds=30,
        arguments={
            "call": {
                "targets": [],
                "domain": None,
                "username": None,
                "parameters": {"input_resource": "certificate.pem"},
                "dry_run": False,
            }
        },
        mission_id="mission-1",
        actor_id="executor",
    )


def test_submit_and_collect_public_provider_job(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    request = _request()
    handle = adapter.submit(
        request,
        (),
        DispatchResultCapture(mode="provider_task", capture_id="capture-1", sink=None),
        request.idempotency_key,
    )
    assert handle.provider_task_id == "job-1"
    binding = ProviderTaskBinding(
        task_id="task-1",
        execution_id="execution-1",
        adapter_identity_digest="adapter-digest",
        provider_identity_digest="provider-digest",
        provider_task_id="job-1",
        dispatch_claim_id="claim-1",
        binding_digest="binding-digest",
    )
    sink = StreamingQuarantineSink(
        sink_id="sink-1",
        execution_id="execution-1",
        quarantine_id="quarantine-1",
        task_binding_digest="binding-digest",
        max_output_bytes=1024 * 1024,
        committed_at=support.T0 + timedelta(seconds=1),
    )
    control = adapter.collect_result("execution-1", binding, sink)
    receipt = sink.commit()
    assert control.provider_status == "succeeded"
    assert receipt.stdout_bytes > 0


def test_capabilities_report_provider_jobs(tmp_path: Path) -> None:
    capabilities = _adapter(tmp_path).get_capabilities()
    assert capabilities.result_delivery_mode == "provider_task"
    assert capabilities.reconciliation is True
    assert capabilities.cancellation is True
