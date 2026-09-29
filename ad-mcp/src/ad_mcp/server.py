"""Official MCP SDK v2 server for the closed AD operation catalog."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations

from ad_mcp.audit import AuditLog
from ad_mcp.auth import authorize_meta, zeroize_all
from ad_mcp.catalog import BY_NAME, CATALOG_REVISION, TOOLS, get_tool, input_schema
from ad_mcp.command import CommandBuilder
from ad_mcp.config import Settings, load_project_token, load_scope, load_settings
from ad_mcp.errors import AdMcpError, ValidationError
from ad_mcp.jobs import JobManager, JobStore
from ad_mcp.models import ProjectAuthorization, ToolCall
from ad_mcp.scope import ScopePolicy
from ad_mcp.storage import RawStorage

SERVER_NAME = "redteam-ad-mcp"
SERVER_VERSION = "0.1.0"


class Runtime:
    def __init__(self, settings: Settings, scope: ScopePolicy, project_token: str) -> None:
        if set(settings.enabled_operations) - set(BY_NAME):
            raise ValidationError("UNKNOWN_ENABLED_OPERATION")
        self.settings = settings
        self._token = project_token
        self._builder = CommandBuilder(settings, scope)
        self._audit = AuditLog(settings.audit_log)
        self._storage = RawStorage(settings.raw_root, settings.retention_hours)
        self._jobs = JobManager(
            JobStore(settings.state_db),
            self._storage,
            self._audit,
            max_concurrent=settings.max_concurrent_jobs,
        )

    def _authorize(
        self, meta: Mapping[str, Any] | None
    ) -> tuple[ProjectAuthorization, tuple[object, ...]]:
        auth, secrets = authorize_meta(
            meta,
            expected_client_id=self.settings.client_id,
            expected_token=self._token,
        )
        return auth, secrets

    async def invoke(
        self, operation_id: str, call: ToolCall, meta: Mapping[str, Any] | None
    ) -> dict[str, object]:
        auth, raw_secrets = authorize_meta(
            meta,
            expected_client_id=self.settings.client_id,
            expected_token=self._token,
        )
        try:
            tool = get_tool(operation_id)
            command = self._builder.build(tool, call, auth, raw_secrets)
            if call.dry_run:
                await self._audit.write(
                    "dry_run",
                    auth,
                    operation_id=operation_id,
                    details={
                        "command": command.plan.redacted_argv,
                        "targets": command.plan.targets,
                        "risk": command.plan.risk.value,
                    },
                )
                return {
                    "result_type": "dry_run",
                    "catalog_revision": CATALOG_REVISION,
                    "plan": command.plan.model_dump(mode="json"),
                    "executed": False,
                }
            job = await self._jobs.start(tool, command, auth)
            return {
                "result_type": "job",
                "catalog_revision": CATALOG_REVISION,
                "job": job.model_dump(mode="json"),
            }
        except AdMcpError as exc:
            await self._audit.write(
                "request_rejected",
                auth,
                operation_id=operation_id,
                details={"error_code": exc.code},
            )
            raise RuntimeError(exc.code) from None
        finally:
            zeroize_all(raw_secrets)

    def describe_catalog(self, meta: Mapping[str, Any] | None) -> dict[str, object]:
        auth, secrets = authorize_meta(
            meta,
            expected_client_id=self.settings.client_id,
            expected_token=self._token,
        )
        del auth
        zeroize_all(secrets)
        return {
            "catalog_revision": CATALOG_REVISION,
            "operations": [
                {
                    "operation_id": tool.operation_id,
                    "category": tool.category,
                    "risk": tool.risk.value,
                    "enabled": tool.operation_id in self.settings.enabled_operations,
                    "remote_windows": tool.remote_windows,
                    "detection_ids": tool.detection_ids,
                }
                for tool in TOOLS
            ],
        }

    def get_job(self, job_id: str, meta: Mapping[str, Any] | None) -> dict[str, object]:
        auth, secrets = authorize_meta(
            meta,
            expected_client_id=self.settings.client_id,
            expected_token=self._token,
        )
        zeroize_all(secrets)
        return self._jobs.get(job_id, auth).model_dump(mode="json")

    async def cancel_job(
        self, job_id: str, meta: Mapping[str, Any] | None
    ) -> dict[str, object]:
        auth, secrets = authorize_meta(
            meta,
            expected_client_id=self.settings.client_id,
            expected_token=self._token,
        )
        zeroize_all(secrets)
        return (await self._jobs.cancel(job_id, auth)).model_dump(mode="json")

    async def cleanup(self, meta: Mapping[str, Any] | None) -> dict[str, object]:
        auth, secrets = authorize_meta(
            meta,
            expected_client_id=self.settings.client_id,
            expected_token=self._token,
        )
        zeroize_all(secrets)
        deleted = self._storage.delete_expired()
        await self._audit.write("retention_cleanup", auth, details={"deleted": deleted})
        return {"deleted_count": len(deleted), "raw_result_refs": deleted}


def _meta(context: Context[Any, Any]) -> Mapping[str, Any] | None:
    return context.request_context.meta


def build_server(runtime: Runtime) -> MCPServer[Any]:
    server: MCPServer[Any] = MCPServer(
        SERVER_NAME,
        version=SERVER_VERSION,
        instructions="Use only through the RedTeam Agent authorization path.",
    )

    @server.tool(name="catalog.describe", structured_output=True)
    async def describe_catalog(context: Context[Any, Any]) -> dict[str, object]:
        """Return non-secret catalog identity and enablement state."""
        return runtime.describe_catalog(_meta(context))

    @server.tool(name="job.get_status", structured_output=True)
    async def get_job_status(job_id: str, context: Context[Any, Any]) -> dict[str, object]:
        """Read a job bound to the caller's execution, actor, and mission."""
        return runtime.get_job(job_id, _meta(context))

    @server.tool(name="job.cancel", structured_output=True)
    async def cancel_job(job_id: str, context: Context[Any, Any]) -> dict[str, object]:
        """Stop a job bound to the caller's execution, actor, and mission."""
        return await runtime.cancel_job(job_id, _meta(context))

    @server.tool(name="storage.cleanup_expired", structured_output=True)
    async def cleanup_expired(context: Context[Any, Any]) -> dict[str, object]:
        """Delete private raw logs whose configured retention has expired."""
        return await runtime.cleanup(_meta(context))

    @server.tool(name="run_allowlisted_tool", structured_output=True)
    async def run_allowlisted_tool(
        operation_id: str, call: ToolCall, context: Context[Any, Any]
    ) -> dict[str, object]:
        """Run an exact registered operation; arbitrary executable names and argv are rejected."""
        if operation_id not in BY_NAME:
            raise RuntimeError("UNKNOWN_OPERATION")
        return await runtime.invoke(operation_id, call, _meta(context))

    for definition in TOOLS:
        server.add_tool(
            _operation_handler(runtime, definition.operation_id),
            name=definition.mcp_name,
            description=definition.description,
            annotations=ToolAnnotations(
                read_only_hint=definition.risk.value in {"passive", "active", "unclassified"},
                destructive_hint=definition.risk.value == "intrusive",
                idempotent_hint=False,
                open_world_hint=definition.network_target_required,
            ),
            meta={
                "io.redteam-agent/catalogRevision": CATALOG_REVISION,
                "io.redteam-agent/risk": definition.risk.value,
                "io.redteam-agent/operationId": definition.operation_id,
            },
            structured_output=True,
        )
        # MCPServer builds the callable schema from ToolCall. Replace only the
        # advertised schema with the per-operation closed form; the handler
        # performs the same checks again before command construction.
        server._tool_manager._tools[definition.mcp_name].parameters = input_schema(
            definition
        )
    return server


def _operation_handler(runtime: Runtime, operation_id: str) -> Any:
    async def invoke(call: ToolCall, context: Context[Any, Any]) -> dict[str, object]:
        return await runtime.invoke(operation_id, call, _meta(context))

    invoke.__name__ = operation_id.replace(".", "_")
    invoke.__doc__ = BY_NAME[operation_id].description
    return invoke


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized AD MCP server")
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--scope", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    arguments = _parser().parse_args(argv)
    settings = load_settings(arguments.settings)
    if settings.transport != "stdio":
        raise ValidationError("TRANSPORT_NOT_APPROVED")
    runtime = Runtime(settings, ScopePolicy(load_scope(arguments.scope)), load_project_token())
    build_server(runtime).run("stdio")


if __name__ == "__main__":
    main()
