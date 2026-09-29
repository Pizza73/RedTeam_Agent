"""Composition boundary for the independent official-SDK AD MCP package."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from redteam_agent.adapters.ad_mcp_adapter import AdMcpAdapter
from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.runtime.clock import Clock


def build_ad_mcp_adapter(
    *,
    server_argv: Sequence[str],
    server_environment: Mapping[str, str],
    project_client_id: str,
    project_token: str,
    approved_tool_schemas: Mapping[str, Mapping[str, object]],
    binding_state_db: Path,
    clock: Clock,
    digest_service: DigestService,
) -> AdMcpAdapter:
    """Start one persistent stdio server and pin its command and catalog identity."""
    if not server_argv or not Path(server_argv[0]).is_absolute():
        raise ValueError("AD MCP server command must use an absolute executable")
    executable = Path(server_argv[0]).resolve(strict=True)
    if str(executable) != server_argv[0] or not executable.is_file():
        raise ValueError("AD MCP server executable identity is invalid")
    try:
        from ad_mcp.client import ProjectStdioClient
    except ImportError as exc:
        raise RuntimeError("the independent ad-mcp package is not installed") from exc
    command_digest = hashlib.sha256(
        canonical_dumps(
            {
                "argv": list(server_argv),
                "environment": dict(sorted(server_environment.items())),
                "transport": "stdio",
                "catalog": "ad-mcp-catalog-v1",
            }
        )
    ).hexdigest()
    executable_digest = _file_sha256(executable)
    catalog_digest = hashlib.sha256(
        canonical_dumps({name: dict(schema) for name, schema in approved_tool_schemas.items()})
    ).hexdigest()
    client = ProjectStdioClient(
        argv=tuple(server_argv),
        environment=server_environment,
        client_id=project_client_id,
        project_token=project_token,
    )
    return AdMcpAdapter(
        client=client,
        approved_tool_schemas=approved_tool_schemas,
        state_db=binding_state_db,
        clock=clock,
        digest_service=digest_service,
        adapter_identity_digest=command_digest,
        provider_identity_digest=hashlib.sha256(
            f"{executable_digest}:{catalog_digest}".encode()
        ).hexdigest(),
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["build_ad_mcp_adapter"]
