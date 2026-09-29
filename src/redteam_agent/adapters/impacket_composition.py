"""Fixed composition for the local read-only Impacket MCP server."""

from __future__ import annotations

import ipaddress
import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Literal

from redteam_agent.adapters.mcp_adapter import MCPAdapter
from redteam_agent.adapters.mcp_stdio_transport import (
    MCPStdioProcessTransport,
    inspect_mcp_stdio_identities,
)
from redteam_agent.adapters.mcp_transport import (
    MCPTransportAttestation,
    finalize_mcp_transport_attestation,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import MCPAdapterUnavailableError
from redteam_agent.mcp_servers.impacket_catalog import (
    IMPACKET_MCP_SERVER_VERSION,
    IMPACKET_VERSION,
    build_impacket_mcp_contract,
    build_impacket_mcp_profile,
)
from redteam_agent.runtime.clock import Clock

IMPACKET_MCP_PACKAGE_IDENTITY = (
    f"redteam-impacket-mcp/{IMPACKET_MCP_SERVER_VERSION};impacket/{IMPACKET_VERSION}"
)


def build_impacket_stdio_argv(
    *, executable_path: str, allowed_targets: tuple[str, ...]
) -> tuple[str, ...]:
    path = Path(executable_path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MCPAdapterUnavailableError(
            "Impacket MCP executable does not exist"
        ) from exc
    if (
        not path.is_absolute()
        or str(resolved) != executable_path
        or not resolved.is_file()
        or not os.access(resolved, os.X_OK)
    ):
        raise MCPAdapterUnavailableError(
            "Impacket MCP executable must be an absolute resolved path"
        )
    if not allowed_targets:
        raise MCPAdapterUnavailableError("Impacket MCP target allowlist is empty")
    canonical: list[str] = []
    for value in allowed_targets:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise MCPAdapterUnavailableError(
                "Impacket MCP target allowlist is invalid"
            ) from exc
        normalized = str(network)
        if normalized != value or normalized in canonical:
            raise MCPAdapterUnavailableError(
                "Impacket MCP target allowlist must be canonical and unique"
            )
        canonical.append(normalized)
    argv: list[str] = [executable_path]
    for allowed_network in sorted(canonical):
        argv.extend(("--allow-target", allowed_network))
    return tuple(argv)


def build_impacket_mcp_adapter(
    *,
    executable_path: str,
    allowed_targets: tuple[str, ...],
    evidence_kind: Literal["test_server", "live"],
    production_eligible: bool,
    sandbox_verified: bool,
    clock: Clock,
    digest_service: DigestService,
) -> MCPAdapter:
    """Build the only production-shaped Impacket MCP adapter composition.

    ``live`` evidence is accepted only after the caller's environment-specific
    sandbox/egress qualification.  Offline tests must use ``test_server`` and
    can never set ``production_eligible``.
    """

    try:
        installed_impacket_version = version("impacket")
    except PackageNotFoundError as exc:
        raise MCPAdapterUnavailableError("Impacket runtime is not installed") from exc
    if installed_impacket_version != IMPACKET_VERSION:
        raise MCPAdapterUnavailableError("Impacket runtime version does not match the pin")
    argv = build_impacket_stdio_argv(
        executable_path=executable_path, allowed_targets=allowed_targets
    )
    identities = inspect_mcp_stdio_identities(
        argv=argv, package_version=IMPACKET_MCP_PACKAGE_IDENTITY
    )
    contract = build_impacket_mcp_contract(digest_service=digest_service)
    profile = build_impacket_mcp_profile(
        identities=identities, digest_service=digest_service
    )
    config = profile.server_config
    assert config is not None
    attestation = finalize_mcp_transport_attestation(
        MCPTransportAttestation(
            evidence_kind=evidence_kind,
            production_eligible=production_eligible,
            adapter_profile_digest=profile.profile_digest,
            server_config_digest=config.config_digest,
            contract_digest=contract.contract_digest(),
            server_id=config.server_id,
            transport="stdio",
            execution_location="local_process",
            verified_transport_identities=identities,
            sandbox_verified=sandbox_verified,
            redirects_disabled=True,
            attested_at=clock.now(),
            attestation_digest="0" * 64,
        ),
        digest_service,
    )
    transport = MCPStdioProcessTransport(
        argv=argv,
        package_version=IMPACKET_MCP_PACKAGE_IDENTITY,
        attestation=attestation,
    )
    return MCPAdapter(
        profile=profile,
        contract=contract,
        transport=transport,
        clock=clock,
        digest_service=digest_service,
    )


__all__ = [
    "IMPACKET_MCP_PACKAGE_IDENTITY",
    "build_impacket_mcp_adapter",
    "build_impacket_stdio_argv",
]
