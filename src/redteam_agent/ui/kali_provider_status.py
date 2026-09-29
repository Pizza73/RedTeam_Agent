"""Read-only provider readiness projection for the Kali-local operator UI."""

from __future__ import annotations

import os
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_IMPACKET_OPERATIONS = (
    "impacket.smb.negotiate",
    "impacket.smb.authenticate",
    "impacket.smb.list_shares",
    "impacket.rpc.endpoint_map",
)


class KaliProviderStatusPort:
    """Report local prerequisites without reading secrets or contacting a target."""

    def __init__(
        self,
        *,
        sliver_credential: Path,
        impacket_executable: Path,
        impacket_allowed_targets: tuple[str, ...],
    ) -> None:
        self._sliver_credential = sliver_credential
        self._impacket_executable = impacket_executable
        self._impacket_allowed_targets = impacket_allowed_targets

    def __call__(self) -> dict[str, object]:
        credential_present = self._sliver_credential.is_file()
        executable_present = self._impacket_executable.is_file() and os.access(
            self._impacket_executable, os.X_OK
        )
        try:
            impacket_version = version("impacket")
        except PackageNotFoundError:  # pragma: no cover - deployment dependent
            impacket_version = None
        return {
            "mode": "live",
            "runtime": {
                "productionEligible": False,
                "missionExecutionEnabled": False,
                "tpmKeyProviderAttested": False,
                "blockers": [
                    "TPM-backed persistent key provider is unavailable on this Kali host.",
                    "Live Sliver Beacon and Phase 5 sandbox attestations are not present.",
                ],
            },
            "tuoni": {"edition": "commercial", "version": "latest", "access": "unconfigured"},
            "sliver": {
                "version": "1.7.7",
                "operator": "joe",
                "operatorConfigLocation": "systemd_credential",
                "operatorAccess": (
                    "credential_present_unattested" if credential_present else "credential_missing"
                ),
                "implantTransport": "http",
                "beaconPresent": False,
                "credentialPresent": credential_present,
                "identityAttested": False,
                "productionEligible": False,
                "blockers": [
                    "A live gRPC/mTLS identity attestation is required.",
                    "No approved live HTTP Beacon is registered.",
                ],
            },
            "impacket": {
                "installed": executable_present and impacket_version is not None,
                "version": impacket_version,
                "server": "redteam-impacket-mcp",
                "operations": list(_IMPACKET_OPERATIONS),
                "executablePresent": executable_present,
                "allowedTargets": list(self._impacket_allowed_targets),
                "sandboxAttested": False,
                "productionEligible": False,
                "blockers": [
                    "An OS-level egress sandbox attestation is required before dispatch.",
                ],
            },
        }


__all__ = ["KaliProviderStatusPort"]
