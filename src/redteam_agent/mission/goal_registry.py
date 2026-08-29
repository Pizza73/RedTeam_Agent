"""Trusted identifiers accepted by deterministic goal validation."""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.errors import UnsupportedGoalIdentifierError
from redteam_agent.models.goals import (
    ADPrincipalPrivilegeCondition,
    LinuxCapabilityCondition,
    WindowsTokenPrivilegeCondition,
)
from redteam_agent.models.mission import Mission


@dataclass(frozen=True)
class KnownGoalIdentifierRegistry:
    """Closed Phase 0A registry; extensions require an application release."""

    windows_privileges: frozenset[str] = frozenset(
        {
            "SeBackupPrivilege",
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege",
        }
    )
    linux_capabilities: frozenset[str] = frozenset(
        {
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SYS_ADMIN",
            "CAP_SYS_PTRACE",
        }
    )
    ad_principal_privileges: frozenset[str] = frozenset(
        {"domain_admin", "enterprise_admin", "directory_replication"}
    )

    def validate(self, mission: Mission) -> None:
        for condition in mission.success_conditions:
            if isinstance(condition, WindowsTokenPrivilegeCondition):
                unknown = condition.required_privileges - self.windows_privileges
            elif isinstance(condition, LinuxCapabilityCondition):
                unknown = condition.required_capabilities - self.linux_capabilities
            elif isinstance(condition, ADPrincipalPrivilegeCondition):
                unknown = frozenset({condition.privilege_identifier}) - self.ad_principal_privileges
            else:
                continue
            if unknown:
                raise UnsupportedGoalIdentifierError(
                    "unregistered goal identifier(s): " + ", ".join(sorted(unknown))
                )
