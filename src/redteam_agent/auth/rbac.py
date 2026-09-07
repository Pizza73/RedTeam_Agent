"""Per-mission RBAC checks (SystemDesign §2.6).

Being an operator/auditor/administrator is not itself approval authority. An
approval is only valid when made by an authenticated principal holding the
approver role assigned to *that* mission and not revoked. Assignments for other
missions or revoked mappings do not grant authority.
"""

from __future__ import annotations

from typing import Protocol

from redteam_agent.auth.models import AuthenticatedPrincipal, MissionRoleAssignment

APPROVER_ROLE = "approver"


class RoleAssignmentReader(Protocol):
    def assignments_for(self, mission_id: str) -> tuple[MissionRoleAssignment, ...]: ...


class RbacPolicy:
    def __init__(self, reader: RoleAssignmentReader) -> None:
        self._reader = reader

    def has_role(self, mission_id: str, principal_id: str, role: str) -> bool:
        for assignment in self._reader.assignments_for(mission_id):
            if (
                assignment.active
                and assignment.mission_id == mission_id
                and assignment.principal_id == principal_id
                and assignment.role == role
            ):
                return True
        return False

    def principal_can_approve(self, mission_id: str, principal: AuthenticatedPrincipal) -> bool:
        return self.has_role(mission_id, principal.principal_id, APPROVER_ROLE)
