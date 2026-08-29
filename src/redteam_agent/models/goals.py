"""Typed mission success conditions (evaluation is intentionally Phase 1)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .base import StrictImmutableBoundaryModel


class SessionExistsCondition(StrictImmutableBoundaryModel):
    type: Literal["session_exists"]
    condition_id: str = Field(min_length=1)
    host_ref: str = Field(min_length=1)
    principal_ref: str | None = None
    required_status: Literal["active"] = "active"


class WindowsTokenPrivilegeCondition(StrictImmutableBoundaryModel):
    type: Literal["windows_token_privilege"]
    condition_id: str = Field(min_length=1)
    session_ref: str = Field(min_length=1)
    required_privileges: frozenset[str] = Field(min_length=1)
    match: Literal["all", "any"] = "all"
    require_enabled: bool = True


class WindowsLocalGroupCondition(StrictImmutableBoundaryModel):
    type: Literal["windows_local_group"]
    condition_id: str = Field(min_length=1)
    host_ref: str = Field(min_length=1)
    principal_ref: str = Field(min_length=1)
    group_sid: str = Field(min_length=1)


class ADGroupMembershipCondition(StrictImmutableBoundaryModel):
    type: Literal["ad_group_membership"]
    condition_id: str = Field(min_length=1)
    principal_ref: str = Field(min_length=1)
    group_sid: str = Field(min_length=1)
    membership: Literal["direct", "transitive"]


class ADPrincipalPrivilegeCondition(StrictImmutableBoundaryModel):
    type: Literal["ad_principal_privilege"]
    condition_id: str = Field(min_length=1)
    principal_ref: str = Field(min_length=1)
    privilege_identifier: str = Field(min_length=1)
    target_ref: str = Field(min_length=1)


class ADPrincipalContextCondition(StrictImmutableBoundaryModel):
    type: Literal["ad_principal_context"]
    condition_id: str = Field(min_length=1)
    session_ref: str = Field(min_length=1)
    principal_ref: str = Field(min_length=1)
    required_group_sid: str | None = None
    required_status: Literal["active"] = "active"


class LinuxUidCondition(StrictImmutableBoundaryModel):
    type: Literal["linux_uid"]
    condition_id: str = Field(min_length=1)
    session_ref: str = Field(min_length=1)
    uid: int = Field(ge=0)
    identity_field: Literal["real", "effective", "saved"] = "effective"


class LinuxGroupCondition(StrictImmutableBoundaryModel):
    type: Literal["linux_group"]
    condition_id: str = Field(min_length=1)
    session_ref: str = Field(min_length=1)
    gid: int | None = Field(default=None, ge=0)
    group_name: str | None = None
    membership: Literal["primary", "supplementary", "either"] = "either"

    @model_validator(mode="after")
    def at_least_one_identifier(self) -> "LinuxGroupCondition":
        if self.gid is None and not self.group_name:
            raise ValueError("gid or group_name is required")
        return self


class LinuxCapabilityCondition(StrictImmutableBoundaryModel):
    type: Literal["linux_capability"]
    condition_id: str = Field(min_length=1)
    session_ref: str = Field(min_length=1)
    required_capabilities: frozenset[str] = Field(min_length=1)
    capability_set: Literal["effective", "permitted", "inheritable", "bounding"]
    match: Literal["all", "any"] = "all"


class EvidenceExistsCondition(StrictImmutableBoundaryModel):
    type: Literal["evidence_exists"]
    condition_id: str = Field(min_length=1)
    finding_type: str = Field(min_length=1)
    target_ref: str = Field(min_length=1)
    minimum_confidence: float = Field(ge=0.0, le=1.0)
    required_verification: Literal["confirmed"] = "confirmed"


class ArtifactEvidenceCondition(StrictImmutableBoundaryModel):
    type: Literal["artifact_evidence"]
    condition_id: str = Field(min_length=1)
    artifact_type: str = Field(min_length=1)
    expected_sha256: str | None = None


SuccessCondition = Annotated[
    SessionExistsCondition
    | WindowsTokenPrivilegeCondition
    | WindowsLocalGroupCondition
    | ADGroupMembershipCondition
    | ADPrincipalPrivilegeCondition
    | ADPrincipalContextCondition
    | LinuxUidCondition
    | LinuxGroupCondition
    | LinuxCapabilityCondition
    | EvidenceExistsCondition
    | ArtifactEvidenceCondition,
    Field(discriminator="type"),
]

