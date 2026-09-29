"""Deployment epoch mirror + lease policy (SystemDesign §10.3 / §32)."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import Field

from redteam_agent.errors import LeaseError
from redteam_agent.models.base import StrictImmutableBoundaryModel


class DeploymentEpochMirror(StrictImmutableBoundaryModel):
    """The single OCC record the composition root fixes from the TPM NV counter.

    Workers read it but cannot write it (no owner guard is handed to them). Every
    normal worker mutation compares its lease epoch to this mirror and to the TPM.
    """

    trust_epoch: int = Field(ge=1)
    deployment_epoch: int = Field(ge=1)
    nv_identity_digest: str = Field(min_length=1)
    provider_identity: str = Field(min_length=1)
    established_at_iso: str = Field(min_length=1)
    record_digest: str = Field(min_length=1)


@dataclass(frozen=True)
class LeasePolicy:
    """Lease timing policy (SystemDesign §10.3): default 60s / heartbeat <=20s, and
    ``lease_duration >= 3 * heartbeat_interval``."""

    lease_duration_seconds: int = 60
    heartbeat_interval_seconds: int = 20

    def __post_init__(self) -> None:
        if self.heartbeat_interval_seconds <= 0 or self.lease_duration_seconds <= 0:
            raise LeaseError("lease timing must be positive")
        if self.heartbeat_interval_seconds > 20:
            raise LeaseError("heartbeat interval must be <= 20 seconds")
        if self.lease_duration_seconds < 3 * self.heartbeat_interval_seconds:
            raise LeaseError("lease_duration must be >= 3 * heartbeat_interval")
