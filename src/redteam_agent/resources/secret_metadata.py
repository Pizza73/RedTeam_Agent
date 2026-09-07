"""Secret version metadata read boundary (SystemDesign §34, F).

A data-access grant for a secret must bind the *exact* current version, its
immutable metadata digest and its lifecycle head, resolved from the source of
truth, not from a caller-supplied reference. This boundary returns metadata
only; it never returns a secret value (that is Phase 0B/0C). A missing,
unconfirmed, revoked/superseded or expired version is rejected upstream.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel

SecretLifecycleState = Literal["DETECTED", "CONFIRMED", "REVOKED", "SUPERSEDED"]


class SecretVersionMetadata(StrictImmutableBoundaryModel):
    secret_version_id: str = Field(min_length=1)
    secret_id: str = Field(min_length=1)
    version: str = Field(min_length=1)  # canonical decimal version string
    metadata_digest: str = Field(min_length=1)
    lifecycle_head_digest: str = Field(min_length=1)
    state: SecretLifecycleState
    expires_at: datetime | None = None


class SecretMetadataReader(Protocol):
    def get(self, secret_version_id: str) -> SecretVersionMetadata | None: ...


class StaticSecretMetadataStore:
    """Fixed metadata source of truth, installed by the composition root."""

    def __init__(self, versions: dict[str, SecretVersionMetadata] | None = None) -> None:
        self._versions = dict(versions or {})

    def put(self, metadata: SecretVersionMetadata) -> None:
        self._versions[metadata.secret_version_id] = metadata

    def get(self, secret_version_id: str) -> SecretVersionMetadata | None:
        return self._versions.get(secret_version_id)
