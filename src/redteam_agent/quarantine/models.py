"""Encrypted-quarantine metadata (SystemDesign §33.1).

Only non-secret metadata lives in the application database; ciphertext lives in the
blob store and key material in the key provider.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.execution.models import ResultTaskBinding
from redteam_agent.models.base import StrictImmutableBoundaryModel

RawResultQuarantineStatus = Literal[
    "OPEN",
    "STREAMING",
    "COMMITTED",
    "RECOVERY_REQUIRED",
    "ABORTED",
    "RETENTION_EXPIRED",
    "DELETED",
]


class RawResultQuarantineMetadata(StrictImmutableBoundaryModel):
    quarantine_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    execution_id: str = Field(min_length=1)
    task_binding: ResultTaskBinding
    encryption_metadata_id: str = Field(min_length=1)
    storage_handle: str = Field(min_length=1)
    ciphertext_digest: str
    size_bytes: int = Field(ge=0)
    chunk_count: int = Field(ge=0)
    committed_at: datetime | None
    retention_until: datetime
    status: RawResultQuarantineStatus
    metadata_digest: str = Field(min_length=1)
