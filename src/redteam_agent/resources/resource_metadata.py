"""Resource (artifact/report/knowledge) metadata read boundary (SystemDesign §22, F/#5).

A context read grant for a non-secret resource must bind the exact current
version and metadata digest resolved from the source of truth, not from the
derived context index alone. The index is a candidate view and must agree with
this source. This boundary returns metadata only; no resource body is read.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.data_access import ResourceType


class ResourceMetadata(StrictImmutableBoundaryModel):
    resource_id: str = Field(min_length=1)
    resource_type: ResourceType
    version: str = Field(min_length=1)
    metadata_digest: str = Field(min_length=1)
    classification: str


class ResourceMetadataReader(Protocol):
    def get(self, resource_id: str) -> ResourceMetadata | None: ...


class StaticResourceMetadataStore:
    """Fixed resource-metadata source of truth, installed by the composition root."""

    def __init__(self, resources: dict[str, ResourceMetadata] | None = None) -> None:
        self._resources = dict(resources or {})

    def put(self, metadata: ResourceMetadata) -> None:
        self._resources[metadata.resource_id] = metadata

    def get(self, resource_id: str) -> ResourceMetadata | None:
        return self._resources.get(resource_id)
