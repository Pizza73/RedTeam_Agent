"""Common value types shared across kernel components."""

from __future__ import annotations

from pydantic import Field

from redteam_agent.models.base import StrictImmutableBoundaryModel


class ToolRef(StrictImmutableBoundaryModel):
    """Application-issued global stable tool identity, pinned to a revision.

    ``tool_id`` is issued by the application and never reused across adapters or
    display names; ``registry_revision`` pins the approving registry revision so
    a ToolRef is unique across the whole application (SystemDesign §20).
    """

    tool_id: str = Field(min_length=1)
    registry_revision: int = Field(ge=1)


class ResourceBinding(StrictImmutableBoundaryModel):
    """Exact resource binding for a data-access grant entry (SystemDesign §22)."""

    resource_id: str = Field(min_length=1)
    resource_version: str = Field(min_length=1)
    resource_digest: str = Field(min_length=1)


class ActionContractReference(StrictImmutableBoundaryModel):
    """Reference to a registered action contract (SystemDesign §6 / AI §5)."""

    contract_id: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    digest: str = Field(min_length=1)
