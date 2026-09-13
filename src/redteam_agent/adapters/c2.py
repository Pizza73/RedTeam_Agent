"""Provider-neutral C2 observation and adapter extension contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field

from redteam_agent.adapters.capabilities import AdapterCapabilities
from redteam_agent.execution.adapter import ExecutionAdapter
from redteam_agent.models.base import StrictImmutableBoundaryModel


class C2SessionObservation(StrictImmutableBoundaryModel):
    """Untrusted provider observation awaiting Session Manager validation."""

    provider_session_id: str = Field(min_length=1)
    provider_status: Literal["active", "stale", "lost", "terminated", "unknown"]
    host: str | None
    os: Literal["windows", "linux", "macos", "other"]
    architecture: str | None
    current_principal: str | None
    capabilities: frozenset[str]
    observed_at: datetime


class C2Adapter(ExecutionAdapter, Protocol):
    """ExecutionAdapter extension kept out of Planner and Executor core."""

    def get_capabilities(self) -> AdapterCapabilities: ...

    def list_sessions(self) -> tuple[C2SessionObservation, ...]: ...

    def get_session(self, provider_session_id: str) -> C2SessionObservation: ...


__all__ = ["C2Adapter", "C2SessionObservation"]
