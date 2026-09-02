"""Metadata-only secure-ingestion contract used before Phase 0C implementation."""

from __future__ import annotations

from typing import Protocol

from redteam_agent.errors import ResultIngestionError
from redteam_agent.models.execution import (
    ExecutionResult,
    SecureIngestionSummary,
)


class SecureResultIngester(Protocol):
    async def run(self, ingestion_id: str) -> SecureIngestionSummary: ...

    async def acknowledge_persisted(
        self,
        ingestion_id: str,
        result: ExecutionResult,
    ) -> None: ...


class MockSecureResultIngester:
    """Mock boundary: consumes receipt metadata and returns already-redacted references."""

    def __init__(
        self,
        *,
        summary: SecureIngestionSummary,
        fail: bool = False,
    ) -> None:
        self._summary = summary
        self._fail = fail
        self.calls = 0

    async def run(self, ingestion_id: str) -> SecureIngestionSummary:
        del ingestion_id
        self.calls += 1
        if self._fail:
            self._fail = False
            raise ResultIngestionError("mock secure ingestion failed")
        return self._summary

    async def acknowledge_persisted(
        self,
        ingestion_id: str,
        result: ExecutionResult,
    ) -> None:
        del ingestion_id, result
