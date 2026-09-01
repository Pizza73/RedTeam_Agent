"""Metadata-only secure-ingestion contract used before Phase 0C implementation."""

from __future__ import annotations

from typing import Protocol

from redteam_agent.errors import ResultIngestionError
from redteam_agent.models.execution import (
    ExecutionResult,
    RawResultReceipt,
    SecureIngestionSummary,
)


class SecureResultIngester(Protocol):
    async def ingest(self, receipt: RawResultReceipt) -> SecureIngestionSummary: ...

    async def acknowledge_persisted(
        self,
        receipt: RawResultReceipt,
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

    async def ingest(self, receipt: RawResultReceipt) -> SecureIngestionSummary:
        del receipt
        self.calls += 1
        if self._fail:
            self._fail = False
            raise ResultIngestionError("mock secure ingestion failed")
        return self._summary

    async def acknowledge_persisted(
        self,
        receipt: RawResultReceipt,
        result: ExecutionResult,
    ) -> None:
        del receipt, result
