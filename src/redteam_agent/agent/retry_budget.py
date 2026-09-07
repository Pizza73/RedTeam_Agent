"""Durable, operation-scoped retry budgets for the coarse Agent loop."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork

RetryKind = Literal["context", "persistent_commit", "dispatch", "collection", "ingestion", "reconciliation"]
_LIMITS: dict[RetryKind, int] = {
    "context": 2, "persistent_commit": 3, "dispatch": 1,
    "collection": 3, "ingestion": 3, "reconciliation": 3,
}
_NS = "agent_retry_budget"


class RetryBudgetRecord(StrictImmutableBoundaryModel):
    budget_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    operation_id: str = Field(min_length=1)
    retry_kind: RetryKind
    max_attempts: int = Field(gt=0)
    consumed_attempts: int = Field(ge=0)
    budget_version: int = Field(ge=1)
    updated_at: datetime
    record_digest: str = Field(min_length=1)


class AgentRetryBudgetService:
    def __init__(self, *, database: Database, digest_service: DigestService, clock: Clock) -> None:
        self._db, self._ds, self._clock = database, digest_service, clock

    def reserve(self, *, mission_id: str, operation_id: str, retry_kind: RetryKind) -> RetryBudgetRecord:
        key = f"{mission_id}:{retry_kind}:{operation_id}"
        row = self._db.occ_get(_NS, key)
        if row is None:
            consumed, version = 0, 0
        else:
            current = RetryBudgetRecord.model_validate_json(row[1])
            payload = current.model_dump(mode="python")
            expected = payload.pop("record_digest")
            self._ds.verify("agent_retry_budget_digest", payload, expected)
            if current.budget_id != key or current.budget_version != row[0]:
                raise AgentLoopError("retry budget identity or version mismatch")
            consumed, version = current.consumed_attempts, row[0]
        limit = _LIMITS[retry_kind]
        if consumed >= limit:
            raise AgentLoopError(f"{retry_kind} retry budget exhausted")
        fields = {
            "budget_id": key, "mission_id": mission_id, "operation_id": operation_id,
            "retry_kind": retry_kind, "max_attempts": limit,
            "consumed_attempts": consumed + 1, "budget_version": version + 1,
            "updated_at": self._clock.now(),
        }
        record = RetryBudgetRecord.model_validate({
            **fields, "record_digest": self._ds.compute("agent_retry_budget_digest", fields)
        })
        text = json.dumps(record.model_dump(mode="json"), sort_keys=True)
        with UnitOfWork(self._db):
            if row is None:
                self._db.occ_insert(_NS, key, 1, text)
            else:
                self._db.occ_update(_NS, key, expected_version=version, new_version=version + 1, json_text=text)
        return record
