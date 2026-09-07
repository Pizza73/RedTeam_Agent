"""Mission-bound unresolved item owner used by Finalization."""

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
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultRepository,
    RawControlMetadataRepository,
    ResultIngestionStateRepository,
)

UnresolvedReason = Literal["EXECUTION_RECONCILED", "COLLECTION_COMPLETE", "INGESTION_COMPLETE"]


class UnresolvedItem(StrictImmutableBoundaryModel):
    unresolved_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    status: Literal["OPEN", "ACCEPTED", "RESOLVED"]
    reason_code: UnresolvedReason
    evidence_digest: str = Field(min_length=1)
    item_version: int = Field(ge=1)
    updated_at: datetime
    item_digest: str = Field(min_length=1)


class UnresolvedItemService:
    _NS = "unresolved_item_current"

    def __init__(
        self,
        *,
        database: Database,
        digest_service: DigestService,
        clock: Clock,
        execution_repository: ExecutionRecordRepository,
        result_repository: ExecutionResultRepository,
        control_metadata_repository: RawControlMetadataRepository,
        ingestion_repository: ResultIngestionStateRepository,
    ) -> None:
        self._db, self._ds, self._clock = database, digest_service, clock
        self._executions, self._results = execution_repository, result_repository
        self._control, self._ingestion = control_metadata_repository, ingestion_repository

    def current(self, mission_id: str) -> tuple[UnresolvedItem, ...]:
        result = []
        for key, version, text in self._db.occ_get_all(self._NS):
            item = self._validate_row(key, (version, text))
            if item.mission_id == mission_id:
                result.append(item)
        return tuple(sorted(result, key=lambda item: item.unresolved_id))

    def open(
        self,
        *,
        unresolved_id: str,
        mission_id: str,
        reason_code: UnresolvedReason,
        evidence_digest: str,
    ) -> UnresolvedItem:
        row = self._db.occ_get(self._NS, unresolved_id)
        if row is not None:
            current = self._validate_row(unresolved_id, row)
            if (
                current.mission_id == mission_id
                and current.status == "OPEN"
                and current.reason_code == reason_code
                and current.evidence_digest == evidence_digest
            ):
                return current
            raise AgentLoopError("unresolved item identity is already in use")
        return self._write(
            unresolved_id=unresolved_id, mission_id=mission_id, status="OPEN",
            reason_code=reason_code, evidence_digest=evidence_digest,
        )

    def resolve_from_execution(
        self,
        *,
        unresolved_id: str,
        execution_id: str,
    ) -> UnresolvedItem:
        row = self._db.occ_get(self._NS, unresolved_id)
        if row is None:
            raise AgentLoopError("unresolved item does not exist")
        current = self._validate_row(unresolved_id, row)
        if current.status == "RESOLVED":
            return current
        execution = self._executions.get(execution_id)
        if execution is None or execution.mission_id != current.mission_id:
            raise AgentLoopError("unresolved item execution binding is invalid")
        source: object
        if current.reason_code == "EXECUTION_RECONCILED":
            if execution.provider_execution_state in {
                "PLANNED",
                "AUTHORIZED",
                "DISPATCH_CLAIMED",
                "DISPATCHED",
                "RUNNING",
                "CANCEL_REQUESTED",
                "RECONCILING",
                "OUTCOME_UNKNOWN",
            }:
                raise AgentLoopError("execution outcome is not reconciled")
            source = execution.model_dump(mode="python")
        elif current.reason_code == "COLLECTION_COMPLETE":
            control = self._control.find_by_execution(execution_id)
            if control is None:
                raise AgentLoopError("result collection is not complete")
            source = control.model_dump(mode="python")
        else:
            ingestion = self._ingestion.find_by_execution(execution_id)
            result = self._results.get(execution_id)
            if ingestion is None or ingestion.status != "SUCCEEDED" or result is None:
                raise AgentLoopError("result ingestion is not complete")
            source = {
                "ingestion": ingestion.model_dump(mode="python"),
                "result": result.model_dump(mode="python"),
            }
        evidence_digest = self._ds.compute(
            "unresolved_resolution_evidence_digest",
            {
                "unresolved_id": unresolved_id,
                "execution_id": execution_id,
                "reason_code": current.reason_code,
                "source": source,
            },
        )
        return self._write(
            unresolved_id=unresolved_id, mission_id=current.mission_id, status="RESOLVED",
            reason_code=current.reason_code, evidence_digest=evidence_digest,
        )

    def _write(
        self,
        *,
        unresolved_id: str,
        mission_id: str,
        status: Literal["OPEN", "RESOLVED"],
        reason_code: UnresolvedReason,
        evidence_digest: str,
    ) -> UnresolvedItem:
        if not evidence_digest:
            raise AgentLoopError("unresolved item transition requires evidence")
        row = self._db.occ_get(self._NS, unresolved_id)
        version = 1 if row is None else row[0] + 1
        fields = {
            "unresolved_id": unresolved_id, "mission_id": mission_id, "status": status,
            "reason_code": reason_code, "evidence_digest": evidence_digest,
            "item_version": version, "updated_at": self._clock.now(),
        }
        item = UnresolvedItem.model_validate({
            **fields, "item_digest": self._ds.compute("unresolved_item_digest", fields)
        })
        text = json.dumps(item.model_dump(mode="json"), sort_keys=True)
        with UnitOfWork(self._db):
            if row is None:
                self._db.occ_insert(self._NS, unresolved_id, version, text)
            else:
                self._db.occ_update(
                    self._NS, unresolved_id, expected_version=row[0],
                    new_version=version, json_text=text,
                )
        return item

    def _validate_row(
        self, unresolved_id: str, row: tuple[int, str]
    ) -> UnresolvedItem:
        version, text = row
        item = UnresolvedItem.model_validate_json(text)
        payload = item.model_dump(mode="python")
        expected = payload.pop("item_digest")
        self._ds.verify("unresolved_item_digest", payload, expected)
        if item.unresolved_id != unresolved_id or item.item_version != version:
            raise AgentLoopError("unresolved item identity or version mismatch")
        return item
