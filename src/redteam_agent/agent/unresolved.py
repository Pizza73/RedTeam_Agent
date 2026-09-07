"""Mission-bound unresolved items derived from audited owner-source events."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.audit.hash_chain import AuditStore
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
UnresolvedStatus = Literal["OPEN", "ACCEPTED", "RESOLVED"]

_UNSETTLED_EXECUTION_STATES = frozenset(
    {
        "PLANNED",
        "AUTHORIZED",
        "DISPATCH_CLAIMED",
        "DISPATCHED",
        "RUNNING",
        "CANCEL_REQUESTED",
        "RECONCILING",
        "OUTCOME_UNKNOWN",
    }
)


class UnresolvedItem(StrictImmutableBoundaryModel):
    unresolved_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    source_execution_id: str = Field(min_length=1)
    status: UnresolvedStatus
    reason_code: UnresolvedReason
    evidence_digest: str = Field(min_length=1)
    item_version: int = Field(ge=1)
    updated_at: datetime
    item_digest: str = Field(min_length=1)


class UnresolvedItemEvent(StrictImmutableBoundaryModel):
    event_id: str = Field(min_length=1)
    unresolved_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    source_execution_id: str = Field(min_length=1)
    status: UnresolvedStatus
    reason_code: UnresolvedReason
    evidence_digest: str = Field(min_length=1)
    item_version: int = Field(ge=1)
    actor_id: Literal["unresolved-item-service"] = "unresolved-item-service"
    actor_role: Literal["source-owner"] = "source-owner"
    previous_event_digest: str | None
    occurred_at: datetime
    event_digest: str = Field(min_length=1)


class UnresolvedItemService:
    _NS = "unresolved_item_current"
    _EVENT_NS = "unresolved_item_event"

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
        audit_store: AuditStore,
    ) -> None:
        self._db, self._ds, self._clock = database, digest_service, clock
        self._executions, self._results = execution_repository, result_repository
        self._control, self._ingestion = control_metadata_repository, ingestion_repository
        self._audit = audit_store

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
        source_execution_id: str,
        reason_code: UnresolvedReason,
    ) -> UnresolvedItem:
        source = self._open_source(
            mission_id=mission_id,
            execution_id=source_execution_id,
            reason_code=reason_code,
        )
        evidence_digest = self._ds.compute(
            "unresolved_open_evidence_digest",
            {
                "unresolved_id": unresolved_id,
                "mission_id": mission_id,
                "source_execution_id": source_execution_id,
                "reason_code": reason_code,
                "source": source,
            },
        )
        row = self._db.occ_get(self._NS, unresolved_id)
        if row is not None:
            current = self._validate_row(unresolved_id, row)
            if (
                current.mission_id == mission_id
                and current.source_execution_id == source_execution_id
                and current.status == "OPEN"
                and current.reason_code == reason_code
                and current.evidence_digest == evidence_digest
            ):
                return current
            raise AgentLoopError("unresolved item identity is already in use")
        return self._write(
            unresolved_id=unresolved_id,
            mission_id=mission_id,
            source_execution_id=source_execution_id,
            status="OPEN",
            reason_code=reason_code,
            evidence_digest=evidence_digest,
        )

    def resolve_from_execution(self, *, unresolved_id: str) -> UnresolvedItem:
        row = self._db.occ_get(self._NS, unresolved_id)
        if row is None:
            raise AgentLoopError("unresolved item does not exist")
        current = self._validate_row(unresolved_id, row)
        if current.status == "RESOLVED":
            return current
        source = self._resolution_source(current)
        evidence_digest = self._ds.compute(
            "unresolved_resolution_evidence_digest",
            {
                "unresolved_id": unresolved_id,
                "mission_id": current.mission_id,
                "source_execution_id": current.source_execution_id,
                "reason_code": current.reason_code,
                "source": source,
            },
        )
        return self._write(
            unresolved_id=unresolved_id,
            mission_id=current.mission_id,
            source_execution_id=current.source_execution_id,
            status="RESOLVED",
            reason_code=current.reason_code,
            evidence_digest=evidence_digest,
        )

    def _open_source(
        self, *, mission_id: str, execution_id: str, reason_code: UnresolvedReason
    ) -> object:
        execution = self._executions.get(execution_id)
        if execution is None or execution.mission_id != mission_id:
            raise AgentLoopError("unresolved item source execution binding is invalid")
        if reason_code == "EXECUTION_RECONCILED":
            if execution.provider_execution_state not in _UNSETTLED_EXECUTION_STATES:
                raise AgentLoopError("execution outcome is already reconciled")
            return execution.model_dump(mode="python")
        if reason_code == "COLLECTION_COMPLETE":
            if self._control.find_by_execution(execution_id) is not None:
                raise AgentLoopError("result collection is already complete")
            return execution.model_dump(mode="python")
        ingestion = self._ingestion.find_by_execution(execution_id)
        result = self._results.get(execution_id)
        if ingestion is not None and ingestion.status == "SUCCEEDED" and result is not None:
            raise AgentLoopError("result ingestion is already complete")
        return {
            "execution": execution.model_dump(mode="python"),
            "ingestion": None if ingestion is None else ingestion.model_dump(mode="python"),
        }

    def _resolution_source(self, item: UnresolvedItem) -> object:
        execution = self._executions.get(item.source_execution_id)
        if execution is None or execution.mission_id != item.mission_id:
            raise AgentLoopError("unresolved item source execution binding is invalid")
        if item.reason_code == "EXECUTION_RECONCILED":
            if execution.provider_execution_state in _UNSETTLED_EXECUTION_STATES:
                raise AgentLoopError("execution outcome is not reconciled")
            return execution.model_dump(mode="python")
        if item.reason_code == "COLLECTION_COMPLETE":
            control = self._control.find_by_execution(item.source_execution_id)
            if control is None:
                raise AgentLoopError("result collection is not complete")
            return control.model_dump(mode="python")
        ingestion = self._ingestion.find_by_execution(item.source_execution_id)
        result = self._results.get(item.source_execution_id)
        if ingestion is None or ingestion.status != "SUCCEEDED" or result is None:
            raise AgentLoopError("result ingestion is not complete")
        return {
            "ingestion": ingestion.model_dump(mode="python"),
            "result": result.model_dump(mode="python"),
        }

    def _write(
        self,
        *,
        unresolved_id: str,
        mission_id: str,
        source_execution_id: str,
        status: Literal["OPEN", "RESOLVED"],
        reason_code: UnresolvedReason,
        evidence_digest: str,
    ) -> UnresolvedItem:
        row = self._db.occ_get(self._NS, unresolved_id)
        version = 1 if row is None else row[0] + 1
        previous = None if row is None else self._event(unresolved_id, row[0]).event_digest
        occurred_at = self._clock.now()
        fields = {
            "unresolved_id": unresolved_id,
            "mission_id": mission_id,
            "source_execution_id": source_execution_id,
            "status": status,
            "reason_code": reason_code,
            "evidence_digest": evidence_digest,
            "item_version": version,
            "updated_at": occurred_at,
        }
        item = UnresolvedItem.model_validate(
            {**fields, "item_digest": self._ds.compute("unresolved_item_digest", fields)}
        )
        event_fields = {
            "event_id": f"unresolved-event-{unresolved_id}-v{version}",
            "unresolved_id": unresolved_id,
            "mission_id": mission_id,
            "source_execution_id": source_execution_id,
            "status": status,
            "reason_code": reason_code,
            "evidence_digest": evidence_digest,
            "item_version": version,
            "actor_id": "unresolved-item-service",
            "actor_role": "source-owner",
            "previous_event_digest": previous,
            "occurred_at": occurred_at,
        }
        event = UnresolvedItemEvent.model_validate(
            {
                **event_fields,
                "event_digest": self._ds.compute("unresolved_item_event_digest", event_fields),
            }
        )
        text = json.dumps(item.model_dump(mode="json"), sort_keys=True)
        event_text = json.dumps(event.model_dump(mode="json"), sort_keys=True)
        with UnitOfWork(self._db):
            if row is None:
                self._db.occ_insert(self._NS, unresolved_id, version, text)
            else:
                self._db.occ_update(
                    self._NS,
                    unresolved_id,
                    expected_version=row[0],
                    new_version=version,
                    json_text=text,
                )
            self._db.occ_insert(self._EVENT_NS, event.event_id, 1, event_text)
            self._audit.append_in_txn(
                mission_id=mission_id,
                event_type="UNRESOLVED_ITEM_CHANGED",
                payload_digest=event.event_digest,
                actor_id=event.actor_id,
                occurred_at_iso=occurred_at.isoformat(),
                record_type="unresolved_item",
                record_id=unresolved_id,
                state_version=version,
                security_projection_digest=item.item_digest,
            )
        return item

    def _event(self, unresolved_id: str, version: int) -> UnresolvedItemEvent:
        event_id = f"unresolved-event-{unresolved_id}-v{version}"
        row = self._db.occ_get(self._EVENT_NS, event_id)
        if row is None or row[0] != 1:
            raise AgentLoopError("unresolved item event is missing")
        event = UnresolvedItemEvent.model_validate_json(row[1])
        payload = event.model_dump(mode="python")
        expected = payload.pop("event_digest")
        self._ds.verify("unresolved_item_event_digest", payload, expected)
        if event.event_id != event_id or event.item_version != version:
            raise AgentLoopError("unresolved item event identity mismatch")
        return event

    def _validate_row(self, unresolved_id: str, row: tuple[int, str]) -> UnresolvedItem:
        version, text = row
        item = UnresolvedItem.model_validate_json(text)
        payload = item.model_dump(mode="python")
        expected = payload.pop("item_digest")
        self._ds.verify("unresolved_item_digest", payload, expected)
        if item.unresolved_id != unresolved_id or item.item_version != version:
            raise AgentLoopError("unresolved item identity or version mismatch")
        event = self._event(unresolved_id, version)
        if (
            event.mission_id != item.mission_id
            or event.source_execution_id != item.source_execution_id
            or event.status != item.status
            or event.reason_code != item.reason_code
            or event.evidence_digest != item.evidence_digest
            or event.occurred_at != item.updated_at
        ):
            raise AgentLoopError("unresolved item current state does not match its event")
        return item
