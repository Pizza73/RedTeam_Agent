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


class UnresolvedItem(StrictImmutableBoundaryModel):
    unresolved_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    status: Literal["OPEN", "ACCEPTED", "RESOLVED"]
    reason_code: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    item_version: int = Field(ge=1)
    updated_at: datetime
    item_digest: str = Field(min_length=1)


class UnresolvedItemService:
    _NS = "unresolved_item_current"

    def __init__(self, *, database: Database, digest_service: DigestService, clock: Clock) -> None:
        self._db, self._ds, self._clock = database, digest_service, clock

    def current(self, mission_id: str) -> tuple[UnresolvedItem, ...]:
        result = []
        for key, version, text in self._db.occ_get_all(self._NS):
            item = UnresolvedItem.model_validate_json(text)
            payload = item.model_dump(mode="python")
            expected = payload.pop("item_digest")
            self._ds.verify("unresolved_item_digest", payload, expected)
            if item.unresolved_id != key or item.item_version != version:
                raise AgentLoopError("unresolved item identity or version mismatch")
            if item.mission_id == mission_id:
                result.append(item)
        return tuple(sorted(result, key=lambda item: item.unresolved_id))

    def open(
        self, *, unresolved_id: str, mission_id: str, reason_code: str,
        evidence_digest: str,
    ) -> UnresolvedItem:
        return self._write(
            unresolved_id=unresolved_id, mission_id=mission_id, status="OPEN",
            reason_code=reason_code, evidence_digest=evidence_digest,
        )

    def resolve(self, *, unresolved_id: str, evidence_digest: str) -> UnresolvedItem:
        row = self._db.occ_get(self._NS, unresolved_id)
        if row is None:
            raise AgentLoopError("unresolved item does not exist")
        current = UnresolvedItem.model_validate_json(row[1])
        if current.status == "RESOLVED":
            return current
        return self._write(
            unresolved_id=unresolved_id, mission_id=current.mission_id, status="RESOLVED",
            reason_code=current.reason_code, evidence_digest=evidence_digest,
        )

    def _write(
        self, *, unresolved_id: str, mission_id: str,
        status: Literal["OPEN", "RESOLVED"], reason_code: str, evidence_digest: str,
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
