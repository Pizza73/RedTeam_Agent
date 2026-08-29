"""Metadata-only context index and immutable context grants."""

from __future__ import annotations

import sqlite3

from redteam_agent.canonical import stable_id, verify_model_digest
from redteam_agent.errors import DigestIntegrityError, MissionTTLExceededError
from redteam_agent.models.context import (
    ContextDataAccessGrant,
    ContextResourceIndexRecord,
    DataAccessGrant,
)
from redteam_agent.models.mission import MissionRevision

from .base import ImmutableJsonRepository, model_json, parse_model_json


class ContextResourceIndexRepository(ImmutableJsonRepository[ContextResourceIndexRecord]):
    table = "context_resource_index"
    id_column = "index_id"
    model_type = ContextResourceIndexRecord

    @staticmethod
    def _verified_row(row: sqlite3.Row) -> ContextResourceIndexRecord:
        from redteam_agent.errors import DigestIntegrityError

        record = parse_model_json(ContextResourceIndexRecord, row["payload_json"])
        if not (
            record.index_id == row["index_id"]
            and record.mission_id == row["mission_id"]
            and record.binding.resource_id == row["resource_id"]
            and record.binding.resource_version == row["resource_version"]
            and record.binding.resource_digest == row["resource_digest"]
            and record.resource_type == row["resource_type"]
        ):
            raise DigestIntegrityError("context resource index payload/columns mismatch")
        return record

    def add(self, record: ContextResourceIndexRecord) -> ContextResourceIndexRecord:
        payload = model_json(record)
        self._insert_or_same(
            "INSERT INTO context_resource_index"
            "(index_id, mission_id, resource_id, resource_version, resource_digest, "
            "resource_type, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                record.index_id,
                record.mission_id,
                record.binding.resource_id,
                record.binding.resource_version,
                record.binding.resource_digest,
                record.resource_type,
                payload,
            ),
            payload,
        )
        return record

    def list_for_mission(self, mission_id: str) -> tuple[ContextResourceIndexRecord, ...]:
        rows = self.database.connection.execute(
            "SELECT * FROM context_resource_index WHERE mission_id = ? "
            "ORDER BY resource_id, resource_version",
            (mission_id,),
        ).fetchall()
        return tuple(self._verified_row(row) for row in rows)

    def current_binding(self, mission_id: str, resource_id: str) -> ContextResourceIndexRecord | None:
        row = self.database.connection.execute(
            "SELECT * FROM context_resource_index "
            "WHERE mission_id = ? AND resource_id = ? ORDER BY rowid DESC LIMIT 1",
            (mission_id, resource_id),
        ).fetchone()
        return None if row is None else self._verified_row(row)


class ContextAuthorizationRepository(ImmutableJsonRepository[ContextDataAccessGrant]):
    table = "context_data_access_grants"
    id_column = "grant_id"
    model_type = ContextDataAccessGrant

    def verify_integrity(self, model: ContextDataAccessGrant) -> None:
        verify_model_digest(model, model.grant_digest, exclude={"grant_digest"})
        base = model.model_dump(mode="python", exclude={"grant_id", "grant_digest"})
        base["schema_version"] = "context-grant-v1"
        if model.grant_id != stable_id("ctxgrant", base):
            raise DigestIntegrityError("context grant ID mismatch")

    def verify_row_binding(self, identifier: str | int, model: ContextDataAccessGrant) -> None:
        row = self.database.connection.execute(
            "SELECT mission_id, mission_revision, authorization_epoch, grant_digest, expires_at "
            "FROM context_data_access_grants WHERE grant_id = ?", (identifier,)
        ).fetchone()
        if row is None or not (
            row["mission_id"] == model.mission_id
            and row["mission_revision"] == model.mission_revision
            and row["authorization_epoch"] == model.authorization_epoch
            and row["grant_digest"] == model.grant_digest
            and row["expires_at"] == model.expires_at.isoformat()
        ):
            from redteam_agent.errors import DigestIntegrityError

            raise DigestIntegrityError("context grant row binding mismatch")

    def _mission_revision(self, grant: ContextDataAccessGrant) -> MissionRevision:
        row = self.database.connection.execute(
            "SELECT payload_json FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (grant.mission_id, grant.mission_revision),
        ).fetchone()
        if row is None:
            raise MissionTTLExceededError("bound mission revision does not exist")
        return parse_model_json(MissionRevision, row["payload_json"])

    def _store_issued(
        self, grant: ContextDataAccessGrant, *, authorizer_token: object
    ) -> ContextDataAccessGrant:
        from redteam_agent.context.authorization import _CONTEXT_AUTHORIZER_TOKEN

        if authorizer_token is not _CONTEXT_AUTHORIZER_TOKEN:
            from redteam_agent.errors import ContextAuthorizationError

            raise ContextAuthorizationError(
                "only ContextAuthorizationApplicationService may persist grants"
            )
        self.verify_integrity(grant)
        index = ContextResourceIndexRepository(self.database)
        for entry in grant.resources:
            current = index.current_binding(grant.mission_id, entry.resource.resource_id)
            if current is None or current.binding != entry.resource:
                from redteam_agent.errors import ContextAuthorizationError

                raise ContextAuthorizationError(
                    "context grant resource binding is absent or stale"
                )
        mission = self._mission_revision(grant)
        if grant.expires_at > mission.valid_until:
            raise MissionTTLExceededError("context grant outlives mission")
        payload = model_json(grant)
        existing = self._get_payload(grant.grant_id)
        if existing is not None:
            self.ensure_same_payload(existing, payload)
            return grant
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO context_data_access_grants"
                "(grant_id, mission_id, mission_revision, authorization_epoch, grant_digest, "
                "expires_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    grant.grant_id,
                    grant.mission_id,
                    grant.mission_revision,
                    grant.authorization_epoch,
                    grant.grant_digest,
                    grant.expires_at.isoformat(),
                    payload,
                ),
            )
            for index, entry in enumerate(grant.resources):
                connection.execute(
                    "INSERT INTO data_access_grants"
                    "(owner_type, owner_id, entry_index, resource_id, resource_version, "
                    "resource_digest, payload_json) VALUES ('context', ?, ?, ?, ?, ?, ?)",
                    (
                        grant.grant_id,
                        index,
                        entry.resource.resource_id,
                        entry.resource.resource_version,
                        entry.resource.resource_digest,
                        model_json(entry),
                    ),
                )
        return grant

    def get(self, identifier: str | int) -> ContextDataAccessGrant | None:
        grant = super().get(identifier)
        if grant is None:
            return None
        rows = self.database.connection.execute(
            "SELECT entry_index, resource_id, resource_version, resource_digest, payload_json "
            "FROM data_access_grants "
            "WHERE owner_type = 'context' AND owner_id = ? ORDER BY entry_index",
            (grant.grant_id,),
        ).fetchall()
        persisted = tuple(parse_model_json(DataAccessGrant, row["payload_json"]) for row in rows)
        if persisted != grant.resources:
            raise DigestIntegrityError("context grant child entries differ from envelope")
        for expected_index, (row, entry) in enumerate(zip(rows, persisted, strict=True)):
            if not (
                row["entry_index"] == expected_index
                and row["resource_id"] == entry.resource.resource_id
                and row["resource_version"] == entry.resource.resource_version
                and row["resource_digest"] == entry.resource.resource_digest
            ):
                raise DigestIntegrityError("context grant child row binding mismatch")
        return grant
