"""Grant-bound redacted Context Builder for Planner and Analyzer."""

from __future__ import annotations

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import CanonicalJsonObject
from redteam_agent.context.authorization import ContextAuthorizationService
from redteam_agent.errors import DataAccessResourceError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.policy.models import DataAccessGrant

MAX_CONTEXT_RESOURCES = 20
_SAFE_CLASSIFICATIONS = frozenset({"public", "internal", "redacted", "summary"})


class ContextBodyRecord(StrictImmutableBoundaryModel):
    resource_id: str
    resource_type: str
    resource_version: str
    resource_digest: str
    classification: str
    body: CanonicalJsonObject


class ContextBodyStore:
    """Application-owned body store used by the Phase 1 mock composition."""

    def __init__(self, digest_service: DigestService) -> None:
        self._ds = digest_service
        self._records: dict[str, ContextBodyRecord] = {}

    def put(self, record: ContextBodyRecord) -> None:
        if record.classification not in _SAFE_CLASSIFICATIONS:
            raise DataAccessResourceError("context body classification is not safe")
        expected = self._ds.compute("security_projection_digest", {"body": record.body})
        if record.resource_digest != expected:
            raise DataAccessResourceError("context body digest does not match its content")
        self._records[record.resource_id] = record

    def read(self, grant: DataAccessGrant) -> ContextBodyRecord:
        record = self._records.get(grant.resource.resource_id)
        if record is None:
            raise DataAccessResourceError("granted context body is unavailable")
        expected_state = self._ds.compute("authorization_state_digest", {
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "resource_version": record.resource_version,
            "resource_digest": record.resource_digest,
            "operations": ["read"],
        })
        if (
            grant.resource_type != record.resource_type
            or grant.resource.resource_version != record.resource_version
            or grant.resource.resource_digest != record.resource_digest
            or grant.authorization_state_digest != expected_state
            or "read" not in grant.operations
            or record.classification not in _SAFE_CLASSIFICATIONS
        ):
            raise DataAccessResourceError("context body no longer matches its exact grant")
        return record


class ContextBuilder:
    def __init__(
        self, *, authorization_service: ContextAuthorizationService, body_store: ContextBodyStore,
    ) -> None:
        self._authorization = authorization_service
        self._bodies = body_store

    def build(self, *, grant_id: str, mission_id: str) -> CanonicalJsonObject:
        grant = self._authorization.verify_grant(grant_id=grant_id, mission_id=mission_id)
        if len(grant.resources) > MAX_CONTEXT_RESOURCES:
            raise DataAccessResourceError("context retrieval exceeds its fixed resource bound")
        records = tuple(self._bodies.read(item) for item in grant.resources)
        return {"resources": [
            {
                "resource_id": item.resource_id,
                "resource_type": item.resource_type,
                "resource_version": item.resource_version,
                "resource_digest": item.resource_digest,
                "classification": item.classification,
                "body": item.body,
            }
            for item in records
        ]}
