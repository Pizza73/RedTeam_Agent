"""Read-model and draft boundary used by the local operator console.

This module never constructs execution authority.  Security-sensitive approval
decisions are delegated to an injected owner callback which must use the existing
ApprovalService and its authenticated actor binding.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel

from redteam_agent.approval.models import ApprovalRecord, ApprovalRequest
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.canonical.json_boundary import load_model_from_json
from redteam_agent.execution.models import ExecutionRecord
from redteam_agent.ingestion.artifact_store import ArtifactReference
from redteam_agent.knowledge.entities import CanonicalEntityRecord
from redteam_agent.knowledge.models import KnowledgeObservation, VerifiedFinding
from redteam_agent.mission.models import MissionLifecycleEvent, MissionState
from redteam_agent.storage.database import Database
from redteam_agent.storage.integrity import verify_object_integrity
from redteam_agent.storage.repositories import (
    MissionLifecycleEventRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PolicyDecisionRepository,
)
from redteam_agent.ui.models import MissionDraftInput, ProviderPolicyDraftInput, StoredDraft, VllmConfigInput

_MISSION_DRAFT_NS = "ui_mission_draft"
_PROVIDER_DRAFT_NS = "ui_provider_policy_draft"


class UIControlPlaneError(RuntimeError):
    """Base class for content-free UI failures."""


class UIDataUnavailableError(UIControlPlaneError):
    """The configured application database is unavailable or unprovisioned."""


class UIConflictError(UIControlPlaneError):
    """The requested operator action is stale or unavailable."""


class ApprovalDecisionPort(Protocol):
    def __call__(self, approval_request_id: str, verdict: str) -> None: ...


class VllmCapabilityPort(Protocol):
    def __call__(self, config: VllmConfigInput) -> dict[str, object]: ...


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class UIControlPlane:
    """Same-host control-plane projection over a provisioned application DB."""

    def __init__(
        self,
        *,
        database_path: str,
        approval_decision_port: ApprovalDecisionPort | None = None,
        vllm_capability_port: VllmCapabilityPort | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if database_path == ":memory:":
            raise UIDataUnavailableError("UI requires a durable application database path")
        self._database_path = str(Path(database_path).expanduser().resolve())
        self._approval_decision_port = approval_decision_port
        self._vllm_capability_port = vllm_capability_port
        self._clock = clock
        self._digests = DigestService()

    def _open(self) -> Database:
        path = Path(self._database_path)
        if not path.is_file():
            raise UIDataUnavailableError("application database does not exist")
        database = Database(self._database_path, create_schema=False)
        if not database.has_table("kv_store") or not database.has_table("occ_store"):
            database.close()
            raise UIDataUnavailableError("application database schema is not provisioned")
        return database

    @staticmethod
    def _json(value: object) -> str:
        payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def health(self) -> dict[str, object]:
        database = self._open()
        try:
            return {
                "status": "healthy",
                "mode": "live",
                "database": "connected",
                "approvalActionsEnabled": self._approval_decision_port is not None,
                "vllmChecksEnabled": self._vllm_capability_port is not None,
            }
        finally:
            database.close()

    def save_mission_draft(self, draft: MissionDraftInput) -> dict[str, object]:
        return self._save_draft(namespace=_MISSION_DRAFT_NS, prefix="mission-draft", draft=draft)

    def save_provider_policy_draft(self, draft: ProviderPolicyDraftInput) -> dict[str, object]:
        return self._save_draft(namespace=_PROVIDER_DRAFT_NS, prefix="provider-draft", draft=draft)

    def _save_draft(
        self, *, namespace: str, prefix: str, draft: MissionDraftInput | ProviderPolicyDraftInput
    ) -> dict[str, object]:
        now = self._clock().astimezone(UTC)
        draft_id = f"{prefix}-{uuid4()}"
        stored = StoredDraft(
            draftId=draft_id,
            savedAt=now,
            draft=draft.model_dump(mode="json"),
        )
        database = self._open()
        try:
            database.put_idempotent(namespace, draft_id, self._json(stored))
        finally:
            database.close()
        return {"draftId": draft_id, "savedAt": now.isoformat()}

    def dashboard(self) -> dict[str, object]:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return {
                    "mission": None,
                    "metrics": {"confirmedFindings": 0, "mappedEntities": 0, "pendingDecisions": 0},
                    "timeline": [],
                }
            revision = MissionRevisionRepository(database, self._digests).get(
                state.mission_id, state.mission_revision
            )
            if revision is None:
                raise UIDataUnavailableError("current mission revision is missing")
            findings = self._verified_findings(database, state.mission_id)
            entities = self._entities(database, state.mission_id)
            pending = sum(
                1
                for item in self._interventions(database)
                if item["missionId"] == state.mission_id and item["state"] == "pending"
            )
            events = MissionLifecycleEventRepository(database, self._digests).events_for(state.mission_id)
            scopes = [self._scope_label(rule.model_dump(mode="json")) for rule in revision.allowed_execution_scope]
            return {
                "mission": {
                    "id": state.mission_id,
                    "title": revision.description or state.mission_id,
                    "state": state.state.lower(),
                    "revision": state.mission_revision,
                    "authorizationEpoch": state.authorization_epoch,
                    "authorizationReference": revision.authorization_reference,
                    "validUntil": revision.valid_until.isoformat(),
                    "objectives": list(revision.objectives),
                    "scopes": scopes,
                },
                "metrics": {
                    "confirmedFindings": len(findings),
                    "mappedEntities": len(entities),
                    "pendingDecisions": pending,
                },
                "timeline": [self._event_view(event) for event in events[-6:]],
            }
        finally:
            database.close()

    def phases(self) -> list[dict[str, object]]:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return []
            status = {
                "DRAFT": "not_started",
                "VALIDATED": "not_started",
                "RUNNING": "current",
                "PAUSED": "blocked",
                "FINALIZING": "current",
                "WAITING_HUMAN_REVIEW": "approval_required",
                "COMPLETED": "completed",
                "COMPLETED_WITH_UNRESOLVED_ITEMS": "completed",
                "FAILED": "failed",
                "ABORTED": "failed",
            }[state.state]
            return [{
                "phase": "OBJECTIVE",
                "label": "Mission objective",
                "status": status,
                "detail": f"Lifecycle state: {state.state}",
            }]
        finally:
            database.close()

    def activity(self) -> dict[str, object] | None:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return None
            rows = database.connection.execute(
                "SELECT json FROM executions WHERE mission_id = ? "
                "ORDER BY json_extract(json, '$.updated_at') DESC, execution_id DESC LIMIT 1",
                (state.mission_id,),
            ).fetchone()
            if rows is None:
                return None
            execution = load_model_from_json(ExecutionRecord, str(rows[0]))
            verify_object_integrity(execution, self._digests)
            terminal = execution.provider_execution_state not in {
                "PLANNED",
                "AUTHORIZED",
                "DISPATCH_CLAIMED",
                "DISPATCHED",
                "RUNNING",
                "CANCEL_REQUESTED",
                "RECONCILING",
            }
            elapsed = max(0, int((execution.updated_at - execution.created_at).total_seconds()))
            return {
                "id": f"activity-{execution.execution_id}",
                "executionId": execution.execution_id,
                "status": self._activity_status(execution.provider_execution_state),
                "title": execution.tool_ref.tool_id,
                "toolDisplayName": execution.tool_ref.tool_id,
                "operation": execution.tool_ref.tool_id,
                "adapterId": execution.resolved_adapter_id,
                "references": [
                    {"name": "mission_ref", "type": "mission", "id": execution.mission_id},
                    {"name": "execution_ref", "type": "execution", "id": execution.execution_id},
                ],
                "startedAt": execution.created_at.isoformat(),
                "completedAt": execution.updated_at.isoformat() if terminal else None,
                "elapsedSeconds": elapsed,
                "rawOutputAvailable": False,
                "summary": f"Sanitized execution state: {execution.provider_execution_state}",
            }
        finally:
            database.close()

    def interventions(self) -> list[dict[str, object]]:
        database = self._open()
        try:
            return self._interventions(database)
        finally:
            database.close()

    def _interventions(self, database: Database) -> list[dict[str, object]]:
        records = self._approval_records(database)
        decision_repository = PolicyDecisionRepository(database, self._digests)
        now = self._clock().astimezone(UTC)
        views: list[dict[str, object]] = []
        for row_key, raw in database.get_all("approval_requests"):
            request = load_model_from_json(ApprovalRequest, raw)
            verify_object_integrity(request, self._digests)
            if row_key != request.approval_request_id:
                raise UIDataUnavailableError("approval request identity is invalid")
            record = records.get(request.approval_request_id)
            if record is not None:
                state = "approved" if record.decision == "APPROVED" else "rejected"
            elif now >= request.expires_at:
                state = "expired"
            else:
                state = "pending"
            decision = decision_repository.get(request.policy_decision_id)
            if decision is None:
                raise UIDataUnavailableError("approval policy decision is missing")
            presentation = request.presentation
            actionable = state == "pending" and self._approval_decision_port is not None
            views.append({
                "id": request.approval_request_id,
                "kind": "approval",
                "missionId": request.mission_id,
                "missionRevision": request.mission_revision,
                "authorizationEpoch": request.authorization_epoch,
                "title": presentation.tool_display_name,
                "summary": "Bound execution intent awaiting an immutable operator decision.",
                "createdAt": request.issued_at.isoformat(),
                "expiresAt": request.expires_at.isoformat(),
                "state": state,
                "actionable": actionable,
                "disabledReason": (
                    None if actionable else "Trusted approval service is not attached or request is closed."
                ),
                "presentationDigest": presentation.presentation_digest,
                "toolDisplayName": presentation.tool_display_name,
                "targets": [
                    self._target_label(target.model_dump(mode="json"))
                    for target in presentation.normalized_targets
                ],
                "redactedArguments": presentation.redacted_arguments,
                "risk": presentation.effective_risk,
                "sideEffect": presentation.side_effect,
                "adapterId": decision.resolved_adapter_id,
            })
        return sorted(views, key=lambda item: (item["state"] != "pending", str(item["createdAt"])), reverse=False)

    def submit_approval(
        self, *, approval_request_id: str, presentation_digest: str, verdict: str
    ) -> dict[str, object]:
        if self._approval_decision_port is None:
            raise UIConflictError("trusted approval service is not attached")
        current = next((item for item in self.interventions() if item["id"] == approval_request_id), None)
        if current is None or current["state"] != "pending" or current["presentationDigest"] != presentation_digest:
            raise UIConflictError("approval request is unavailable, stale, or binding-mismatched")
        self._approval_decision_port(approval_request_id, verdict.upper())
        updated = next((item for item in self.interventions() if item["id"] == approval_request_id), None)
        if updated is None:
            raise UIConflictError("approval decision outcome is unavailable")
        return updated

    def knowledge(self) -> dict[str, object]:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return {"nodes": [], "edges": [], "findings": [], "artifacts": []}
            entities = self._entities(database, state.mission_id)
            observations = self._observations(database, state.mission_id)
            findings = self._verified_findings(database, state.mission_id)
            artifacts = self._artifacts(database, state.mission_id)
            node_ids = {entity.entity_id for entity in entities}
            nodes = [self._entity_view(entity) for entity in entities]
            edges = [
                {
                    "id": observation.observation_id,
                    "source": observation.subject_ref,
                    "target": observation.object_ref,
                    "label": observation.predicate,
                }
                for observation in observations
                if observation.object_ref is not None
                and observation.subject_ref in node_ids
                and observation.object_ref in node_ids
            ]
            artifact_views = [self._artifact_view(artifact) for artifact in artifacts]
            return {
                "nodes": nodes,
                "edges": edges,
                "findings": [self._finding_view(finding) for finding in findings],
                "artifacts": artifact_views,
            }
        finally:
            database.close()

    def provider_status(self) -> dict[str, object]:
        database = self._open()
        try:
            rows = database.get_all(_PROVIDER_DRAFT_NS)
            latest = None
            if rows:
                drafts = [StoredDraft.from_untrusted_json(raw) for _key, raw in rows]
                selected = max(drafts, key=lambda draft: draft.savedAt)
                validated = ProviderPolicyDraftInput.from_untrusted_json(
                    json.dumps(thaw(selected.draft), sort_keys=True).encode("utf-8")
                )
                latest = {
                    "draftId": selected.draftId,
                    "savedAt": selected.savedAt.isoformat(),
                    "draft": validated.model_dump(mode="json"),
                }
            try:
                from importlib.metadata import version

                impacket_version = version("impacket")
            except Exception:  # pragma: no cover - environment dependent, result is intentionally coarse
                impacket_version = None
            return {
                "mode": "live",
                "tuoni": {"edition": "commercial", "version": "latest", "access": "unconfigured"},
                "sliver": {
                    "version": "1.7.3",
                    "operator": "joe",
                    "operatorConfigLocation": "downloads",
                    "operatorAccess": "unconfigured",
                    "implantTransport": "http",
                    "beaconPresent": False,
                },
                "impacket": {
                    "installed": impacket_version is not None,
                    "version": impacket_version,
                    "server": "redteam-impacket-mcp",
                    "operations": [
                        "impacket.smb.negotiate",
                        "impacket.smb.authenticate",
                        "impacket.smb.list_shares",
                        "impacket.rpc.endpoint_map",
                    ],
                },
                "latestDraft": latest,
            }
        finally:
            database.close()

    def check_vllm(self, config: VllmConfigInput) -> dict[str, object]:
        if self._vllm_capability_port is None:
            return {
                "status": "failed",
                "summary": "The trusted Phase 2 capability gateway is not attached; no network request was sent.",
                "latencyMs": 0,
                "checkedAt": self._clock().astimezone(UTC).isoformat(),
                "checks": [{
                    "name": "Trusted gateway",
                    "status": "failed",
                    "detail": "Start the UI from the production composition root with a capability port.",
                }],
            }
        return self._vllm_capability_port(config)

    def _selected_mission_state(self, database: Database) -> MissionState | None:
        states = MissionStateRepository(database, self._digests).all_states()
        if not states:
            return None
        priority = {
            "RUNNING": 0,
            "WAITING_HUMAN_REVIEW": 1,
            "FINALIZING": 2,
            "PAUSED": 3,
            "VALIDATED": 4,
            "DRAFT": 5,
            "FAILED": 6,
            "ABORTED": 7,
            "COMPLETED_WITH_UNRESOLVED_ITEMS": 8,
            "COMPLETED": 9,
        }
        return sorted(states, key=lambda item: (priority[item.state], item.mission_id))[0]

    def _approval_records(self, database: Database) -> dict[str, ApprovalRecord]:
        records: dict[str, ApprovalRecord] = {}
        for row_key, raw in database.get_all("approvals"):
            record = load_model_from_json(ApprovalRecord, raw)
            verify_object_integrity(record, self._digests)
            if row_key != record.approval_id or record.approval_request_id in records:
                raise UIDataUnavailableError("approval record identity is invalid")
            records[record.approval_request_id] = record
        return records

    def _entities(self, database: Database, mission_id: str) -> tuple[CanonicalEntityRecord, ...]:
        result: list[CanonicalEntityRecord] = []
        for row_key, version, raw in database.occ_get_all("canonical_entity"):
            entity = load_model_from_json(CanonicalEntityRecord, raw)
            if row_key != entity.entity_id or version != entity.entity_version:
                raise UIDataUnavailableError("knowledge entity identity is invalid")
            payload = entity.model_dump(mode="python")
            digest = str(payload.pop("record_digest"))
            self._digests.verify("canonical_entity_digest", payload, digest)
            if entity.mission_id == mission_id:
                result.append(entity)
        return tuple(result)

    def _observations(self, database: Database, mission_id: str) -> tuple[KnowledgeObservation, ...]:
        result: list[KnowledgeObservation] = []
        for row_key, _version, raw in database.occ_get_all("knowledge_observation"):
            observation = load_model_from_json(KnowledgeObservation, raw)
            if row_key != observation.observation_id:
                raise UIDataUnavailableError("knowledge observation identity is invalid")
            payload = observation.model_dump(mode="python")
            digest = str(payload.pop("observation_digest"))
            self._digests.verify("knowledge_observation_digest", payload, digest)
            if observation.mission_id == mission_id:
                result.append(observation)
        return tuple(result)

    def _verified_findings(self, database: Database, mission_id: str) -> tuple[VerifiedFinding, ...]:
        result: list[VerifiedFinding] = []
        for row_key, version, raw in database.occ_get_all("verified_finding"):
            finding = load_model_from_json(VerifiedFinding, raw)
            if row_key != finding.finding_id or version != finding.finding_version:
                raise UIDataUnavailableError("verified finding identity is invalid")
            payload = finding.model_dump(mode="python")
            digest = str(payload.pop("finding_digest"))
            self._digests.verify("verified_finding_digest", payload, digest)
            if finding.mission_id == mission_id:
                result.append(finding)
        return tuple(result)

    def _artifacts(self, database: Database, mission_id: str) -> tuple[ArtifactReference, ...]:
        result: list[ArtifactReference] = []
        for row_key, _version, raw in database.occ_get_all("artifact"):
            artifact = load_model_from_json(ArtifactReference, raw)
            if row_key != artifact.artifact_id:
                raise UIDataUnavailableError("artifact identity is invalid")
            payload = artifact.model_dump(mode="python")
            digest = str(payload.pop("artifact_digest"))
            self._digests.verify("artifact_digest", payload, digest)
            if artifact.mission_id == mission_id and artifact.variant == "redacted":
                result.append(artifact)
        return tuple(result)

    @staticmethod
    def _scope_label(scope: dict[str, Any]) -> str:
        kind = str(scope.get("type", "scope"))
        if kind == "network":
            return f"network:{','.join(str(item) for item in scope.get('cidrs', []))}"
        for field in ("host_id", "session_id", "hostname", "domain", "path_prefix"):
            if scope.get(field):
                return f"{kind}:{scope[field]}"
        return kind

    @staticmethod
    def _target_label(target: dict[str, Any]) -> str:
        suffix = ""
        if target.get("port") is not None:
            suffix = f":{target['port']}/{target.get('protocol') or 'unknown'}"
        return f"{target.get('type', 'target')}:{target.get('canonical_value', 'unknown')}{suffix}"

    @staticmethod
    def _event_view(event: MissionLifecycleEvent) -> dict[str, object]:
        return {
            "id": f"{event.mission_id}-{event.sequence_number}",
            "title": f"{event.from_state} → {event.to_state}",
            "detail": event.reason,
            "timestamp": event.occurred_at.isoformat(),
        }

    @staticmethod
    def _activity_status(state: str) -> str:
        if state in {
            "PLANNED",
            "AUTHORIZED",
            "DISPATCH_CLAIMED",
            "DISPATCHED",
            "RUNNING",
            "CANCEL_REQUESTED",
            "RECONCILING",
        }:
            return "running"
        if state == "SUCCEEDED":
            return "completed"
        if state == "BLOCKED":
            return "blocked"
        return "failed"

    @staticmethod
    def _entity_view(entity: CanonicalEntityRecord) -> dict[str, object]:
        category = {
            "host": "asset",
            "network_asset": "asset",
            "ad_principal": "account",
            "windows_local_principal": "account",
            "linux_principal": "account",
            "domain": "domain",
            "session": "session",
        }[entity.entity_type]
        return {
            "id": entity.entity_id,
            "label": entity.strong_key_value,
            "category": category,
            "verification": "confirmed",
            "detail": f"{entity.entity_type} · {entity.strong_key_type} · version {entity.entity_version}",
        }

    @staticmethod
    def _finding_view(finding: VerifiedFinding) -> dict[str, object]:
        return {
            "id": finding.finding_id,
            "title": finding.predicate.replace("_", " "),
            "target": finding.subject_ref,
            "verification": finding.verification_state,
            "confidence": 1.0,
            "sourceExecutionId": finding.source_execution_id,
            "artifactId": None,
            "timestamp": finding.recorded_at.isoformat(),
            "summary": "Deterministically verified execution outcome.",
        }

    @staticmethod
    def _artifact_view(artifact: ArtifactReference) -> dict[str, object]:
        classification = {
            "normal": "normal",
            "sensitive": "sensitive",
            "secret": "secret_reference",
        }[artifact.classification]
        return {
            "id": artifact.artifact_id,
            "mediaType": artifact.media_type,
            "sizeBytes": artifact.size_bytes,
            "classification": classification,
            "variant": "redacted",
            "createdAt": artifact.created_at.isoformat(),
        }
