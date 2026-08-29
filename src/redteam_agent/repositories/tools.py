"""Trusted registry and deterministic availability snapshot repositories."""

from __future__ import annotations

from redteam_agent.canonical import sha256_digest, stable_id, verify_model_digest
from redteam_agent.errors import DigestIntegrityError, MissionTTLExceededError
from redteam_agent.models.mission import MissionRevision
from redteam_agent.models.tools import AvailableToolSnapshot, ToolRegistryRevision
from redteam_agent.tools.registry import registry_payload

from .base import ImmutableJsonRepository, model_json, parse_model_json
from .capabilities import (
    AdapterCapabilitySnapshotRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
)


class ToolRegistryRepository(ImmutableJsonRepository[ToolRegistryRevision]):
    table = "tool_registry_revisions"
    id_column = "registry_revision"
    model_type = ToolRegistryRevision

    def verify_integrity(self, model: ToolRegistryRevision) -> None:
        actual = sha256_digest(registry_payload(model.tools, model.registry_revision))
        if actual != model.registry_digest:
            raise DigestIntegrityError("tool registry digest mismatch")

    def verify_row_binding(self, identifier: str | int, model: ToolRegistryRevision) -> None:
        row = self.database.connection.execute(
            "SELECT registry_digest FROM tool_registry_revisions WHERE registry_revision = ?",
            (identifier,),
        ).fetchone()
        if row is None or row["registry_digest"] != model.registry_digest:
            raise DigestIntegrityError("tool registry row binding mismatch")

    def add(self, revision: ToolRegistryRevision) -> ToolRegistryRevision:
        self.verify_integrity(revision)
        payload = model_json(revision)
        self._insert_or_same(
            "INSERT INTO tool_registry_revisions"
            "(registry_revision, registry_digest, payload_json) VALUES (?, ?, ?)",
            (revision.registry_revision, revision.registry_digest, payload),
            payload,
        )
        return revision


class AvailableToolSnapshotRepository(ImmutableJsonRepository[AvailableToolSnapshot]):
    table = "available_tool_snapshots"
    id_column = "snapshot_id"
    model_type = AvailableToolSnapshot

    def verify_integrity(self, model: AvailableToolSnapshot) -> None:
        verify_model_digest(model, model.snapshot_digest, exclude={"snapshot_digest"})
        calculation_payload = {
            "schema_version": "tool-availability-calculation-v1",
            "mission_id": model.mission_id,
            "mission_revision": model.mission_revision,
            "authorization_epoch": model.authorization_epoch,
            "registry_digest": model.registry_digest,
            "policy_version": model.policy_version,
            "execution_scope_digest": model.execution_scope_digest,
            "session_security_context_digest": model.session_security_context_digest,
            "adapter_capabilities_digest": model.adapter_capabilities_digest,
            "sandbox_capabilities_digest": model.sandbox_capabilities_digest,
            "remote_mcp_trust_policy_digest": model.remote_mcp_trust_policy_digest,
            "tools": [view.model_dump(mode="python") for view in model.tools],
        }
        if sha256_digest(calculation_payload) != model.calculation_digest:
            raise DigestIntegrityError("available-tool calculation digest mismatch")
        identity = {
            "schema_version": "available-tool-snapshot-v1",
            "calculation_digest": model.calculation_digest,
            "created_at": model.created_at,
            "expires_at": model.expires_at,
        }
        if model.snapshot_id != stable_id("toolsnapshot", identity):
            raise DigestIntegrityError("available-tool snapshot ID mismatch")

    def verify_row_binding(self, identifier: str | int, model: AvailableToolSnapshot) -> None:
        row = self.database.connection.execute(
            "SELECT snapshot_digest, mission_id, mission_revision, authorization_epoch, expires_at "
            "FROM available_tool_snapshots WHERE snapshot_id = ?", (identifier,)
        ).fetchone()
        if row is None or not (
            row["snapshot_digest"] == model.snapshot_digest
            and row["mission_id"] == model.mission_id
            and row["mission_revision"] == model.mission_revision
            and row["authorization_epoch"] == model.authorization_epoch
            and row["expires_at"] == model.expires_at.isoformat()
        ):
            raise DigestIntegrityError("available-tool snapshot row binding mismatch")

        self._verify_parent_bindings(model)

    def _verify_parent_bindings(self, snapshot: AvailableToolSnapshot) -> None:
        row = self.database.connection.execute(
            "SELECT payload_json FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (snapshot.mission_id, snapshot.mission_revision),
        ).fetchone()
        if row is None:
            raise MissionTTLExceededError("bound mission revision does not exist")
        mission = parse_model_json(MissionRevision, row["payload_json"])
        if snapshot.expires_at > mission.valid_until:
            raise MissionTTLExceededError("available-tool snapshot outlives mission")
        registry_row = self.database.connection.execute(
            "SELECT registry_revision FROM tool_registry_revisions "
            "WHERE registry_digest = ?",
            (snapshot.registry_digest,),
        ).fetchone()
        registry = (
            ToolRegistryRepository(self.database).get(registry_row["registry_revision"])
            if registry_row is not None
            else None
        )
        if registry is None or registry.registry_digest != snapshot.registry_digest:
            raise DigestIntegrityError("available-tool snapshot registry binding is missing")
        registry_refs = {tool.tool_ref for tool in registry.tools}
        if any(view.tool_ref not in registry_refs for view in snapshot.tools):
            raise DigestIntegrityError("available-tool snapshot contains an unregistered tool")
        required_snapshots = (
            (
                SessionSecurityContextSnapshotRepository(self.database),
                snapshot.session_security_context_digest,
                snapshot.mission_id,
            ),
            (
                AdapterCapabilitySnapshotRepository(self.database),
                snapshot.adapter_capabilities_digest,
                None,
            ),
            (
                SandboxCapabilitySnapshotRepository(self.database),
                snapshot.sandbox_capabilities_digest,
                None,
            ),
            (
                RemoteMCPTrustSnapshotRepository(self.database),
                snapshot.remote_mcp_trust_policy_digest,
                None,
            ),
        )
        for repository, digest, mission_id in required_snapshots:
            query = (
                f"SELECT snapshot_id FROM {repository.table} "  # noqa: S608
                "WHERE snapshot_digest = ?"
            )
            parameters: tuple[object, ...] = (digest,)
            if mission_id is not None:
                query += " AND mission_id = ?"
                parameters = (digest, mission_id)
            capability_row = self.database.connection.execute(query, parameters).fetchone()
            if capability_row is None or repository.get(capability_row["snapshot_id"]) is None:
                raise DigestIntegrityError(
                    "available-tool snapshot capability binding is missing or corrupt: "
                    f"{repository.table}"
                )

    def add(self, snapshot: AvailableToolSnapshot) -> AvailableToolSnapshot:
        self.verify_integrity(snapshot)
        self._verify_parent_bindings(snapshot)
        payload = model_json(snapshot)
        self._insert_or_same(
            "INSERT INTO available_tool_snapshots"
            "(snapshot_id, snapshot_digest, mission_id, mission_revision, authorization_epoch, "
            "expires_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                snapshot.snapshot_id,
                snapshot.snapshot_digest,
                snapshot.mission_id,
                snapshot.mission_revision,
                snapshot.authorization_epoch,
                snapshot.expires_at.isoformat(),
                payload,
            ),
            payload,
        )
        return snapshot
