"""Repositories preserve full capability snapshots, not digest-only records."""

from __future__ import annotations

from typing import Any

from redteam_agent.models.capabilities import (
    AdapterCapabilitySnapshot,
    RemoteMCPTrustSnapshot,
    SandboxCapabilitySnapshot,
    SessionSecurityContextSnapshot,
)
from redteam_agent.tools.capability_snapshots import verify_capability_snapshot

from .base import ImmutableJsonRepository, model_json


class SessionSecurityContextSnapshotRepository(
    ImmutableJsonRepository[SessionSecurityContextSnapshot]
):
    table = "session_security_context_snapshots"
    id_column = "snapshot_id"
    model_type = SessionSecurityContextSnapshot

    def verify_integrity(self, model: SessionSecurityContextSnapshot) -> None:
        verify_capability_snapshot(model)

    def verify_row_binding(
        self, identifier: str | int, model: SessionSecurityContextSnapshot
    ) -> None:
        row = self.database.connection.execute(
            "SELECT snapshot_digest, mission_id FROM session_security_context_snapshots "
            "WHERE snapshot_id = ?",
            (identifier,),
        ).fetchone()
        if (
            row is None
            or row["snapshot_digest"] != model.snapshot_digest
            or row["mission_id"] != model.mission_id
        ):
            from redteam_agent.errors import DigestIntegrityError

            raise DigestIntegrityError("session snapshot row binding mismatch")

    def add(self, snapshot: SessionSecurityContextSnapshot) -> SessionSecurityContextSnapshot:
        self.verify_integrity(snapshot)
        payload = model_json(snapshot)
        self._insert_or_same(
            "INSERT INTO session_security_context_snapshots"
            "(snapshot_id, snapshot_digest, mission_id, payload_json) VALUES (?, ?, ?, ?)",
            (snapshot.snapshot_id, snapshot.snapshot_digest, snapshot.mission_id, payload),
            payload,
        )
        return snapshot


class AdapterCapabilitySnapshotRepository(ImmutableJsonRepository[AdapterCapabilitySnapshot]):
    table = "adapter_capability_snapshots"
    id_column = "snapshot_id"
    model_type = AdapterCapabilitySnapshot

    def verify_integrity(self, model: AdapterCapabilitySnapshot) -> None:
        verify_capability_snapshot(model)

    def verify_row_binding(self, identifier: str | int, model: AdapterCapabilitySnapshot) -> None:
        _verify_snapshot_digest_column(self, identifier, model.snapshot_digest)

    def add(self, snapshot: AdapterCapabilitySnapshot) -> AdapterCapabilitySnapshot:
        self.verify_integrity(snapshot)
        payload = model_json(snapshot)
        self._insert_or_same(
            "INSERT INTO adapter_capability_snapshots"
            "(snapshot_id, snapshot_digest, payload_json) VALUES (?, ?, ?)",
            (snapshot.snapshot_id, snapshot.snapshot_digest, payload),
            payload,
        )
        return snapshot


class SandboxCapabilitySnapshotRepository(ImmutableJsonRepository[SandboxCapabilitySnapshot]):
    table = "sandbox_capability_snapshots"
    id_column = "snapshot_id"
    model_type = SandboxCapabilitySnapshot

    def verify_integrity(self, model: SandboxCapabilitySnapshot) -> None:
        verify_capability_snapshot(model)

    def verify_row_binding(self, identifier: str | int, model: SandboxCapabilitySnapshot) -> None:
        _verify_snapshot_digest_column(self, identifier, model.snapshot_digest)

    def add(self, snapshot: SandboxCapabilitySnapshot) -> SandboxCapabilitySnapshot:
        self.verify_integrity(snapshot)
        payload = model_json(snapshot)
        self._insert_or_same(
            "INSERT INTO sandbox_capability_snapshots"
            "(snapshot_id, snapshot_digest, payload_json) VALUES (?, ?, ?)",
            (snapshot.snapshot_id, snapshot.snapshot_digest, payload),
            payload,
        )
        return snapshot


class RemoteMCPTrustSnapshotRepository(ImmutableJsonRepository[RemoteMCPTrustSnapshot]):
    table = "remote_mcp_trust_snapshots"
    id_column = "snapshot_id"
    model_type = RemoteMCPTrustSnapshot

    def verify_integrity(self, model: RemoteMCPTrustSnapshot) -> None:
        verify_capability_snapshot(model)

    def verify_row_binding(self, identifier: str | int, model: RemoteMCPTrustSnapshot) -> None:
        _verify_snapshot_digest_column(self, identifier, model.snapshot_digest)

    def add(self, snapshot: RemoteMCPTrustSnapshot) -> RemoteMCPTrustSnapshot:
        self.verify_integrity(snapshot)
        payload = model_json(snapshot)
        self._insert_or_same(
            "INSERT INTO remote_mcp_trust_snapshots"
            "(snapshot_id, snapshot_digest, payload_json) VALUES (?, ?, ?)",
            (snapshot.snapshot_id, snapshot.snapshot_digest, payload),
            payload,
        )
        return snapshot


def _verify_snapshot_digest_column(repository: Any, identifier: str | int, expected: str) -> None:
    row = repository.database.connection.execute(
        f"SELECT snapshot_digest FROM {repository.table} WHERE {repository.id_column} = ?",  # noqa: S608
        (identifier,),
    ).fetchone()
    if row is None or row["snapshot_digest"] != expected:
        from redteam_agent.errors import DigestIntegrityError

        raise DigestIntegrityError("capability snapshot digest column mismatch")
