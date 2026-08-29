"""Deterministic builders and digest verification for mock/real capability snapshots."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical import sha256_digest, stable_id
from redteam_agent.errors import DigestIntegrityError
from redteam_agent.models.capabilities import (
    AdapterCapabilities,
    AdapterCapabilitySnapshot,
    RemoteMCPTrust,
    RemoteMCPTrustSnapshot,
    SandboxCapabilities,
    SandboxCapabilitySnapshot,
    SessionSecurityContext,
    SessionSecurityContextSnapshot,
)


def _build_snapshot(
    *,
    prefix: str,
    schema_version: str,
    field_name: str,
    values: tuple[object, ...],
    source: str,
    created_at: datetime,
    model_type: type,
    mission_id: str | None = None,
) -> object:
    content = {
        "schema_version": schema_version,
        field_name: [value.model_dump(mode="python") for value in values],
    }
    digest = sha256_digest(content)
    identity = {**content, "source": source, "created_at": created_at}
    if mission_id is not None:
        identity["mission_id"] = mission_id
    kwargs = {
        "snapshot_id": stable_id(prefix, identity),
        "snapshot_digest": digest,
        field_name: values,
        "source": source,
        "created_at": created_at,
    }
    if mission_id is not None:
        kwargs["mission_id"] = mission_id
    return model_type(**kwargs)


def build_session_snapshot(
    *, mission_id: str, contexts: tuple[SessionSecurityContext, ...], source: str, created_at: datetime
) -> SessionSecurityContextSnapshot:
    ordered = tuple(sorted(contexts, key=lambda item: item.session_id))
    return _build_snapshot(
        prefix="sessioncap",
        schema_version="session-security-context-v1",
        field_name="contexts",
        values=ordered,
        source=source,
        created_at=created_at,
        model_type=SessionSecurityContextSnapshot,
        mission_id=mission_id,
    )


def build_adapter_snapshot(
    *, adapters: tuple[AdapterCapabilities, ...], source: str, created_at: datetime
) -> AdapterCapabilitySnapshot:
    ordered = tuple(sorted(adapters, key=lambda item: (item.adapter_type, item.adapter_id)))
    return _build_snapshot(
        prefix="adaptercap",
        schema_version="adapter-capability-v1",
        field_name="adapters",
        values=ordered,
        source=source,
        created_at=created_at,
        model_type=AdapterCapabilitySnapshot,
    )


def build_sandbox_snapshot(
    *, sandboxes: tuple[SandboxCapabilities, ...], source: str, created_at: datetime
) -> SandboxCapabilitySnapshot:
    ordered = tuple(sorted(sandboxes, key=lambda item: item.sandbox_id))
    return _build_snapshot(
        prefix="sandboxcap",
        schema_version="sandbox-capability-v1",
        field_name="sandboxes",
        values=ordered,
        source=source,
        created_at=created_at,
        model_type=SandboxCapabilitySnapshot,
    )


def build_remote_trust_snapshot(
    *, policies: tuple[RemoteMCPTrust, ...], source: str, created_at: datetime
) -> RemoteMCPTrustSnapshot:
    ordered = tuple(sorted(policies, key=lambda item: item.adapter_id))
    return _build_snapshot(
        prefix="remotetrust",
        schema_version="remote-mcp-trust-v1",
        field_name="policies",
        values=ordered,
        source=source,
        created_at=created_at,
        model_type=RemoteMCPTrustSnapshot,
    )


def verify_capability_snapshot(snapshot: object) -> None:
    mapping = {
        SessionSecurityContextSnapshot: ("session-security-context-v1", "contexts"),
        AdapterCapabilitySnapshot: ("adapter-capability-v1", "adapters"),
        SandboxCapabilitySnapshot: ("sandbox-capability-v1", "sandboxes"),
        RemoteMCPTrustSnapshot: ("remote-mcp-trust-v1", "policies"),
    }
    for model_type, (schema, field) in mapping.items():
        if isinstance(snapshot, model_type):
            values = getattr(snapshot, field)
            actual = sha256_digest(
                {
                    "schema_version": schema,
                    field: [value.model_dump(mode="python") for value in values],
                }
            )
            if actual != snapshot.snapshot_digest:
                raise DigestIntegrityError(f"{field} capability snapshot digest mismatch")
            content = {
                "schema_version": schema,
                field: [value.model_dump(mode="python") for value in values],
            }
            identity = {
                **content,
                "source": snapshot.source,
                "created_at": snapshot.created_at,
            }
            if isinstance(snapshot, SessionSecurityContextSnapshot):
                identity["mission_id"] = snapshot.mission_id
            prefix = {
                SessionSecurityContextSnapshot: "sessioncap",
                AdapterCapabilitySnapshot: "adaptercap",
                SandboxCapabilitySnapshot: "sandboxcap",
                RemoteMCPTrustSnapshot: "remotetrust",
            }[model_type]
            if snapshot.snapshot_id != stable_id(prefix, identity):
                raise DigestIntegrityError(f"{field} capability snapshot ID mismatch")
            return
    raise TypeError("unsupported capability snapshot")
