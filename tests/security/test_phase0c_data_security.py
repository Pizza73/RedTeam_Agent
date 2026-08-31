from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from redteam_agent.canonical import CanonicalJsonObject, sha256_digest
from redteam_agent.data_security import (
    ArtifactStore,
    AuditContext,
    AuditReferencePayload,
    EncryptedRawResultQuarantine,
    EncryptedRawResultSinkFactory,
    EncryptedSecureResultIngester,
    InMemoryEncryptionKeyProvider,
    MissionAuditLog,
    MissionAuditRecorder,
    QuarantineStreamBinding,
    SandboxPolicy,
    SandboxRequirement,
    SecretStore,
    SecureIngestor,
    require_sandbox_capabilities,
)
from redteam_agent.errors import (
    ArtifactSecurityError,
    AuditIntegrityError,
    AuditSequenceConflictError,
    DigestIntegrityError,
    EncryptionIntegrityError,
    EncryptionKeyUnavailableError,
    EncryptionNonceReuseError,
    RawResultQuarantineError,
    SandboxCapabilityStaleError,
    SecretAccessError,
    SecureIngestionError,
)
from redteam_agent.models.capabilities import SandboxCapabilities
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.execution import RawArtifactMetadata
from redteam_agent.models.scope import DataAccessOperation, DataResourceType
from redteam_agent.storage import Database

NOW = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)


class _ExactEnvelopeAuthorizer:
    def __init__(self) -> None:
        self._grants: dict[str, tuple[DataAccessGrant, ...]] = {}
        self._ingestion_writes: set[tuple[str, str]] = set()

    def set_grants(self, mission_id: str, grants: tuple[DataAccessGrant, ...]) -> None:
        self._grants[mission_id] = grants

    def allow_ingestion_write(self, mission_id: str, source_execution_id: str) -> None:
        self._ingestion_writes.add((mission_id, source_execution_id))

    def require_access(
        self,
        *,
        mission_id: str,
        resource_type: DataResourceType,
        resource: ResourceBinding,
        operation: DataAccessOperation,
        now: datetime,
    ) -> None:
        del now
        if not any(
            grant.resource_type == resource_type
            and grant.resource == resource
            and operation in grant.operations
            for grant in self._grants.get(mission_id, ())
        ):
            raise SecretAccessError("trusted authorization envelope denied resource access")

    def require_ingestion_write(
        self,
        *,
        mission_id: str,
        source_execution_id: str,
        resource_type: str,
        resource: ResourceBinding,
        now: datetime,
    ) -> None:
        del resource_type, resource, now
        if (mission_id, source_execution_id) not in self._ingestion_writes:
            raise SecretAccessError("trusted ingestion authorization denied resource write")


class _AuditContexts:
    def current_context(self, mission_id: str, *, now: datetime) -> AuditContext:
        del mission_id, now
        return AuditContext(mission_revision=1, authorization_epoch=0)


class _StreamBindings:
    def __init__(self, binding: QuarantineStreamBinding) -> None:
        self.binding = binding

    def resolve(self, execution_id: str) -> QuarantineStreamBinding:
        if execution_id != self.binding.execution_id:
            raise ArtifactSecurityError("unknown execution stream binding")
        return self.binding


def _keys() -> InMemoryEncryptionKeyProvider:
    provider = InMemoryEncryptionKeyProvider()
    for index, domain in enumerate(
        ("raw_result_quarantine", "artifact_store", "secret_store"), start=1
    ):
        provider.register_key(
            domain=domain,
            key_id=f"{domain}-key-v1",
            key_version=1,
            key_separation_tag=f"{domain}-separation-v1",
            material=bytes([index]) * 32,
            created_at=NOW,
        )
    return provider


def _stores(
    root: Path,
) -> tuple[
    EncryptedRawResultQuarantine,
    ArtifactStore,
    SecretStore,
    _ExactEnvelopeAuthorizer,
    MissionAuditLog,
]:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    quarantine = EncryptedRawResultQuarantine(
        root=root / "quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    artifacts = ArtifactStore(
        root=root / "artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    secrets = SecretStore(
        root=root / "secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    return quarantine, artifacts, secrets, authorizer, audit_log


def test_secure_ingestion_exposes_only_redacted_references(tmp_path: Path) -> None:
    quarantine, artifacts, secrets, authorizer, audit_log = _stores(tmp_path)
    with pytest.raises(SecretAccessError):
        artifacts.put(
            mission_id="mission-a",
            content=b"redacted",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-a",
            created_at=NOW,
        )
    authorizer.allow_ingestion_write("mission-a", "execution-a")
    raw_secret = b"correct-horse-battery-staple"
    json_secret = b"quoted-json-private-value"
    camel_secret = b"camel-case-private-value"
    receipt = quarantine.commit(
        mission_id="mission-a",
        mission_revision=1,
        execution_id="execution-a",
        content=(
            b'{"nested":{"api_key":"'
            + json_secret
            + b'"}} user=alice password='
            + raw_secret
            + b' other={"apiKey":"'
            + camel_secret
            + b'"} status=ok'
        ),
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )

    result = SecureIngestor(
        quarantine=quarantine, artifacts=artifacts, secrets=secrets
    ).ingest(receipt, now=NOW)

    assert len(result.redacted_artifacts) == 1
    assert len(result.detected_secrets) == 3
    assert result.redaction_metadata.redaction_count == 3
    assert raw_secret.decode() not in result.model_dump_json()
    assert json_secret.decode() not in result.model_dump_json()
    assert camel_secret.decode() not in result.model_dump_json()
    assert all(raw_secret not in path.read_bytes() for path in tmp_path.rglob("*.json"))
    assert not any((tmp_path / "quarantine").rglob("*.json"))
    assert tuple(event.event_type for event in audit_log.events_for("mission-a")) == (
        "raw_result_quarantine.commit",
        "raw_result_quarantine.resume",
        "secret_reference.create",
        "secret_reference.create",
        "secret_reference.create",
        "artifact.create",
        "raw_result_quarantine.delete",
    )

    artifact = result.redacted_artifacts[0]
    authorizer.set_grants(
        "mission-a",
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=artifact.artifact_id,
                    resource_version="1",
                    resource_digest=artifact.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    visible = artifacts.read(artifact, operation="read", now=NOW)
    assert raw_secret not in visible
    assert json_secret not in visible
    assert camel_secret not in visible
    assert b"password=[REDACTED]" in visible
    assert b'"api_key":"[REDACTED]"' in visible
    assert b'"apiKey":"[REDACTED]"' in visible
    assert audit_log.events_for("mission-a")[-1].event_type == "artifact.read"


def test_secret_resolution_requires_trusted_exact_mission_grant(tmp_path: Path) -> None:
    _, _, secrets, authorizer, audit_log = _stores(tmp_path)
    with pytest.raises(SecretAccessError):
        secrets.create(
            mission_id="mission-a",
            secret_value=b"denied-value",
            credential_type="token",
            associated_principal_ref=None,
            source_execution_id="execution-a",
            created_at=NOW,
        )
    authorizer.allow_ingestion_write("mission-a", "execution-a")
    with pytest.raises(SecretAccessError):
        secrets.create(
            mission_id="mission-b",
            secret_value=b"cross-mission-value",
            credential_type="token",
            associated_principal_ref=None,
            source_execution_id="execution-a",
            created_at=NOW,
        )
    metadata = secrets.create(
        mission_id="mission-a",
        secret_value=b"private-value",
        credential_type="token",
        associated_principal_ref="principal-a",
        source_execution_id="execution-a",
        created_at=NOW,
    )
    repeated_metadata = secrets.create(
        mission_id="mission-a",
        secret_value=b"private-value",
        credential_type="token",
        associated_principal_ref="principal-a",
        source_execution_id="execution-a",
        created_at=NOW + timedelta(seconds=1),
    )
    assert repeated_metadata == metadata
    assert len(
        [
            event
            for event in audit_log.events_for("mission-a")
            if event.event_type == "secret_reference.create"
        ]
    ) == 1
    with pytest.raises(SecretAccessError):
        secrets.resolve(metadata, now=NOW)

    authorizer.set_grants(
        "mission-b",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=sha256_digest(metadata),
                ),
                operations=frozenset({"resolve"}),
            ),
        ),
    )
    with pytest.raises(SecretAccessError):
        secrets.resolve(metadata, now=NOW)

    authorizer.set_grants(
        "mission-a",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=sha256_digest(metadata),
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    with pytest.raises(SecretAccessError):
        secrets.resolve(metadata, now=NOW)

    authorizer.set_grants(
        "mission-a",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=sha256_digest(metadata),
                ),
                operations=frozenset({"resolve"}),
            ),
        ),
    )
    assert secrets.resolve(metadata, now=NOW) == b"private-value"
    assert audit_log.events_for("mission-a")[-1].event_type == "secret_reference.resolve"
    authorizer.set_grants(
        "mission-a",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=sha256_digest(metadata),
                ),
                operations=frozenset({"write"}),
            ),
        ),
    )
    revoked = secrets.revoke(metadata, now=NOW + timedelta(seconds=1))
    assert revoked.verification_state == "revoked"
    stale = metadata.model_copy(update={"verification_state": "detected"})
    with pytest.raises(SecretAccessError):
        secrets.resolve(stale, now=NOW + timedelta(seconds=2))
    assert b"private-value" not in b"".join(
        path.read_bytes() for path in tmp_path.rglob("*.json")
    )


def test_artifact_create_audit_is_reconciled_after_write_crash(tmp_path: Path) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write("mission-audit", "execution-audit")
    audit_log = MissionAuditLog()
    durable_audit = MissionAuditRecorder(
        audit_log=audit_log, contexts=_AuditContexts()
    )

    class FailFirstArtifactCreateAudit:
        def __init__(self) -> None:
            self.failed = False

        def record(self, **kwargs):
            if (
                kwargs["resource_type"] == "artifact"
                and kwargs["operation"] == "create"
                and not self.failed
            ):
                self.failed = True
                raise AuditIntegrityError("simulated crash before artifact audit")
            return durable_audit.record(**kwargs)

    root = tmp_path / "artifact-audit-recovery"
    interrupted = ArtifactStore(
        root=root,
        keys=keys,
        authorizer=authorizer,
        audit=FailFirstArtifactCreateAudit(),
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    with pytest.raises(AuditIntegrityError):
        interrupted.put(
            mission_id="mission-audit",
            content=b"already-durable",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-audit",
            created_at=NOW,
        )

    restarted = ArtifactStore(
        root=root,
        keys=keys,
        authorizer=authorizer,
        audit=durable_audit,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    reference = restarted.put(
        mission_id="mission-audit",
        content=b"already-durable",
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id="execution-audit",
        created_at=NOW + timedelta(seconds=1),
    )
    assert reference.created_at == NOW
    assert tuple(
        event.event_type for event in audit_log.events_for("mission-audit")
    ) == ("artifact.create",)


def test_key_domain_nonce_aad_tamper_and_revocation_fail_closed() -> None:
    keys = _keys()
    aad = {"mission_id": "mission-a", "resource_id": "artifact-a"}
    sealed = keys.seal("artifact_store", b"classified", aad, nonce=b"n" * 24)
    assert keys.open("artifact_store", sealed, aad) == b"classified"

    with pytest.raises(EncryptionNonceReuseError):
        keys.seal("artifact_store", b"other", aad, nonce=b"n" * 24)
    with pytest.raises(EncryptionKeyUnavailableError):
        keys.open("secret_store", sealed, aad)
    with pytest.raises(EncryptionIntegrityError):
        keys.open("artifact_store", sealed, {**aad, "mission_id": "mission-b"})
    tampered = sealed.model_copy(update={"ciphertext": "Y2xhc3NpZmllZA=="})
    with pytest.raises(EncryptionIntegrityError):
        keys.open("artifact_store", tampered, aad)
    with pytest.raises(EncryptionKeyUnavailableError):
        keys.register_key(
            domain="audit_signing",
            key_id="artifact_store-key-v1",
            key_version=1,
            key_separation_tag="audit-separation-v1",
            material=b"z" * 32,
            created_at=NOW,
        )
    keys.set_rotation_state("artifact_store", "artifact_store-key-v1", 1, "revoked")
    with pytest.raises(EncryptionKeyUnavailableError):
        keys.open("artifact_store", sealed, aad)
    with pytest.raises(EncryptionKeyUnavailableError):
        keys.set_rotation_state("artifact_store", "artifact_store-key-v1", 1, "active")
    keys.set_rotation_state("artifact_store", "artifact_store-key-v1", 1, "destroyed")
    with pytest.raises(EncryptionKeyUnavailableError):
        keys.set_rotation_state("artifact_store", "artifact_store-key-v1", 1, "decrypt_only")
    resource = keys.seal_for_resource(
        "secret_store",
        "secret_resource-parent-check",
        b"classified-resource",
        aad,
        created_at=NOW,
    )
    keys.set_rotation_state("secret_store", "secret_store-key-v1", 1, "revoked")
    with pytest.raises(EncryptionKeyUnavailableError):
        keys.open("secret_store", resource, aad)


def test_storage_rejects_traversal_symlink_quota_retention_and_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit = MissionAuditRecorder(audit_log=MissionAuditLog(), contexts=_AuditContexts())
    root = tmp_path / "quarantine"
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=8,
        mission_quota_bytes=10,
    )
    reference = quarantine.commit(
        mission_id="mission-a",
        mission_revision=1,
        execution_id="execution-a",
        content=b"12345678",
        created_at=NOW,
        retention_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ArtifactSecurityError):
        quarantine.commit(
            mission_id="mission-a",
            mission_revision=1,
            execution_id="execution-b",
            content=b"123",
            created_at=NOW,
            retention_until=NOW + timedelta(minutes=5),
        )
    with pytest.raises(ArtifactSecurityError):
        quarantine.commit(
            mission_id="../escape",
            mission_revision=1,
            execution_id="execution-c",
            content=b"x",
            created_at=NOW,
            retention_until=NOW + timedelta(minutes=5),
        )
    (root / "mission-link").symlink_to(tmp_path)
    with pytest.raises(ArtifactSecurityError):
        quarantine.commit(
            mission_id="mission-link",
            mission_revision=1,
            execution_id="execution-d",
            content=b"x",
            created_at=NOW,
            retention_until=NOW + timedelta(minutes=5),
        )
    with pytest.raises(ArtifactSecurityError):
        quarantine.resume(reference, now=NOW + timedelta(minutes=5))

    erase_reference = quarantine.commit(
        mission_id="mission-erase",
        mission_revision=1,
        execution_id="execution-erase",
        content=b"erase-me",
        created_at=NOW,
        retention_until=NOW + timedelta(minutes=5),
    )
    erase_path = next((root / "mission-erase").glob("*.json"))
    filesystem_snapshot = erase_path.read_bytes()
    quarantine.delete(erase_reference, now=NOW)
    erase_path.write_bytes(filesystem_snapshot)
    with pytest.raises(EncryptionKeyUnavailableError):
        quarantine.resume(erase_reference, now=NOW)

    stored_path = next((root / "mission-a").glob("*.json"))
    envelope = json.loads(stored_path.read_text(encoding="utf-8"))
    envelope["plaintext_sha256"] = "sha256:" + ("0" * 64)
    stored_path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises((DigestIntegrityError, EncryptionIntegrityError)):
        quarantine.resume(reference, now=NOW)

    stream_audit_log = MissionAuditLog()
    stream_audit = MissionAuditRecorder(
        audit_log=stream_audit_log, contexts=_AuditContexts()
    )
    stream_quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "stream-quarantine",
        keys=keys,
        audit=stream_audit,
        max_item_bytes=1024,
        mission_quota_bytes=128 * 1024,
    )
    stream_binding = QuarantineStreamBinding(
        mission_id="mission-stream",
        mission_revision=1,
        execution_id="execution-stream",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=64 * 1024,
        resume_mode="from_start",
    )
    stream_bindings = _StreamBindings(stream_binding)
    stream_factory = EncryptedRawResultSinkFactory(
        quarantine=stream_quarantine,
        bindings=stream_bindings,
        clock=lambda: NOW,
    )
    chunks_list = [bytes([index % 251]) * 512 for index in range(64)]
    raw_secret = b"split-secret"
    quoted_prefix = b' {"api_key":"split'
    quoted_suffix = b'-secret"} '
    chunks_list[20] = b"A" * (512 - len(quoted_prefix)) + quoted_prefix
    chunks_list[21] = quoted_suffix + b"B" * (512 - len(quoted_suffix))
    chunks = tuple(chunks_list)
    stream_authorizer = _ExactEnvelopeAuthorizer()
    stream_authorizer.allow_ingestion_write("mission-stream", "execution-stream")
    stream_artifacts = ArtifactStore(
        root=tmp_path / "stream-artifacts",
        keys=keys,
        authorizer=stream_authorizer,
        audit=stream_audit,
        max_item_bytes=64 * 1024,
        mission_quota_bytes=128 * 1024,
    )
    stream_secrets = SecretStore(
        root=tmp_path / "stream-secrets",
        keys=keys,
        authorizer=stream_authorizer,
        audit=stream_audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )

    async def stream_with_restart() -> None:
        first_sink = stream_factory.for_execution("execution-stream")
        for chunk in chunks[:20]:
            await first_sink.write_stdout(chunk)
        recovery = first_sink.recovery_metadata(updated_at=NOW)
        assert recovery.state == "RECOVERY_REQUIRED"
        assert recovery.last_chunk_sequence == 19

        replay_sink = stream_factory.for_execution("execution-stream")
        for chunk in chunks[:20]:
            await replay_sink.write_stdout(chunk)
        stream_bindings.binding = stream_binding.model_copy(
            update={"resume_mode": "from_cursor", "resume_cursor": 19}
        )
        with pytest.raises(RawResultQuarantineError):
            stream_factory.for_execution("execution-stream")
        stream_bindings.binding = stream_binding.model_copy(
            update={"resume_mode": "from_cursor", "resume_cursor": 20}
        )
        restarted_sink = stream_factory.for_execution("execution-stream")
        for chunk in chunks[20:]:
            await restarted_sink.write_stdout(chunk)
        receipt = await restarted_sink.commit()
        assert receipt.stdout_bytes == 64 * 512
        assert receipt.stderr_bytes == 0
        assert receipt.artifact_count == 0
        assert restarted_sink.max_observed_chunk_bytes == 512
        stream_bindings.binding = stream_binding.model_copy(
            update={"resume_mode": "from_cursor", "resume_cursor": 64}
        )
        final_sink = stream_factory.for_execution("execution-stream")
        assert await final_sink.commit() == receipt
        ingestor = SecureIngestor(
            quarantine=stream_quarantine,
            artifacts=stream_artifacts,
            secrets=stream_secrets,
        )
        with pytest.raises(SecureIngestionError):
            await ingestor.ingest_stream(
                final_sink,
                receipt.model_copy(update={"receipt_id": "forged-receipt"}),
                now=NOW,
            )
        with pytest.raises(SecureIngestionError):
            await ingestor.ingest_stream(
                final_sink, receipt, now=NOW, retain_encrypted_raw=True
            )
        encrypted_snapshot_path = next(
            (tmp_path / "stream-quarantine").rglob("streamchunk_*.json")
        )
        encrypted_snapshot = encrypted_snapshot_path.read_bytes()
        summary = await EncryptedSecureResultIngester(
            ingestor=ingestor,
            sinks=stream_factory,
            clock=lambda: NOW,
        ).ingest(receipt)
        assert summary.secure_ingestion_id.startswith("secureingestion_")
        assert len(summary.redacted_artifact_references) == 1
        artifact_id = summary.redacted_artifact_references[0]
        artifact = stream_artifacts._stored_reference(
            mission_id="mission-stream", artifact_id=artifact_id, now=NOW
        )
        assert artifact.classification == "sensitive"
        assert stream_artifacts.max_observed_stream_chunk_bytes <= 4 * 1024
        artifact_envelopes = stream_artifacts._store.envelopes_for("mission-stream")
        artifact_chunks = [
            envelope
            for envelope in artifact_envelopes
            if envelope.binding.to_dict().get("record_type")
            == "artifact_stream_chunk"
        ]
        assert len(artifact_chunks) > 1
        assert all(envelope.plaintext_size <= 4 * 1024 for envelope in artifact_chunks)
        assert all(envelope.plaintext_size < artifact.size_bytes for envelope in artifact_chunks)
        stream_authorizer.set_grants(
            "mission-stream",
            (
                DataAccessGrant(
                    resource_type="artifact",
                    resource=ResourceBinding(
                        resource_id=artifact.artifact_id,
                        resource_version="1",
                        resource_digest=artifact.sha256,
                    ),
                    operations=frozenset({"read"}),
                ),
            ),
        )
        visible = stream_artifacts.read(artifact, operation="read", now=NOW)
        assert raw_secret not in visible
        assert b'"api_key":"[REDACTED]"' in visible
        assert len(
            [
                event
                for event in stream_audit_log.events_for("mission-stream")
                if event.event_type == "secret_reference.create"
            ]
        ) == 1
        assert not any(
            (tmp_path / "stream-quarantine").rglob("streamchunk_*.json")
        )
        recovered_summary = await EncryptedSecureResultIngester(
            ingestor=ingestor,
            sinks=stream_factory,
            clock=lambda: NOW + timedelta(seconds=1),
        ).ingest(receipt)
        assert recovered_summary == summary
        encrypted_snapshot_path.write_bytes(encrypted_snapshot)
        restored_sink = stream_factory.for_execution("execution-stream")
        assert restored_sink._durable_ingestion_result(receipt) is not None
        assert not encrypted_snapshot_path.exists()

    asyncio.run(stream_with_restart())
    assert len(
        [
            event
            for event in stream_audit_log.events_for("mission-stream")
            if event.event_type == "raw_result_quarantine.write_chunk"
        ]
    ) == 64

    artifact_quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "artifact-stream-quarantine",
        keys=keys,
        audit=stream_audit,
        max_item_bytes=1024,
        mission_quota_bytes=8192,
    )
    artifact_binding = QuarantineStreamBinding(
        mission_id="mission-artifact",
        mission_revision=1,
        execution_id="execution-artifact",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=4096,
        resume_mode="from_start",
    )
    artifact_bindings = _StreamBindings(artifact_binding)
    artifact_factory = EncryptedRawResultSinkFactory(
        quarantine=artifact_quarantine,
        bindings=artifact_bindings,
        clock=lambda: NOW,
    )

    async def resume_inside_artifact() -> None:
        metadata = RawArtifactMetadata(
            artifact_sequence=0,
            suggested_name="evidence.bin",
            media_type="application/octet-stream",
            declared_size=11,
        )
        first = artifact_factory.for_execution("execution-artifact")

        async def interrupted_chunks():
            yield b"first-"
            raise RuntimeError("simulated provider stream interruption")

        with pytest.raises(RuntimeError):
            await first.write_artifact(metadata, interrupted_chunks())
        artifact_bindings.binding = artifact_binding.model_copy(
            update={"resume_mode": "from_cursor", "resume_cursor": 1}
        )
        resumed = artifact_factory.for_execution("execution-artifact")

        async def remaining_chunks():
            yield b"part2"

        await resumed.write_artifact(metadata, remaining_chunks())
        artifact_receipt = await resumed.commit()
        assert artifact_receipt.artifact_count == 1
        assert resumed.recovery_metadata(updated_at=NOW).state == "COMMITTED"
        artifact_bindings.binding = artifact_binding.model_copy(
            update={"resume_mode": "from_cursor", "resume_cursor": 2}
        )
        final_artifact_sink = artifact_factory.for_execution("execution-artifact")
        assert await final_artifact_sink.commit() == artifact_receipt

    asyncio.run(resume_inside_artifact())
    artifact_events = stream_audit_log.events_for("mission-artifact")
    assert len(
        [event for event in artifact_events if event.event_type.endswith("write_chunk")]
    ) == 2
    assert len(
        [
            event
            for event in artifact_events
            if event.event_type.endswith("commit_artifact")
        ]
    ) == 1

    audit_crash_log = MissionAuditLog()
    durable_audit = MissionAuditRecorder(
        audit_log=audit_crash_log, contexts=_AuditContexts()
    )

    class FailCommitAudit:
        def __init__(self) -> None:
            self.failed = False

        def record(self, **kwargs):
            if kwargs["operation"] == "commit" and not self.failed:
                self.failed = True
                raise AuditIntegrityError("simulated crash before commit audit")
            return durable_audit.record(**kwargs)

    audit_crash_root = tmp_path / "audit-crash-quarantine"
    audit_crash_quarantine = EncryptedRawResultQuarantine(
        root=audit_crash_root,
        keys=keys,
        audit=FailCommitAudit(),
        max_item_bytes=1024,
        mission_quota_bytes=8192,
    )
    audit_crash_binding = QuarantineStreamBinding(
        mission_id="mission-audit-crash",
        mission_revision=1,
        execution_id="execution-audit-crash",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=4096,
        resume_mode="from_start",
    )
    audit_crash_bindings = _StreamBindings(audit_crash_binding)
    failed_audit_factory = EncryptedRawResultSinkFactory(
        quarantine=audit_crash_quarantine,
        bindings=audit_crash_bindings,
        clock=lambda: NOW,
    )

    async def crash_before_commit_audit() -> None:
        sink = failed_audit_factory.for_execution("execution-audit-crash")
        await sink.write_stdout(b"auditable")
        with pytest.raises(AuditIntegrityError):
            await sink.commit()

    asyncio.run(crash_before_commit_audit())
    recovered_quarantine = EncryptedRawResultQuarantine(
        root=audit_crash_root,
        keys=keys,
        audit=durable_audit,
        max_item_bytes=1024,
        mission_quota_bytes=8192,
    )
    audit_crash_bindings.binding = audit_crash_binding.model_copy(
        update={"resume_mode": "from_cursor", "resume_cursor": 1}
    )
    recovered_factory = EncryptedRawResultSinkFactory(
        quarantine=recovered_quarantine,
        bindings=audit_crash_bindings,
        clock=lambda: NOW,
    )
    recovered_sink = recovered_factory.for_execution("execution-audit-crash")
    recovered_receipt = asyncio.run(recovered_sink.commit())
    assert recovered_receipt.stdout_bytes == len(b"auditable")
    assert len(
        [
            event
            for event in audit_crash_log.events_for("mission-audit-crash")
            if event.event_type.endswith(".commit")
        ]
    ) == 1

    delete_quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "delete-crash-quarantine",
        keys=keys,
        audit=stream_audit,
        max_item_bytes=1024,
        mission_quota_bytes=8192,
    )
    delete_binding = QuarantineStreamBinding(
        mission_id="mission-delete-crash",
        mission_revision=1,
        execution_id="execution-delete-crash",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=4096,
        resume_mode="from_start",
    )
    delete_bindings = _StreamBindings(delete_binding)
    delete_factory = EncryptedRawResultSinkFactory(
        quarantine=delete_quarantine,
        bindings=delete_bindings,
        clock=lambda: NOW,
    )

    async def commit_delete_stream():
        sink = delete_factory.for_execution("execution-delete-crash")
        await sink.write_stdout(b"one")
        await sink.write_stdout(b"two")
        await sink.write_stdout(b"three")
        return sink, await sink.commit()

    delete_sink, delete_receipt = asyncio.run(commit_delete_stream())
    original_erase = delete_sink._store.erase_resource
    erase_calls = 0

    def interrupt_erasure(*, mission_id: str, resource_id: str) -> None:
        nonlocal erase_calls
        original_erase(mission_id=mission_id, resource_id=resource_id)
        erase_calls += 1
        if erase_calls == 1:
            raise ArtifactSecurityError("simulated crash during streamed erasure")

    monkeypatch.setattr(delete_sink._store, "erase_resource", interrupt_erasure)
    stream_authorizer.allow_ingestion_write(
        "mission-delete-crash", "execution-delete-crash"
    )
    delete_ingestor = SecureIngestor(
        quarantine=delete_quarantine,
        artifacts=stream_artifacts,
        secrets=stream_secrets,
    )
    with pytest.raises(SecureIngestionError):
        asyncio.run(
            delete_ingestor.ingest_stream(
                delete_sink,
                delete_receipt,
                now=NOW,
            )
        )
    monkeypatch.setattr(delete_sink._store, "erase_resource", original_erase)
    delete_bindings.binding = delete_binding.model_copy(
        update={"resume_mode": "from_cursor", "resume_cursor": 3}
    )
    recovered_delete_sink = delete_factory.for_execution("execution-delete-crash")
    recovered_delete = recovered_delete_sink._durable_ingestion_result(delete_receipt)
    assert recovered_delete is not None
    assert recovered_delete.ingestion_id.startswith("secureingestion_")
    assert not any(
        (tmp_path / "delete-crash-quarantine").rglob("streamchunk_*.json")
    )
    assert len(
        [
            event
            for event in stream_audit_log.events_for("mission-delete-crash")
            if event.event_type.endswith(".delete")
        ]
    ) == 1
    assert all(
        raw_secret not in path.read_bytes() for path in tmp_path.rglob("*.json")
    )


def test_sqlite_audit_chain_persists_events_and_trusted_head(tmp_path: Path) -> None:
    database_path = tmp_path / "durable-audit.sqlite3"
    with Database(database_path) as database:
        database.connection.execute(
            "INSERT INTO missions(mission_id, payload_json, created_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            ("mission-durable", "{}", NOW.isoformat(), "test"),
        )
        audit = MissionAuditLog(database)
        first = audit.append(
            mission_id="mission-durable",
            mission_revision=1,
            authorization_epoch=0,
            payload=AuditReferencePayload(
                resource_type="artifact",
                resource_id="artifact_" + "d" * 32,
                operation="create",
                operation_id="auditop_" + "1" * 32,
                metadata_digest="sha256:" + "1" * 64,
            ),
            occurred_at=NOW,
        )
        second = audit.append(
            mission_id="mission-durable",
            mission_revision=1,
            authorization_epoch=0,
            payload=AuditReferencePayload(
                resource_type="artifact",
                resource_id="artifact_" + "d" * 32,
                operation="read",
                operation_id="auditop_" + "2" * 32,
                metadata_digest="sha256:" + "1" * 64,
            ),
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert audit.verify("mission-durable") == (first, second)

    with Database(database_path) as database:
        restarted = MissionAuditLog(database)
        assert restarted.verify("mission-durable") == (first, second)
        third = restarted.append(
            mission_id="mission-durable",
            mission_revision=1,
            authorization_epoch=0,
            payload=AuditReferencePayload(
                resource_type="artifact",
                resource_id="artifact_" + "d" * 32,
                operation="export",
                operation_id="auditop_" + "3" * 32,
                metadata_digest="sha256:" + "1" * 64,
            ),
            occurred_at=NOW + timedelta(seconds=2),
        )
        assert third.sequence_number == 3
        assert restarted.verify("mission-durable") == (first, second, third)

    with Database(database_path) as database:
        database.connection.execute(
            "DELETE FROM audit_logs WHERE event_id = ?", (second.event_id,)
        )
        with pytest.raises(AuditIntegrityError):
            MissionAuditLog(database).verify("mission-durable")


def test_audit_chain_and_sandbox_capabilities_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        AuditReferencePayload.model_validate(
            {
                "resource_type": "artifact",
                "resource_id": "artifact_" + "a" * 32,
                "operation": "create",
                "metadata_digest": "sha256:" + "1" * 64,
                "credential": {"value": "must-not-enter-audit"},
            }
        )
    with pytest.raises(ValidationError):
        AuditReferencePayload(
            resource_type="artifact",
            resource_id="raw-secret-value",
            operation="create",
            metadata_digest="sha256:" + "1" * 64,
        )
    audit = MissionAuditLog()
    first = audit.append(
        mission_id="mission-a",
        mission_revision=1,
        authorization_epoch=0,
        payload=AuditReferencePayload(
            resource_type="artifact",
            resource_id="artifact_" + "a" * 32,
            operation="create",
            operation_id="auditop_" + "1" * 32,
            metadata_digest="sha256:" + "1" * 64,
        ),
        occurred_at=NOW,
        expected_sequence_number=1,
    )
    second = audit.append(
        mission_id="mission-a",
        mission_revision=1,
        authorization_epoch=0,
        payload=AuditReferencePayload(
            resource_type="artifact",
            resource_id="artifact_" + "a" * 32,
            operation="read",
            metadata_digest="sha256:" + "1" * 64,
        ),
        occurred_at=NOW + timedelta(seconds=1),
        expected_sequence_number=2,
    )
    repeated_first = audit.append(
        mission_id="mission-a",
        mission_revision=1,
        authorization_epoch=0,
        payload=AuditReferencePayload(
            resource_type="artifact",
            resource_id="artifact_" + "a" * 32,
            operation="create",
            operation_id="auditop_" + "1" * 32,
            metadata_digest="sha256:" + "1" * 64,
        ),
        occurred_at=NOW,
    )
    assert repeated_first == first
    other = audit.append(
        mission_id="mission-b",
        mission_revision=1,
        authorization_epoch=0,
        payload=AuditReferencePayload(
            resource_type="raw_result_quarantine",
            resource_id="quarantine_" + "b" * 32,
            operation="commit",
            metadata_digest="sha256:" + "2" * 64,
        ),
        occurred_at=NOW,
    )
    assert audit.verify("mission-a") == (first, second)
    assert audit.verify("mission-b") == (other,)
    with pytest.raises(AuditSequenceConflictError):
        audit.append(
            mission_id="mission-a",
            mission_revision=1,
            authorization_epoch=0,
            payload=AuditReferencePayload(
                resource_type="artifact",
                resource_id="artifact_" + "a" * 32,
                operation="export",
                metadata_digest="sha256:" + "1" * 64,
            ),
            occurred_at=NOW + timedelta(seconds=2),
            expected_sequence_number=2,
        )
    for corrupted in (
        (),
        (first,),
        (second,),
        (second, first),
        (first, second.model_copy(update={"previous_event_hash": "sha256:" + "0" * 64})),
        (
            first,
            second.model_copy(
                update={"canonical_payload": CanonicalJsonObject({"artifact_id": "changed"})}
            ),
        ),
    ):
        with pytest.raises(AuditIntegrityError):
            audit.verify("mission-a", events=corrupted)

    policy = SandboxPolicy(
        sandbox_id="sandbox-a",
        filesystem_allowlist=(str(tmp_path.resolve()),),
        allowed_egress_targets=(),
        allowed_environment_keys=frozenset({"LANG"}),
        cpu_limit_millis=1000,
        memory_limit_bytes=1024,
        process_limit=1,
    )
    requirement = SandboxRequirement(
        dedicated_os_user=True,
        process_isolation=True,
        container_or_namespace=True,
        filesystem_allowlist_required=True,
        network_egress_control_required=True,
        environment_allowlist_required=True,
        secret_injection_control_required=True,
        cpu_limit_required=True,
        memory_limit_required=True,
        process_limit_required=True,
    )
    incomplete = SandboxCapabilities(
        sandbox_id="sandbox-a",
        runtime_id="runtime-a",
        adapter_id="adapter-a",
        execution_location="local_process",
        dedicated_os_user=True,
        process_isolation=True,
        container_or_namespace=True,
        filesystem_allowlist=True,
        network_egress_control=False,
        environment_allowlist=True,
        secret_injection_control=True,
        cpu_limit=True,
        memory_limit=True,
        process_limit=True,
    )
    with pytest.raises(SandboxCapabilityStaleError):
        require_sandbox_capabilities(
            requirement=requirement,
            policy=policy,
            capabilities=incomplete,
            expected_runtime_id="runtime-a",
            expected_adapter_id="adapter-a",
        )
