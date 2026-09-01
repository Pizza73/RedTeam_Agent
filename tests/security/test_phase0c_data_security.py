from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock
from typing import Literal

import pytest
from pydantic import ValidationError

from redteam_agent.canonical import CanonicalJsonObject, sha256_digest, stable_id
from redteam_agent.data_security import (
    ArtifactReference,
    ArtifactStore,
    AuditContext,
    AuditReferencePayload,
    EncryptedRawResultQuarantine,
    EncryptedRawResultSinkFactory,
    EncryptedSecureResultIngester,
    InMemoryEncryptionKeyProvider,
    KeyedAuditChainAuthenticator,
    KeyedFileAuditHeadStore,
    MissionAuditLog,
    MissionAuditRecorder,
    QuarantineStreamBinding,
    SandboxPolicy,
    SandboxRequirement,
    SecretStore,
    SecureIngestor,
    WrappedFileEncryptionKeyProvider,
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
    RawResultStreamingError,
    SandboxCapabilityStaleError,
    SecretAccessError,
    SecureIngestionError,
)
from redteam_agent.executor import MockExecutionAdapter
from redteam_agent.models.capabilities import SandboxCapabilities
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.execution import RawArtifactMetadata
from redteam_agent.models.scope import DataAccessOperation, DataResourceType
from redteam_agent.seeds import FIXED_TIME
from redteam_agent.storage import Database
from tests.phase0b_helpers import (
    build_execution_harness,
    executor_with_adapter,
    prepare_execution,
)

NOW = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)


class _ExactEnvelopeAuthorizer:
    def __init__(self) -> None:
        self._grants: dict[str, tuple[DataAccessGrant, ...]] = {}
        self._ingestion_writes: set[tuple[str, str]] = set()
        self.ingestion_write_resources: list[tuple[str, ResourceBinding]] = []

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
        del now
        if (mission_id, source_execution_id) not in self._ingestion_writes:
            raise SecretAccessError("trusted ingestion authorization denied resource write")
        self.ingestion_write_resources.append((resource_type, resource))


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


class _GenerationStore:
    def __init__(self) -> None:
        self.generation = 0
        self._lock = Lock()

    def current_generation(self) -> int:
        with self._lock:
            return self.generation

    def compare_and_set_generation(self, *, expected: int, new: int) -> bool:
        with self._lock:
            if self.generation != expected or new != expected + 1:
                return False
            self.generation = new
            return True


class _FaultingGenerationStore(_GenerationStore):
    def __init__(self) -> None:
        super().__init__()
        self.failure: Literal["before", "after"] | None = None

    def compare_and_set_generation(self, *, expected: int, new: int) -> bool:
        if self.failure == "before":
            raise RuntimeError("simulated anchor failure before commit")
        advanced = super().compare_and_set_generation(expected=expected, new=new)
        if self.failure == "after" and advanced:
            raise RuntimeError("simulated anchor failure after commit")
        return advanced


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


def _wrapped_keys(
    state_path: Path,
    *,
    generation_store: _GenerationStore,
    wrapping_key: bytes = b"wrapped-provider-root-key-material",
) -> WrappedFileEncryptionKeyProvider:
    first_creation = generation_store.current_generation() == 0
    provider = WrappedFileEncryptionKeyProvider(
        state_path=state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    if first_creation:
        for index, domain in enumerate(
            (
                "raw_result_quarantine",
                "artifact_store",
                "secret_store",
                "audit_signing",
            ),
            start=1,
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


def _audit_head_store(
    state_path: Path,
    *,
    keys: InMemoryEncryptionKeyProvider,
    generation_store: _GenerationStore,
) -> KeyedFileAuditHeadStore:
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return KeyedFileAuditHeadStore(
        state_path=state_path,
        authenticator=KeyedAuditChainAuthenticator(keys),
        generation_store=generation_store,
    )


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
        mission_quota_bytes=32 * 1024,
    )
    artifacts = ArtifactStore(
        root=root / "artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    secrets = SecretStore(
        root=root / "secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
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


def test_bearer_authorization_is_redacted_before_artifact_publication(
    tmp_path: Path,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    authorizer.allow_ingestion_write("mission-bearer", "execution-bearer")
    bearer_secret = b"eyJhbGciOiJIUzI1NiJ9.fake-signature"
    receipt = quarantine.commit(
        mission_id="mission-bearer",
        mission_revision=1,
        execution_id="execution-bearer",
        content=b"Authorization: Bearer " + bearer_secret + b"\nstatus=ok",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )

    result = SecureIngestor(
        quarantine=quarantine,
        artifacts=artifacts,
        secrets=secrets,
    ).ingest(receipt, now=NOW)

    assert result.redaction_metadata.redaction_count == 1
    assert result.redacted_artifacts[0].classification == "sensitive"
    assert result.detected_secrets[0].credential_type == "bearer"
    assert bearer_secret.decode() not in result.model_dump_json()
    artifact = result.redacted_artifacts[0]
    authorizer.set_grants(
        "mission-bearer",
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
    assert visible == b"Authorization: Bearer [REDACTED]\nstatus=ok"
    assert bearer_secret not in visible


def test_basic_authorization_is_redacted_complete_and_across_stream_chunks(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-basic"
    execution_id = "execution-basic"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "basic-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    factory = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(
            QuarantineStreamBinding(
                mission_id=mission_id,
                mission_revision=1,
                execution_id=execution_id,
                retention_until=NOW + timedelta(hours=1),
                max_result_bytes=4096,
                resume_mode="from_start",
            )
        ),
        clock=lambda: NOW,
    )
    artifacts = ArtifactStore(
        root=tmp_path / "basic-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    secrets = SecretStore(
        root=tmp_path / "basic-secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    complete_secret = b"dXNlcjpwYXNz"
    split_secret = b"YWRtaW46c2VjcmV0"

    async def ingest_basic_stream():
        sink = factory.for_execution(execution_id)
        await sink.write_stdout(
            b"Authorization: Basic "
            + complete_secret
            + b"\nAuthorization: Ba"
        )
        await sink.write_stdout(b"sic " + split_secret + b"\nstatus=ok")
        receipt = await sink.commit()
        return await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest_stream(sink, receipt, now=NOW)

    result = asyncio.run(ingest_basic_stream())
    assert result.redaction_metadata.redaction_count == 2
    assert {item.credential_type for item in result.detected_secrets} == {"basic"}
    artifact = result.redacted_artifacts[0]
    authorizer.set_grants(
        mission_id,
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
    assert visible == (
        b"Authorization: Basic [REDACTED]\n"
        b"Authorization: Basic [REDACTED]\nstatus=ok"
    )
    for value in (complete_secret, split_secret):
        assert value not in visible
        assert value.decode() not in result.model_dump_json()


def test_unsupported_authorization_schemes_are_redacted_complete_and_split(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "unsupported-auth-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    artifacts = ArtifactStore(
        root=tmp_path / "unsupported-auth-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    secrets = SecretStore(
        root=tmp_path / "unsupported-auth-secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )

    async def ingest(
        case: str,
        chunks: tuple[bytes, ...],
        secret: bytes,
        *,
        credential_type: str | None = None,
    ) -> None:
        mission_id = f"mission-unsupported-{case}"
        execution_id = f"execution-unsupported-{case}"
        authorizer.allow_ingestion_write(mission_id, execution_id)
        sink = EncryptedRawResultSinkFactory(
            quarantine=quarantine,
            bindings=_StreamBindings(
                QuarantineStreamBinding(
                    mission_id=mission_id,
                    mission_revision=1,
                    execution_id=execution_id,
                    retention_until=NOW + timedelta(hours=1),
                    max_result_bytes=4096,
                    resume_mode="from_start",
                )
            ),
            clock=lambda: NOW,
        ).for_execution(execution_id)
        for chunk in chunks:
            await sink.write_stdout(chunk)
        receipt = await sink.commit()
        result = await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest_stream(sink, receipt, now=NOW)
        assert result.redaction_metadata.redaction_count == 1
        assert result.detected_secrets[0].credential_type == (
            credential_type or case
        )
        assert secret.decode() not in result.model_dump_json()
        artifact = result.redacted_artifacts[0]
        authorizer.set_grants(
            mission_id,
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
        assert secret not in visible
        assert b"[REDACTED]" in visible

    asyncio.run(
        ingest(
            "apikey",
            (b"Authorization: ApiKey abc123",),
            b"abc123",
        )
    )
    asyncio.run(
        ingest(
            "digest",
            (
                b'host=example\n"Authorization":"Di',
                b'gest username=admin, response=response-value"',
            ),
            b"username=admin, response=response-value",
        )
    )
    asyncio.run(
        ingest(
            "escaped-bearer",
            (b'{"authoriz\\u0061tion":"Bearer complete-escaped-secret"}',),
            b"complete-escaped-secret",
            credential_type="bearer",
        )
    )
    asyncio.run(
        ingest(
            "escaped-basic-split",
            (
                b'{"authoriz\\u00',
                b'61tion":"Basic split-escaped-secret"}',
            ),
            b"split-escaped-secret",
            credential_type="basic",
        )
    )


def test_private_key_field_is_redacted_before_artifact_publication(
    tmp_path: Path,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    authorizer.allow_ingestion_write("mission-private-key", "execution-private-key")
    private_key = b"-----BEGIN PRIVATE KEY-----private-material"
    receipt = quarantine.commit(
        mission_id="mission-private-key",
        mission_revision=1,
        execution_id="execution-private-key",
        content=b'{"private_key":"' + private_key + b'"}',
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )

    result = SecureIngestor(
        quarantine=quarantine,
        artifacts=artifacts,
        secrets=secrets,
    ).ingest(receipt, now=NOW)

    assert result.redaction_metadata.redaction_count == 1
    assert result.detected_secrets[0].credential_type == "private_key"
    artifact = result.redacted_artifacts[0]
    authorizer.set_grants(
        "mission-private-key",
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
    assert visible == b'{"private_key":"[REDACTED]"}'
    assert private_key not in visible
    assert private_key.decode() not in result.model_dump_json()


def test_standalone_private_key_blocks_are_redacted_complete_and_split(
    tmp_path: Path,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    complete_block = (
        b"-----BEGIN PRIVATE KEY-----\ncomplete-material\n"
        b"-----END PRIVATE KEY-----"
    )
    authorizer.allow_ingestion_write("mission-pem", "execution-pem-complete")
    reference = quarantine.commit(
        mission_id="mission-pem",
        mission_revision=1,
        execution_id="execution-pem-complete",
        content=complete_block,
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    complete = SecureIngestor(
        quarantine=quarantine,
        artifacts=artifacts,
        secrets=secrets,
    ).ingest(reference, now=NOW)
    assert complete.redaction_metadata.redaction_count == 1
    assert complete.detected_secrets[0].credential_type == "private_key"
    assert complete_block.decode() not in complete.model_dump_json()

    split_block = (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nsplit-material\n"
        b"-----END OPENSSH PRIVATE KEY-----"
    )
    mission_id = "mission-pem-split"
    execution_id = "execution-pem-split"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    sink = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(
            QuarantineStreamBinding(
                mission_id=mission_id,
                mission_revision=1,
                execution_id=execution_id,
                retention_until=NOW + timedelta(hours=1),
                max_result_bytes=4096,
                resume_mode="from_start",
            )
        ),
        clock=lambda: NOW,
    ).for_execution(execution_id)

    async def ingest_split_key():
        await sink.write_stdout(b"-----BEGIN OPENSSH PRI")
        await sink.write_stdout(
            b"VATE KEY-----\nsplit-material\n-----END OPENSSH PRIVATE"
        )
        await sink.write_stdout(b" KEY-----")
        receipt = await sink.commit()
        return await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest_stream(sink, receipt, now=NOW)

    split = asyncio.run(ingest_split_key())
    assert split.redaction_metadata.redaction_count == 1
    assert split.detected_secrets[0].credential_type == "private_key"
    assert split_block.decode() not in split.model_dump_json()
    for result, block in ((complete, complete_block), (split, split_block)):
        artifact = result.redacted_artifacts[0]
        authorizer.set_grants(
            artifact.mission_id,
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
        assert visible == b"[REDACTED]"
        assert block not in visible


@pytest.mark.parametrize(
    ("case", "chunks", "private_key_block"),
    (
        (
            "encrypted",
            (
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----\ncomplete-material\n"
                b"-----END ENCRYPTED PRIVATE KEY-----",
            ),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\ncomplete-material\n"
            b"-----END ENCRYPTED PRIVATE KEY-----",
        ),
        (
            "dsa-split",
            (
                b"-----BEGIN DSA PRI",
                b"VATE KEY-----\nsplit-material\n-----END DSA PRIVATE",
                b" KEY-----",
            ),
            b"-----BEGIN DSA PRIVATE KEY-----\nsplit-material\n"
            b"-----END DSA PRIVATE KEY-----",
        ),
    ),
)
def test_additional_private_key_pem_labels_are_redacted_complete_and_split(
    tmp_path: Path,
    case: str,
    chunks: tuple[bytes, ...],
    private_key_block: bytes,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    mission_id = f"mission-pem-{case}"
    execution_id = f"execution-pem-{case}"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    sink = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(
            QuarantineStreamBinding(
                mission_id=mission_id,
                mission_revision=1,
                execution_id=execution_id,
                retention_until=NOW + timedelta(hours=1),
                max_result_bytes=1024,
                resume_mode="from_start",
            )
        ),
        clock=lambda: NOW,
    ).for_execution(execution_id)

    async def ingest_private_key():
        for chunk in chunks:
            await sink.write_stdout(chunk)
        receipt = await sink.commit()
        return await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest_stream(sink, receipt, now=NOW)

    result = asyncio.run(ingest_private_key())
    assert result.redaction_metadata.redaction_count == 1
    assert result.detected_secrets[0].credential_type == "private_key"
    assert private_key_block.decode() not in result.model_dump_json()
    artifact = result.redacted_artifacts[0]
    authorizer.set_grants(
        mission_id,
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
    assert artifacts.read(artifact, operation="read", now=NOW) == b"[REDACTED]"


def test_encrypted_raw_artifact_cannot_be_used_as_context_read(
    tmp_path: Path,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    authorizer.allow_ingestion_write("mission-raw", "execution-raw")
    raw = b"raw-result-that-must-not-enter-context"
    receipt = quarantine.commit(
        mission_id="mission-raw",
        mission_revision=1,
        execution_id="execution-raw",
        content=raw,
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    result = SecureIngestor(
        quarantine=quarantine,
        artifacts=artifacts,
        secrets=secrets,
    ).ingest(receipt, now=NOW, retain_encrypted_raw=True)
    encrypted_raw = result.encrypted_raw_artifacts[0]
    grant_resource = ResourceBinding(
        resource_id=encrypted_raw.artifact_id,
        resource_version="1",
        resource_digest=encrypted_raw.sha256,
    )
    authorizer.set_grants(
        "mission-raw",
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=grant_resource,
                operations=frozenset({"read"}),
            ),
        ),
    )

    with pytest.raises(SecretAccessError, match="context reads"):
        artifacts.read(encrypted_raw, operation="read", now=NOW)

    authorizer.set_grants(
        "mission-raw",
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=grant_resource,
                operations=frozenset({"export"}),
            ),
        ),
    )
    assert artifacts.read(encrypted_raw, operation="export", now=NOW) == raw


def test_secure_ingestion_replacement_exception_drops_secret_bearing_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    authorizer.allow_ingestion_write("mission-traceback", "execution-traceback")
    raw = b"traceback-private-result"
    receipt = quarantine.commit(
        mission_id="mission-traceback",
        mission_revision=1,
        execution_id="execution-traceback",
        content=raw,
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )

    def fail_artifact_write(**kwargs) -> None:
        del kwargs
        raise ArtifactSecurityError("simulated publication failure")

    monkeypatch.setattr(artifacts, "put", fail_artifact_write)
    with pytest.raises(SecureIngestionError) as caught:
        SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest(receipt, now=NOW)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    traceback = caught.value.__traceback__
    checked_ingestion_frame = False
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith("data_security/ingestion.py"):
            checked_ingestion_frame = True
            assert "raw" not in traceback.tb_frame.f_locals
            assert raw not in traceback.tb_frame.f_locals.values()
        traceback = traceback.tb_next
    assert checked_ingestion_frame


def test_release_audit_failures_drop_decrypted_traceback_locals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, artifacts, secrets, authorizer, _ = _stores(tmp_path)
    mission_id = "mission-release-audit"
    execution_id = "execution-release-audit"
    secret_value = b"resolved-secret-must-not-enter-traceback"
    raw_value = b"exported-raw-must-not-enter-traceback"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    secret = secrets.create(
        mission_id=mission_id,
        secret_value=secret_value,
        credential_type="token",
        associated_principal_ref=None,
        source_execution_id=execution_id,
        created_at=NOW,
    )
    encrypted_raw = artifacts.put(
        mission_id=mission_id,
        content=raw_value,
        media_type="application/octet-stream",
        classification="secret",
        variant="encrypted_raw",
        source_execution_id=execution_id,
        created_at=NOW,
    )
    authorizer.set_grants(
        mission_id,
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=secret.secret_reference_id,
                    resource_version="1",
                    resource_digest=sha256_digest(secret),
                ),
                operations=frozenset({"resolve"}),
            ),
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=encrypted_raw.artifact_id,
                    resource_version="1",
                    resource_digest=encrypted_raw.sha256,
                ),
                operations=frozenset({"export"}),
            ),
        ),
    )

    durable_audit = artifacts._audit

    class FailReleaseAudit:
        def record(self, **kwargs):
            if kwargs["operation"] in {"resolve", "export"}:
                raise AuditIntegrityError("simulated release audit failure")
            return durable_audit.record(**kwargs)

    failing_audit = FailReleaseAudit()
    monkeypatch.setattr(secrets, "_audit", failing_audit)
    monkeypatch.setattr(artifacts, "_audit", failing_audit)

    with pytest.raises(SecretAccessError) as secret_error:
        secrets.resolve(secret, now=NOW)
    with pytest.raises(ArtifactSecurityError) as artifact_error:
        artifacts.read(encrypted_raw, operation="export", now=NOW)

    def assert_sanitized(
        error: Exception,
        *,
        prohibited_name: str,
        prohibited_value: bytes,
    ) -> None:
        assert error.__cause__ is None
        assert error.__context__ is None
        traceback = error.__traceback__
        checked_store_frame = False
        while traceback is not None:
            if traceback.tb_frame.f_code.co_filename.endswith("data_security/stores.py"):
                checked_store_frame = True
                assert prohibited_name not in traceback.tb_frame.f_locals
                assert prohibited_value not in traceback.tb_frame.f_locals.values()
            traceback = traceback.tb_next
        assert checked_store_frame

    assert_sanitized(
        secret_error.value,
        prohibited_name="value",
        prohibited_value=secret_value,
    )
    assert_sanitized(
        artifact_error.value,
        prohibited_name="content",
        prohibited_value=raw_value,
    )


def test_oauth_fields_are_redacted_across_stream_chunks(tmp_path: Path) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write("mission-oauth", "execution-oauth")
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "oauth-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=8192,
        mission_quota_bytes=64 * 1024,
    )
    binding = QuarantineStreamBinding(
        mission_id="mission-oauth",
        mission_revision=1,
        execution_id="execution-oauth",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=4096,
        resume_mode="from_start",
    )
    factory = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(binding),
        clock=lambda: NOW,
    )
    artifacts = ArtifactStore(
        root=tmp_path / "oauth-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    secrets = SecretStore(
        root=tmp_path / "oauth-secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=32 * 1024,
    )

    async def ingest_oauth_stream():
        sink = factory.for_execution("execution-oauth")
        await sink.write_stdout(b'{"tokenValue":"prefix-value","credential":')
        await sink.write_stdout(b'"complete-value","access_')
        await sink.write_stdout(b'token":"access-value","serviceCred')
        await sink.write_stdout(b'ential":"cross-value","password')
        await sink.write_stdout(b'Hash":"hash-value","client')
        await sink.write_stdout(b'Secret":"client-value","refresh_')
        await sink.write_stdout(
            b'token":"refresh-value","oauthToken":"oauth-value","sshPrivate'
        )
        await sink.write_stdout(
            b'Key":"ssh-value","api\\u005fkey":"escaped-api-value",'
            b'"client\\u00'
        )
        await sink.write_stdout(b'5fsecret":"escaped-client-value"} ')
        await sink.write_stdout(b"passwordHash=unquoted-hash token")
        await sink.write_stdout(b"Value: unquoted-token")
        await sink.write_stdout(
            b" machine complete.example login user password complete-netrc "
        )
        await sink.write_stdout(b"machine split.example login user pass")
        await sink.write_stdout(b"word split-netrc")
        await sink.write_stdout(b" X<password>complete-xml</password> <client")
        await sink.write_stdout(b"Secret>split-xml</clientSec")
        await sink.write_stdout(b"ret>")
        receipt = await sink.commit()
        return await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest_stream(sink, receipt, now=NOW)

    result = asyncio.run(ingest_oauth_stream())
    assert result.redaction_metadata.redaction_count == 17
    assert result.redacted_artifacts[0].classification == "sensitive"
    assert {item.credential_type for item in result.detected_secrets} == {
        "tokenvalue",
        "credential",
        "access_token",
        "servicecredential",
        "passwordhash",
        "clientsecret",
        "refresh_token",
        "oauthtoken",
        "sshprivatekey",
        "api_key",
        "client_secret",
        "password",
    }
    artifact = result.redacted_artifacts[0]
    authorizer.set_grants(
        "mission-oauth",
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
    assert visible == (
        b'{"tokenValue":"[REDACTED]","credential":"[REDACTED]",'
        b'"access_token":"[REDACTED]","serviceCredential":"[REDACTED]",'
        b'"passwordHash":"[REDACTED]","clientSecret":"[REDACTED]",'
        b'"refresh_token":"[REDACTED]","oauthToken":"[REDACTED]",'
        b'"sshPrivateKey":"[REDACTED]","api\\u005fkey":"[REDACTED]",'
        b'"client\\u005fsecret":"[REDACTED]"} '
        b"passwordHash=[REDACTED] tokenValue: [REDACTED]"
        b" machine complete.example login user password [REDACTED] "
        b"machine split.example login user password [REDACTED]"
        b" X<password>[REDACTED]</password> "
        b"<clientSecret>[REDACTED]</clientSecret>"
    )
    for value in (
        b"prefix-value",
        b"complete-value",
        b"access-value",
        b"cross-value",
        b"hash-value",
        b"client-value",
        b"refresh-value",
        b"oauth-value",
        b"ssh-value",
        b"escaped-api-value",
        b"escaped-client-value",
        b"unquoted-hash",
        b"unquoted-token",
        b"complete-netrc",
        b"split-netrc",
        b"complete-xml",
        b"split-xml",
    ):
        assert value not in visible
        assert value.decode() not in result.model_dump_json()


@pytest.mark.parametrize(
    ("channel", "failure_mode"),
    (
        ("stdout", "storage"),
        ("stderr", "encryption"),
        ("artifact", "audit"),
    ),
)
def test_raw_chunk_failures_leave_no_secret_in_streaming_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
    failure_mode: str,
) -> None:
    mission_id = f"mission-stream-failure-{failure_mode}"
    execution_id = f"execution-stream-failure-{failure_mode}"
    keys = _keys()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / f"{failure_mode}-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    sink = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(
            QuarantineStreamBinding(
                mission_id=mission_id,
                mission_revision=1,
                execution_id=execution_id,
                retention_until=NOW + timedelta(hours=1),
                max_result_bytes=4096,
                resume_mode="from_start",
            )
        ),
        clock=lambda: NOW,
    ).for_execution(execution_id)

    if failure_mode == "storage":

        def fail_storage(**kwargs) -> None:
            del kwargs
            raise ArtifactSecurityError("simulated storage failure")

        monkeypatch.setattr(sink._store, "write", fail_storage)
    elif failure_mode == "encryption":

        def fail_encryption(*args, **kwargs) -> None:
            del args, kwargs
            raise EncryptionKeyUnavailableError("simulated encryption failure")

        monkeypatch.setattr(
            sink._store._keys,
            "seal_for_resource",
            fail_encryption,
        )
    else:

        def fail_audit(**kwargs) -> None:
            del kwargs
            raise AuditIntegrityError("simulated audit failure")

        monkeypatch.setattr(sink._audit, "record", fail_audit)

    raw_chunk = b"raw-provider-secret-must-not-enter-traceback"

    async def write_failing_chunk() -> None:
        if channel == "stdout":
            await sink.write_stdout(raw_chunk)
        elif channel == "stderr":
            await sink.write_stderr(raw_chunk)
        else:

            async def chunks():
                yield raw_chunk

            await sink.write_artifact(
                RawArtifactMetadata(
                    artifact_sequence=0,
                    suggested_name="result.bin",
                    media_type="application/octet-stream",
                    declared_size=len(raw_chunk),
                ),
                chunks(),
            )

    with pytest.raises(RawResultStreamingError) as captured:
        asyncio.run(write_failing_chunk())

    error = captured.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert raw_chunk.decode() not in str(error)
    traceback = error.__traceback__
    checked_streaming_frame = False
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.endswith(
            "data_security/streaming.py"
        ):
            checked_streaming_frame = True
            assert "chunk" not in traceback.tb_frame.f_locals
            assert raw_chunk not in traceback.tb_frame.f_locals.values()
        traceback = traceback.tb_next
    assert checked_streaming_frame


def test_terminal_storage_and_key_failures_are_typed_for_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "terminal-failures",
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=8192,
    )

    def factory(execution_id: str) -> EncryptedRawResultSinkFactory:
        return EncryptedRawResultSinkFactory(
            quarantine=quarantine,
            bindings=_StreamBindings(
                QuarantineStreamBinding(
                    mission_id=f"mission-{execution_id}",
                    mission_revision=1,
                    execution_id=execution_id,
                    retention_until=NOW + timedelta(hours=1),
                    max_result_bytes=1024,
                    resume_mode="from_start",
                )
            ),
            clock=lambda: NOW,
        )

    storage_factory = factory("execution-terminal-storage")
    storage_sink = storage_factory.for_execution("execution-terminal-storage")
    asyncio.run(storage_sink.write_stdout(b"durable-before-terminal"))
    original_write = storage_sink._store.write

    def fail_terminal_write(**kwargs):
        if str(kwargs["resource_id"]).startswith("streamterminal_"):
            raise ArtifactSecurityError("simulated terminal filesystem failure")
        return original_write(**kwargs)

    monkeypatch.setattr(storage_sink._store, "write", fail_terminal_write)
    with pytest.raises(RawResultQuarantineError, match="terminal persistence"):
        asyncio.run(storage_sink.commit())
    assert storage_sink.recovery_metadata(updated_at=NOW).state == "RECOVERY_REQUIRED"
    monkeypatch.setattr(storage_sink._store, "write", original_write)
    assert asyncio.run(storage_sink.commit()).stdout_bytes == len(
        b"durable-before-terminal"
    )

    key_factory = factory("execution-terminal-key")
    key_sink = key_factory.for_execution("execution-terminal-key")
    asyncio.run(key_sink.write_stdout(b"durable-before-key-failure"))
    original_seal = keys.seal_for_resource

    def fail_terminal_key(*args, **kwargs):
        if str(args[3]["resource_id"]).startswith("streamterminal_"):
            raise EncryptionKeyUnavailableError("simulated terminal key failure")
        return original_seal(*args, **kwargs)

    monkeypatch.setattr(keys, "seal_for_resource", fail_terminal_key)
    with pytest.raises(RawResultQuarantineError, match="terminal persistence"):
        asyncio.run(key_sink.commit())
    assert key_sink.recovery_metadata(updated_at=NOW).state == "RECOVERY_REQUIRED"
    monkeypatch.setattr(keys, "seal_for_resource", original_seal)
    assert asyncio.run(key_sink.commit()).stdout_bytes == len(
        b"durable-before-key-failure"
    )


def test_encrypted_store_fsyncs_parent_before_acknowledging_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "durable-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    original_fsync = os.fsync
    directory_sync_attempts = 0

    def fail_mission_directory_sync(descriptor: int) -> None:
        nonlocal directory_sync_attempts
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_sync_attempts += 1
            if directory_sync_attempts == 2:
                raise OSError("simulated parent-directory sync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_mission_directory_sync)
    with pytest.raises(ArtifactSecurityError, match="directory sync"):
        quarantine.commit(
            mission_id="mission-durable",
            mission_revision=1,
            execution_id="execution-durable",
            content=b"encrypted-result",
            created_at=NOW,
            retention_until=NOW + timedelta(hours=1),
        )
    assert directory_sync_attempts == 2
    assert audit_log.events_for("mission-durable") == ()

    reference = quarantine.commit(
        mission_id="mission-durable",
        mission_revision=1,
        execution_id="execution-durable",
        content=b"encrypted-result",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    assert directory_sync_attempts == 7
    assert quarantine.resume(reference, now=NOW) == b"encrypted-result"
    assert tuple(
        event.event_type for event in audit_log.events_for("mission-durable")
    ) == (
        "raw_result_quarantine.commit",
        "raw_result_quarantine.resume",
    )


def test_encrypted_store_write_is_anchored_during_mission_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(
        audit_log=audit_log,
        contexts=_AuditContexts(),
    )
    root = tmp_path / "anchored-quarantine"
    outside = tmp_path / "outside-store"
    outside.mkdir()
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    mission_root = root / "mission-swap"
    detached_mission_root = root / "detached-mission-swap"
    original_link = os.link
    swapped = False

    def swap_before_link(src, dst, **kwargs) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            mission_root.rename(detached_mission_root)
            mission_root.symlink_to(outside, target_is_directory=True)
        original_link(src, dst, **kwargs)

    monkeypatch.setattr(os, "link", swap_before_link)
    with pytest.raises(ArtifactSecurityError, match="directory changed"):
        quarantine.commit(
            mission_id="mission-swap",
            mission_revision=1,
            execution_id="execution-swap",
            content=b"anchored-content",
            created_at=NOW,
            retention_until=NOW + timedelta(hours=1),
        )

    assert swapped
    assert not list(outside.iterdir())
    assert not list(detached_mission_root.glob("*.json"))
    assert audit_log.events_for("mission-swap") == ()

    mission_root.unlink()
    detached_mission_root.rename(mission_root)
    reference = quarantine.commit(
        mission_id="mission-swap",
        mission_revision=1,
        execution_id="execution-swap",
        content=b"anchored-content",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    assert quarantine.resume(reference, now=NOW) == b"anchored-content"


def test_encrypted_erasure_is_anchored_during_mission_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    root = tmp_path / "anchored-erasure"
    outside = tmp_path / "outside-erasure"
    outside.mkdir()
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    reference = quarantine.commit(
        mission_id="mission-erase-swap",
        mission_revision=1,
        execution_id="execution-erase-swap",
        content=b"erase-only-inside",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    envelope = quarantine._store.verified_envelope(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
        now=None,
    )
    resource_name = f"{reference.quarantine_id}.json"
    outside_resource = outside / resource_name
    outside_resource.write_bytes(b"outside-must-survive")
    mission_root = root / reference.mission_id
    detached_mission_root = root / "detached-erase-swap"
    original_open = os.open
    swapped = False

    def swap_after_resource_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if not swapped and path == resource_name and dir_fd is not None:
            swapped = True
            mission_root.rename(detached_mission_root)
            mission_root.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(os, "open", swap_after_resource_open)
    with pytest.raises(ArtifactSecurityError, match="directory changed"):
        quarantine._store.erase_resource(
            mission_id=reference.mission_id,
            resource_id=reference.quarantine_id,
        )
    monkeypatch.setattr(os, "open", original_open)

    assert swapped
    assert outside_resource.read_bytes() == b"outside-must-survive"
    assert not keys.resource_key_destroyed(envelope.payload.metadata)
    assert (detached_mission_root / resource_name).is_file()
    mission_root.unlink()
    detached_mission_root.rename(mission_root)
    quarantine._store.erase_resource(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
    )
    assert keys.resource_key_destroyed(envelope.payload.metadata)
    assert not (mission_root / resource_name).exists()
    assert outside_resource.read_bytes() == b"outside-must-survive"


def test_encrypted_store_fsyncs_store_root_for_first_mission_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "first-mission-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    original_fsync = os.fsync
    directory_sync_attempts = 0

    def fail_first_directory_sync(descriptor: int) -> None:
        nonlocal directory_sync_attempts
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_sync_attempts += 1
            if directory_sync_attempts == 1:
                raise OSError("simulated store-root sync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_directory_sync)
    with pytest.raises(ArtifactSecurityError, match="directory sync"):
        quarantine.commit(
            mission_id="mission-first-write",
            mission_revision=1,
            execution_id="execution-first-write",
            content=b"first-encrypted-result",
            created_at=NOW,
            retention_until=NOW + timedelta(hours=1),
        )
    assert directory_sync_attempts == 1
    assert audit_log.events_for("mission-first-write") == ()
    assert not list(
        (tmp_path / "first-mission-quarantine" / "mission-first-write").glob(
            "*.json"
        )
    )

    reference = quarantine.commit(
        mission_id="mission-first-write",
        mission_revision=1,
        execution_id="execution-first-write",
        content=b"first-encrypted-result",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    assert directory_sync_attempts == 5
    assert quarantine.resume(reference, now=NOW) == b"first-encrypted-result"
    assert tuple(
        event.event_type for event in audit_log.events_for("mission-first-write")
    ) == (
        "raw_result_quarantine.commit",
        "raw_result_quarantine.resume",
    )


def test_encrypted_store_fsyncs_new_nested_root_before_acknowledging_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    nested_root = tmp_path / "new-store-parent" / "nested-quarantine"
    original_fsync = os.fsync
    directory_sync_attempts = 0

    def fail_new_root_entry_sync(descriptor: int) -> None:
        nonlocal directory_sync_attempts
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_sync_attempts += 1
            if directory_sync_attempts == 3:
                raise OSError("simulated new-store-root sync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_new_root_entry_sync)
    with pytest.raises(ArtifactSecurityError, match="directory sync"):
        EncryptedRawResultQuarantine(
            root=nested_root,
            keys=keys,
            audit=audit,
            max_item_bytes=1024,
            mission_quota_bytes=4096,
        )
    assert directory_sync_attempts == 3
    assert nested_root.is_dir()
    assert audit_log.events_for("mission-new-store") == ()

    quarantine = EncryptedRawResultQuarantine(
        root=nested_root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    assert directory_sync_attempts == 4
    reference = quarantine.commit(
        mission_id="mission-new-store",
        mission_revision=1,
        execution_id="execution-new-store",
        content=b"new-store-encrypted-result",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    assert directory_sync_attempts == 8
    assert quarantine.resume(reference, now=NOW) == b"new-store-encrypted-result"
    assert tuple(
        event.event_type for event in audit_log.events_for("mission-new-store")
    ) == (
        "raw_result_quarantine.commit",
        "raw_result_quarantine.resume",
    )


def test_encrypted_store_rejects_intermediate_symlink_in_configured_root(
    tmp_path: Path,
) -> None:
    keys = _keys()
    audit = MissionAuditRecorder(audit_log=MissionAuditLog(), contexts=_AuditContexts())
    trusted_parent = tmp_path / "trusted-parent"
    external_parent = tmp_path / "external-parent"
    trusted_parent.mkdir()
    external_parent.mkdir()
    (trusted_parent / "linked").symlink_to(external_parent, target_is_directory=True)

    with pytest.raises(ArtifactSecurityError, match="ancestry"):
        EncryptedRawResultQuarantine(
            root=trusted_parent / "linked" / "quarantine",
            keys=keys,
            audit=audit,
            max_item_bytes=1024,
            mission_quota_bytes=4096,
        )

    assert not (external_parent / "quarantine").exists()


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


def test_secret_reference_and_public_binding_do_not_expose_guess_verifiers(
    tmp_path: Path,
) -> None:
    _, _, secrets, authorizer, _ = _stores(tmp_path)
    mission_id = "mission-low-entropy"
    execution_id = "execution-low-entropy"
    credential_type = "password"
    secret_value = b"1234"
    authorizer.allow_ingestion_write(mission_id, execution_id)

    metadata = secrets.create(
        mission_id=mission_id,
        secret_value=secret_value,
        credential_type=credential_type,
        associated_principal_ref=None,
        source_execution_id=execution_id,
        created_at=NOW,
    )

    plaintext_digest = "sha256:" + hashlib.sha256(secret_value).hexdigest()
    former_reference_id = stable_id(
        "secret",
        {
            "mission_id": mission_id,
            "source_execution_id": execution_id,
            "credential_type": credential_type,
            "secret_digest": plaintext_digest,
        },
    )
    secret_write = next(
        resource
        for resource_type, resource in authorizer.ingestion_write_resources
        if resource_type == "secret_reference"
    )
    assert metadata.secret_reference_id != former_reference_id
    assert secret_write.resource_digest != plaintext_digest
    assert plaintext_digest.encode("ascii") not in b"".join(
        path.read_bytes() for path in (tmp_path / "secrets").rglob("*.json")
    )


def test_quarantine_verifiers_do_not_expose_low_entropy_plaintext_digests(
    tmp_path: Path,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    root = tmp_path / "keyed-quarantine"
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
    )
    low_entropy = b"0"
    plaintext_digest = "sha256:" + hashlib.sha256(low_entropy).hexdigest()
    reference = quarantine.commit(
        mission_id="mission-keyed",
        mission_revision=1,
        execution_id="execution-keyed",
        content=low_entropy,
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    assert reference.sha256 != plaintext_digest
    assert quarantine.resume(reference, now=NOW) == low_entropy

    binding = QuarantineStreamBinding(
        mission_id="mission-keyed-stream",
        mission_revision=1,
        execution_id="execution-keyed-stream",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=1024,
        resume_mode="from_start",
    )
    bindings = _StreamBindings(binding)
    factory = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=bindings,
        clock=lambda: NOW,
    )

    async def write_and_resume_stream() -> None:
        sink = factory.for_execution("execution-keyed-stream")
        await sink.write_stdout(low_entropy)
        receipt = await sink.commit()
        recovered = factory.for_execution("execution-keyed-stream")
        resumed = b"".join(
            [chunk async for chunk in recovered._iter_committed_chunks(receipt, now=NOW)]
        )
        assert resumed == low_entropy

    asyncio.run(write_and_resume_stream())
    stored = b"".join(path.read_bytes() for path in root.rglob("*.json"))
    assert plaintext_digest.encode("ascii") not in stored
    assert all(
        event.canonical_payload.to_dict()["metadata_digest"] != plaintext_digest
        for mission_id in ("mission-keyed", "mission-keyed-stream")
        for event in audit_log.events_for(mission_id)
    )


def test_quarantine_verifiers_remain_bound_across_domain_key_rotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "rotated-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
    )
    reference = quarantine.commit(
        mission_id="mission-rotation",
        mission_revision=1,
        execution_id="execution-rotation",
        content=b"pre-rotation",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    binding = QuarantineStreamBinding(
        mission_id="mission-stream-rotation",
        mission_revision=1,
        execution_id="execution-stream-rotation",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=1024,
        resume_mode="from_start",
    )
    bindings = _StreamBindings(binding)
    factory = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=bindings,
        clock=lambda: NOW,
    )

    async def write_first_chunk() -> None:
        sink = factory.for_execution("execution-stream-rotation")
        await sink.write_stdout(b"first-version")

    asyncio.run(write_first_chunk())
    keys.set_rotation_state(
        "raw_result_quarantine",
        "raw_result_quarantine-key-v1",
        1,
        "decrypt_only",
    )
    keys.register_key(
        domain="raw_result_quarantine",
        key_id="raw_result_quarantine-key-v2",
        key_version=2,
        key_separation_tag="raw_result_quarantine-separation-v2",
        material=b"\x09" * 32,
        created_at=NOW + timedelta(minutes=1),
    )
    assert quarantine.resume(reference, now=NOW) == b"pre-rotation"
    assert (
        quarantine.commit(
            mission_id="mission-rotation",
            mission_revision=1,
            execution_id="execution-rotation",
            content=b"pre-rotation",
            created_at=NOW,
            retention_until=NOW + timedelta(hours=1),
        )
        == reference
    )

    async def replay_continue_and_resume() -> None:
        replay = factory.for_execution("execution-stream-rotation")
        await replay.write_stdout(b"first-version")
        await replay.write_stdout(b"second-version")
        receipt = await replay.commit()
        recovered = factory.for_execution("execution-stream-rotation")
        resumed = b"".join(
            [chunk async for chunk in recovered._iter_committed_chunks(receipt, now=NOW)]
        )
        assert resumed == b"first-versionsecond-version"

    asyncio.run(replay_continue_and_resume())

    original_seal = keys.seal_for_resource
    rotated_during_write = False

    def rotate_before_seal(*args, **kwargs):
        nonlocal rotated_during_write
        if not rotated_during_write:
            rotated_during_write = True
            keys.set_rotation_state(
                "raw_result_quarantine",
                "raw_result_quarantine-key-v2",
                2,
                "decrypt_only",
            )
            keys.register_key(
                domain="raw_result_quarantine",
                key_id="raw_result_quarantine-key-v3",
                key_version=3,
                key_separation_tag="raw_result_quarantine-separation-v3",
                material=b"\x0a" * 32,
                created_at=NOW + timedelta(minutes=2),
            )
        return original_seal(*args, **kwargs)

    monkeypatch.setattr(keys, "seal_for_resource", rotate_before_seal)
    with pytest.raises(ArtifactSecurityError, match="verifier key changed"):
        quarantine.commit(
            mission_id="mission-rotation-race",
            mission_revision=1,
            execution_id="execution-rotation-race",
            content=b"rotation-race",
            created_at=NOW,
            retention_until=NOW + timedelta(hours=1),
        )
    monkeypatch.setattr(keys, "seal_for_resource", original_seal)
    race_reference = quarantine.commit(
        mission_id="mission-rotation-race",
        mission_revision=1,
        execution_id="execution-rotation-race",
        content=b"rotation-race",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    assert quarantine.resume(race_reference, now=NOW) == b"rotation-race"


def test_aborted_stream_erasure_resumes_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "aborted-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
    )
    binding = QuarantineStreamBinding(
        mission_id="mission-aborted",
        mission_revision=1,
        execution_id="execution-aborted",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=1024,
        resume_mode="from_start",
    )
    factory = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(binding),
        clock=lambda: NOW,
    )
    sink = factory.for_execution("execution-aborted")

    async def write_chunks() -> None:
        await sink.write_stdout(b"first-aborted-secret")

        async def artifact_chunks():
            yield b"second-aborted-secret"

        await sink.write_artifact(
            RawArtifactMetadata(
                artifact_sequence=0,
                suggested_name="aborted.bin",
                media_type="application/octet-stream",
                declared_size=len(b"second-aborted-secret"),
            ),
            artifact_chunks(),
        )

    asyncio.run(write_chunks())
    chunk_metadata = tuple(
        envelope.payload.metadata for _, envelope in sink._chunks
    )
    artifact_metadata = tuple(
        envelope.payload.metadata for _, envelope in sink._artifact_terminals.values()
    )
    original_erase = sink._store.erase_resource
    erased = 0

    def interrupt_after_first_erasure(**kwargs) -> None:
        nonlocal erased
        original_erase(**kwargs)
        erased += 1
        if erased == 1:
            raise ArtifactSecurityError("simulated abort erasure interruption")

    monkeypatch.setattr(sink._store, "erase_resource", interrupt_after_first_erasure)
    with pytest.raises(RawResultQuarantineError, match="terminal persistence"):
        asyncio.run(sink.abort())
    assert sink._terminal_envelope is not None
    terminal_metadata = sink._terminal_envelope.payload.metadata
    monkeypatch.setattr(sink._store, "erase_resource", original_erase)

    recovered = factory.for_execution("execution-aborted")
    assert recovered.recovery_metadata(updated_at=NOW).state == "ABORTED"
    assert not list(
        (tmp_path / "aborted-quarantine").rglob("streamchunk_*.json")
    )
    assert not list(
        (tmp_path / "aborted-quarantine").rglob("streamartifact_*.json")
    )
    assert not list(
        (tmp_path / "aborted-quarantine").rglob("streamterminal_*.json")
    )
    assert not list(
        (tmp_path / "aborted-quarantine").rglob("streamdeletion_*.json")
    )
    assert all(
        keys.resource_key_destroyed(metadata)
        for metadata in (*chunk_metadata, *artifact_metadata, terminal_metadata)
    )
    recovered_again = factory.for_execution("execution-aborted")
    assert recovered_again.recovery_metadata(updated_at=NOW).state == "ABORTED"
    assert not list(
        (tmp_path / "aborted-quarantine").rglob("streamdeletion_*.json")
    )
    event_types = tuple(
        event.event_type for event in audit_log.events_for("mission-aborted")
    )
    assert event_types.count("raw_result_quarantine.abort") == 1
    assert event_types.count("raw_result_quarantine.delete") == 1


def test_wrapped_key_provider_recovers_committed_stream_after_restart(
    tmp_path: Path,
) -> None:
    key_state_directory = tmp_path / "key-state"
    key_state_directory.mkdir(mode=0o700)
    key_state_path = key_state_directory / "provider.json"
    quarantine_root = tmp_path / "persistent-quarantine"
    wrapping_key = b"external-os-keystore-root-key-material"
    generation_store = _GenerationStore()
    first_keys = _wrapped_keys(
        key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    first_audit_log = MissionAuditLog(
        authenticator=KeyedAuditChainAuthenticator(first_keys)
    )
    first_quarantine = EncryptedRawResultQuarantine(
        root=quarantine_root,
        keys=first_keys,
        audit=MissionAuditRecorder(
            audit_log=first_audit_log,
            contexts=_AuditContexts(),
        ),
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
    )
    binding = QuarantineStreamBinding(
        mission_id="mission-persistent-keys",
        mission_revision=1,
        execution_id="execution-persistent-keys",
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=1024,
        resume_mode="from_start",
    )
    first_factory = EncryptedRawResultSinkFactory(
        quarantine=first_quarantine,
        bindings=_StreamBindings(binding),
        clock=lambda: NOW,
    )

    async def commit_before_restart():
        sink = first_factory.for_execution(binding.execution_id)
        await sink.write_stdout(b"restart-safe-secret-result")
        return await sink.commit()

    receipt = asyncio.run(commit_before_restart())
    persisted_slots = tuple(
        path.read_bytes() for path in first_keys._state_paths if path.exists()
    )
    assert len(persisted_slots) == 2
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in first_keys._state_paths
    )
    for index in range(1, 5):
        assert all(
            base64.b64encode(bytes([index]) * 32) not in persisted
            for persisted in persisted_slots
        )

    restarted_keys = _wrapped_keys(
        key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    restarted_quarantine = EncryptedRawResultQuarantine(
        root=quarantine_root,
        keys=restarted_keys,
        audit=MissionAuditRecorder(
            audit_log=MissionAuditLog(
                authenticator=KeyedAuditChainAuthenticator(restarted_keys)
            ),
            contexts=_AuditContexts(),
        ),
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
    )
    restarted_factory = EncryptedRawResultSinkFactory(
        quarantine=restarted_quarantine,
        bindings=_StreamBindings(binding),
        clock=lambda: NOW,
    )

    async def recover_after_restart() -> bytes:
        recovered = restarted_factory.for_execution(binding.execution_id)
        return b"".join(
            [
                chunk
                async for chunk in recovered._iter_committed_chunks(
                    receipt,
                    now=NOW,
                )
            ]
        )

    assert asyncio.run(recover_after_restart()) == b"restart-safe-secret-result"
    with pytest.raises(EncryptionKeyUnavailableError, match="authentication failed"):
        WrappedFileEncryptionKeyProvider(
            state_path=key_state_path,
            wrapping_key=b"different-external-keystore-key-material",
            generation_store=generation_store,
        )

    concurrent_keys = _wrapped_keys(
        key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    aad = {"mission_id": binding.mission_id, "purpose": "concurrency-regression"}
    first_resource = restarted_keys.seal_for_resource(
        "artifact_store",
        "artifact_concurrent_first",
        b"first-concurrent-resource",
        aad,
        created_at=NOW,
    )
    second_resource = concurrent_keys.seal_for_resource(
        "artifact_store",
        "artifact_concurrent_second",
        b"second-concurrent-resource",
        aad,
        created_at=NOW,
    )
    assert (
        restarted_keys.open("artifact_store", second_resource, aad)
        == b"second-concurrent-resource"
    )
    pre_destruction_generation = generation_store.current_generation()
    pre_destruction_state = concurrent_keys._state_path_for_generation(
        pre_destruction_generation
    ).read_bytes()
    concurrent_keys.destroy_resource_key(first_resource.metadata)
    with pytest.raises(EncryptionKeyUnavailableError, match="unavailable"):
        restarted_keys.open("artifact_store", first_resource, aad)

    concurrent_keys._state_path_for_generation(
        generation_store.current_generation()
    ).write_bytes(pre_destruction_state)
    with pytest.raises(EncryptionKeyUnavailableError, match="rollback"):
        WrappedFileEncryptionKeyProvider(
            state_path=key_state_path,
            wrapping_key=wrapping_key,
            generation_store=generation_store,
        )


def test_wrapped_key_state_recovers_both_generation_commit_boundaries(
    tmp_path: Path,
) -> None:
    key_state_directory = tmp_path / "recoverable-key-state"
    key_state_directory.mkdir(mode=0o700)
    key_state_path = key_state_directory / "provider.json"
    wrapping_key = b"recoverable-os-keystore-root-key-material"
    generation_store = _FaultingGenerationStore()
    provider = WrappedFileEncryptionKeyProvider(
        state_path=key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    provider.register_key(
        domain="artifact_store",
        key_id="artifact-key-v1",
        key_version=1,
        key_separation_tag="artifact-separation-v1",
        material=b"A" * 32,
        created_at=NOW,
    )
    assert generation_store.current_generation() == 1

    generation_store.failure = "before"
    with pytest.raises(EncryptionKeyUnavailableError, match="unavailable"):
        provider.register_key(
            domain="secret_store",
            key_id="secret-key-v1",
            key_version=1,
            key_separation_tag="secret-separation-v1",
            material=b"S" * 32,
            created_at=NOW,
        )
    assert generation_store.current_generation() == 1
    generation_store.failure = None
    recovered_before_anchor = WrappedFileEncryptionKeyProvider(
        state_path=key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    assert (
        recovered_before_anchor.get_active_key_metadata("artifact_store").key_id
        == "artifact-key-v1"
    )
    with pytest.raises(EncryptionKeyUnavailableError, match="unavailable"):
        recovered_before_anchor.get_active_key_metadata("secret_store")
    recovered_before_anchor.register_key(
        domain="secret_store",
        key_id="secret-key-v1",
        key_version=1,
        key_separation_tag="secret-separation-v1",
        material=b"S" * 32,
        created_at=NOW,
    )
    assert generation_store.current_generation() == 2

    generation_store.failure = "after"
    with pytest.raises(EncryptionKeyUnavailableError, match="unavailable"):
        recovered_before_anchor.register_key(
            domain="raw_result_quarantine",
            key_id="quarantine-key-v1",
            key_version=1,
            key_separation_tag="quarantine-separation-v1",
            material=b"Q" * 32,
            created_at=NOW,
        )
    assert generation_store.current_generation() == 3
    generation_store.failure = None
    recovered_after_anchor = WrappedFileEncryptionKeyProvider(
        state_path=key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    assert (
        recovered_after_anchor.get_active_key_metadata(
            "raw_result_quarantine"
        ).key_id
        == "quarantine-key-v1"
    )
    assert (
        recovered_after_anchor.get_active_key_metadata("secret_store").key_id
        == "secret-key-v1"
    )


def test_wrapped_key_providers_share_lock_during_parent_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_directory = tmp_path / "swapped-key-state"
    key_directory.mkdir(mode=0o700)
    state_path = key_directory / "provider.json"
    detached_directory = tmp_path / "detached-key-state"
    outside_directory = tmp_path / "outside-key-state"
    outside_directory.mkdir(mode=0o700)
    generation_store = _GenerationStore()
    first_provider = _wrapped_keys(
        state_path,
        generation_store=generation_store,
    )
    second_provider = _wrapped_keys(
        state_path,
        generation_store=generation_store,
    )
    first_write_started = Event()
    release_first_write = Event()
    second_call_started = Event()
    second_write_started = Event()
    original_first_write = first_provider._write_wrapped_state_locked
    original_second_write = second_provider._write_wrapped_state_locked
    original_open = os.open
    swapped = False

    def swap_parent_on_lock_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        path_name = Path(os.fsdecode(os.fspath(path))).name
        if not swapped and path_name == ".provider.json.lock":
            key_directory.rename(detached_directory)
            key_directory.symlink_to(outside_directory, target_is_directory=True)
            try:
                descriptor = original_open(
                    path,
                    flags,
                    mode,
                    dir_fd=dir_fd,
                )
            finally:
                key_directory.unlink()
                detached_directory.rename(key_directory)
            swapped = True
            return descriptor
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def pause_first_write(
        state_path: Path,
        content: bytes,
        *,
        directory_descriptor: int,
    ) -> None:
        first_write_started.set()
        if not release_first_write.wait(timeout=5):
            raise AssertionError("timed out waiting to release the first key write")
        original_first_write(
            state_path,
            content,
            directory_descriptor=directory_descriptor,
        )

    def observe_second_write(
        state_path: Path,
        content: bytes,
        *,
        directory_descriptor: int,
    ) -> None:
        second_write_started.set()
        original_second_write(
            state_path,
            content,
            directory_descriptor=directory_descriptor,
        )

    monkeypatch.setattr(os, "open", swap_parent_on_lock_open)
    monkeypatch.setattr(
        first_provider,
        "_write_wrapped_state_locked",
        pause_first_write,
    )
    monkeypatch.setattr(
        second_provider,
        "_write_wrapped_state_locked",
        observe_second_write,
    )
    first_aad = {"purpose": "parent-swap-first"}
    second_aad = {"purpose": "parent-swap-second"}

    def seal_first():
        return first_provider.seal_for_resource(
            "artifact_store",
            "artifact_parent_swap_first",
            b"first-parent-swap-state",
            first_aad,
            created_at=NOW + timedelta(minutes=1),
        )

    def seal_second():
        second_call_started.set()
        return second_provider.seal_for_resource(
            "artifact_store",
            "artifact_parent_swap_second",
            b"second-parent-swap-state",
            second_aad,
            created_at=NOW + timedelta(minutes=2),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(seal_first)
        assert first_write_started.wait(timeout=5)
        second_future = executor.submit(seal_second)
        assert second_call_started.wait(timeout=5)
        try:
            assert not second_write_started.wait(timeout=0.2)
        finally:
            release_first_write.set()
        first_payload = first_future.result(timeout=5)
        second_payload = second_future.result(timeout=5)

    assert swapped
    assert not list(outside_directory.iterdir())
    restarted = _wrapped_keys(
        state_path,
        generation_store=generation_store,
    )
    assert (
        restarted.open("artifact_store", first_payload, first_aad)
        == b"first-parent-swap-state"
    )
    assert (
        restarted.open("artifact_store", second_payload, second_aad)
        == b"second-parent-swap-state"
    )


def test_wrapped_key_generation_requires_post_commit_state_reachability(
    tmp_path: Path,
) -> None:
    key_directory = tmp_path / "post-commit-key-state"
    key_directory.mkdir(mode=0o700)
    detached_directory = tmp_path / "detached-post-commit-key-state"
    state_path = key_directory / "provider.json"

    class SwappingGenerationStore(_GenerationStore):
        def __init__(self) -> None:
            super().__init__()
            self.swap_on_next_commit = False

        def compare_and_set_generation(self, *, expected: int, new: int) -> bool:
            advanced = super().compare_and_set_generation(
                expected=expected,
                new=new,
            )
            if self.swap_on_next_commit and advanced:
                self.swap_on_next_commit = False
                key_directory.rename(detached_directory)
                key_directory.mkdir(mode=0o700)
            return advanced

    generation_store = SwappingGenerationStore()
    provider = _wrapped_keys(
        state_path,
        generation_store=generation_store,
    )
    provider.set_rotation_state(
        "audit_signing",
        "audit_signing-key-v1",
        1,
        "decrypt_only",
    )
    generation_before_swap = generation_store.current_generation()
    generation_store.swap_on_next_commit = True
    with pytest.raises(EncryptionKeyUnavailableError, match="directory identity"):
        provider.register_key(
            domain="audit_signing",
            key_id="audit_signing-key-v2",
            key_version=2,
            key_separation_tag="audit_signing-separation-v2",
            material=b"N" * 32,
            created_at=NOW + timedelta(minutes=1),
        )

    assert generation_store.current_generation() == generation_before_swap + 1
    assert not list(key_directory.iterdir())
    key_directory.rmdir()
    detached_directory.rename(key_directory)
    restarted = _wrapped_keys(
        state_path,
        generation_store=generation_store,
    )
    active = restarted.get_active_key_metadata("audit_signing")
    assert (active.key_id, active.key_version) == ("audit_signing-key-v2", 2)


def test_expired_committed_and_abandoned_streams_are_erased_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "expired-streams",
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
    )
    current_time = [NOW]

    def factory_for(execution_id: str) -> EncryptedRawResultSinkFactory:
        return EncryptedRawResultSinkFactory(
            quarantine=quarantine,
            bindings=_StreamBindings(
                QuarantineStreamBinding(
                    mission_id=f"mission-{execution_id}",
                    mission_revision=1,
                    execution_id=execution_id,
                    retention_until=NOW + timedelta(minutes=5),
                    max_result_bytes=1024,
                    resume_mode="from_start",
                )
            ),
            clock=lambda: current_time[0],
        )

    committed_factory = factory_for("execution-expired-committed")
    abandoned_factory = factory_for("execution-expired-abandoned")
    committed = committed_factory.for_execution("execution-expired-committed")
    abandoned = abandoned_factory.for_execution("execution-expired-abandoned")

    async def populate() -> None:
        await committed.write_stdout(b"committed-expired-secret")
        await committed.commit()
        await abandoned.write_stdout(b"abandoned-expired-secret")

    asyncio.run(populate())
    committed_metadata = tuple(
        envelope.payload.metadata for _, envelope in committed._chunks
    )
    assert committed._terminal_envelope is not None
    committed_terminal_metadata = committed._terminal_envelope.payload.metadata
    abandoned_metadata = tuple(
        envelope.payload.metadata for _, envelope in abandoned._chunks
    )
    current_time[0] = NOW + timedelta(minutes=6)
    original_erase = quarantine._store.erase_resource
    erase_count = 0

    def interrupt_first_expiry_erasure(**kwargs) -> None:
        nonlocal erase_count
        original_erase(**kwargs)
        erase_count += 1
        if erase_count == 1:
            raise ArtifactSecurityError("simulated expiry erasure interruption")

    monkeypatch.setattr(
        quarantine._store,
        "erase_resource",
        interrupt_first_expiry_erasure,
    )
    with pytest.raises(RawResultQuarantineError, match="reconstruction"):
        committed_factory.for_execution("execution-expired-committed")
    monkeypatch.setattr(quarantine._store, "erase_resource", original_erase)

    recovered_committed = committed_factory.for_execution(
        "execution-expired-committed"
    )
    recovered_abandoned = abandoned_factory.for_execution(
        "execution-expired-abandoned"
    )
    assert recovered_committed._deleted
    assert recovered_abandoned._deleted
    with pytest.raises(RawResultQuarantineError, match="deleted quarantine"):
        asyncio.run(recovered_committed.commit())
    assert all(
        keys.resource_key_destroyed(metadata)
        for metadata in (
            *committed_metadata,
            committed_terminal_metadata,
            *abandoned_metadata,
        )
    )
    assert not list((tmp_path / "expired-streams").rglob("streamchunk_*.json"))
    assert not list(
        (tmp_path / "expired-streams").rglob("streamterminal_*.json")
    )
    for execution_id in (
        "execution-expired-committed",
        "execution-expired-abandoned",
    ):
        mission_id = f"mission-{execution_id}"
        event_types = tuple(
            event.event_type for event in audit_log.events_for(mission_id)
        )
        assert event_types.count("raw_result_quarantine.delete") == 1
        recovered_again = factory_for(execution_id).for_execution(execution_id)
        assert recovered_again._deleted
    assert not list(
        (tmp_path / "expired-streams").rglob("streamdeletion_*.json")
    )


def test_secret_revocation_reconciles_interrupted_erasure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, secrets, authorizer, _ = _stores(tmp_path)
    authorizer.allow_ingestion_write("mission-revoke", "execution-revoke")
    metadata = secrets.create(
        mission_id="mission-revoke",
        secret_value=b"revocation-recovery-value",
        credential_type="token",
        associated_principal_ref=None,
        source_execution_id="execution-revoke",
        created_at=NOW,
    )
    authorizer.set_grants(
        "mission-revoke",
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
    envelope = secrets._store.verified_envelope(
        mission_id=metadata.mission_id,
        resource_id=metadata.secret_reference_id,
        now=None,
    )
    original_delete = secrets._store.delete

    def interrupt_before_delete(**kwargs) -> None:
        del kwargs
        raise ArtifactSecurityError("simulated crash before secret erasure")

    monkeypatch.setattr(secrets._store, "delete", interrupt_before_delete)
    with pytest.raises(ArtifactSecurityError):
        secrets.revoke(metadata, now=NOW + timedelta(seconds=1))
    assert secrets._store.has_resource(
        mission_id=metadata.mission_id,
        resource_id=metadata.secret_reference_id,
    )

    revoked = metadata.model_copy(update={"verification_state": "revoked"})
    authorizer.set_grants(
        "mission-revoke",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="2",
                    resource_digest=sha256_digest(revoked),
                ),
                operations=frozenset({"write"}),
            ),
        ),
    )
    monkeypatch.setattr(secrets._store, "delete", original_delete)
    assert secrets.revoke(metadata, now=NOW + timedelta(seconds=2)) == revoked
    assert not secrets._store.has_resource(
        mission_id=metadata.mission_id,
        resource_id=metadata.secret_reference_id,
    )
    assert secrets._store._keys.resource_key_destroyed(envelope.payload.metadata)


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
        mission_quota_bytes=1536,
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

    corrupt_reference = quarantine.commit(
        mission_id="mission-corrupt",
        mission_revision=1,
        execution_id="execution-corrupt",
        content=b"corrupt",
        created_at=NOW,
        retention_until=NOW + timedelta(minutes=5),
    )
    stored_path = next((root / "mission-corrupt").glob("*.json"))
    envelope = json.loads(stored_path.read_text(encoding="utf-8"))
    envelope["plaintext_sha256"] = "sha256:" + ("0" * 64)
    stored_path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises((DigestIntegrityError, EncryptionIntegrityError)):
        quarantine.resume(corrupt_reference, now=NOW)

    stream_audit_log = MissionAuditLog()
    stream_audit = MissionAuditRecorder(
        audit_log=stream_audit_log, contexts=_AuditContexts()
    )
    stream_quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "stream-quarantine",
        keys=keys,
        audit=stream_audit,
        max_item_bytes=1024,
        mission_quota_bytes=256 * 1024,
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

        def operation_recorded(self, **kwargs):
            return durable_audit.operation_recorded(**kwargs)

        def operation_metadata_digest(self, **kwargs):
            return durable_audit.operation_metadata_digest(**kwargs)

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
        with pytest.raises(RawResultQuarantineError, match="terminal persistence"):
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
        mission_quota_bytes=16 * 1024,
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


def test_executor_resumes_deleted_ingestion_without_recollecting_raw_chunks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = build_execution_harness()
    prepared = prepare_execution(harness)
    keys = _keys()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    current_time = [FIXED_TIME + timedelta(minutes=3)]
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "executor-crash-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=64 * 1024,
        clock=lambda: current_time[0],
    )
    binding = QuarantineStreamBinding(
        mission_id=prepared.mission_id,
        mission_revision=prepared.mission_revision,
        execution_id=prepared.execution_id,
        retention_until=FIXED_TIME + timedelta(hours=1),
        max_result_bytes=harness.environment.tool.max_output_bytes,
        resume_mode="from_start",
    )
    sink_factory = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(binding),
        clock=lambda: current_time[0],
    )
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write(prepared.mission_id, prepared.execution_id)
    artifacts = ArtifactStore(
        root=tmp_path / "executor-crash-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=64 * 1024,
    )
    secrets = SecretStore(
        root=tmp_path / "executor-crash-secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    adapter = MockExecutionAdapter(
        capabilities=harness.environment.adapter_snapshot.adapters[0],
        now=current_time[0],
        stdout_chunks=(b"password executor-crash-secret",),
    )
    harness.executor = executor_with_adapter(
        harness,
        adapter,
        sink_factory=sink_factory,  # type: ignore[arg-type]
    )
    running = asyncio.run(
        harness.executor.dispatch(
            prepared.execution_id,
            now=current_time[0],
        )
    )
    ingestor = SecureIngestor(
        quarantine=quarantine,
        artifacts=artifacts,
        secrets=secrets,
    )
    current_time[0] = FIXED_TIME + timedelta(minutes=4)

    def crash_before_result_record(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated crash before ExecutionResult persistence")

    with monkeypatch.context() as crash:
        crash.setattr(harness.results, "add", crash_before_result_record)
        with pytest.raises(RuntimeError, match="ExecutionResult persistence"):
            asyncio.run(
                harness.executor.ingest_result(
                    running.execution_id,
                    ingester=EncryptedSecureResultIngester(
                        ingestor=ingestor,
                        sinks=sink_factory,
                        clock=lambda: current_time[0],
                    ),
                    now=current_time[0],
                )
            )

    reconstructed = sink_factory.for_execution(running.execution_id)
    assert reconstructed.committed
    assert reconstructed._deleted
    assert harness.results.get_by_execution(running.execution_id) is None
    assert adapter.collect_calls == 1

    current_time[0] = FIXED_TIME + timedelta(minutes=6)
    original_erase = reconstructed._store.erase_resource
    acknowledgment_id = reconstructed._ingestion_ack_resource_id()
    interrupted_ack = False

    def interrupt_ack_cleanup(*, mission_id: str, resource_id: str) -> None:
        nonlocal interrupted_ack
        acknowledgment_exists = reconstructed._store.has_resource(
            mission_id=mission_id,
            resource_id=acknowledgment_id,
        )
        original_erase(mission_id=mission_id, resource_id=resource_id)
        if acknowledgment_exists and not interrupted_ack:
            interrupted_ack = True
            raise ArtifactSecurityError(
                "simulated crash during persisted-result acknowledgment"
            )

    with monkeypatch.context() as crash:
        crash.setattr(
            reconstructed._store,
            "erase_resource",
            interrupt_ack_cleanup,
        )
        with pytest.raises(ArtifactSecurityError, match="acknowledgment"):
            asyncio.run(
                harness.executor.resume_result_ingestion(
                    running.execution_id,
                    ingester=EncryptedSecureResultIngester(
                        ingestor=ingestor,
                        sinks=sink_factory,
                        clock=lambda: current_time[0],
                    ),
                    now=current_time[0],
                )
            )
    assert interrupted_ack
    assert harness.results.get_by_execution(running.execution_id) is not None
    assert reconstructed._store.has_resource(
        mission_id=prepared.mission_id,
        resource_id=acknowledgment_id,
    )

    current_time[0] = FIXED_TIME + timedelta(minutes=7)
    recovered = asyncio.run(
        harness.executor.resume_result_ingestion(
            running.execution_id,
            ingester=EncryptedSecureResultIngester(
                ingestor=ingestor,
                sinks=sink_factory,
                clock=lambda: current_time[0],
            ),
            now=current_time[0],
        )
    )
    assert recovered.execution_id == running.execution_id
    assert harness.results.get_by_execution(running.execution_id) == recovered
    final_execution = harness.executions.get(running.execution_id)
    final_ingestion = harness.ingestions.get_by_execution(running.execution_id)
    assert final_execution is not None
    assert final_execution.result_ingestion_state == "SUCCEEDED"
    assert final_ingestion is not None and final_ingestion.status == "SUCCEEDED"
    assert adapter.submit_calls == 1
    assert adapter.collect_calls == 2
    quarantine_directory = (
        quarantine._store._root / prepared.mission_id
    )
    assert not list(quarantine_directory.glob("*.json"))

    repeated = asyncio.run(
        harness.executor.resume_result_ingestion(
            running.execution_id,
            ingester=EncryptedSecureResultIngester(
                ingestor=ingestor,
                sinks=sink_factory,
                clock=lambda: current_time[0] + timedelta(seconds=1),
            ),
            now=current_time[0] + timedelta(seconds=1),
        )
    )
    assert repeated == recovered
    assert adapter.collect_calls == 2
    assert not list(quarantine_directory.glob("*.json"))


def test_expired_non_stream_quarantine_is_erased_and_resumed_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(
        audit_log=audit_log,
        contexts=_AuditContexts(),
    )
    root = tmp_path / "expiring-object-quarantine"
    current_time = [NOW]
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: current_time[0],
    )
    retention_until = NOW + timedelta(minutes=5)
    reference = quarantine.commit(
        mission_id="mission-expiring-object",
        mission_revision=1,
        execution_id="execution-expiring-object",
        content=b"expired-object-secret",
        created_at=NOW,
        retention_until=retention_until,
    )
    target_envelope = quarantine._store.verified_envelope(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
        now=None,
    )
    current_time[0] = retention_until
    store_type = type(quarantine._store)
    original_erase = store_type.erase_resource

    def interrupt_after_target_erasure(
        store,
        *,
        mission_id: str,
        resource_id: str,
    ) -> None:
        original_erase(
            store,
            mission_id=mission_id,
            resource_id=resource_id,
        )
        if resource_id == reference.quarantine_id:
            raise ArtifactSecurityError("simulated expiry cleanup interruption")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(
            store_type,
            "erase_resource",
            interrupt_after_target_erasure,
        )
        with pytest.raises(ArtifactSecurityError, match="cleanup interruption"):
            EncryptedRawResultQuarantine(
                root=root,
                keys=keys,
                audit=audit,
                max_item_bytes=1024,
                mission_quota_bytes=4096,
                clock=lambda: current_time[0],
            )

    pending = quarantine._store.envelopes_for(reference.mission_id)
    assert len(pending) == 1
    assert pending[0].resource_id.startswith("quarantineexpiry_")
    intent_metadata = pending[0].payload.metadata
    current_time[0] += timedelta(seconds=1)
    restarted = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: current_time[0],
    )
    assert not restarted._store.resource_ids_with_prefix(
        mission_id=reference.mission_id,
        prefix="quarantine_",
    )
    assert not restarted._store.resource_ids_with_prefix(
        mission_id=reference.mission_id,
        prefix="quarantineexpiry_",
    )
    assert keys.resource_key_destroyed(target_envelope.payload.metadata)
    assert keys.resource_key_destroyed(intent_metadata)
    assert (
        len(
            [
                event
                for event in audit_log.events_for(reference.mission_id)
                if event.event_type == "raw_result_quarantine.delete"
            ]
        )
        == 1
    )
    with pytest.raises(ArtifactSecurityError, match="retention"):
        restarted.resume(reference, now=current_time[0])


def test_expired_quarantine_existence_check_uses_anchored_mission_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "anchored-expiry-quarantine",
        keys=keys,
        audit=MissionAuditRecorder(
            audit_log=audit_log,
            contexts=_AuditContexts(),
        ),
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: NOW,
    )
    retention_until = NOW + timedelta(minutes=5)
    reference = quarantine.commit(
        mission_id="mission-anchored-expiry",
        mission_revision=1,
        execution_id="execution-anchored-expiry",
        content=b"anchored-expiry-secret",
        created_at=NOW,
        retention_until=retention_until,
    )
    target_envelope = quarantine._store.verified_envelope(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
        now=None,
    )
    mission_root = quarantine._store._root / reference.mission_id
    detached_root = quarantine._store._root / "detached-anchored-expiry"
    target_name = f"{reference.quarantine_id}.json"
    original_stat = os.stat
    swapped = False

    def swap_during_existence_stat(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal swapped
        path_name = (
            ""
            if isinstance(path, int)
            else Path(os.fsdecode(os.fspath(path))).name
        )
        if not swapped and path_name == target_name:
            mission_root.rename(detached_root)
            mission_root.mkdir(mode=0o700)
            try:
                metadata = original_stat(
                    path,
                    dir_fd=dir_fd,
                    follow_symlinks=follow_symlinks,
                )
            finally:
                mission_root.rmdir()
                detached_root.rename(mission_root)
                swapped = True
            return metadata
        return original_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(os, "stat", swap_during_existence_stat)
    with pytest.raises(ArtifactSecurityError, match="retention"):
        quarantine.resume(reference, now=retention_until)

    assert swapped
    assert not quarantine._store.has_resource(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
    )
    assert keys.resource_key_destroyed(target_envelope.payload.metadata)
    assert len(
        [
            event
            for event in audit_log.events_for(reference.mission_id)
            if event.event_type == "raw_result_quarantine.delete"
        ]
    ) == 1


def test_quarantine_restart_enumeration_uses_anchored_mission_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(
        audit_log=audit_log,
        contexts=_AuditContexts(),
    )
    current_time = [NOW]
    root = tmp_path / "anchored-recovery-enumeration"
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: current_time[0],
    )
    retention_until = NOW + timedelta(minutes=5)
    reference = quarantine.commit(
        mission_id="mission-anchored-recovery",
        mission_revision=1,
        execution_id="execution-anchored-recovery",
        content=b"restart-enumeration-secret",
        created_at=NOW,
        retention_until=retention_until,
    )
    envelope = quarantine._store.verified_envelope(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
        now=None,
    )
    mission_root = root / reference.mission_id
    detached_root = root / "detached-anchored-recovery"
    mission_metadata = os.stat(mission_root, follow_symlinks=False)
    original_scandir = os.scandir
    swap_count = 0

    def swap_during_recovery_enumeration(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes] = ".",
    ):
        nonlocal swap_count
        if isinstance(path, int):
            metadata = os.fstat(path)
            scans_mission = (
                metadata.st_dev == mission_metadata.st_dev
                and metadata.st_ino == mission_metadata.st_ino
            )
        else:
            scans_mission = Path(os.path.abspath(path)) == mission_root
        if scans_mission and swap_count < 2:
            mission_root.rename(detached_root)
            mission_root.mkdir(mode=0o700)
            try:
                iterator = original_scandir(path)
            finally:
                mission_root.rmdir()
                detached_root.rename(mission_root)
                swap_count += 1
            return iterator
        return original_scandir(path)

    current_time[0] = retention_until
    monkeypatch.setattr(os, "scandir", swap_during_recovery_enumeration)
    restarted = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: current_time[0],
    )

    assert swap_count == 2
    assert not restarted._store.has_resource(
        mission_id=reference.mission_id,
        resource_id=reference.quarantine_id,
    )
    assert keys.resource_key_destroyed(envelope.payload.metadata)


def test_artifact_quota_is_serialized_across_store_instances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write("mission-quota", "execution-first")
    authorizer.allow_ingestion_write("mission-quota", "execution-second")
    audit = MissionAuditRecorder(audit_log=MissionAuditLog(), contexts=_AuditContexts())
    artifact_root = tmp_path / "concurrent-artifacts"
    first_store = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=10,
        mission_quota_bytes=2048,
    )
    second_store = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=10,
        mission_quota_bytes=2048,
    )
    first_atomic_started = Event()
    release_first_write = Event()
    second_call_started = Event()
    second_atomic_started = Event()
    original_first_atomic_write = first_store._store._atomic_write_anchored
    original_second_atomic_write = second_store._store._atomic_write_anchored

    def pause_first_atomic_write(
        *,
        path: Path,
        data: bytes,
        root_descriptor: int,
        mission_descriptor: int,
        mission_metadata: os.stat_result,
    ) -> None:
        first_atomic_started.set()
        if not release_first_write.wait(timeout=5):
            raise AssertionError("timed out waiting to release the first write")
        original_first_atomic_write(
            path=path,
            data=data,
            root_descriptor=root_descriptor,
            mission_descriptor=mission_descriptor,
            mission_metadata=mission_metadata,
        )

    def observe_second_atomic_write(
        *,
        path: Path,
        data: bytes,
        root_descriptor: int,
        mission_descriptor: int,
        mission_metadata: os.stat_result,
    ) -> None:
        second_atomic_started.set()
        original_second_atomic_write(
            path=path,
            data=data,
            root_descriptor=root_descriptor,
            mission_descriptor=mission_descriptor,
            mission_metadata=mission_metadata,
        )

    monkeypatch.setattr(
        first_store._store,
        "_atomic_write_anchored",
        pause_first_atomic_write,
    )
    monkeypatch.setattr(
        second_store._store,
        "_atomic_write_anchored",
        observe_second_atomic_write,
    )

    def put_first():
        return first_store.put(
            mission_id="mission-quota",
            content=b"first!",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-first",
            created_at=NOW,
        )

    def put_second():
        second_call_started.set()
        return second_store.put(
            mission_id="mission-quota",
            content=b"second",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-second",
            created_at=NOW,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(put_first)
        assert first_atomic_started.wait(timeout=5)
        second_future = executor.submit(put_second)
        assert second_call_started.wait(timeout=5)
        try:
            assert not second_atomic_started.wait(timeout=0.2)
        finally:
            release_first_write.set()
        first_reference = first_future.result(timeout=5)
        with pytest.raises(ArtifactSecurityError, match="quota"):
            second_future.result(timeout=5)

    assert not second_atomic_started.is_set()
    assert len(list((artifact_root / "mission-quota").glob("*.json"))) == 1
    authorizer.set_grants(
        "mission-quota",
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=first_reference.artifact_id,
                    resource_version="1",
                    resource_digest=first_reference.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    assert first_store.read(first_reference, operation="read", now=NOW) == b"first!"


def test_artifact_quota_scan_stays_on_anchored_mission_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write("mission-quota-swap", "execution-first")
    authorizer.allow_ingestion_write("mission-quota-swap", "execution-second")
    artifacts = ArtifactStore(
        root=tmp_path / "quota-swap-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=MissionAuditRecorder(
            audit_log=MissionAuditLog(),
            contexts=_AuditContexts(),
        ),
        max_item_bytes=10,
        mission_quota_bytes=2048,
    )
    artifacts.put(
        mission_id="mission-quota-swap",
        content=b"first!",
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id="execution-first",
        created_at=NOW,
    )
    mission_root = artifacts._store._root / "mission-quota-swap"
    detached_root = artifacts._store._root / "detached-mission-quota-swap"
    original_usage = artifacts._store._mission_usage_anchored
    swapped = False

    def swap_during_quota_scan(
        *,
        mission_id: str,
        mission_descriptor: int,
    ) -> int:
        nonlocal swapped
        mission_root.rename(detached_root)
        mission_root.mkdir(mode=0o700)
        try:
            usage = original_usage(
                mission_id=mission_id,
                mission_descriptor=mission_descriptor,
            )
        finally:
            mission_root.rmdir()
            detached_root.rename(mission_root)
        swapped = True
        return usage

    monkeypatch.setattr(
        artifacts._store,
        "_mission_usage_anchored",
        swap_during_quota_scan,
    )
    with pytest.raises(ArtifactSecurityError, match="quota"):
        artifacts.put(
            mission_id="mission-quota-swap",
            content=b"second",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-second",
            created_at=NOW,
        )

    assert swapped
    assert len(list(mission_root.glob("*.json"))) == 1


def test_artifact_quota_lock_stays_on_anchored_store_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-root-lock-quota"
    authorizer.allow_ingestion_write(mission_id, "execution-first")
    authorizer.allow_ingestion_write(mission_id, "execution-second")
    artifact_root = tmp_path / "root-lock-artifacts"
    detached_root = tmp_path / "detached-root-lock-artifacts"
    outside_root = tmp_path / "outside-root-lock-artifacts"
    outside_root.mkdir(mode=0o700)
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    first_store = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=10,
        mission_quota_bytes=2048,
    )
    second_store = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=10,
        mission_quota_bytes=2048,
    )
    original_open = os.open
    original_first_write = first_store._store._atomic_write_anchored
    original_second_write = second_store._store._atomic_write_anchored
    first_write_started = Event()
    release_first_write = Event()
    second_call_started = Event()
    second_write_started = Event()
    swapped = False

    def swap_root_on_lock_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        path_name = Path(os.fsdecode(os.fspath(path))).name
        if not swapped and path_name == ".write-transaction.lock":
            artifact_root.rename(detached_root)
            artifact_root.symlink_to(outside_root, target_is_directory=True)
            try:
                descriptor = original_open(
                    path,
                    flags,
                    mode,
                    dir_fd=dir_fd,
                )
            finally:
                artifact_root.unlink()
                detached_root.rename(artifact_root)
            swapped = True
            return descriptor
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def pause_first_write(**kwargs: object) -> None:
        first_write_started.set()
        if not release_first_write.wait(timeout=5):
            raise AssertionError("timed out waiting to release anchored root write")
        original_first_write(**kwargs)  # type: ignore[arg-type]

    def observe_second_write(**kwargs: object) -> None:
        second_write_started.set()
        original_second_write(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", swap_root_on_lock_open)
    monkeypatch.setattr(
        first_store._store,
        "_atomic_write_anchored",
        pause_first_write,
    )
    monkeypatch.setattr(
        second_store._store,
        "_atomic_write_anchored",
        observe_second_write,
    )

    def put_first():
        return first_store.put(
            mission_id=mission_id,
            content=b"first!",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-first",
            created_at=NOW,
        )

    def put_second():
        second_call_started.set()
        return second_store.put(
            mission_id=mission_id,
            content=b"second",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-second",
            created_at=NOW,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(put_first)
        assert first_write_started.wait(timeout=5)
        second_future = executor.submit(put_second)
        assert second_call_started.wait(timeout=5)
        try:
            assert not second_write_started.wait(timeout=0.2)
        finally:
            release_first_write.set()
        first_future.result(timeout=5)
        with pytest.raises(ArtifactSecurityError, match="quota"):
            second_future.result(timeout=5)

    assert swapped
    assert not second_write_started.is_set()
    assert not list(outside_root.iterdir())
    assert len(list((artifact_root / mission_id).glob("*.json"))) == 1


def test_empty_artifacts_consume_record_quota(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-empty-record-quota"
    execution_ids = tuple(f"execution-empty-{index}" for index in range(4))
    for execution_id in execution_ids:
        authorizer.allow_ingestion_write(mission_id, execution_id)
    artifacts = ArtifactStore(
        root=tmp_path / "empty-record-quota",
        keys=keys,
        authorizer=authorizer,
        audit=MissionAuditRecorder(
            audit_log=MissionAuditLog(),
            contexts=_AuditContexts(),
        ),
        max_item_bytes=10,
        mission_quota_bytes=4096,
    )
    for execution_id in execution_ids[:3]:
        reference = artifacts.put(
            mission_id=mission_id,
            content=b"",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id=execution_id,
            created_at=NOW,
        )
        assert reference.size_bytes == 0
    with pytest.raises(ArtifactSecurityError, match="quota"):
        artifacts.put(
            mission_id=mission_id,
            content=b"",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id=execution_ids[3],
            created_at=NOW,
        )

    assert len(list((artifacts._store._root / mission_id).glob("*.json"))) == 3


def test_identical_streamed_artifacts_keep_cross_execution_provenance(
    tmp_path: Path,
) -> None:
    _, artifacts, _, authorizer, _ = _stores(tmp_path / "artifact-provenance")
    mission_id = "mission-artifact-provenance"
    execution_ids = ("execution-artifact-first", "execution-artifact-second")
    for execution_id in execution_ids:
        authorizer.allow_ingestion_write(mission_id, execution_id)

    async def empty_chunks():
        if False:
            yield b""

    async def persist(execution_id: str) -> ArtifactReference:
        return await artifacts.put_stream(
            mission_id=mission_id,
            chunks=empty_chunks(),
            media_type="text/plain",
            classification=lambda: "normal",
            variant="redacted",
            source_execution_id=execution_id,
            created_at=NOW,
        )

    first = asyncio.run(persist(execution_ids[0]))
    second = asyncio.run(persist(execution_ids[1]))

    assert first.artifact_id != second.artifact_id
    assert first.sha256 == second.sha256
    assert first.size_bytes == second.size_bytes == 0
    authorizer.set_grants(
        mission_id,
        tuple(
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=reference.artifact_id,
                    resource_version="1",
                    resource_digest=reference.sha256,
                ),
                operations=frozenset({"read"}),
            )
            for reference in (first, second)
        ),
    )
    assert artifacts.read(first, operation="read", now=NOW) == b""
    assert artifacts.read(second, operation="read", now=NOW) == b""


@pytest.mark.parametrize("read_mode", ("read", "read_bound"))
def test_artifact_reads_reject_concurrent_mission_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    read_mode: str,
) -> None:
    _, artifacts, _, authorizer, _ = _stores(tmp_path / f"anchored-{read_mode}")
    mission_id = "mission-anchored-read"
    execution_id = "execution-anchored-read"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    reference = artifacts.put(
        mission_id=mission_id,
        content=b"descriptor-anchored-content",
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id=execution_id,
        created_at=NOW,
    )
    authorizer.set_grants(
        mission_id,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=reference.artifact_id,
                    resource_version="1",
                    resource_digest=reference.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    mission_root = artifacts._store._root / mission_id
    retained_root = artifacts._store._root / f"{mission_id}-retained"
    replacement_root = tmp_path / f"outside-{read_mode}"
    replacement_root.mkdir()
    (replacement_root / f"{reference.artifact_id}.json").write_bytes(
        b"x" * (1024 * 1024)
    )
    original_open = os.open
    swapped = False

    def swap_before_resource_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if (
            not swapped
            and path == f"{reference.artifact_id}.json"
            and dir_fd is not None
        ):
            mission_root.rename(retained_root)
            mission_root.symlink_to(replacement_root, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_before_resource_open)
    with pytest.raises(ArtifactSecurityError, match="changed during read"):
        if read_mode == "read":
            artifacts.read(reference, operation="read", now=NOW)
        else:
            artifacts._store.read_bound(
                mission_id=mission_id,
                resource_id=reference.artifact_id,
                now=NOW,
            )
    assert swapped


def test_artifact_expiry_is_audited_and_resumes_cryptographic_erasure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write("mission-expiry", "execution-expiry")
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    artifact_root = tmp_path / "expiry-artifacts"
    artifacts = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=32 * 1024,
    )

    async def artifact_chunks():
        yield b"A" * 4096
        yield b"B" * 17

    retention_until = NOW + timedelta(minutes=5)
    reference = asyncio.run(
        artifacts.put_stream(
            mission_id="mission-expiry",
            chunks=artifact_chunks(),
            media_type="application/octet-stream",
            classification=lambda: "normal",
            variant="redacted",
            source_execution_id="execution-expiry",
            created_at=NOW,
            retention_until=retention_until,
        )
    )
    target_ids = artifacts._deletion_targets(reference)
    target_envelopes = {
        resource_id: artifacts._store.verified_envelope(
            mission_id=reference.mission_id,
            resource_id=resource_id,
            now=None,
        )
        for resource_id in target_ids
    }
    target_snapshots = {
        resource_id: artifacts._store._path(
            reference.mission_id,
            resource_id,
            create_parent=False,
        ).read_bytes()
        for resource_id in target_ids
    }

    intent_path = artifacts._store._path(
        reference.mission_id,
        artifacts._deletion_intent_id(reference.artifact_id),
        create_parent=False,
    )
    intent_path.symlink_to(tmp_path)
    with pytest.raises(ArtifactSecurityError):
        artifacts.expire(reference, now=retention_until)
    intent_path.unlink()

    with pytest.raises(ArtifactSecurityError):
        artifacts.expire(reference, now=retention_until - timedelta(seconds=1))
    with pytest.raises(SecretAccessError):
        artifacts.expire(reference, now=retention_until)
    assert all(
        artifacts._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=resource_id,
        )
        for resource_id in target_ids
    )

    authorizer.set_grants(
        reference.mission_id,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=reference.artifact_id,
                    resource_version="1",
                    resource_digest=reference.sha256,
                ),
                operations=frozenset({"write"}),
            ),
        ),
    )
    original_erase = artifacts._store.erase_resource
    erase_calls = 0

    def interrupt_erasure(*, mission_id: str, resource_id: str) -> None:
        nonlocal erase_calls
        original_erase(mission_id=mission_id, resource_id=resource_id)
        erase_calls += 1
        if erase_calls == 1:
            raise ArtifactSecurityError("simulated artifact erasure interruption")

    monkeypatch.setattr(artifacts._store, "erase_resource", interrupt_erasure)
    with pytest.raises(ArtifactSecurityError):
        artifacts.expire(reference, now=retention_until)

    first_target = target_ids[0]
    first_path = artifacts._store._path(
        reference.mission_id,
        first_target,
        create_parent=False,
    )
    first_path.write_bytes(target_snapshots[first_target])
    with pytest.raises(EncryptionKeyUnavailableError):
        artifacts._store.read_bound(
            mission_id=reference.mission_id,
            resource_id=first_target,
            now=None,
        )

    monkeypatch.setattr(artifacts._store, "erase_resource", original_erase)
    restarted = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=32 * 1024,
    )
    restarted.expire(reference, now=retention_until + timedelta(seconds=1))
    restarted.expire(reference, now=retention_until + timedelta(seconds=2))
    assert all(
        not restarted._store.has_resource(
            mission_id=reference.mission_id,
            resource_id=resource_id,
        )
        for resource_id in target_ids
    )
    assert all(
        restarted._store._keys.resource_key_destroyed(envelope.payload.metadata)
        for envelope in target_envelopes.values()
    )
    assert len(
        [
            event
            for event in audit_log.events_for(reference.mission_id)
            if event.event_type == "artifact.delete"
        ]
    ) == 1


def test_artifact_expiry_sweeps_without_caller_reference_after_restart(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-autonomous-artifact-expiry"
    execution_id = "execution-autonomous-artifact-expiry"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(
        audit_log=audit_log,
        contexts=_AuditContexts(),
    )
    current_time = [NOW]
    artifact_root = tmp_path / "autonomous-artifact-expiry"
    artifacts = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: current_time[0],
    )
    retention_until = NOW + timedelta(minutes=5)
    reference = artifacts.put(
        mission_id=mission_id,
        content=b"autonomously-expired-artifact",
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id=execution_id,
        created_at=NOW,
        retention_until=retention_until,
    )
    envelope = artifacts._store.verified_envelope(
        mission_id=mission_id,
        resource_id=reference.artifact_id,
        now=None,
    )
    current_time[0] = retention_until

    restarted = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
        clock=lambda: current_time[0],
    )

    assert not restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=reference.artifact_id,
    )
    assert keys.resource_key_destroyed(envelope.payload.metadata)
    assert len(
        [
            event
            for event in audit_log.events_for(mission_id)
            if event.event_type == "artifact.create"
        ]
    ) == 1
    assert len(
        [
            event
            for event in audit_log.events_for(mission_id)
            if event.event_type == "artifact.delete"
        ]
    ) == 1


def test_completed_stream_cleanup_reconciles_create_audit_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-stream-audit-recovery"
    execution_id = "execution-stream-audit-recovery"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(
        audit_log=audit_log,
        contexts=_AuditContexts(),
    )
    artifact_root = tmp_path / "stream-audit-recovery"
    artifacts = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=32 * 1024,
    )

    async def chunks():
        yield b"manifest-is-durable-before-create-audit"

    def crash_before_create_audit(reference: ArtifactReference) -> None:
        del reference
        raise SystemExit("simulated process crash before artifact create audit")

    with monkeypatch.context() as crash:
        crash.setattr(
            artifacts,
            "_reconcile_create_audit",
            crash_before_create_audit,
        )
        with pytest.raises(SystemExit, match="simulated process crash"):
            asyncio.run(
                artifacts.put_stream(
                    mission_id=mission_id,
                    chunks=chunks(),
                    media_type="text/plain",
                    classification=lambda: "normal",
                    variant="redacted",
                    source_execution_id=execution_id,
                    created_at=NOW,
                )
            )

    artifact_ids = artifacts._store.resource_ids_with_prefix(
        mission_id=mission_id,
        prefix="artifact_",
    )
    assert len(artifact_ids) == 1
    reference = artifacts._stored_reference(
        mission_id=mission_id,
        artifact_id=artifact_ids[0],
        now=None,
    )
    assert artifacts._store.resource_ids_with_prefix(
        mission_id=mission_id,
        prefix="artifactcleanup_",
    )
    assert not [
        event
        for event in audit_log.events_for(mission_id)
        if event.event_type == "artifact.create"
    ]

    restarted = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=32 * 1024,
    )
    assert not restarted._store.resource_ids_with_prefix(
        mission_id=mission_id,
        prefix="artifactcleanup_",
    )
    assert len(
        [
            event
            for event in audit_log.events_for(mission_id)
            if event.event_type == "artifact.create"
        ]
    ) == 1
    authorizer.set_grants(
        mission_id,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=reference.artifact_id,
                    resource_version="1",
                    resource_digest=reference.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    assert restarted.read(reference, operation="read", now=NOW) == (
        b"manifest-is-durable-before-create-audit"
    )


def test_partial_artifact_stream_cleanup_resumes_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    authorizer.allow_ingestion_write("mission-partial", "execution-partial")
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    artifact_root = tmp_path / "partial-artifacts"
    artifacts = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=32 * 1024,
    )

    async def failing_chunks():
        yield b"A" * 4096
        raise ArtifactSecurityError("simulated redaction failure")

    def interrupt_cleanup(**kwargs) -> None:
        del kwargs
        raise ArtifactSecurityError("simulated cleanup interruption")

    monkeypatch.setattr(artifacts._store, "erase_resource", interrupt_cleanup)
    with pytest.raises(ArtifactSecurityError, match="redaction failure"):
        asyncio.run(
            artifacts.put_stream(
                mission_id="mission-partial",
                chunks=failing_chunks(),
                media_type="application/octet-stream",
                classification=lambda: "normal",
                variant="redacted",
                source_execution_id="execution-partial",
                created_at=NOW,
            )
        )
    pending_envelopes = artifacts._store.envelopes_for("mission-partial")
    pending_metadata = tuple(
        envelope.payload.metadata for envelope in pending_envelopes
    )
    assert any(
        envelope.resource_id.startswith("artifactchunk_")
        for envelope in pending_envelopes
    )
    assert any(
        envelope.resource_id.startswith("artifactcleanup_")
        for envelope in pending_envelopes
    )

    mission_root = artifact_root / "mission-partial"
    detached_root = artifact_root / "detached-mission-partial"
    mission_metadata = os.stat(mission_root, follow_symlinks=False)
    original_scandir = os.scandir
    swapped = False

    def swap_during_cleanup_enumeration(
        path: int | str | bytes | os.PathLike[str] | os.PathLike[bytes] = ".",
    ):
        nonlocal swapped
        if isinstance(path, int):
            metadata = os.fstat(path)
            scans_mission = (
                metadata.st_dev == mission_metadata.st_dev
                and metadata.st_ino == mission_metadata.st_ino
            )
        else:
            scans_mission = Path(os.path.abspath(path)) == mission_root
        if scans_mission and not swapped:
            mission_root.rename(detached_root)
            mission_root.mkdir(mode=0o700)
            try:
                iterator = original_scandir(path)
            finally:
                mission_root.rmdir()
                detached_root.rename(mission_root)
                swapped = True
            return iterator
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", swap_during_cleanup_enumeration)

    ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=32 * 1024,
    )
    assert swapped
    assert not list((artifact_root / "mission-partial").glob("*.json"))
    assert all(keys.resource_key_destroyed(metadata) for metadata in pending_metadata)
    assert audit_log.events_for("mission-partial") == ()


def test_conflicting_artifact_stream_attempts_are_serialized_before_cleanup(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-concurrent-artifact"
    execution_id = "execution-concurrent-artifact"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    artifacts = ArtifactStore(
        root=tmp_path / "concurrent-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=16 * 1024,
        mission_quota_bytes=64 * 1024,
    )

    async def exercise_conflict() -> ArtifactReference:
        first_started = asyncio.Event()
        release_failure = asyncio.Event()

        async def failing_chunks():
            first_started.set()
            yield b"A" * 4096
            await release_failure.wait()
            raise ArtifactSecurityError("simulated concurrent stream failure")

        async def winning_chunks():
            yield b"B" * 4096
            yield b"winning-tail"

        common = {
            "mission_id": mission_id,
            "media_type": "application/octet-stream",
            "classification": lambda: "normal",
            "variant": "redacted",
            "source_execution_id": execution_id,
            "created_at": NOW,
        }
        failing_task = asyncio.create_task(
            artifacts.put_stream(chunks=failing_chunks(), **common)
        )
        await first_started.wait()
        winning_task = asyncio.create_task(
            artifacts.put_stream(chunks=winning_chunks(), **common)
        )
        await asyncio.sleep(0.03)
        assert not winning_task.done()
        release_failure.set()
        with pytest.raises(ArtifactSecurityError, match="concurrent stream failure"):
            await failing_task
        return await winning_task

    winner = asyncio.run(exercise_conflict())

    async def retry_winner() -> ArtifactReference:
        async def chunks():
            yield b"B" * 4096
            yield b"winning-tail"

        return await artifacts.put_stream(
            mission_id=mission_id,
            chunks=chunks(),
            media_type="application/octet-stream",
            classification=lambda: "normal",
            variant="redacted",
            source_execution_id=execution_id,
            created_at=NOW,
        )

    assert asyncio.run(retry_winner()) == winner
    authorizer.set_grants(
        mission_id,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=winner.artifact_id,
                    resource_version="1",
                    resource_digest=winner.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    assert artifacts.read(winner, operation="read", now=NOW) == (
        b"B" * 4096 + b"winning-tail"
    )
    assert not artifacts._store.resource_ids_with_prefix(
        mission_id=mission_id,
        prefix="artifactcleanup_",
    )


def test_sqlite_audit_chain_persists_events_and_trusted_head(tmp_path: Path) -> None:
    database_path = tmp_path / "durable-audit.sqlite3"
    head_state_path = tmp_path / "durable-audit-head" / "heads.json"
    key_state_directory = tmp_path / "audit-keys"
    key_state_directory.mkdir(mode=0o700)
    key_state_path = key_state_directory / "provider.json"
    wrapping_key = b"audit-os-keystore-root-key-material"
    generation_store = _GenerationStore()
    head_generation_store = _GenerationStore()
    first_keys = _wrapped_keys(
        key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    with Database(database_path) as database:
        database.connection.execute(
            "INSERT INTO missions(mission_id, payload_json, created_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            ("mission-durable", "{}", NOW.isoformat(), "test"),
        )
        with pytest.raises(AuditIntegrityError, match="external authenticator"):
            MissionAuditLog(database)
        with pytest.raises(AuditIntegrityError, match="head store"):
            MissionAuditLog(
                database,
                authenticator=KeyedAuditChainAuthenticator(first_keys),
            )
        audit = MissionAuditLog(
            database,
            authenticator=KeyedAuditChainAuthenticator(first_keys),
            head_store=_audit_head_store(
                head_state_path,
                keys=first_keys,
                generation_store=head_generation_store,
            ),
        )
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
        first_keys.set_rotation_state(
            "audit_signing",
            "audit_signing-key-v1",
            1,
            "decrypt_only",
        )
        first_keys.register_key(
            domain="audit_signing",
            key_id="audit_signing-key-v2",
            key_version=2,
            key_separation_tag="audit_signing-separation-v2",
            material=b"\x05" * 32,
            created_at=NOW + timedelta(minutes=1),
        )
        assert audit.verify("mission-durable") == (first, second)

    with Database(database_path) as database:
        restarted_keys = _wrapped_keys(
            key_state_path,
            wrapping_key=wrapping_key,
            generation_store=generation_store,
        )
        restarted = MissionAuditLog(
            database,
            authenticator=KeyedAuditChainAuthenticator(restarted_keys),
            head_store=_audit_head_store(
                head_state_path,
                keys=restarted_keys,
                generation_store=head_generation_store,
            ),
        )
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
        assert third.signing_key_id == "audit_signing-key-v2"
        assert first.signing_key_id == "audit_signing-key-v1"
        assert restarted.verify("mission-durable") == (first, second, third)

    with Database(database_path) as database:
        database.connection.execute(
            "DELETE FROM audit_logs WHERE event_id = ?", (third.event_id,)
        )
        database.connection.execute(
            "UPDATE audit_log_heads SET sequence_number = ?, event_hash = ? "
            "WHERE mission_id = ?",
            (second.sequence_number, second.event_hash, "mission-durable"),
        )
        with pytest.raises(AuditIntegrityError, match="head"):
            truncated_keys = _wrapped_keys(
                key_state_path,
                wrapping_key=wrapping_key,
                generation_store=generation_store,
            )
            MissionAuditLog(
                database,
                authenticator=KeyedAuditChainAuthenticator(truncated_keys),
                head_store=_audit_head_store(
                    head_state_path,
                    keys=truncated_keys,
                    generation_store=head_generation_store,
                ),
            ).verify("mission-durable")


def test_sqlite_audit_recovers_prepared_appends_across_commit_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "recoverable-audit.sqlite3"
    head_state_path = tmp_path / "recoverable-audit-head" / "heads.json"
    key_directory = tmp_path / "recoverable-audit-keys"
    key_directory.mkdir(mode=0o700)
    generation_store = _GenerationStore()
    head_generation_store = _GenerationStore()
    keys = _wrapped_keys(
        key_directory / "provider.json",
        generation_store=generation_store,
    )
    authenticator = KeyedAuditChainAuthenticator(keys)
    mission_id = "mission-recoverable-audit"

    with Database(database_path) as database:
        database.connection.execute(
            "INSERT INTO missions(mission_id, payload_json, created_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            (mission_id, "{}", NOW.isoformat(), "test"),
        )
        head_store = _audit_head_store(
            head_state_path,
            keys=keys,
            generation_store=head_generation_store,
        )
        audit = MissionAuditLog(
            database,
            authenticator=authenticator,
            head_store=head_store,
        )
        first = audit.append(
            mission_id=mission_id,
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
        if audit._repository is None:
            raise AssertionError("durable audit repository was not created")
        original_insert_event = audit._repository.insert_event

        def interrupt_before_database_insert(**kwargs: object) -> None:
            del kwargs
            raise AuditIntegrityError("simulated interruption before database insert")

        monkeypatch.setattr(
            audit._repository,
            "insert_event",
            interrupt_before_database_insert,
        )
        with pytest.raises(AuditIntegrityError, match="simulated interruption"):
            audit.append(
                mission_id=mission_id,
                mission_revision=1,
                authorization_epoch=0,
                payload=AuditReferencePayload(
                    resource_type="artifact",
                    resource_id="artifact_" + "a" * 32,
                    operation="read",
                    operation_id="auditop_" + "2" * 32,
                    metadata_digest="sha256:" + "2" * 64,
                ),
                occurred_at=NOW + timedelta(seconds=1),
            )
        prepared_second = head_store.prepared_append(mission_id)
        assert prepared_second is not None
        assert audit.events_for(mission_id) == (first,)
        monkeypatch.setattr(
            audit._repository,
            "insert_event",
            original_insert_event,
        )

        restarted_head_store = _audit_head_store(
            head_state_path,
            keys=keys,
            generation_store=head_generation_store,
        )
        restarted = MissionAuditLog(
            database,
            authenticator=authenticator,
            head_store=restarted_head_store,
        )
        assert restarted.verify(mission_id) == (first, prepared_second)
        assert restarted_head_store.prepared_append(mission_id) is None
        original_commit_append = restarted_head_store.commit_append

        def interrupt_after_database_commit(
            requested_mission_id: str,
            *,
            event: object,
        ) -> bool:
            del requested_mission_id, event
            raise AuditIntegrityError("simulated interruption after database commit")

        monkeypatch.setattr(
            restarted_head_store,
            "commit_append",
            interrupt_after_database_commit,
        )
        with pytest.raises(AuditIntegrityError, match="simulated interruption"):
            restarted.append(
                mission_id=mission_id,
                mission_revision=1,
                authorization_epoch=0,
                payload=AuditReferencePayload(
                    resource_type="artifact",
                    resource_id="artifact_" + "a" * 32,
                    operation="export",
                    operation_id="auditop_" + "3" * 32,
                    metadata_digest="sha256:" + "3" * 64,
                ),
                occurred_at=NOW + timedelta(seconds=2),
            )
        prepared_third = restarted_head_store.prepared_append(mission_id)
        assert prepared_third is not None
        assert restarted.events_for(mission_id) == (
            first,
            prepared_second,
            prepared_third,
        )
        monkeypatch.setattr(
            restarted_head_store,
            "commit_append",
            original_commit_append,
        )

        database.connection.execute(
            "DELETE FROM audit_logs WHERE event_id = ?",
            (prepared_third.event_id,),
        )
        database.connection.execute(
            "UPDATE audit_log_heads SET sequence_number = ?, event_hash = ? "
            "WHERE mission_id = ?",
            (
                prepared_second.sequence_number,
                prepared_second.event_hash,
                mission_id,
            ),
        )
        recovered_head_store = _audit_head_store(
            head_state_path,
            keys=keys,
            generation_store=head_generation_store,
        )
        recovered = MissionAuditLog(
            database,
            authenticator=authenticator,
            head_store=recovered_head_store,
        )
        assert recovered.verify(mission_id) == (
            first,
            prepared_second,
            prepared_third,
        )
        assert recovered_head_store.prepared_append(mission_id) is None
        assert recovered_head_store.head(mission_id) == (
            prepared_third.sequence_number,
            prepared_third.event_hash,
        )


def test_audit_head_write_stays_on_validated_directory_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_directory = tmp_path / "audit-head-swap-keys"
    key_directory.mkdir(mode=0o700)
    keys = _wrapped_keys(
        key_directory / "provider.json",
        generation_store=_GenerationStore(),
    )
    authenticator = KeyedAuditChainAuthenticator(keys)
    event = MissionAuditLog(authenticator=authenticator).append(
        mission_id="mission-audit-head-swap",
        mission_revision=1,
        authorization_epoch=0,
        payload=AuditReferencePayload(
            resource_type="artifact",
            resource_id="artifact_" + "b" * 32,
            operation="create",
            operation_id="auditop_" + "4" * 32,
            metadata_digest="sha256:" + "4" * 64,
        ),
        occurred_at=NOW,
    )
    head_directory = tmp_path / "audit-head-swap"
    detached_directory = tmp_path / "detached-audit-head-swap"
    outside_directory = tmp_path / "outside-audit-head-swap"
    outside_directory.mkdir(mode=0o700)
    outside_state = outside_directory / "heads.json"
    outside_state.write_bytes(b"outside-state-must-not-change")
    generation_store = _GenerationStore()
    head_store = _audit_head_store(
        head_directory / "heads.json",
        keys=keys,
        generation_store=generation_store,
    )
    original_replace = os.replace
    swapped = False

    def swap_parent_before_replace(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if not swapped:
            head_directory.rename(detached_directory)
            head_directory.symlink_to(outside_directory, target_is_directory=True)
            swapped = True
        original_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(os, "replace", swap_parent_before_replace)
    with pytest.raises(AuditIntegrityError, match="directory identity changed"):
        head_store.prepare_append(
            event.mission_id,
            expected=None,
            event=event,
        )

    assert swapped
    assert generation_store.current_generation() == 0
    assert outside_state.read_bytes() == b"outside-state-must-not-change"
    assert (detached_directory / "heads.json").is_file()


def test_keyed_sqlite_audit_rejects_recomputed_forged_chain(tmp_path: Path) -> None:
    database_path = tmp_path / "forged-audit.sqlite3"
    head_state_path = tmp_path / "forged-audit-head" / "heads.json"
    key_state_directory = tmp_path / "forged-audit-keys"
    key_state_directory.mkdir(mode=0o700)
    key_state_path = key_state_directory / "provider.json"
    wrapping_key = b"forged-audit-os-keystore-key-material"
    generation_store = _GenerationStore()
    head_generation_store = _GenerationStore()
    keys = _wrapped_keys(
        key_state_path,
        wrapping_key=wrapping_key,
        generation_store=generation_store,
    )
    with Database(database_path) as database:
        database.connection.execute(
            "INSERT INTO missions(mission_id, payload_json, created_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            ("mission-forged", "{}", NOW.isoformat(), "test"),
        )
        audit = MissionAuditLog(
            database,
            authenticator=KeyedAuditChainAuthenticator(keys),
            head_store=_audit_head_store(
                head_state_path,
                keys=keys,
                generation_store=head_generation_store,
            ),
        )
        for sequence in (1, 2):
            audit.append(
                mission_id="mission-forged",
                mission_revision=1,
                authorization_epoch=0,
                payload=AuditReferencePayload(
                    resource_type="artifact",
                    resource_id="artifact_" + "e" * 32,
                    operation="create" if sequence == 1 else "read",
                    operation_id="auditop_" + str(sequence) * 32,
                    metadata_digest="sha256:" + str(sequence) * 64,
                ),
                occurred_at=NOW + timedelta(seconds=sequence),
            )

        rows = tuple(
            database.connection.execute(
                "SELECT event_id, payload_json FROM audit_logs "
                "WHERE mission_id = ? ORDER BY sequence_number",
                ("mission-forged",),
            )
        )
        previous_hash: str | None = None
        for sequence, row in enumerate(rows, start=1):
            forged = json.loads(str(row["payload_json"]))
            if sequence == 1:
                forged["canonical_payload"]["metadata_digest"] = (
                    "sha256:" + "f" * 64
                )
            forged["previous_event_hash"] = previous_hash
            digest_payload = {
                field: forged[field]
                for field in (
                    "event_id",
                    "mission_id",
                    "mission_revision",
                    "authorization_epoch",
                    "chain_scope",
                    "sequence_number",
                    "previous_event_hash",
                    "signing_key_id",
                    "signing_key_version",
                    "event_type",
                    "canonical_payload",
                    "occurred_at",
                )
            }
            forged_hash = sha256_digest(digest_payload)
            forged["event_hash"] = forged_hash
            database.connection.execute(
                "UPDATE audit_logs SET event_hash = ?, payload_json = ? "
                "WHERE event_id = ?",
                (
                    forged_hash,
                    json.dumps(forged, sort_keys=True, separators=(",", ":")),
                    row["event_id"],
                ),
            )
            previous_hash = forged_hash
        database.connection.execute(
            "UPDATE audit_log_heads SET sequence_number = ?, event_hash = ? "
            "WHERE mission_id = ?",
            (len(rows), previous_hash, "mission-forged"),
        )

    with Database(database_path) as database:
        restarted_keys = _wrapped_keys(
            key_state_path,
            wrapping_key=wrapping_key,
            generation_store=generation_store,
        )
        with pytest.raises(AuditIntegrityError, match="event hash failed"):
            MissionAuditLog(
                database,
                authenticator=KeyedAuditChainAuthenticator(restarted_keys),
                head_store=_audit_head_store(
                    head_state_path,
                    keys=restarted_keys,
                    generation_store=head_generation_store,
                ),
            ).verify("mission-forged")


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


def test_yaml_block_scalar_credentials_fail_closed_complete_and_split(
    tmp_path: Path,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(
        tmp_path / "yaml-block-scalars"
    )
    complete_mission = "mission-yaml-block-complete"
    complete_execution = "execution-yaml-block-complete"
    complete_secret = b"complete-yaml-private-value"
    authorizer.allow_ingestion_write(complete_mission, complete_execution)
    complete_reference = quarantine.commit(
        mission_id=complete_mission,
        mission_revision=1,
        execution_id=complete_execution,
        content=b"password: |\n  " + complete_secret + b"\nstatus: ok\n",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    with pytest.raises(SecureIngestionError) as complete_failure:
        SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest(complete_reference, now=NOW)
    assert complete_secret.decode() not in str(complete_failure.value)
    assert not list(
        (artifacts._store._root / complete_mission).glob("artifact*.json")
    )
    assert not list((secrets._store._root / complete_mission).glob("secret*.json"))

    split_mission = "mission-yaml-block-split"
    split_execution = "execution-yaml-block-split"
    split_secret = b"split-yaml-private-value"
    authorizer.allow_ingestion_write(split_mission, split_execution)
    sink = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(
            QuarantineStreamBinding(
                mission_id=split_mission,
                mission_revision=1,
                execution_id=split_execution,
                retention_until=NOW + timedelta(hours=1),
                max_result_bytes=4096,
                resume_mode="from_start",
            )
        ),
        clock=lambda: NOW,
    ).for_execution(split_execution)

    async def ingest_split_block_scalar() -> None:
        await sink.write_stdout(b"password:")
        await sink.write_stdout(b" >-\n  split-yaml-")
        await sink.write_stdout(b"private-value\nstatus: ok\n")
        receipt = await sink.commit()
        with pytest.raises(SecureIngestionError) as split_failure:
            await SecureIngestor(
                quarantine=quarantine,
                artifacts=artifacts,
                secrets=secrets,
            ).ingest_stream(sink, receipt, now=NOW)
        assert split_secret.decode() not in str(split_failure.value)

    asyncio.run(ingest_split_block_scalar())
    assert not list((artifacts._store._root / split_mission).glob("*.json"))
    assert not list((secrets._store._root / split_mission).glob("*.json"))


def test_artifact_quota_charges_durable_envelope_bytes(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-durable-byte-quota"
    for execution_id in ("execution-durable-first", "execution-durable-second"):
        authorizer.allow_ingestion_write(mission_id, execution_id)
    quota_bytes = 2048
    artifacts = ArtifactStore(
        root=tmp_path / "durable-byte-quota",
        keys=keys,
        authorizer=authorizer,
        audit=MissionAuditRecorder(
            audit_log=MissionAuditLog(),
            contexts=_AuditContexts(),
        ),
        max_item_bytes=16,
        mission_quota_bytes=quota_bytes,
    )
    first = artifacts.put(
        mission_id=mission_id,
        content=b"",
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id="execution-durable-first",
        created_at=NOW,
    )
    mission_root = artifacts._store._root / mission_id
    durable_usage = sum(path.stat().st_size for path in mission_root.glob("*.json"))
    assert first.size_bytes == 0
    assert 0 < durable_usage <= quota_bytes
    with pytest.raises(ArtifactSecurityError, match="quota"):
        artifacts.put(
            mission_id=mission_id,
            content=b"",
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id="execution-durable-second",
            created_at=NOW,
        )
    assert sum(path.stat().st_size for path in mission_root.glob("*.json")) == (
        durable_usage
    )


def test_full_quota_artifact_expiry_recovers_without_caller_capacity(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-full-quota-expiry"
    execution_id = "execution-full-quota-expiry"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    artifact_root = tmp_path / "full-quota-expiry"
    current_time = [NOW]
    initial = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=8192,
        clock=lambda: current_time[0],
    )
    retention_until = NOW + timedelta(minutes=5)
    reference = initial.put(
        mission_id=mission_id,
        content=b"artifact-filling-its-configured-quota",
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id=execution_id,
        created_at=NOW,
        retention_until=retention_until,
    )
    envelope = initial._store.verified_envelope(
        mission_id=mission_id,
        resource_id=reference.artifact_id,
        now=None,
    )
    mission_root = artifact_root / mission_id
    exact_usage = sum(path.stat().st_size for path in mission_root.glob("*.json"))
    current_time[0] = retention_until

    restarted = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=exact_usage,
        clock=lambda: current_time[0],
    )

    assert not restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=reference.artifact_id,
    )
    assert not restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=restarted._deletion_intent_id(reference.artifact_id),
    )
    assert keys.resource_key_destroyed(envelope.payload.metadata)
    assert len(
        [
            event
            for event in audit_log.events_for(mission_id)
            if event.event_type == "artifact.delete"
        ]
    ) == 1


def test_completed_expiry_removes_intent_and_allows_safe_recreation(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = "mission-artifact-recreation"
    execution_id = "execution-artifact-recreation"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit_log = MissionAuditLog()
    audit = MissionAuditRecorder(audit_log=audit_log, contexts=_AuditContexts())
    artifact_root = tmp_path / "artifact-recreation"
    artifacts = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
        clock=lambda: NOW,
    )
    content = b"recreatable-artifact"
    first_retention = NOW + timedelta(minutes=5)
    first = artifacts.put(
        mission_id=mission_id,
        content=content,
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id=execution_id,
        created_at=NOW,
        retention_until=first_retention,
    )
    authorizer.set_grants(
        mission_id,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=first.artifact_id,
                    resource_version="1",
                    resource_digest=first.sha256,
                ),
                operations=frozenset({"write"}),
            ),
        ),
    )
    artifacts.expire(first, now=first_retention)
    artifacts.expire(first, now=first_retention + timedelta(seconds=1))
    intent_id = artifacts._deletion_intent_id(first.artifact_id)
    assert not artifacts._store.has_resource(
        mission_id=mission_id,
        resource_id=intent_id,
    )

    second_created_at = NOW + timedelta(minutes=10)
    second_retention = second_created_at + timedelta(minutes=5)
    second = artifacts.put(
        mission_id=mission_id,
        content=content,
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id=execution_id,
        created_at=second_created_at,
        retention_until=second_retention,
    )
    assert second.artifact_id == first.artifact_id
    assert second.encryption_metadata_id != first.encryption_metadata_id

    restarted = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=1024,
        mission_quota_bytes=16 * 1024,
        clock=lambda: second_created_at + timedelta(minutes=1),
    )
    assert restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=second.artifact_id,
    )
    assert not restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=intent_id,
    )
    with pytest.raises(DigestIntegrityError):
        restarted.expire(first, now=second_retention)
    restarted.expire(second, now=second_retention)
    restarted.expire(second, now=second_retention + timedelta(seconds=1))
    assert not restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=second.artifact_id,
    )
    assert not restarted._store.has_resource(
        mission_id=mission_id,
        resource_id=intent_id,
    )
    assert len(
        [
            event
            for event in audit_log.events_for(mission_id)
            if event.event_type == "artifact.create"
        ]
    ) == 2
    assert len(
        [
            event
            for event in audit_log.events_for(mission_id)
            if event.event_type == "artifact.delete"
        ]
    ) == 2


def test_wrapped_key_state_limit_is_enforced_before_generation_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_directory = tmp_path / "bounded-wrapped-key-state"
    key_directory.mkdir(mode=0o700)
    state_path = key_directory / "provider.json"
    generation_store = _GenerationStore()
    provider = _wrapped_keys(
        state_path,
        generation_store=generation_store,
    )
    committed_generation = generation_store.current_generation()
    committed_path = provider._state_path_for_generation(committed_generation)
    committed_state = committed_path.read_bytes()
    monkeypatch.setattr(
        "redteam_agent.data_security.keys._MAX_WRAPPED_STATE_BYTES",
        len(committed_state),
    )

    with pytest.raises(EncryptionKeyUnavailableError, match="provider limit"):
        provider.seal_for_resource(
            "artifact_store",
            "artifact-state-limit-crossing",
            b"threshold-crossing-content",
            {"purpose": "wrapped-state-threshold"},
            created_at=NOW + timedelta(minutes=1),
        )

    assert generation_store.current_generation() == committed_generation
    assert committed_path.read_bytes() == committed_state
    restarted = WrappedFileEncryptionKeyProvider(
        state_path=state_path,
        wrapping_key=b"wrapped-provider-root-key-material",
        generation_store=generation_store,
    )
    assert (
        restarted.get_active_key_metadata("artifact_store").key_id
        == "artifact_store-key-v1"
    )


@pytest.mark.parametrize("interruption", ("before_link", "after_link"))
def test_resource_creation_reconciles_wrapped_keys_across_envelope_link_crashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interruption: Literal["before_link", "after_link"],
) -> None:
    key_directory = tmp_path / f"creation-{interruption}-keys"
    key_directory.mkdir(mode=0o700)
    key_state_path = key_directory / "provider.json"
    generation_store = _GenerationStore()
    keys = _wrapped_keys(
        key_state_path,
        generation_store=generation_store,
    )
    baseline_record_count = len(keys._records)
    authorizer = _ExactEnvelopeAuthorizer()
    mission_id = f"mission-creation-{interruption}"
    execution_id = f"execution-creation-{interruption}"
    authorizer.allow_ingestion_write(mission_id, execution_id)
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    artifact_root = tmp_path / f"creation-{interruption}-artifacts"
    initial = ArtifactStore(
        root=artifact_root,
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    content = b"resource-creation-crash-recovery"
    captured_metadata = []
    original_seal = keys.seal_for_resource

    def capture_seal(*args, **kwargs):
        payload = original_seal(*args, **kwargs)
        captured_metadata.append(payload.metadata)
        return payload

    monkeypatch.setattr(keys, "seal_for_resource", capture_seal)
    original_write = initial._store._atomic_write_anchored

    class _SimulatedProcessCrash(BaseException):
        pass

    def interrupt_envelope_link(**kwargs) -> None:
        if interruption == "after_link":
            original_write(**kwargs)
        raise _SimulatedProcessCrash

    monkeypatch.setattr(
        initial._store,
        "_atomic_write_anchored",
        interrupt_envelope_link,
    )
    with pytest.raises(_SimulatedProcessCrash):
        initial.put(
            mission_id=mission_id,
            content=content,
            media_type="text/plain",
            classification="normal",
            variant="redacted",
            source_execution_id=execution_id,
            created_at=NOW,
        )

    assert len(captured_metadata) == 1
    mission_root = artifact_root / mission_id
    assert len(list(mission_root.glob(".resource-creation-*.intent"))) == 1

    restarted_keys = _wrapped_keys(
        key_state_path,
        generation_store=generation_store,
    )
    restarted = ArtifactStore(
        root=artifact_root,
        keys=restarted_keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )

    assert not list(mission_root.glob(".resource-creation-*.intent"))
    if interruption == "before_link":
        assert len(restarted_keys._records) == baseline_record_count
        with pytest.raises(
            EncryptionKeyUnavailableError,
            match="unavailable",
        ):
            restarted_keys.get_key_metadata(
                captured_metadata[0].key_domain,
                captured_metadata[0].key_id,
                captured_metadata[0].key_version,
            )
    else:
        assert len(restarted_keys._records) == baseline_record_count + 1
        assert not restarted_keys.resource_key_destroyed(
            captured_metadata[0]
        )
    recovered = restarted.put(
        mission_id=mission_id,
        content=content,
        media_type="text/plain",
        classification="normal",
        variant="redacted",
        source_execution_id=execution_id,
        created_at=NOW,
    )
    if interruption == "before_link":
        assert recovered.encryption_metadata_id != restarted_keys.metadata_id(
            captured_metadata[0]
        )
    else:
        assert recovered.encryption_metadata_id == restarted_keys.metadata_id(
            captured_metadata[0]
        )


def test_atomic_envelope_failures_do_not_accumulate_wrapped_key_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_directory = tmp_path / "creation-failure-keys"
    key_directory.mkdir(mode=0o700)
    keys = _wrapped_keys(
        key_directory / "provider.json",
        generation_store=_GenerationStore(),
    )
    baseline_record_count = len(keys._records)
    authorizer = _ExactEnvelopeAuthorizer()
    artifacts = ArtifactStore(
        root=tmp_path / "creation-failure-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=MissionAuditRecorder(
            audit_log=MissionAuditLog(),
            contexts=_AuditContexts(),
        ),
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )

    def fail_envelope_write(**kwargs) -> None:
        del kwargs
        raise ArtifactSecurityError("simulated envelope write failure")

    monkeypatch.setattr(
        artifacts._store,
        "_atomic_write_anchored",
        fail_envelope_write,
    )
    for index in range(3):
        mission_id = f"mission-creation-failure-{index}"
        execution_id = f"execution-creation-failure-{index}"
        authorizer.allow_ingestion_write(mission_id, execution_id)
        with pytest.raises(ArtifactSecurityError, match="write failure"):
            artifacts.put(
                mission_id=mission_id,
                content=f"failed-content-{index}".encode(),
                media_type="text/plain",
                classification="normal",
                variant="redacted",
                source_execution_id=execution_id,
                created_at=NOW,
            )
        assert len(keys._records) == baseline_record_count
        assert not list(
            (artifacts._store._root / mission_id).glob(
                ".resource-creation-*.intent"
            )
        )


def test_long_ordinary_tokens_do_not_exhaust_uri_stream_lookahead(
    tmp_path: Path,
) -> None:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    quarantine = EncryptedRawResultQuarantine(
        root=tmp_path / "long-token-quarantine",
        keys=keys,
        audit=audit,
        max_item_bytes=128 * 1024,
        mission_quota_bytes=1024 * 1024,
    )
    artifacts = ArtifactStore(
        root=tmp_path / "long-token-artifacts",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=128 * 1024,
        mission_quota_bytes=1024 * 1024,
    )
    secret_store = SecretStore(
        root=tmp_path / "long-token-secrets",
        keys=keys,
        authorizer=authorizer,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=64 * 1024,
    )
    ordinary_token = b"a" * (70 * 1024)

    async def ingest(case: str, chunks: tuple[bytes, ...]) -> None:
        mission_id = f"mission-long-token-{case}"
        execution_id = f"execution-long-token-{case}"
        authorizer.allow_ingestion_write(mission_id, execution_id)
        sink = EncryptedRawResultSinkFactory(
            quarantine=quarantine,
            bindings=_StreamBindings(
                QuarantineStreamBinding(
                    mission_id=mission_id,
                    mission_revision=1,
                    execution_id=execution_id,
                    retention_until=NOW + timedelta(hours=1),
                    max_result_bytes=len(ordinary_token),
                    resume_mode="from_start",
                )
            ),
            clock=lambda: NOW,
        ).for_execution(execution_id)
        for chunk in chunks:
            await sink.write_stdout(chunk)
        receipt = await sink.commit()
        result = await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secret_store,
        ).ingest_stream(sink, receipt, now=NOW)
        assert result.redaction_metadata.redaction_count == 0
        assert not result.detected_secrets
        artifact = result.redacted_artifacts[0]
        authorizer.set_grants(
            mission_id,
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
        assert artifacts.read(artifact, operation="read", now=NOW) == ordinary_token

    asyncio.run(ingest("complete", (ordinary_token,)))
    asyncio.run(
        ingest(
            "split",
            (ordinary_token[:128], ordinary_token[128:]),
        )
    )


def test_connection_uri_credentials_are_redacted_complete_and_split(
    tmp_path: Path,
) -> None:
    quarantine, artifacts, secrets, authorizer, _ = _stores(
        tmp_path / "credential-uri"
    )
    complete_mission = "mission-uri-complete"
    complete_execution = "execution-uri-complete"
    complete_secret = b"complete-uri-password"
    authorizer.allow_ingestion_write(complete_mission, complete_execution)
    complete_reference = quarantine.commit(
        mission_id=complete_mission,
        mission_revision=1,
        execution_id=complete_execution,
        content=(
            b"dsn=ssh://alice:"
            + complete_secret
            + b"@database.local/app status=ok"
        ),
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )
    complete = SecureIngestor(
        quarantine=quarantine,
        artifacts=artifacts,
        secrets=secrets,
    ).ingest(complete_reference, now=NOW)
    assert complete.redaction_metadata.redaction_count == 1
    assert complete.detected_secrets[0].credential_type == "uri_password"
    complete_artifact = complete.redacted_artifacts[0]
    authorizer.set_grants(
        complete_mission,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=complete_artifact.artifact_id,
                    resource_version="1",
                    resource_digest=complete_artifact.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    complete_visible = artifacts.read(
        complete_artifact,
        operation="read",
        now=NOW,
    )
    assert complete_secret not in complete_visible
    assert b"ssh://alice:[REDACTED]@database.local/app" in complete_visible

    split_mission = "mission-uri-split"
    split_execution = "execution-uri-split"
    split_secret = b"split-uri-password"
    authorizer.allow_ingestion_write(split_mission, split_execution)
    split_binding = QuarantineStreamBinding(
        mission_id=split_mission,
        mission_revision=1,
        execution_id=split_execution,
        retention_until=NOW + timedelta(hours=1),
        max_result_bytes=4096,
        resume_mode="from_start",
    )
    split_sink = EncryptedRawResultSinkFactory(
        quarantine=quarantine,
        bindings=_StreamBindings(split_binding),
        clock=lambda: NOW,
    ).for_execution(split_execution)

    async def ingest_split_uri():
        await split_sink.write_stdout(b"transfer=sf")
        await split_sink.write_stdout(b"tp://worker:split-uri-")
        await split_sink.write_stdout(b"password@files.local/home status=ok")
        receipt = await split_sink.commit()
        return await SecureIngestor(
            quarantine=quarantine,
            artifacts=artifacts,
            secrets=secrets,
        ).ingest_stream(split_sink, receipt, now=NOW)

    split = asyncio.run(ingest_split_uri())
    assert split.redaction_metadata.redaction_count == 1
    assert split.detected_secrets[0].credential_type == "uri_password"
    split_artifact = split.redacted_artifacts[0]
    authorizer.set_grants(
        split_mission,
        (
            DataAccessGrant(
                resource_type="artifact",
                resource=ResourceBinding(
                    resource_id=split_artifact.artifact_id,
                    resource_version="1",
                    resource_digest=split_artifact.sha256,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    split_visible = artifacts.read(split_artifact, operation="read", now=NOW)
    assert split_secret not in split_visible
    assert b"sftp://worker:[REDACTED]@files.local/home" in split_visible


def test_full_quota_quarantine_cleanup_survives_restart(
    tmp_path: Path,
) -> None:
    keys = _keys()
    audit = MissionAuditRecorder(
        audit_log=MissionAuditLog(),
        contexts=_AuditContexts(),
    )
    non_stream_root = tmp_path / "full-non-stream-quarantine"
    non_stream = EncryptedRawResultQuarantine(
        root=non_stream_root,
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    non_stream_mission = "mission-full-non-stream"
    non_stream_reference = non_stream.commit(
        mission_id=non_stream_mission,
        mission_revision=1,
        execution_id="execution-full-non-stream",
        content=b"full-quota-non-stream-secret",
        created_at=NOW,
        retention_until=NOW + timedelta(minutes=5),
    )
    non_stream_usage = sum(
        path.stat().st_size
        for path in (non_stream_root / non_stream_mission).glob("*.json")
    )
    non_stream._store._mission_quota_bytes = non_stream_usage
    with pytest.raises(ArtifactSecurityError, match="retention has expired"):
        non_stream.resume(
            non_stream_reference,
            now=NOW + timedelta(minutes=5),
        )
    assert not list((non_stream_root / non_stream_mission).glob("*.json"))
    EncryptedRawResultQuarantine(
        root=non_stream_root,
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=non_stream_usage,
        clock=lambda: NOW + timedelta(minutes=6),
    )

    stream_root = tmp_path / "full-stream-quarantine"
    stream = EncryptedRawResultQuarantine(
        root=stream_root,
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=16 * 1024,
    )
    stream_mission = "mission-full-stream"
    stream_execution = "execution-full-stream"
    stream_binding = QuarantineStreamBinding(
        mission_id=stream_mission,
        mission_revision=1,
        execution_id=stream_execution,
        retention_until=NOW + timedelta(minutes=5),
        max_result_bytes=4096,
        resume_mode="from_start",
    )
    current_time = [NOW]
    stream_factory = EncryptedRawResultSinkFactory(
        quarantine=stream,
        bindings=_StreamBindings(stream_binding),
        clock=lambda: current_time[0],
    )

    async def populate_stream() -> None:
        sink = stream_factory.for_execution(stream_execution)
        await sink.write_stdout(b"full-quota-stream-secret")
        await sink.commit()

    asyncio.run(populate_stream())
    stream_usage = sum(
        path.stat().st_size
        for path in (stream_root / stream_mission).glob("*.json")
    )
    stream._store._mission_quota_bytes = stream_usage
    current_time[0] = NOW + timedelta(minutes=5)
    expired = stream_factory.for_execution(stream_execution)
    assert expired._deleted
    assert not list((stream_root / stream_mission).glob("streamchunk_*.json"))
    assert not list((stream_root / stream_mission).glob("streamterminal_*.json"))
    restarted_stream = EncryptedRawResultQuarantine(
        root=stream_root,
        keys=keys,
        audit=audit,
        max_item_bytes=4096,
        mission_quota_bytes=stream_usage,
    )
    restarted = EncryptedRawResultSinkFactory(
        quarantine=restarted_stream,
        bindings=_StreamBindings(stream_binding),
        clock=lambda: NOW + timedelta(minutes=6),
    ).for_execution(stream_execution)
    assert restarted._deleted


def test_audit_head_generation_requires_post_commit_path_reachability(
    tmp_path: Path,
) -> None:
    key_directory = tmp_path / "post-cas-audit-head-keys"
    key_directory.mkdir(mode=0o700)
    keys = _wrapped_keys(
        key_directory / "provider.json",
        generation_store=_GenerationStore(),
    )
    authenticator = KeyedAuditChainAuthenticator(keys)
    mission_id = "mission-post-cas-audit-head"
    event = MissionAuditLog(authenticator=authenticator).append(
        mission_id=mission_id,
        mission_revision=1,
        authorization_epoch=0,
        payload=AuditReferencePayload(
            resource_type="artifact",
            resource_id="artifact_" + "a" * 32,
            operation="create",
            operation_id="auditop_" + "a" * 32,
            metadata_digest="sha256:" + "a" * 64,
        ),
        occurred_at=NOW,
    )
    head_directory = tmp_path / "post-cas-audit-head"
    detached_directory = tmp_path / "detached-post-cas-audit-head"

    class SwappingGenerationStore(_GenerationStore):
        def __init__(self) -> None:
            super().__init__()
            self.swap_on_commit = True

        def compare_and_set_generation(self, *, expected: int, new: int) -> bool:
            advanced = super().compare_and_set_generation(
                expected=expected,
                new=new,
            )
            if self.swap_on_commit and advanced:
                self.swap_on_commit = False
                head_directory.rename(detached_directory)
                head_directory.mkdir(mode=0o700)
            return advanced

    generation_store = SwappingGenerationStore()
    head_store = _audit_head_store(
        head_directory / "heads.json",
        keys=keys,
        generation_store=generation_store,
    )
    with pytest.raises(AuditIntegrityError, match="directory identity changed"):
        head_store.prepare_append(
            mission_id,
            expected=None,
            event=event,
        )

    assert generation_store.current_generation() == 1
    assert not list(head_directory.iterdir())
    assert (detached_directory / "heads.json").is_file()
    head_directory.rmdir()
    detached_directory.rename(head_directory)
    recovered = _audit_head_store(
        head_directory / "heads.json",
        keys=keys,
        generation_store=generation_store,
    )
    assert recovered.prepared_append(mission_id) == event


def test_deterministic_audit_operation_is_idempotent_across_epoch_change() -> None:
    class EpochContexts:
        def __init__(self) -> None:
            self.epoch = 0

        def current_context(
            self,
            mission_id: str,
            *,
            now: datetime,
        ) -> AuditContext:
            del mission_id, now
            return AuditContext(
                mission_revision=1,
                authorization_epoch=self.epoch,
            )

    contexts = EpochContexts()
    audit_log = MissionAuditLog()
    recorder = MissionAuditRecorder(
        audit_log=audit_log,
        contexts=contexts,
    )
    mission_id = "mission-epoch-audit-retry"
    resource_id = "artifact_" + "e" * 32
    operation_id = "auditop_" + "e" * 32
    metadata_digest = "sha256:" + "e" * 64
    first = recorder.record(
        mission_id=mission_id,
        resource_type="artifact",
        resource_id=resource_id,
        operation="create",
        operation_id=operation_id,
        metadata_digest=metadata_digest,
        occurred_at=NOW,
    )
    contexts.epoch = 1
    retried = recorder.record(
        mission_id=mission_id,
        resource_type="artifact",
        resource_id=resource_id,
        operation="create",
        operation_id=operation_id,
        metadata_digest=metadata_digest,
        occurred_at=NOW + timedelta(hours=1),
    )

    assert retried == first
    assert retried.authorization_epoch == 0
    assert audit_log.events_for(mission_id) == (first,)
    assert recorder.operation_recorded(
        mission_id=mission_id,
        resource_type="artifact",
        resource_id=resource_id,
        operation="create",
        operation_id=operation_id,
        metadata_digest=metadata_digest,
    )
