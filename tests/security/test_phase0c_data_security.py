from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from redteam_agent.canonical import CanonicalJsonObject
from redteam_agent.data_security import (
    ArtifactStore,
    EncryptedRawResultQuarantine,
    InMemoryEncryptionKeyProvider,
    MissionAuditLog,
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
    SandboxCapabilityStaleError,
    SecretAccessError,
)
from redteam_agent.models.capabilities import SandboxCapabilities
from redteam_agent.models.context import DataAccessGrant, ResourceBinding
from redteam_agent.models.scope import DataAccessOperation, DataResourceType

NOW = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)


class _ExactEnvelopeAuthorizer:
    def __init__(self) -> None:
        self._grants: dict[str, tuple[DataAccessGrant, ...]] = {}

    def set_grants(self, mission_id: str, grants: tuple[DataAccessGrant, ...]) -> None:
        self._grants[mission_id] = grants

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
]:
    keys = _keys()
    authorizer = _ExactEnvelopeAuthorizer()
    quarantine = EncryptedRawResultQuarantine(
        root=root / "quarantine",
        keys=keys,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    artifacts = ArtifactStore(
        root=root / "artifacts",
        keys=keys,
        authorizer=authorizer,
        max_item_bytes=4096,
        mission_quota_bytes=8192,
    )
    secrets = SecretStore(
        root=root / "secrets",
        keys=keys,
        authorizer=authorizer,
        max_item_bytes=1024,
        mission_quota_bytes=4096,
    )
    return quarantine, artifacts, secrets, authorizer


def test_secure_ingestion_exposes_only_redacted_references(tmp_path: Path) -> None:
    quarantine, artifacts, secrets, authorizer = _stores(tmp_path)
    raw_secret = b"correct-horse-battery-staple"
    receipt = quarantine.commit(
        mission_id="mission-a",
        mission_revision=1,
        execution_id="execution-a",
        content=b"user=alice password=" + raw_secret + b" status=ok",
        created_at=NOW,
        retention_until=NOW + timedelta(hours=1),
    )

    result = SecureIngestor(
        quarantine=quarantine, artifacts=artifacts, secrets=secrets
    ).ingest(receipt, now=NOW)

    assert len(result.redacted_artifacts) == 1
    assert len(result.detected_secrets) == 1
    assert result.redaction_metadata.redaction_count == 1
    assert raw_secret.decode() not in result.model_dump_json()
    assert all(raw_secret not in path.read_bytes() for path in tmp_path.rglob("*.json"))
    assert not any((tmp_path / "quarantine").rglob("*.json"))

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
    assert b"password=[REDACTED]" in visible


def test_secret_resolution_requires_trusted_exact_mission_grant(tmp_path: Path) -> None:
    _, _, secrets, authorizer = _stores(tmp_path)
    metadata = secrets.create(
        mission_id="mission-a",
        secret_value=b"private-value",
        credential_type="token",
        associated_principal_ref="principal-a",
        source_execution_id="execution-a",
        created_at=NOW,
    )
    with pytest.raises(SecretAccessError):
        secrets.resolve(metadata, source_execution_id="execution-a", now=NOW)

    authorizer.set_grants(
        "mission-b",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=metadata.encryption_metadata_id,
                ),
                operations=frozenset({"resolve"}),
            ),
        ),
    )
    with pytest.raises(SecretAccessError):
        secrets.resolve(metadata, source_execution_id="execution-a", now=NOW)

    authorizer.set_grants(
        "mission-a",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=metadata.encryption_metadata_id,
                ),
                operations=frozenset({"read"}),
            ),
        ),
    )
    with pytest.raises(SecretAccessError):
        secrets.resolve(metadata, source_execution_id="execution-a", now=NOW)

    authorizer.set_grants(
        "mission-a",
        (
            DataAccessGrant(
                resource_type="secret_reference",
                resource=ResourceBinding(
                    resource_id=metadata.secret_reference_id,
                    resource_version="1",
                    resource_digest=metadata.encryption_metadata_id,
                ),
                operations=frozenset({"resolve"}),
            ),
        ),
    )
    assert secrets.resolve(metadata, source_execution_id="execution-a", now=NOW) == b"private-value"


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


def test_storage_rejects_traversal_symlink_quota_retention_and_corruption(
    tmp_path: Path,
) -> None:
    keys = _keys()
    root = tmp_path / "quarantine"
    quarantine = EncryptedRawResultQuarantine(
        root=root,
        keys=keys,
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

    stored_path = next((root / "mission-a").glob("*.json"))
    envelope = json.loads(stored_path.read_text(encoding="utf-8"))
    envelope["plaintext_sha256"] = "sha256:" + ("0" * 64)
    stored_path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises((DigestIntegrityError, EncryptionIntegrityError)):
        quarantine.resume(reference, now=NOW)


def test_audit_chain_and_sandbox_capabilities_fail_closed(tmp_path: Path) -> None:
    audit = MissionAuditLog()
    first = audit.append(
        event_id="event-a1",
        mission_id="mission-a",
        mission_revision=1,
        authorization_epoch=0,
        event_type="artifact.created",
        canonical_payload=CanonicalJsonObject({"artifact_id": "artifact-a"}),
        occurred_at=NOW,
        expected_sequence_number=1,
    )
    second = audit.append(
        event_id="event-a2",
        mission_id="mission-a",
        mission_revision=1,
        authorization_epoch=0,
        event_type="artifact.read",
        canonical_payload=CanonicalJsonObject({"artifact_id": "artifact-a"}),
        occurred_at=NOW + timedelta(seconds=1),
        expected_sequence_number=2,
    )
    other = audit.append(
        event_id="event-b1",
        mission_id="mission-b",
        mission_revision=1,
        authorization_epoch=0,
        event_type="mission.started",
        canonical_payload=CanonicalJsonObject({"source": "operator"}),
        occurred_at=NOW,
    )
    assert audit.verify("mission-a") == (first, second)
    assert audit.verify("mission-b") == (other,)
    with pytest.raises(AuditSequenceConflictError):
        audit.append(
            event_id="event-a3",
            mission_id="mission-a",
            mission_revision=1,
            authorization_epoch=0,
            event_type="artifact.export",
            canonical_payload=CanonicalJsonObject({"artifact_id": "artifact-a"}),
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
