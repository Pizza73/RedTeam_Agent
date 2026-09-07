"""Durable append-only secret lifecycle + legacy migration (SystemDesign §34)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redteam_agent.audit.hash_chain import AuditStore
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto.key_provider import InMemoryEnvelopeKeyProvider
from redteam_agent.errors import SecretConfirmationError, SecretLifecycleError, SecretMigrationRequiredError
from redteam_agent.quarantine.blob_store import InMemoryQuarantineBlobStore
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.secrets.migration import LegacySecretMigrator, LegacySecretReference
from redteam_agent.secrets.store import SecretLifecycleStore


def _store():
    from redteam_agent.storage.database import Database

    ds = DigestService()
    db = Database(":memory:")
    store = SecretLifecycleStore(
        database=db, digest_service=ds, clock=ManualClock(datetime(2026, 1, 15, tzinfo=UTC)),
        audit_store=AuditStore(db, ds), key_provider=InMemoryEnvelopeKeyProvider(digest_service=ds),
        secret_blob_store=InMemoryQuarantineBlobStore(),
    )
    return ds, db, store


def _confirm(store: SecretLifecycleStore, version_id: str, *, active: str | None) -> None:
    event = store.latest_event(version_id)
    logical = store.logical_head(store.get_version(version_id).secret_id)
    store.confirm(
        secret_version_id=version_id, mission_id="mission-1", mission_revision=1, authorization_epoch=0,
        approver_id="op-approver", source_evidence_digest="se", reason_code="operator_review",
        expected_lifecycle_head_digest=store.lifecycle_head_digest(event),
        expected_logical_version_head_digest=logical.head_digest, expected_active_version_id=active,
    )


def test_detect_confirm_supersede_revoke_flow() -> None:
    ds, db, store = _store()
    v1 = store.detect(secret_id="sec-a", mission_id="mission-1", credential_type="password",
                      associated_principal_ref="svc", value=b"v1", actor_id="ingest", actor_role="ingestion",
                      evidence_digest="e1", reason_code="detected")
    assert v1.version == 1 and store.current_state(v1.secret_version_id) == "DETECTED"
    assert bytes(store.open_version(v1.secret_version_id)) == b"v1"
    _confirm(store, v1.secret_version_id, active=None)
    assert store.current_state(v1.secret_version_id) == "CONFIRMED"
    assert store.active_head("sec-a").active_version_id == v1.secret_version_id

    v2 = store.detect(secret_id="sec-a", mission_id="mission-1", credential_type="password",
                      associated_principal_ref="svc", value=b"v2", actor_id="ingest", actor_role="ingestion",
                      evidence_digest="e2", reason_code="rotated",
                      expected_logical_head_digest=store.logical_head("sec-a").head_digest)
    assert v2.version == 2 and v2.supersedes_secret_version_id == v1.secret_version_id
    _confirm(store, v2.secret_version_id, active=v1.secret_version_id)
    assert store.current_state(v1.secret_version_id) == "SUPERSEDED"
    assert store.active_head("sec-a").active_version_id == v2.secret_version_id

    store.revoke(secret_version_id=v2.secret_version_id, mission_id="mission-1", actor_id="op",
                 actor_role="operator", evidence_digest="rv", reason_code="compromised")
    assert store.current_state(v2.secret_version_id) == "REVOKED"
    assert store.active_head("sec-a").active_version_id is None


def test_terminal_no_revival() -> None:
    ds, db, store = _store()
    v1 = store.detect(secret_id="sec-b", mission_id="mission-1", credential_type="password",
                      associated_principal_ref=None, value=b"v", actor_id="ingest", actor_role="ingestion",
                      evidence_digest="e", reason_code="detected")
    store.revoke(secret_version_id=v1.secret_version_id, mission_id="mission-1", actor_id="op",
                 actor_role="operator", evidence_digest="rv", reason_code="x")
    with pytest.raises(SecretLifecycleError):
        store.revoke(secret_version_id=v1.secret_version_id, mission_id="mission-1", actor_id="op",
                     actor_role="operator", evidence_digest="rv2", reason_code="x")


def test_confirmation_head_occ_mismatch_rejected() -> None:
    ds, db, store = _store()
    v1 = store.detect(secret_id="sec-c", mission_id="mission-1", credential_type="password",
                      associated_principal_ref=None, value=b"v", actor_id="ingest", actor_role="ingestion",
                      evidence_digest="e", reason_code="detected")
    with pytest.raises(SecretConfirmationError):
        store.confirm(secret_version_id=v1.secret_version_id, mission_id="mission-1", mission_revision=1,
                      authorization_epoch=0, approver_id="op-approver", source_evidence_digest="se",
                      reason_code="operator_review", expected_lifecycle_head_digest="STALE",
                      expected_logical_version_head_digest=store.logical_head("sec-c").head_digest,
                      expected_active_version_id=None)


def test_metadata_view_reflects_state_change() -> None:
    ds, db, store = _store()
    v1 = store.detect(secret_id="sec-d", mission_id="mission-1", credential_type="password",
                      associated_principal_ref=None, value=b"v", actor_id="ingest", actor_role="ingestion",
                      evidence_digest="e", reason_code="detected")
    detected_head = store.metadata_view(v1.secret_version_id).lifecycle_head_digest
    _confirm(store, v1.secret_version_id, active=None)
    view = store.metadata_view(v1.secret_version_id)
    assert view.state == "CONFIRMED" and view.lifecycle_head_digest != detected_head


def test_legacy_migration_one_to_one_read_only() -> None:
    ds, db, store = _store()
    migrator = LegacySecretMigrator(db, ds)
    refs = (
        LegacySecretReference(legacy_reference_id="old-1", mission_id="m-legacy", legacy_state="confirmed",
                              legacy_state_digest="sd", legacy_ciphertext_digest="cd", legacy_key_metadata_digest="kd",
                              audit_provenance_digest="ad"),
    )
    archived = migrator.migrate(refs)
    assert len(archived) == 1
    record = archived[0]
    assert record.usable_for_dispatch is False and record.archived_state == "ARCHIVED_CONFIRMED"
    # Idempotent re-migration returns the same archive.
    again = migrator.migrate(refs)
    assert again[0].archive_digest == record.archive_digest


def test_legacy_migration_ambiguous_fails_closed() -> None:
    ds, db, store = _store()
    migrator = LegacySecretMigrator(db, ds)
    same_logical = (
        LegacySecretReference(legacy_reference_id="dup", mission_id="m", legacy_state="detected",
                              legacy_state_digest="a", legacy_ciphertext_digest="a", legacy_key_metadata_digest="a",
                              audit_provenance_digest="a"),
        LegacySecretReference(legacy_reference_id="dup", mission_id="m", legacy_state="revoked",
                              legacy_state_digest="b", legacy_ciphertext_digest="b", legacy_key_metadata_digest="b",
                              audit_provenance_digest="b"),
    )
    # Same logical id derived twice with conflicting archive digests -> stop.
    with pytest.raises(SecretMigrationRequiredError):
        migrator.migrate(same_logical)
