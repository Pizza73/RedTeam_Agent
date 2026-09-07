"""Versioned digest catalog coverage + fail-closed (SystemDesign §32.2)."""

from __future__ import annotations

import pytest

from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG, DigestCatalog, DigestDefinition
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import DigestCatalogError

# Every Phase 0C security-sensitive digest name that the models/services rely on.
_REQUIRED_PHASE_0C_DIGESTS = frozenset({
    "domain_key_metadata_digest", "encryption_metadata_digest", "key_destruction_result_digest",
    "quarantine_metadata_digest", "secret_version_metadata_digest", "secret_lifecycle_event_digest",
    "secret_confirmation_digest", "secret_lifecycle_head_digest", "secret_logical_head_digest",
    "secret_active_head_digest", "migration_plan_digest", "collection_lease_digest", "ingestion_lease_digest",
    "deployment_epoch_digest", "publication_rule_digest", "artifact_digest", "redaction_metadata_digest",
    "manifest_digest", "deletion_intent_digest", "erasure_claim_digest", "cleanup_intent_digest",
    "cleanup_claim_digest", "copy_inventory_digest", "erasure_evidence_digest", "audit_event_digest",
    "audit_head_digest", "generation_record_digest", "generation_commit_payload_digest", "witness_digest",
    "generation_witness_policy_digest", "wrapped_key_state_digest", "nv_index_identity_digest",
    "security_state_binding_digest", "security_projection_digest", "critical_witness_intent_digest",
})


def test_all_phase0c_digests_registered_uniquely() -> None:
    names = DEFAULT_DIGEST_CATALOG.names()
    missing = _REQUIRED_PHASE_0C_DIGESTS - names
    assert not missing, f"unregistered Phase 0C digests: {sorted(missing)}"


def test_duplicate_owner_definition_rejected() -> None:
    dupes = (
        DigestDefinition(digest_name="x", schema_version="v1", owner_component="a"),
        DigestDefinition(digest_name="x", schema_version="v1", owner_component="b"),
    )
    with pytest.raises(DigestCatalogError):
        DigestCatalog(dupes)


def test_unregistered_name_fails_closed() -> None:
    service = DigestService()
    with pytest.raises(DigestCatalogError):
        service.compute("not_a_registered_digest", {"k": 1})


def test_field_set_mismatch_fails_closed_without_echoing_keys() -> None:
    service = DigestService()
    # audit_head_digest is explicit-input; a missing/extra field must be rejected.
    with pytest.raises(DigestCatalogError) as exc:
        service.compute("audit_head_digest", {"mission_id": "m", "unexpected": 1})
    assert "unexpected" not in str(exc.value)  # error text stays content-free


def test_non_sha256_algorithm_rejected() -> None:
    with pytest.raises(DigestCatalogError):
        DigestDefinition(digest_name="y", schema_version="v1", owner_component="a", algorithm="md5")
