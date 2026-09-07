"""Canonical JSON and digest catalog/service tests (B-06 primitives)."""

from __future__ import annotations

import pytest

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG, DigestCatalog, DigestDefinition
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import CanonicalJsonError, DigestCatalogError, DigestIntegrityError


def test_canonical_is_key_order_independent() -> None:
    assert canonical_dumps({"a": 1, "b": 2}) == canonical_dumps({"b": 2, "a": 1})


def test_canonical_sorts_sets_but_preserves_list_order() -> None:
    assert canonical_dumps(frozenset({"b", "a"})) == canonical_dumps(["a", "b"])
    assert canonical_dumps([2, 1]) != canonical_dumps([1, 2])


def test_canonical_rejects_naive_datetime() -> None:
    from datetime import datetime

    with pytest.raises(CanonicalJsonError):
        canonical_dumps(datetime(2026, 1, 1, 0, 0, 0))


def test_digest_is_deterministic_and_domain_separated() -> None:
    service = DigestService()
    payload = {"x": 1, "y": [1, 2]}
    # authorization_state_digest / dns_resolution_digest are generic (no fixed
    # field set), so they accept an arbitrary payload shape.
    assert service.compute("authorization_state_digest", payload) == service.compute(
        "authorization_state_digest", payload
    )
    # Different digest names (domain separators) yield different digests.
    assert service.compute("authorization_state_digest", payload) != service.compute(
        "dns_resolution_digest", payload
    )


def test_verify_detects_mismatch() -> None:
    service = DigestService()
    digest = service.compute("authorization_state_digest", {"x": 1})
    with pytest.raises(DigestIntegrityError):
        service.verify("authorization_state_digest", {"x": 2}, digest)


def test_field_set_enforced_for_explicit_digest() -> None:
    service = DigestService()
    # execution_scope_digest requires exactly its three fields.
    with pytest.raises(DigestCatalogError):
        service.compute("execution_scope_digest", {"allowed": [], "prohibited": []})  # missing field
    with pytest.raises(DigestCatalogError):
        service.compute(
            "execution_scope_digest",
            {"allowed": [], "prohibited": [], "implemented_scope_types": [], "extra": 1},  # unknown field
        )


def test_unregistered_digest_name_fails_closed() -> None:
    service = DigestService()
    with pytest.raises(DigestCatalogError):
        service.compute("not_a_registered_digest", {})


def test_duplicate_definition_rejected() -> None:
    definition = DigestDefinition(digest_name="dup", schema_version="v1", owner_component="x")
    with pytest.raises(DigestCatalogError):
        DigestCatalog((definition, definition))


def test_object_integrity_excludes_own_digest_field() -> None:
    service = DigestService()
    # decision_digest excludes the decision_digest field itself.
    payload = {"decision_digest": "ignored", "a": 1}
    without = {"a": 1}
    assert service.compute("decision_digest", payload) == service.compute("decision_digest", without)


def test_catalog_digest_is_stable() -> None:
    assert DEFAULT_DIGEST_CATALOG.catalog_digest == DEFAULT_DIGEST_CATALOG.catalog_digest
    assert len(DEFAULT_DIGEST_CATALOG.catalog_digest) == 64
