"""The single canonical digest computation entry point (SystemDesign §32.2).

Components pass a registered digest name and a typed mapping of inputs; they
never hash bytes directly. Verification recomputes and compares in constant
time and fails closed on mismatch (B-06 / H-03).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG, DigestCatalog
from redteam_agent.errors import DigestCatalogError, DigestIntegrityError


class DigestService:
    """Compute and verify named digests through a versioned catalog."""

    def __init__(self, catalog: DigestCatalog | None = None) -> None:
        self._catalog = catalog if catalog is not None else DEFAULT_DIGEST_CATALOG

    @property
    def catalog(self) -> DigestCatalog:
        return self._catalog

    def compute(self, digest_name: str, payload: Mapping[str, Any]) -> str:
        definition = self._catalog.get(digest_name)
        if definition.included_field_paths:
            # Explicit field set: reject a missing or unknown field so a dropped
            # or extra authorization field cannot pass silently (§32.2).
            expected = set(definition.included_field_paths)
            actual = set(payload)
            if actual != expected:
                # Report only counts, never the (possibly caller-controlled) key
                # names, so a synthetic key cannot leak into an exception/log.
                missing = len(expected - actual)
                unknown = len(actual - expected)
                raise DigestCatalogError(
                    f"{digest_name}: field-set mismatch (missing={missing}, unknown={unknown})"
                )
            included = {key: payload[key] for key in definition.included_field_paths}
        else:
            included = {key: value for key, value in payload.items() if key not in definition.excluded_field_paths}
        domain = definition.domain_separator.encode("utf-8")
        body = canonical_dumps(included)
        return hashlib.sha256(domain + b"\x00" + body).hexdigest()

    def verify(self, digest_name: str, payload: Mapping[str, Any], expected: str) -> None:
        actual = self.compute(digest_name, payload)
        if not hmac.compare_digest(actual, expected):
            raise DigestIntegrityError(
                f"digest mismatch for {digest_name}: expected {expected}, recomputed {actual}"
            )
