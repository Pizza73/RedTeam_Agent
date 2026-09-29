"""Canonical JSON, trust-boundary parsing, and the digest catalog/service.

This package is the *only* owner of duplicate-key rejection, canonical
serialization, and digest computation. Domain components pass a digest name and
typed input; they never implement digest rules themselves (SystemDesign §32.2).
"""

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.digest_catalog import DEFAULT_DIGEST_CATALOG, DigestCatalog, DigestDefinition
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.json_boundary import (
    CanonicalJsonObject,
    JsonValue,
    load_model_from_json,
    parse_json_no_duplicate_keys,
)

__all__ = [
    "DEFAULT_DIGEST_CATALOG",
    "CanonicalJsonObject",
    "DigestCatalog",
    "DigestDefinition",
    "DigestService",
    "JsonValue",
    "canonical_dumps",
    "load_model_from_json",
    "parse_json_no_duplicate_keys",
]
