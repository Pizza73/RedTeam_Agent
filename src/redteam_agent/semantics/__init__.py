"""Versioned semantic catalog (SystemDesign §16.2).

Phase 0A ships a small, fixed catalog of registered semantic identifiers (fact
types, selector types, privilege levels, success-condition kinds). Mission
success conditions must reference only registered definitions; unregistered or
unsupported conditions are Default Deny at validation time. This is an explicit
test-double catalog; no new persistent authorization record is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticCatalog:
    catalog_revision: str
    fact_types: frozenset[str]
    selector_types: frozenset[str]
    privilege_levels: frozenset[str]
    condition_kinds: frozenset[str]


def default_semantic_catalog() -> SemanticCatalog:
    return SemanticCatalog(
        catalog_revision="semantic-catalog-v1",
        fact_types=frozenset({"identity", "service", "relationship", "finding", "execution_outcome"}),
        selector_types=frozenset({"exact_session", "active_session"}),
        privilege_levels=frozenset({"linux_uid0", "windows_system", "windows_high_integrity"}),
        condition_kinds=frozenset({"session_established", "host_privilege", "finding_confirmed"}),
    )
