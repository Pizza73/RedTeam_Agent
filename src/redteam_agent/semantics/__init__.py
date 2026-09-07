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
    # Fact types eligible for a finding_confirmed goal condition. ``execution_outcome``
    # is deliberately excluded: it has no direct goal correspondence (R11).
    finding_fact_types: frozenset[str]
    # Canonical entity references known to the (fixed test-double) entity catalog.
    registered_entity_refs: frozenset[str]
    registered_session_refs: frozenset[str] = frozenset()
    registered_host_refs: frozenset[str] = frozenset()
    # (condition kind, goal rule, proof schema, source capability).  This is a
    # fixed Phase 0A catalog binding, not runtime goal-evaluation state.
    condition_support_bindings: frozenset[tuple[str, str, str, str]] = frozenset()


def default_semantic_catalog() -> SemanticCatalog:
    return SemanticCatalog(
        catalog_revision="semantic-catalog-v1",
        fact_types=frozenset({"identity", "service", "relationship", "finding", "execution_outcome"}),
        selector_types=frozenset({"exact_session", "active_session"}),
        privilege_levels=frozenset({"linux_uid0", "windows_system", "windows_high_integrity"}),
        condition_kinds=frozenset({"session_established", "host_privilege", "finding_confirmed"}),
        finding_fact_types=frozenset({"identity", "service", "relationship", "finding"}),
        registered_entity_refs=frozenset({"entity:host-1", "entity:dc-01", "entity:svc-http"}),
        registered_session_refs=frozenset({"sess-1"}),
        registered_host_refs=frozenset({"host-1"}),
        condition_support_bindings=frozenset(
            {
                (
                    "session_established",
                    "goal-rule:session-established-v1",
                    "proof-schema:session-established-v1",
                    "source-capability:session-catalog-v1",
                ),
                (
                    "host_privilege",
                    "goal-rule:host-privilege-v1",
                    "proof-schema:host-privilege-v1",
                    "source-capability:session-security-context-v1",
                ),
                (
                    "finding_confirmed",
                    "goal-rule:finding-confirmed-v1",
                    "proof-schema:finding-confirmed-v1",
                    "source-capability:knowledge-fact-v1",
                ),
            }
        ),
    )
