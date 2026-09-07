"""Versioned, closed semantic identifiers accepted from the Phase 1 Analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import KnowledgeStateIntegrityError

ObservationType = Literal["asset", "identity", "relationship", "finding"]


@dataclass(frozen=True)
class SemanticDefinition:
    observation_type: ObservationType
    predicate: str


class SemanticCatalog:
    """Application-owned allowlist; Analyzer text cannot add semantic identifiers."""

    def __init__(
        self, *, revision: str, definitions: tuple[SemanticDefinition, ...],
        digest_service: DigestService,
    ) -> None:
        if not revision or not definitions:
            raise KnowledgeStateIntegrityError("semantic catalog must be versioned and non-empty")
        keys = tuple((item.observation_type, item.predicate) for item in definitions)
        if any(not predicate for _kind, predicate in keys) or len(keys) != len(set(keys)):
            raise KnowledgeStateIntegrityError("semantic catalog definitions must be unique")
        self.revision = revision
        self._keys = frozenset(keys)
        self.catalog_digest = digest_service.compute(
            "semantic_catalog_digest",
            {"revision": revision, "definitions": sorted(keys)},
        )

    def validate(self, *, observation_type: ObservationType, predicate: str) -> None:
        if (observation_type, predicate) not in self._keys:
            raise KnowledgeStateIntegrityError("Analyzer predicate is not in the semantic catalog")


def build_phase1_semantic_catalog(digest_service: DigestService) -> SemanticCatalog:
    return SemanticCatalog(
        revision="phase1-semantic-v1",
        definitions=(
            SemanticDefinition("asset", "host_observed"),
            SemanticDefinition("asset", "network_asset_observed"),
            SemanticDefinition("identity", "principal_observed"),
            SemanticDefinition("identity", "session_candidate"),
            SemanticDefinition("relationship", "identity_relationship"),
            SemanticDefinition("relationship", "network_relationship"),
            SemanticDefinition("finding", "finding_candidate"),
            SemanticDefinition("finding", "service_observed"),
            SemanticDefinition("finding", "session_candidate"),
        ),
        digest_service=digest_service,
    )
