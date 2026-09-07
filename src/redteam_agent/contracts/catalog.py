"""Action contract definitions and catalog."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.canonical.immutable import thaw
from redteam_agent.errors import ToolRegistryValidationError
from redteam_agent.models.common import ActionContractReference


@dataclass(frozen=True)
class ActionContractDefinition:
    contract_id: str
    revision: str
    tool_id: str
    registry_revision: int
    parameter_schema_digest: str
    target_extractor_id: str | None
    evidence_rule_ids: tuple[str, ...]
    output_publication_rule_id: str
    minimum_risk_level: str
    side_effect: str

    @property
    def definition_digest(self) -> str:
        payload = {
            "contract_id": self.contract_id,
            "revision": self.revision,
            "tool_id": self.tool_id,
            "registry_revision": self.registry_revision,
            "parameter_schema_digest": self.parameter_schema_digest,
            "target_extractor_id": self.target_extractor_id,
            "evidence_rule_ids": list(self.evidence_rule_ids),
            "output_publication_rule_id": self.output_publication_rule_id,
            "minimum_risk_level": self.minimum_risk_level,
            "side_effect": self.side_effect,
        }
        return hashlib.sha256(b"action-contract-v1\x00" + canonical_dumps(payload)).hexdigest()

    def reference(self) -> ActionContractReference:
        return ActionContractReference(
            contract_id=self.contract_id, revision=self.revision, digest=self.definition_digest
        )


def parameter_schema_digest(parameter_schema: object) -> str:
    return hashlib.sha256(b"parameter-schema-v1\x00" + canonical_dumps(thaw(parameter_schema))).hexdigest()


class ActionContractCatalog:
    def __init__(self, definitions: tuple[ActionContractDefinition, ...]) -> None:
        by_id: dict[str, ActionContractDefinition] = {}
        for definition in definitions:
            if definition.contract_id in by_id:
                raise ToolRegistryValidationError(f"duplicate action contract: {definition.contract_id}")
            by_id[definition.contract_id] = definition
        self._by_id = by_id

    def get(self, contract_id: str) -> ActionContractDefinition | None:
        return self._by_id.get(contract_id)
