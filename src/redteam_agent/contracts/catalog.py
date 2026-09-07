"""Action contract and rule catalogs (SystemDesign AI-control §5, §20).

Each tool binds to a registered action contract keyed by exact ToolRef. The
contract records the parameter-schema digest, target extractor, evidence/
publication/outcome rules, risk/side-effect floor, and the typed prerequisite
contract (``preconditions``/``observes``/``may_change``/``outcome_rule_id``).
The Application-owned ``execution_precondition_digest`` is computed from the
contract's preconditions, so an empty or caller-chosen digest is rejected. The
referenced rules must exist in the registered rule catalog. Phase 0A does not
implement prerequisite search; contracts may declare an explicit empty
prerequisite set.
"""

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
    preconditions: tuple[str, ...] = ()
    observes: tuple[str, ...] = ()
    may_change: tuple[str, ...] = ()
    outcome_rule_id: str = ""

    @property
    def execution_precondition_digest(self) -> str:
        payload = {
            "contract_id": self.contract_id,
            "revision": self.revision,
            "tool_id": self.tool_id,
            "preconditions": list(self.preconditions),
            "observes": list(self.observes),
            "may_change": list(self.may_change),
            "outcome_rule_id": self.outcome_rule_id,
        }
        return hashlib.sha256(b"execution-precondition-v1\x00" + canonical_dumps(payload)).hexdigest()

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
            "execution_precondition_digest": self.execution_precondition_digest,
        }
        return hashlib.sha256(b"action-contract-v1\x00" + canonical_dumps(payload)).hexdigest()

    def reference(self) -> ActionContractReference:
        return ActionContractReference(
            contract_id=self.contract_id, revision=self.revision, digest=self.definition_digest
        )


def parameter_schema_digest(parameter_schema: object) -> str:
    return hashlib.sha256(b"parameter-schema-v1\x00" + canonical_dumps(thaw(parameter_schema))).hexdigest()


class ActionContractCatalog:
    """A Root-provisioned registry of action contracts, keyed by contract id."""

    def __init__(self, definitions: tuple[ActionContractDefinition, ...] = ()) -> None:
        self._by_id: dict[str, ActionContractDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ActionContractDefinition) -> None:
        # Phase 0A has no trusted predicate evaluator.  Accepting free-form
        # predicates would turn a digest match into a fabricated proof, so the
        # only registered contract is the explicit no-additional-preconditions
        # form. Later phases may replace this closed rule with typed predicates.
        if definition.preconditions or definition.observes or definition.may_change:
            raise ToolRegistryValidationError(
                "Phase 0A action contracts cannot declare unevaluated predicates"
            )
        existing = self._by_id.get(definition.contract_id)
        if existing is not None and existing != definition:
            raise ToolRegistryValidationError(f"conflicting action contract: {definition.contract_id}")
        self._by_id[definition.contract_id] = definition

    def get(self, contract_id: str) -> ActionContractDefinition | None:
        return self._by_id.get(contract_id)


class RuleCatalog:
    """A Root-provisioned registry of publication/evidence/outcome rule ids."""

    def __init__(
        self,
        *,
        publication_rule_ids: frozenset[str] = frozenset(),
        evidence_rule_ids: frozenset[str] = frozenset(),
        outcome_rule_ids: frozenset[str] = frozenset(),
    ) -> None:
        self._publication = set(publication_rule_ids)
        self._evidence = set(evidence_rule_ids)
        self._outcome = set(outcome_rule_ids)

    def register_publication(self, rule_id: str) -> None:
        self._publication.add(rule_id)

    def register_evidence(self, rule_id: str) -> None:
        self._evidence.add(rule_id)

    def register_outcome(self, rule_id: str) -> None:
        if rule_id:
            self._outcome.add(rule_id)

    def has_publication(self, rule_id: str) -> bool:
        return rule_id in self._publication

    def has_evidence(self, rule_id: str) -> bool:
        return rule_id in self._evidence

    def has_outcome(self, rule_id: str) -> bool:
        return rule_id == "" or rule_id in self._outcome
