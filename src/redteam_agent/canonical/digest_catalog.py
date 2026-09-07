"""Versioned normative digest catalog (SystemDesign §32.2, Phase 0A subset).

Each ``*_digest`` field used by the authorization kernel is registered here
exactly once. The catalog owns *only* the digest computation rules: which
fields are excluded, the domain separator, and the algorithm. Semantics and
policy live elsewhere. Registering an unknown name, a duplicate name, or a
non-sha256 algorithm fails closed at construction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from redteam_agent.canonical.canonical_json import canonical_dumps
from redteam_agent.errors import DigestCatalogError

CATALOG_REVISION = "digest-catalog-v1"


@dataclass(frozen=True)
class DigestDefinition:
    """The rule for computing one named digest."""

    digest_name: str
    schema_version: str
    owner_component: str
    canonical_model: str = ""
    included_field_paths: tuple[str, ...] = ()
    excluded_field_paths: tuple[str, ...] = ()
    algorithm: str = "sha256"

    def __post_init__(self) -> None:
        if self.algorithm != "sha256":
            raise DigestCatalogError(f"unsupported algorithm for {self.digest_name}: {self.algorithm}")

    @property
    def domain_separator(self) -> str:
        return f"{CATALOG_REVISION}:{self.digest_name}:{self.schema_version}"

    @property
    def definition_digest(self) -> str:
        payload = {
            "digest_name": self.digest_name,
            "schema_version": self.schema_version,
            "owner_component": self.owner_component,
            "canonical_model": self.canonical_model,
            "included_field_paths": sorted(self.included_field_paths),
            "excluded_field_paths": sorted(self.excluded_field_paths),
            "algorithm": self.algorithm,
        }
        return hashlib.sha256(canonical_dumps(payload)).hexdigest()


def _obj(name: str, owner: str, *, exclude_self: str | None = None) -> DigestDefinition:
    excluded = (exclude_self,) if exclude_self else (name,)
    return DigestDefinition(
        digest_name=name,
        schema_version="v1",
        owner_component=owner,
        canonical_model=name,
        excluded_field_paths=excluded,
    )


def _explicit(name: str, owner: str, included: tuple[str, ...] = ()) -> DigestDefinition:
    return DigestDefinition(
        digest_name=name,
        schema_version="v1",
        owner_component=owner,
        canonical_model=name,
        included_field_paths=included,
    )


_AUTHORIZATION_DIGEST_FIELDS = (
    "mission_id", "mission_revision", "authorization_epoch", "proposal_digest", "tool_ref",
    "resolved_adapter", "resolved_adapter_id", "session_id", "arguments", "normalized_targets",
    "target_dispatch_bindings", "authorized_data_access", "effective_risk", "side_effect",
    "approval_rule", "policy_version", "registry_digest", "available_tool_snapshot_id",
    "available_tool_snapshot_digest", "session_security_context_digest", "adapter_capabilities_digest",
    "sandbox_capabilities_digest", "remote_mcp_trust_policy_digest", "action_contract_ref",
    "execution_precondition_digest",
)

_DEFINITIONS: tuple[DigestDefinition, ...] = (
    # Explicit-input digests: the caller supplies exactly the included fields;
    # the service rejects a missing or unknown field (§32.2 field-set fixing).
    _explicit(
        "proposal_digest", "plan",
        ("schema_version", "objective", "phase", "tool_ref", "requested_targets", "session_id", "arguments"),
    ),
    _explicit("authorization_digest", "policy", _AUTHORIZATION_DIGEST_FIELDS),
    _explicit("execution_scope_digest", "tools", ("allowed", "prohibited", "implemented_scope_types")),
    _explicit("session_security_context_digest", "session", ("sessions",)),
    _explicit("adapter_capabilities_digest", "adapters", ("adapters",)),
    _explicit("sandbox_capabilities_digest", "sandbox", ("sandboxes",)),
    _explicit("remote_mcp_trust_policy_digest", "adapters", ("policies",)),
    # Generic state digests hash the supplied payload as-is (variable shape).
    _explicit("authorization_state_digest", "policy"),
    _explicit("dns_resolution_digest", "policy"),
    # Object-integrity digests: caller supplies the full record; the record's
    # own digest field is excluded.
    _obj("decision_digest", "policy"),
    _obj("grant_digest", "context"),
    _obj("request_digest", "approval"),
    _obj("record_digest", "approval"),
    _obj("presentation_digest", "approval"),
    _obj("registry_digest", "tools"),
    _obj("snapshot_digest", "tools"),
    _obj("binding_digest", "policy"),
    _obj("policy_digest", "policy"),
    _obj("mission_revision_digest", "mission"),
    _obj("profile_digest", "llm"),
    _obj("sandbox_binding_digest", "sandbox"),
    # Phase 0B execution-safety object-integrity digests. Each excludes its own
    # digest field; the record's identity/binding fields are covered by the hash.
    _obj("execution_record_digest", "executor", exclude_self="record_digest"),
    _obj("dispatch_claim_digest", "executor", exclude_self="record_digest"),
    _obj("result_task_binding_digest", "executor", exclude_self="binding_digest"),
    _obj("result_collection_state_digest", "executor", exclude_self="record_digest"),
    _obj("result_ingestion_state_digest", "executor", exclude_self="record_digest"),
    _obj("raw_control_metadata_digest", "executor", exclude_self="record_digest"),
    _obj("execution_result_projection_digest", "executor", exclude_self="projection_digest"),
    _obj("mission_execution_budget_digest", "executor", exclude_self="record_digest"),
    _obj("execution_recovery_authority_digest", "executor", exclude_self="authority_digest"),
    _obj("cancel_attempt_digest", "executor", exclude_self="record_digest"),
    # Explicit-input progress/intent digests (variable-shape payloads).
    _explicit("raw_result_receipt_digest", "executor"),
    _explicit("result_progress_digest", "executor"),
    _explicit("cancel_intent_digest", "executor"),
    _explicit("consumption_id_digest", "executor"),
    _explicit("secret_version_bindings_digest", "executor"),
    _explicit("secret_lifecycle_heads_digest", "executor"),
)


class DigestCatalog:
    """An immutable, validated collection of digest definitions."""

    def __init__(self, definitions: tuple[DigestDefinition, ...]) -> None:
        by_name: dict[str, DigestDefinition] = {}
        for definition in definitions:
            if definition.digest_name in by_name:
                raise DigestCatalogError(f"duplicate digest definition: {definition.digest_name}")
            by_name[definition.digest_name] = definition
        self._by_name = by_name
        self.revision = CATALOG_REVISION

    def get(self, digest_name: str) -> DigestDefinition:
        try:
            return self._by_name[digest_name]
        except KeyError as exc:
            raise DigestCatalogError(f"unregistered digest name: {digest_name}") from exc

    def names(self) -> frozenset[str]:
        return frozenset(self._by_name)

    @property
    def catalog_digest(self) -> str:
        payload = [
            definition.definition_digest for definition in sorted(self._by_name.values(), key=lambda d: d.digest_name)
        ]
        return hashlib.sha256(canonical_dumps({"revision": self.revision, "definitions": payload})).hexdigest()


DEFAULT_DIGEST_CATALOG = DigestCatalog(_DEFINITIONS)
