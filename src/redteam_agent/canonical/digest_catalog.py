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


def _obj_ex(name: str, owner: str, excluded: tuple[str, ...]) -> DigestDefinition:
    """Object-integrity digest excluding several fields (e.g. digest + auth tag)."""
    return DigestDefinition(
        digest_name=name,
        schema_version="v1",
        owner_component=owner,
        canonical_model=name,
        excluded_field_paths=excluded,
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
    # --- Phase 0C: data security / audit ---------------------------------
    # Envelope encryption key metadata (SystemDesign §34.1).
    _obj("domain_key_metadata_digest", "crypto", exclude_self="metadata_digest"),
    _obj("encryption_metadata_digest", "crypto", exclude_self="metadata_digest"),
    _obj("key_destruction_result_digest", "crypto", exclude_self="result_digest"),
    # Encrypted raw result quarantine (SystemDesign §33.1).
    _obj("quarantine_metadata_digest", "quarantine", exclude_self="metadata_digest"),
    # Secret lifecycle (SystemDesign §34).
    _obj("secret_version_metadata_digest", "secret_store", exclude_self="metadata_digest"),
    _obj("secret_lifecycle_event_digest", "secret_store", exclude_self="event_digest"),
    _obj("secret_confirmation_digest", "secret_store", exclude_self="record_digest"),
    _explicit("secret_lifecycle_head_digest", "secret_store"),
    _explicit("secret_logical_head_digest", "secret_store"),
    _explicit("secret_active_head_digest", "secret_store"),
    _explicit("migration_plan_digest", "secret_store"),
    # Typed leases + deployment epoch (SystemDesign §10.3 / §32).
    _obj("collection_lease_digest", "collection", exclude_self="record_digest"),
    _obj("ingestion_lease_digest", "ingestion", exclude_self="record_digest"),
    _obj("deployment_epoch_digest", "composition", exclude_self="record_digest"),
    # Secure ingestion publication (SystemDesign §33 / §33.2).
    _obj("publication_rule_digest", "ingestion", exclude_self="rule_digest"),
    _obj("artifact_digest", "ingestion", exclude_self="artifact_digest"),
    _obj("redaction_metadata_digest", "ingestion", exclude_self="redaction_metadata_digest"),
    _obj("manifest_digest", "ingestion", exclude_self="manifest_digest"),
    _obj("secure_ingestion_state_digest", "ingestion", exclude_self="record_digest"),
    # Verified erasure (SystemDesign §33.2 / §34.1).
    _obj("deletion_intent_digest", "verified_erasure", exclude_self="intent_digest"),
    _obj("erasure_claim_digest", "verified_erasure", exclude_self="claim_digest"),
    _obj("cleanup_intent_digest", "verified_erasure", exclude_self="intent_digest"),
    _obj("cleanup_claim_digest", "verified_erasure", exclude_self="claim_digest"),
    _explicit("copy_inventory_digest", "verified_erasure"),
    _explicit("erasure_evidence_digest", "verified_erasure"),
    # Audit hash chain + TPM-witnessed generation (SystemDesign §34.2).
    _obj("audit_event_digest", "logging", exclude_self="event_digest"),
    _explicit("audit_head_digest", "logging",
              ("mission_id", "head_sequence", "head_event_digest", "updated_at_iso")),
    _obj_ex("generation_record_digest", "logging", ("record_digest", "record_authentication_tag")),
    _explicit("generation_commit_payload_digest", "logging"),
    # witness_digest uses the TPM raw-byte formula SHA256(raw prev || raw payload);
    # it is registered for catalog coverage but computed by the generation coordinator,
    # never through canonical-JSON (SystemDesign §34.2.1).
    _explicit("witness_digest", "logging"),
    _obj("generation_witness_policy_digest", "logging", exclude_self="policy_digest"),
    _obj("wrapped_key_state_digest", "logging", exclude_self="state_digest"),
    _obj("nv_index_identity_digest", "logging", exclude_self="identity_digest"),
    _obj("security_state_binding_digest", "logging", exclude_self="binding_digest"),
    _explicit("security_projection_digest", "logging"),
    _obj("critical_witness_intent_digest", "logging", exclude_self="intent_digest"),
    _obj("trust_recovery_approval_digest", "logging", exclude_self="approval_digest"),
    _obj("trust_recovery_consumption_digest", "logging", exclude_self="consumption_digest"),
    # --- Phase 1: knowledge, goal evaluation and bounded workflow --------
    _obj("knowledge_security_head_digest", "knowledge", exclude_self="head_digest"),
    _obj("knowledge_observation_digest", "knowledge", exclude_self="observation_digest"),
    _obj("goal_evaluation_digest", "goal", exclude_self="evaluation_digest"),
    _explicit("goal_source_snapshot_digest", "goal", ("sessions",)),
    _obj("agent_checkpoint_digest", "agent", exclude_self="checkpoint_digest"),
    _obj("planner_context_envelope_digest", "agent", exclude_self="envelope_digest"),
    _explicit("action_candidate_digest", "agent"),
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
