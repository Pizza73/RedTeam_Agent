"""Production startup self-checks (SystemDesign §35.2 / §34.2.2).

These enforce the fail-closed production preconditions before any mission is admitted:
the trusted anchor and key provider must be real (not the in-memory test doubles), the
topology must be single-host, the schema must already exist (no auto-migration), the
standard AEAD backend must be present, and the ``tpm2_nv`` witness tools must be usable.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.audit.nv_witness import NvExtendDigestWitness, Tpm2NvCliWitness
from redteam_agent.crypto.aead import cryptography_available
from redteam_agent.errors import (
    EncryptionUnavailableError,
    GenerationWitnessError,
    ProductionCompositionError,
    SchemaMigrationRequiredError,
)
from redteam_agent.storage.database import Database

# Tables that must already exist for a normal (non-provisioning) production start.
_REQUIRED_TABLES = ("kv_store", "executions", "occ_store", "checkpoints", "writes")


@dataclass(frozen=True)
class ProductionTopology:
    single_host: bool
    tpm_provider: str
    application_db_paths: tuple[str, ...]
    composition_roots: int


def reject_test_doubles(*, witness: object, key_provider: object) -> None:
    """Refuse an in-memory witness, an in-memory key provider, or a non-tpm2_nv witness."""
    if not getattr(witness, "is_production", False):
        raise ProductionCompositionError("production rejects a non-production (in-memory) TPM witness")
    if getattr(witness, "provider_kind", "") != "tpm2_nv":
        raise ProductionCompositionError("production requires the tpm2_nv witness provider")
    if not getattr(key_provider, "is_production", False):
        raise ProductionCompositionError("production rejects the in-memory envelope key provider")


def check_topology(topology: ProductionTopology) -> None:
    if not topology.single_host:
        raise ProductionCompositionError("Phase 0C production is single-host; multi-host is rejected at startup")
    if topology.tpm_provider != "tpm2_nv":
        raise ProductionCompositionError("production requires a single tpm2_nv provider")
    if len(topology.application_db_paths) != 1:
        raise ProductionCompositionError("production requires exactly one application database")
    if topology.composition_roots != 1:
        raise ProductionCompositionError("production requires exactly one composition root")


def check_aead_backend() -> None:
    if not cryptography_available():
        raise EncryptionUnavailableError("standard AEAD backend (cryptography) is required in production")


def check_key_provider(key_provider: object) -> None:
    """Require the production provider to verify its own domain/root configuration."""
    self_check = getattr(key_provider, "self_check", None)
    if not callable(self_check):
        raise ProductionCompositionError("production key provider requires a startup self-check")
    self_check()
    if not isinstance(getattr(key_provider, "provider_identity", None), str):
        raise ProductionCompositionError("production key provider identity is missing")


def check_schema_read_only(database: Database) -> None:
    """Read-only schema inspection; a missing/unknown schema fails closed (no migration)."""
    missing = [table for table in _REQUIRED_TABLES if not database.has_table(table)]
    if missing:
        raise SchemaMigrationRequiredError(
            f"normal startup found a missing/unknown schema ({', '.join(missing)}); "
            "an explicit stopped-worker migration is required"
        )
    if not database.graph_checkpoint_schema_is_current():
        raise SchemaMigrationRequiredError(
            "normal startup found an unknown LangGraph checkpoint schema; "
            "an explicit stopped-worker migration is required"
        )


def check_tpm_witness(witness: NvExtendDigestWitness) -> None:
    if isinstance(witness, Tpm2NvCliWitness):
        witness.self_check()  # raises GenerationWitnessError if tpm2 tools are absent
    else:  # pragma: no cover - defensive; reject_test_doubles already ran
        raise GenerationWitnessError("production witness must be the tpm2_nv CLI witness")
