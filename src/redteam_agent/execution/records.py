"""Builders that finalize object-integrity digests for execution records.

Each digest-bearing record is constructed with a placeholder digest, its digest
is computed over the remaining fields through the versioned catalog, and a frozen
copy with the real digest is returned. The repositories re-verify the same digest
on write and read, so a ``model_construct`` bypass or a raw row edit fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.execution.models import (
    LocalResultBinding,
    ProviderTaskBinding,
    RawResultReceipt,
)


def finalize_object_digest[M: BaseModel](
    model: M, *, digest_field: str, digest_name: str, digest_service: DigestService
) -> M:
    """Return a copy of ``model`` with ``digest_field`` set to its object digest."""
    payload = model.model_dump(mode="python")
    payload.pop(digest_field, None)
    digest = digest_service.compute(digest_name, payload)
    return model.model_copy(update={digest_field: digest})


def compute_receipt_digest(receipt: RawResultReceipt, digest_service: DigestService) -> str:
    return digest_service.compute("raw_result_receipt_digest", receipt.model_dump(mode="python"))


def finalize_provider_task_binding(
    binding: ProviderTaskBinding, digest_service: DigestService
) -> ProviderTaskBinding:
    return finalize_object_digest(
        binding, digest_field="binding_digest", digest_name="result_task_binding_digest",
        digest_service=digest_service,
    )


def finalize_local_result_binding(
    binding: LocalResultBinding, digest_service: DigestService
) -> LocalResultBinding:
    return finalize_object_digest(
        binding, digest_field="binding_digest", digest_name="result_task_binding_digest",
        digest_service=digest_service,
    )


def compute_secret_version_bindings_digest(
    secret_version_ids: tuple[str, ...], digest_service: DigestService
) -> str:
    """Digest over the exact, sorted set of bound secret version ids."""
    payload = {"secret_version_ids": sorted(secret_version_ids)}
    return digest_service.compute("secret_version_bindings_digest", payload)


def compute_secret_lifecycle_heads_digest(
    lifecycle_heads: Mapping[str, str], digest_service: DigestService
) -> str:
    """Digest over each bound version's current lifecycle head (sorted by id)."""
    payload = {"lifecycle_heads": [[key, lifecycle_heads[key]] for key in sorted(lifecycle_heads)]}
    return digest_service.compute("secret_lifecycle_heads_digest", payload)


def compute_consumption_id(
    *, claim_id: str, authorization_digest: str, execution_state_version: int, digest_service: DigestService
) -> str:
    """Deterministic consumption id from the target identity/digest/state version.

    A re-request with the same identity reconciles to the same stored record; it
    does not mint a new dispatch/secret authority (SystemDesign §10).
    """
    payload = {
        "claim_id": claim_id,
        "authorization_digest": authorization_digest,
        "execution_state_version": execution_state_version,
    }
    return digest_service.compute("consumption_id_digest", payload)


def compute_progress_digest(
    *, collection_id: str, status: str, last_committed_chunk_sequence: int,
    receipt_digest: str | None, digest_service: DigestService,
) -> str:
    payload = {
        "collection_id": collection_id,
        "status": status,
        "last_committed_chunk_sequence": last_committed_chunk_sequence,
        "receipt_digest": receipt_digest,
    }
    return digest_service.compute("result_progress_digest", payload)


def compute_cancel_intent_digest(
    *, execution_id: str, provider_task_id: str, resolved_adapter_id: str,
    recovery_authority_id: str, reason: str, digest_service: DigestService,
) -> str:
    """Cancel intent digest binds execution/task/adapter/authority/reason only.

    It deliberately excludes any later attempt/request digest so no cyclic digest
    is formed (SystemDesign §21.1.2).
    """
    payload = {
        "execution_id": execution_id,
        "provider_task_id": provider_task_id,
        "resolved_adapter_id": resolved_adapter_id,
        "recovery_authority_id": recovery_authority_id,
        "reason": reason,
    }
    return digest_service.compute("cancel_intent_digest", payload)
