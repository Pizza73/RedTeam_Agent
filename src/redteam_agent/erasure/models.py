"""Quarantine deletion intents and single-use erasure claims (SystemDesign §33.2).

Three intent types carry disjoint required evidence: ``post_ingestion`` needs the
committed publication trail (manifest); ``retention_expiry`` needs the receipt + final
ingestion evidence; ``incomplete_collection_expiry`` needs partial ciphertext / chunk
progress and requires neither receipt nor manifest. The repository only ever exposes a
*consumed* claim (created and consumed in the same state-transition transaction).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.models.base import StrictImmutableBoundaryModel

DeletionIntentType = Literal["post_ingestion", "retention_expiry", "incomplete_collection_expiry"]
DeletionReason = Literal["POST_INGESTION", "EVIDENCE_RETENTION_EXPIRED", "INCOMPLETE_COLLECTION_EXPIRED"]

_REASON_FOR: dict[DeletionIntentType, DeletionReason] = {
    "post_ingestion": "POST_INGESTION",
    "retention_expiry": "EVIDENCE_RETENTION_EXPIRED",
    "incomplete_collection_expiry": "INCOMPLETE_COLLECTION_EXPIRED",
}


class QuarantineDeletionIntent(StrictImmutableBoundaryModel):
    deletion_intent_id: str = Field(min_length=1)
    intent_type: DeletionIntentType
    reason: DeletionReason
    quarantine_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    ingestion_id: str | None
    encryption_metadata_id: str = Field(min_length=1)
    key_metadata_digest: str = Field(min_length=1)
    resource_copy_inventory_digest: str = Field(min_length=1)
    # May be empty for an uncommitted/incomplete quarantine (no committed ciphertext yet).
    quarantine_ciphertext_digest: str
    result_task_binding_digest: str = Field(min_length=1)
    retention_deadline: datetime
    # post_ingestion evidence
    manifest_id: str | None
    manifest_digest: str | None
    # retention_expiry evidence
    receipt_id: str | None
    receipt_digest: str | None
    final_ingestion_state: str | None
    # incomplete_collection_expiry evidence
    last_committed_chunk_sequence: int | None
    quarantine_status: str | None
    created_at: datetime
    intent_digest: str = Field(min_length=1)

    @model_validator(mode="after")
    def _type_specific_evidence(self) -> QuarantineDeletionIntent:
        if self.reason != _REASON_FOR[self.intent_type]:
            raise ValueError("deletion intent reason does not match its type")
        if self.intent_type == "post_ingestion":
            if self.manifest_id is None or self.manifest_digest is None or self.ingestion_id is None:
                raise ValueError("post_ingestion intent requires manifest and ingestion bindings")
        elif self.intent_type == "retention_expiry":
            if self.receipt_id is None or self.receipt_digest is None or self.final_ingestion_state is None:
                raise ValueError("retention_expiry intent requires receipt and final ingestion evidence")
            if self.manifest_id is not None:
                raise ValueError("retention_expiry intent must not carry a manifest")
        else:  # incomplete_collection_expiry
            if self.last_committed_chunk_sequence is None or self.quarantine_status is None:
                raise ValueError("incomplete_collection_expiry intent requires chunk/status evidence")
            if self.manifest_id is not None or self.receipt_id is not None:
                raise ValueError("incomplete_collection_expiry intent requires neither manifest nor receipt")
        return self


class QuarantineErasureClaim(StrictImmutableBoundaryModel):
    erasure_id: str = Field(min_length=1)
    deletion_intent_id: str = Field(min_length=1)
    intent_type: DeletionIntentType
    quarantine_id: str = Field(min_length=1)
    encryption_metadata_id: str = Field(min_length=1)
    key_metadata_digest: str = Field(min_length=1)
    resource_copy_inventory_digest: str = Field(min_length=1)
    intent_digest: str = Field(min_length=1)
    claim_state: Literal["consumed"] = "consumed"
    consumption_id: str = Field(min_length=1)
    consumed_at: datetime
    claim_digest: str = Field(min_length=1)


def reason_for(intent_type: DeletionIntentType) -> DeletionReason:
    return _REASON_FOR[intent_type]
