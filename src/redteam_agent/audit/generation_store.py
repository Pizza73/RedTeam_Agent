"""Authenticated SQLite generation record / immutable blob store (SystemDesign §34.2).

Records and blobs live in the generic OCC store. A record's identity is unique per
``(namespace, trust_epoch, generation)`` and per ``(namespace, trust_epoch,
witness_digest)`` (a companion index row enforces the second). Each record carries a
``record_authentication_tag`` produced by an opaque authentication key that is never
stored in the database or config (TPM-sealed / OS key store in production; an in-memory
opaque handle in tests). Reads verify the record digest, the authentication tag and the
referenced immutable blob before returning.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol

from redteam_agent.audit.models import GenerationCommitRecord, GenerationNamespace, ImmutableGenerationBlob
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AnchorRecoveryRequiredError, GenerationWitnessError
from redteam_agent.storage.database import Database

_RECORD_NS = "generation_record"
_WITNESS_NS = "generation_record_witness"
_BLOB_NS = "generation_blob"


class RecordAuthenticationKey(Protocol):
    is_production: bool

    def authenticate(self, record_digest: str) -> str: ...
    def verify(self, record_digest: str, tag: str) -> bool: ...


class InMemoryRecordAuthenticationKey:
    """Opaque HMAC-SHA256 record authentication key held in memory (not in the DB)."""

    is_production = False

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)

    def authenticate(self, record_digest: str) -> str:
        return hmac.new(self._key, record_digest.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, record_digest: str, tag: str) -> bool:
        return hmac.compare_digest(self.authenticate(record_digest), tag)


def blob_id_for(namespace: GenerationNamespace, blob_digest: str) -> str:
    return f"blob-{namespace}-{blob_digest}"


class GenerationRecordStore:
    def __init__(self, database: Database, digest_service: DigestService, auth_key: RecordAuthenticationKey) -> None:
        self._db = database
        self._ds = digest_service
        self._auth = auth_key

    @property
    def database(self) -> Database:
        return self._db

    @property
    def authentication_is_production(self) -> bool:
        return bool(getattr(self._auth, "is_production", False))

    # --- digests ----------------------------------------------------------

    def record_digest(self, record_fields: dict[str, object]) -> str:
        payload = {k: v for k, v in record_fields.items()
                   if k not in ("record_digest", "record_authentication_tag")}
        return self._ds.compute("generation_record_digest", payload)

    def authenticate(self, record_digest: str) -> str:
        return self._auth.authenticate(record_digest)

    # --- writes (within an ApplicationUnitOfWork) ------------------------

    def store(self, record: GenerationCommitRecord, blob: ImmutableGenerationBlob) -> None:
        import json

        record_json = json.dumps(record.model_dump(mode="json"), sort_keys=True)
        blob_json = json.dumps(blob.model_dump(mode="json"), sort_keys=True)
        gen_key = f"{record.namespace}/{record.trust_epoch}/{record.generation}"
        wit_key = f"{record.namespace}/{record.trust_epoch}/{record.witness_digest}"
        self._db.occ_insert_idempotent(_RECORD_NS, gen_key, 1, record_json)
        self._db.occ_insert_idempotent(_WITNESS_NS, wit_key, 1, json.dumps(
            {"generation": record.generation}, sort_keys=True))
        self._db.occ_insert_idempotent(_BLOB_NS, blob.blob_id, 1, blob_json)

    # --- reads ------------------------------------------------------------

    def _load_record(self, gen_key: str) -> GenerationCommitRecord | None:
        row = self._db.occ_get(_RECORD_NS, gen_key)
        if row is None:
            return None
        record = GenerationCommitRecord.model_validate_json(row[1])
        expected = self.record_digest(record.model_dump(mode="python"))
        if not hmac.compare_digest(expected, record.record_digest):
            raise GenerationWitnessError("generation record digest mismatch")
        if not self._auth.verify(record.record_digest, record.record_authentication_tag):
            raise GenerationWitnessError("generation record authentication tag mismatch")
        return record

    def get_record(
        self, namespace: GenerationNamespace, trust_epoch: int, generation: int
    ) -> GenerationCommitRecord | None:
        return self._load_record(f"{namespace}/{trust_epoch}/{generation}")

    def get_by_witness(
        self, namespace: GenerationNamespace, trust_epoch: int, witness_digest: str
    ) -> GenerationCommitRecord | None:
        import json

        row = self._db.occ_get(_WITNESS_NS, f"{namespace}/{trust_epoch}/{witness_digest}")
        if row is None:
            return None
        generation = int(json.loads(row[1])["generation"])
        record = self._load_record(f"{namespace}/{trust_epoch}/{generation}")
        if record is None or record.witness_digest != witness_digest:
            raise AnchorRecoveryRequiredError("witness index points to a missing/mismatched record")
        return record

    def get_blob(self, blob_id: str) -> ImmutableGenerationBlob | None:
        row = self._db.occ_get(_BLOB_NS, blob_id)
        if row is None:
            return None
        blob = ImmutableGenerationBlob.model_validate_json(row[1])
        recomputed = hashlib.sha256(f"gen-blob-v1\x00{blob.content}".encode()).hexdigest()
        if not hmac.compare_digest(recomputed, blob.blob_digest):
            raise GenerationWitnessError("generation blob digest mismatch")
        if not hmac.compare_digest(blob.blob_id, blob_id):
            raise GenerationWitnessError("generation blob row key / model id mismatch")
        expected_id = blob_id_for(blob.namespace, recomputed)
        if not hmac.compare_digest(expected_id, blob_id):
            raise GenerationWitnessError("generation blob content-address mismatch")
        expected_kind = "audit_head_set" if blob.namespace == "audit_head" else "wrapped_key_state"
        if blob.content_kind != expected_kind:
            raise GenerationWitnessError("generation blob namespace / content kind mismatch")
        return blob

    def latest_generation(self, namespace: GenerationNamespace, trust_epoch: int) -> int | None:
        rows = self._db.occ_get_all(_RECORD_NS)
        prefix = f"{namespace}/{trust_epoch}/"
        gens = [int(key.rsplit("/", 1)[1]) for key, _v, _j in rows if key.startswith(prefix)]
        return max(gens) if gens else None
