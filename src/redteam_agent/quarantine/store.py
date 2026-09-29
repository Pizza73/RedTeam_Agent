"""Encrypted raw-result quarantine store, streaming sink and reader (SystemDesign §33.1).

The store owns one resource DEK per quarantine (domain ``raw_result_quarantine``). The
sink encrypts each chunk with a fresh nonce and a domain/mission/execution/quarantine
AAD, writing ciphertext to a fence-specific staging prefix in bounded memory (never
buffering the whole result). The reader streams plaintext back chunk-by-chunk for
secure ingestion. Constructing a sink/reader (the factory/lookup) has no side effect;
only ``write_*`` and ``unlink`` perform I/O. Cryptographic erasure destroys the DEK, so
the ciphertext becomes permanently undecryptable regardless of blob retention.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Literal

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.crypto.key_provider import EncryptionKeyProvider, OpaqueKeyHandle
from redteam_agent.crypto.models import EncryptionMetadata, EnvelopeCiphertext
from redteam_agent.errors import RawResultQuarantineError
from redteam_agent.execution.models import RawArtifactMetadata, RawResultReceipt, ResultTaskBinding
from redteam_agent.quarantine.blob_store import QuarantineBlobStore, chunk_handle, staging_prefix
from redteam_agent.quarantine.models import RawResultQuarantineMetadata, RawResultQuarantineStatus
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database

_META_NS = "raw_result_quarantine_metadata"
_ENCRYPTION_NS = "encryption_metadata"
_CIPHERTEXT_DOMAIN = b"phase0c-quarantine-stream-v1"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EncryptedStreamingQuarantineSink:
    """A bounded-memory AES-GCM streaming sink writing to fence-specific staging."""

    def __init__(
        self, *, sink_id: str, quarantine_id: str, execution_id: str, mission_id: str,
        task_binding_digest: str, storage_handle: str, key_handle: OpaqueKeyHandle,
        encryption_metadata_id: str, blob_store: QuarantineBlobStore, max_output_bytes: int,
        committed_at: datetime, authorize_mutation: Callable[[Callable[[], None]], None],
        max_single_chunk_bytes: int = 1024 * 1024,
    ) -> None:
        self._sink_id = sink_id
        self._quarantine_id = quarantine_id
        self._execution_id = execution_id
        self._mission_id = mission_id
        self._task_binding_digest = task_binding_digest
        self._prefix = storage_handle
        self._handle = key_handle
        self._encryption_metadata_id = encryption_metadata_id
        self._blobs = blob_store
        self._max_output_bytes = max_output_bytes
        self._committed_at = committed_at
        self._authorize_mutation = authorize_mutation
        self._max_single_chunk_bytes = max_single_chunk_bytes
        self._hasher = hashlib.sha256(_CIPHERTEXT_DOMAIN)
        self._counts = {"stdout": 0, "stderr": 0}
        self._artifact_count = 0
        self._total_plain = 0
        self._chunk_count = 0
        self._sequence = {"stdout": 0, "stderr": 0, "artifact": 0}
        self.max_single_chunk_bytes = 0
        self._state: str = "OPEN"
        self._receipt: RawResultReceipt | None = None

    @property
    def sink_id(self) -> str:
        return self._sink_id

    @property
    def state(self) -> str:
        return self._state

    def _require_open(self) -> None:
        if self._state != "OPEN":
            raise RawResultQuarantineError(f"quarantine sink is not open (state={self._state})")

    def _write_chunk(self, stream: str, chunk: bytes) -> None:
        self._require_open()
        if len(chunk) > self._max_single_chunk_bytes:
            raise RawResultQuarantineError("chunk exceeds the bounded sink buffer")
        self.max_single_chunk_bytes = max(self.max_single_chunk_bytes, len(chunk))
        self._total_plain += len(chunk)
        if self._total_plain > self._max_output_bytes:
            self._state = "RECOVERY_REQUIRED"
            raise RawResultQuarantineError("raw result exceeded the tool output cap")
        sequence = self._sequence[stream]
        self._sequence[stream] = sequence + 1
        nonce = os.urandom(12)
        envelope = self._handle.encrypt(
            encryption_metadata_id=self._encryption_metadata_id, nonce=nonce, plaintext=chunk,
            aad_fields={"mission_id": self._mission_id, "execution_id": self._execution_id,
                        "quarantine_id": self._quarantine_id, "stream": stream, "sequence": sequence},
        )
        handle = chunk_handle(self._prefix, stream, sequence)
        encoded = json.dumps(envelope.model_dump(mode="json"), sort_keys=True).encode("utf-8")
        self._authorize_mutation(lambda: self._blobs.put(handle, encoded))
        self._hasher.update(bytes.fromhex(envelope.ciphertext_digest))
        self._chunk_count += 1

    def write_stdout(self, chunk: bytes) -> None:
        self._write_chunk("stdout", chunk)
        self._counts["stdout"] += len(chunk)

    def write_stderr(self, chunk: bytes) -> None:
        self._write_chunk("stderr", chunk)
        self._counts["stderr"] += len(chunk)

    def write_artifact(self, metadata: RawArtifactMetadata, chunks: object) -> None:
        self._require_open()
        for chunk in chunks:  # type: ignore[attr-defined]
            self._write_chunk("artifact", chunk)
        self._artifact_count += 1

    def commit(self) -> RawResultReceipt:
        if self._receipt is not None:
            return self._receipt
        self._require_open()
        self._authorize_mutation(lambda: None)
        self._receipt = RawResultReceipt(
            receipt_id=f"receipt-{self._execution_id}", execution_id=self._execution_id,
            quarantine_id=self._quarantine_id, task_binding_digest=self._task_binding_digest,
            stdout_bytes=self._counts["stdout"], stderr_bytes=self._counts["stderr"],
            artifact_count=self._artifact_count, ciphertext_digest=self._hasher.hexdigest(),
            committed_at=self._committed_at,
        )
        self._state = "COMMITTED"
        self._handle.close()
        return self._receipt

    @property
    def chunk_count(self) -> int:
        return self._chunk_count

    @property
    def size_bytes(self) -> int:
        return self._total_plain

    def abort(self) -> None:
        if self._state == "COMMITTED":
            raise RawResultQuarantineError("cannot abort a committed quarantine sink")
        self._authorize_mutation(lambda: None)
        self._state = "ABORTED"
        self._handle.close()


class EncryptedQuarantineReader:
    """Streams plaintext back from a committed quarantine (secure ingestion input)."""

    def __init__(
        self, *, metadata: RawResultQuarantineMetadata, key_handle: OpaqueKeyHandle,
        blob_store: QuarantineBlobStore,
    ) -> None:
        self._metadata = metadata
        self._handle = key_handle
        self._blobs = blob_store

    def _chunks(self, stream: str) -> Iterator[tuple[int, EnvelopeCiphertext]]:
        prefix = f"{self._metadata.storage_handle}/{stream}"
        for handle in self._blobs.list_prefix(prefix):
            sequence = int(handle.rsplit("/", 1)[1])
            envelope = EnvelopeCiphertext.model_validate_json(self._blobs.get(handle).decode("utf-8"))
            yield sequence, envelope

    def iter_stream(self, stream: Literal["stdout", "stderr", "artifact"]) -> Iterator[bytes]:
        for sequence, envelope in sorted(self._chunks(stream), key=lambda item: item[0]):
            yield self._handle.decrypt(
                record=envelope,
                aad_fields={"mission_id": self._metadata.mission_id, "execution_id": self._metadata.execution_id,
                            "quarantine_id": self._metadata.quarantine_id, "stream": stream, "sequence": sequence},
            )

    def verify_ciphertext_digest(self) -> None:
        hasher = hashlib.sha256(_CIPHERTEXT_DOMAIN)
        for stream in ("stdout", "stderr", "artifact"):
            for _seq, envelope in sorted(self._chunks(stream), key=lambda item: item[0]):
                hasher.update(bytes.fromhex(envelope.ciphertext_digest))
        if hasher.hexdigest() != self._metadata.ciphertext_digest:
            raise RawResultQuarantineError("quarantine ciphertext digest mismatch on read-back")

    def close(self) -> None:
        self._handle.close()


class EncryptedQuarantineStore:
    def __init__(
        self, *, database: Database, blob_store: QuarantineBlobStore,
        key_provider: EncryptionKeyProvider, digest_service: DigestService, clock: Clock,
    ) -> None:
        self._db = database
        self._blobs = blob_store
        self._keys = key_provider
        self._ds = digest_service
        self._clock = clock

    # --- metadata ---------------------------------------------------------

    def _metadata_digest(self, fields: dict[str, object]) -> str:
        payload = {k: v for k, v in fields.items() if k != "metadata_digest"}
        return self._ds.compute("quarantine_metadata_digest", payload)

    def _finalize(self, metadata: RawResultQuarantineMetadata) -> RawResultQuarantineMetadata:
        digest = self._metadata_digest(metadata.model_dump(mode="python"))
        return metadata.model_copy(update={"metadata_digest": digest})

    def get_metadata(self, quarantine_id: str) -> RawResultQuarantineMetadata | None:
        row = self._db.occ_get(_META_NS, quarantine_id)
        if row is None:
            return None
        metadata = RawResultQuarantineMetadata.model_validate_json(row[1])
        payload = {k: v for k, v in metadata.model_dump(mode="python").items() if k != "metadata_digest"}
        self._ds.verify("quarantine_metadata_digest", payload, metadata.metadata_digest)
        return metadata

    def encryption_metadata(self, quarantine_id: str) -> EncryptionMetadata:
        row = self._db.occ_get(_ENCRYPTION_NS, quarantine_id)
        if row is None:
            raise RawResultQuarantineError("quarantine encryption metadata missing")
        return EncryptionMetadata.model_validate_json(row[1])

    def encryption_key_metadata_digest(self, quarantine_id: str) -> str:
        return self.encryption_metadata(quarantine_id).metadata_digest

    def _encryption_metadata(self, quarantine_id: str) -> EncryptionMetadata:
        return self.encryption_metadata(quarantine_id)

    def _version(self, quarantine_id: str) -> int | None:
        row = self._db.occ_get(_META_NS, quarantine_id)
        return None if row is None else row[0]

    def _store_metadata(self, metadata: RawResultQuarantineMetadata) -> None:
        text = json.dumps(metadata.model_dump(mode="json"), sort_keys=True)
        own_txn = not self._db.in_transaction
        if own_txn:
            self._db.connection.execute("BEGIN")
        try:
            existing = self._version(metadata.quarantine_id)
            if existing is None:
                self._db.occ_insert(_META_NS, metadata.quarantine_id, 1, text)
            else:
                self._db.occ_update(_META_NS, metadata.quarantine_id, expected_version=existing,
                                    new_version=existing + 1, json_text=text)
        except BaseException:
            if own_txn:
                self._db.connection.rollback()
            raise
        if own_txn:
            self._db.connection.commit()

    # --- lifecycle (called within the caller's unit of work) -------------

    def create_quarantine(
        self, *, quarantine_id: str, mission_id: str, mission_revision: int, execution_id: str,
        task_binding: ResultTaskBinding, deployment_epoch: int, fencing_token: int, retention_until: datetime,
    ) -> RawResultQuarantineMetadata:
        expected_prefix = staging_prefix(quarantine_id, deployment_epoch, fencing_token)
        existing = self.get_metadata(quarantine_id)
        if existing is not None:
            if (
                existing.execution_id != execution_id
                or existing.task_binding.binding_digest != task_binding.binding_digest
            ):
                raise RawResultQuarantineError("existing quarantine binding mismatch")
            if existing.storage_handle == expected_prefix:
                return existing
            if existing.status not in ("OPEN", "STREAMING", "RECOVERY_REQUIRED", "ABORTED"):
                raise RawResultQuarantineError("committed quarantine cannot be rebound to a new fence")
            restaged = self._finalize(existing.model_copy(update={
                "storage_handle": expected_prefix,
                "ciphertext_digest": "",
                "size_bytes": 0,
                "chunk_count": 0,
                "committed_at": None,
                "status": "OPEN",
                "metadata_digest": "pending",
            }))
            self._store_metadata(restaged)
            return restaged
        enc = self._keys.create_resource_key(
            domain="raw_result_quarantine", resource_binding_type="quarantine_id", resource_binding_id=quarantine_id
        )
        self._db.occ_insert_idempotent(
            _ENCRYPTION_NS, quarantine_id, 1, json.dumps(enc.model_dump(mode="json"), sort_keys=True)
        )
        metadata = self._finalize(RawResultQuarantineMetadata(
            quarantine_id=quarantine_id, mission_id=mission_id, mission_revision=mission_revision,
            execution_id=execution_id, task_binding=task_binding, encryption_metadata_id=enc.resource_key_id,
            storage_handle=expected_prefix, ciphertext_digest="", size_bytes=0, chunk_count=0, committed_at=None,
            retention_until=retention_until, status="OPEN", metadata_digest="pending",
        ))
        self._store_metadata(metadata)
        return metadata

    def open_writer(
        self, quarantine_id: str, *, sink_id: str, task_binding_digest: str, max_output_bytes: int,
        deployment_epoch: int, fencing_token: int,
        authorize_mutation: Callable[[Callable[[], None]], None],
    ) -> EncryptedStreamingQuarantineSink:
        metadata = self.get_metadata(quarantine_id)
        if metadata is None:
            raise RawResultQuarantineError("quarantine not found")
        expected_prefix = staging_prefix(quarantine_id, deployment_epoch, fencing_token)
        if metadata.storage_handle != expected_prefix or metadata.status != "OPEN":
            raise RawResultQuarantineError("quarantine writer fence does not own the current staging prefix")
        enc = self._encryption_metadata(quarantine_id)
        handle = self._keys.open_resource_key_handle(metadata=enc, operation="encrypt")
        return EncryptedStreamingQuarantineSink(
            sink_id=sink_id, quarantine_id=quarantine_id, execution_id=metadata.execution_id,
            mission_id=metadata.mission_id, task_binding_digest=task_binding_digest,
            storage_handle=metadata.storage_handle, key_handle=handle,
            encryption_metadata_id=enc.resource_key_id, blob_store=self._blobs,
            max_output_bytes=max_output_bytes, committed_at=self._clock.now(),
            authorize_mutation=authorize_mutation,
        )

    def set_status(self, quarantine_id: str, status: RawResultQuarantineStatus) -> RawResultQuarantineMetadata:
        metadata = self.get_metadata(quarantine_id)
        if metadata is None:
            raise RawResultQuarantineError("quarantine not found")
        updated = self._finalize(metadata.model_copy(update={"status": status, "metadata_digest": "pending"}))
        self._store_metadata(updated)
        return updated

    def commit_metadata(
        self, quarantine_id: str, *, receipt: RawResultReceipt, chunk_count: int, size_bytes: int
    ) -> RawResultQuarantineMetadata:
        metadata = self.get_metadata(quarantine_id)
        if metadata is None:
            raise RawResultQuarantineError("quarantine not found")
        updated = self._finalize(metadata.model_copy(update={
            "status": "COMMITTED", "committed_at": self._clock.now(), "ciphertext_digest": receipt.ciphertext_digest,
            "chunk_count": chunk_count, "size_bytes": size_bytes, "metadata_digest": "pending",
        }))
        self._store_metadata(updated)
        return updated

    def _open_reader_for_ingestion(self, quarantine_id: str) -> EncryptedQuarantineReader:
        """Owner port used only by SecureIngestionService; absent from the public store API."""
        metadata = self.get_metadata(quarantine_id)
        if metadata is None:
            raise RawResultQuarantineError("quarantine not found")
        if metadata.status not in ("COMMITTED", "RETENTION_EXPIRED"):
            raise RawResultQuarantineError("quarantine is not readable in its current state")
        enc = self._encryption_metadata(quarantine_id)
        handle = self._keys.open_resource_key_handle(metadata=enc, operation="decrypt")
        return EncryptedQuarantineReader(metadata=metadata, key_handle=handle, blob_store=self._blobs)

    def _unlink_ciphertext_for_erasure(self, quarantine_id: str) -> int:
        """Remove all ciphertext blobs after confirmed key destruction (eraser only)."""
        metadata = self.get_metadata(quarantine_id)
        if metadata is None:
            raise RawResultQuarantineError("quarantine not found")
        return self._blobs.delete_prefix(metadata.storage_handle)

    def ciphertext_handles(self, quarantine_id: str) -> tuple[str, ...]:
        """Read back ciphertext inventory without exposing ciphertext contents."""
        metadata = self.get_metadata(quarantine_id)
        if metadata is None:
            raise RawResultQuarantineError("quarantine not found")
        return self._blobs.list_prefix(metadata.storage_handle)
