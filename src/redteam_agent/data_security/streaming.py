"""Executor-compatible encrypted raw-result streaming with durable resume metadata."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Callable
from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, model_validator

from redteam_agent.canonical import (
    canonical_loads,
    canonicalize,
    digest_model,
    sha256_digest,
    stable_id,
)
from redteam_agent.errors import (
    DigestIntegrityError,
    RawResultQuarantineError,
    RawResultStreamingError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import UtcDatetime
from redteam_agent.models.execution import (
    RawArtifactMetadata,
    RawResultReceipt,
    RawResultRecoveryMetadata,
)

from .stores import EncryptedRawResultQuarantine, _StoredEnvelope


class QuarantineStreamBinding(StrictImmutableBoundaryModel):
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    execution_id: str = Field(min_length=1)
    retention_until: UtcDatetime
    max_result_bytes: int = Field(gt=0)
    resume_mode: Literal["from_start", "from_cursor"]
    resume_cursor: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def cursor_matches_resume_mode(self) -> QuarantineStreamBinding:
        if self.resume_mode == "from_start" and self.resume_cursor is not None:
            raise ValueError("from-start recovery cannot carry a resume cursor")
        if self.resume_mode == "from_cursor" and self.resume_cursor is None:
            raise ValueError("cursor recovery requires a verified resume cursor")
        return self


class QuarantineStreamBindingResolver(Protocol):
    def resolve(self, execution_id: str) -> QuarantineStreamBinding: ...


class _ChunkBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_chunk"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    sequence_number: int = Field(ge=0)
    plaintext_size: int = Field(ge=0)
    ciphertext_offset: int = Field(ge=0)
    channel: Literal["stdout", "stderr", "artifact"]
    artifact_sequence: int | None = Field(default=None, ge=0)
    artifact_metadata_digest: str | None = None
    chunk_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def artifact_binding(self) -> _ChunkBinding:
        if self.channel == "artifact" and (
            self.artifact_sequence is None or self.artifact_metadata_digest is None
        ):
            raise ValueError("artifact chunks require metadata bindings")
        if self.channel != "artifact" and (
            self.artifact_sequence is not None or self.artifact_metadata_digest is not None
        ):
            raise ValueError("non-artifact chunks cannot carry artifact metadata")
        return self


class _TerminalBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_commit", "stream_abort"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    chunk_count: int = Field(ge=0)
    aggregate_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    receipt_digest: str | None = None


class EncryptedRawResultSink:
    """Persists each bounded chunk before accepting the next provider chunk."""

    def __init__(
        self,
        *,
        quarantine: EncryptedRawResultQuarantine,
        binding: QuarantineStreamBinding,
        clock: Callable[[], datetime],
    ) -> None:
        self._quarantine = quarantine
        self._store = quarantine._store
        self._audit = quarantine._audit
        self.binding = binding
        self._binding_digest = digest_model(
            binding, exclude={"resume_mode", "resume_cursor"}
        )
        self.execution_id = binding.execution_id
        self.sink_id = stable_id(
            "sink",
            {"schema_version": "encrypted-stream-v1", "execution_id": binding.execution_id},
        )
        self.quarantine_id = stable_id(
            "quarantine",
            {"schema_version": "encrypted-stream-v1", "execution_id": binding.execution_id},
        )
        self._clock = clock
        self._chunks: list[tuple[_ChunkBinding, _StoredEnvelope]] = []
        self._receipt: RawResultReceipt | None = None
        self._terminal_envelope: _StoredEnvelope | None = None
        self._aborted = False
        self._recovery_required = False
        self.max_observed_chunk_bytes = 0
        self._load_durable_state()
        if (
            binding.resume_mode == "from_cursor"
            and binding.resume_cursor != len(self._chunks)
        ):
            raise RawResultQuarantineError(
                "verified resume cursor differs from durable chunk sequence"
            )
        if self._chunks and self._receipt is None and not self._aborted:
            self._audit.record(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="resume",
                metadata_digest=self._aggregate_digest(),
                occurred_at=self._clock(),
            )
        self._input_sequence = (
            0 if binding.resume_mode == "from_start" else len(self._chunks)
        )

    @property
    def bytes_received(self) -> int:
        return sum(envelope.plaintext_size for _, envelope in self._chunks)

    @property
    def committed(self) -> bool:
        return self._receipt is not None

    def mark_recovery_required(self) -> None:
        if self._receipt is None and not self._aborted:
            self._recovery_required = True

    async def write_stdout(self, chunk: bytes) -> None:
        self._write(channel="stdout", chunk=chunk)

    async def write_stderr(self, chunk: bytes) -> None:
        self._write(channel="stderr", chunk=chunk)

    async def write_artifact(
        self,
        metadata: RawArtifactMetadata,
        chunks: AsyncIterator[bytes],
    ) -> None:
        metadata_digest = digest_model(metadata)
        existing_sequences = {
            item.artifact_sequence
            for item, _ in self._chunks
            if item.artifact_sequence is not None
        }
        replaying_same = (
            self._input_sequence < len(self._chunks)
            and self._chunks[self._input_sequence][0].artifact_sequence
            == metadata.artifact_sequence
        )
        if metadata.artifact_sequence in existing_sequences and not replaying_same:
            raise RawResultStreamingError("artifact sequence was reused")
        wrote = False
        async for chunk in chunks:
            wrote = True
            self._write(
                channel="artifact",
                chunk=chunk,
                artifact_sequence=metadata.artifact_sequence,
                artifact_metadata_digest=metadata_digest,
            )
        if not wrote:
            self._write(
                channel="artifact",
                chunk=b"",
                artifact_sequence=metadata.artifact_sequence,
                artifact_metadata_digest=metadata_digest,
            )

    async def commit(self) -> RawResultReceipt:
        if self._aborted:
            raise RawResultQuarantineError("aborted quarantine cannot be committed")
        if self._receipt is not None:
            return self._receipt
        if self._input_sequence < len(self._chunks):
            raise RawResultQuarantineError("stream replay did not verify every durable chunk")
        now = self._clock()
        self._require_live(now)
        aggregate_digest = self._aggregate_digest()
        stdout_bytes, stderr_bytes, artifact_count = self._receipt_counts()
        identity = {
            "schema_version": "raw-result-receipt-v1",
            "execution_id": self.execution_id,
            "quarantine_id": self.quarantine_id,
            "sink_id": self.sink_id,
        }
        provisional = RawResultReceipt(
            receipt_id=stable_id("receipt", identity),
            receipt_digest="pending",
            execution_id=self.execution_id,
            quarantine_id=self.quarantine_id,
            sink_id=self.sink_id,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            artifact_count=artifact_count,
            ciphertext_digest=aggregate_digest,
            committed_at=now,
        )
        receipt = provisional.model_copy(
            update={"receipt_digest": digest_model(provisional, exclude={"receipt_digest"})}
        )
        terminal = _TerminalBinding(
            record_type="stream_commit",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            chunk_count=len(self._chunks),
            aggregate_digest=aggregate_digest,
            receipt_digest=receipt.receipt_digest,
        )
        self._store.write(
            mission_id=self.binding.mission_id,
            resource_id=self._terminal_resource_id("commit"),
            content=canonicalize(receipt.model_dump(mode="python")),
            binding=terminal.model_dump(mode="python"),
            created_at=now,
            retention_until=self.binding.retention_until,
        )
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="commit",
            metadata_digest=receipt.receipt_digest,
            occurred_at=now,
        )
        self._receipt = receipt
        self._terminal_envelope = next(
            item
            for item in self._store.envelopes_for(self.binding.mission_id)
            if item.resource_id == self._terminal_resource_id("commit")
        )
        return receipt

    async def abort(self) -> None:
        if self._receipt is not None or self._aborted:
            return
        now = self._clock()
        terminal = _TerminalBinding(
            record_type="stream_abort",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            chunk_count=len(self._chunks),
            aggregate_digest=self._aggregate_digest(),
            receipt_digest=None,
        )
        self._store.write(
            mission_id=self.binding.mission_id,
            resource_id=self._terminal_resource_id("abort"),
            content=b"",
            binding=terminal.model_dump(mode="python"),
            created_at=now,
            retention_until=self.binding.retention_until,
        )
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="abort",
            metadata_digest=terminal.aggregate_digest,
            occurred_at=now,
        )
        self._aborted = True

    def recovery_metadata(self, *, updated_at: datetime) -> RawResultRecoveryMetadata:
        state: Literal["OPEN", "COMMITTED", "RECOVERY_REQUIRED", "ABORTED"] = (
            "COMMITTED"
            if self._receipt is not None
            else "ABORTED"
            if self._aborted
            else "RECOVERY_REQUIRED"
            if self._chunks or self._recovery_required
            else "OPEN"
        )
        identity = {
            "schema_version": "raw-result-recovery-v1",
            "execution_id": self.execution_id,
            "quarantine_id": self.quarantine_id,
        }
        provisional = RawResultRecoveryMetadata(
            recovery_id=stable_id("recovery", identity),
            recovery_digest="pending",
            execution_id=self.execution_id,
            quarantine_id=self.quarantine_id,
            sink_id=self.sink_id,
            state=state,
            bytes_received=self.bytes_received,
            last_chunk_sequence=len(self._chunks) - 1,
            receipt_id=None if self._receipt is None else self._receipt.receipt_id,
            updated_at=updated_at,
        )
        return provisional.model_copy(
            update={
                "recovery_digest": digest_model(
                    provisional, exclude={"recovery_digest"}
                )
            }
        )

    def _iter_committed_chunks(
        self, receipt: RawResultReceipt, *, now: datetime
    ) -> AsyncIterator[bytes]:
        async def iterate() -> AsyncIterator[bytes]:
            if self._receipt is None or receipt != self._receipt:
                raise RawResultQuarantineError("raw-result stream is not committed")
            self._audit.record(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="resume",
                metadata_digest=self._receipt.receipt_digest,
                occurred_at=now,
            )
            for binding, envelope in self._chunks:
                content, _ = self._store.read_bound(
                    mission_id=self.binding.mission_id,
                    resource_id=envelope.resource_id,
                    now=now,
                )
                if "sha256:" + hashlib.sha256(content).hexdigest() != binding.chunk_digest:
                    raise DigestIntegrityError("committed stream chunk integrity failed")
                yield content

        return iterate()

    def _delete_committed(self, *, now: datetime) -> None:
        if self._receipt is None or self._terminal_envelope is None:
            raise RawResultQuarantineError("raw-result stream is not committed")
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="delete",
            metadata_digest=self._receipt.receipt_digest,
            occurred_at=now,
        )
        for binding, envelope in self._chunks:
            self._store.delete(
                mission_id=self.binding.mission_id,
                resource_id=envelope.resource_id,
                binding=binding.model_dump(mode="python"),
                expected_encryption_metadata_id=envelope.encryption_metadata_id,
            )
        terminal = _TerminalBinding.model_validate(
            self._terminal_envelope.binding.to_dict()
        )
        self._store.delete(
            mission_id=self.binding.mission_id,
            resource_id=self._terminal_envelope.resource_id,
            binding=terminal.model_dump(mode="python"),
            expected_encryption_metadata_id=self._terminal_envelope.encryption_metadata_id,
        )

    def _write(
        self,
        *,
        channel: Literal["stdout", "stderr", "artifact"],
        chunk: bytes,
        artifact_sequence: int | None = None,
        artifact_metadata_digest: str | None = None,
    ) -> None:
        if self._receipt is not None or self._aborted:
            raise RawResultStreamingError("raw-result sink is no longer writable")
        if not isinstance(chunk, bytes):
            raise RawResultStreamingError("raw-result chunks must be bytes")
        self.max_observed_chunk_bytes = max(self.max_observed_chunk_bytes, len(chunk))
        digest = "sha256:" + hashlib.sha256(chunk).hexdigest()
        sequence = self._input_sequence
        ciphertext_offset = sum(
            envelope.plaintext_size for _, envelope in self._chunks[:sequence]
        )
        expected = _ChunkBinding(
            record_type="stream_chunk",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            sequence_number=sequence,
            plaintext_size=len(chunk),
            ciphertext_offset=ciphertext_offset,
            channel=channel,
            artifact_sequence=artifact_sequence,
            artifact_metadata_digest=artifact_metadata_digest,
            chunk_digest=digest,
        )
        if sequence < len(self._chunks):
            existing, envelope = self._chunks[sequence]
            existing_content, _ = self._store.read_bound(
                mission_id=self.binding.mission_id,
                resource_id=envelope.resource_id,
                now=self._clock(),
            )
            if existing != expected or existing_content != chunk:
                raise DigestIntegrityError("resumed raw-result chunk differs from durable content")
            self._input_sequence += 1
            return
        next_size = self.bytes_received + len(chunk)
        if next_size > self.binding.max_result_bytes:
            raise RawResultQuarantineError("raw-result quarantine size limit exceeded")
        resource_id = stable_id(
            "streamchunk",
            {
                "schema_version": "stream-chunk-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
                "sequence_number": sequence,
            },
        )
        now = self._clock()
        self._require_live(now)
        self._store.write(
            mission_id=self.binding.mission_id,
            resource_id=resource_id,
            content=chunk,
            binding=expected.model_dump(mode="python"),
            created_at=now,
            retention_until=self.binding.retention_until,
        )
        envelope = next(
            item
            for item in self._store.envelopes_for(self.binding.mission_id)
            if item.resource_id == resource_id
        )
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="write_chunk",
            metadata_digest=digest,
            occurred_at=now,
        )
        self._chunks.append((expected, envelope))
        self._input_sequence += 1

    def _load_durable_state(self) -> None:
        terminals: list[tuple[_TerminalBinding, _StoredEnvelope]] = []
        for envelope in self._store.envelopes_for(self.binding.mission_id):
            value = envelope.binding.to_dict()
            execution_matches = value.get("execution_id") == self.execution_id
            sink_matches = value.get("sink_id") == self.sink_id
            if not execution_matches or not sink_matches:
                continue
            record_type = value.get("record_type")
            try:
                if record_type == "stream_chunk":
                    self._chunks.append((_ChunkBinding.model_validate(value), envelope))
                elif record_type in {"stream_commit", "stream_abort"}:
                    terminals.append((_TerminalBinding.model_validate(value), envelope))
                else:
                    raise ValueError("unknown stream record type")
            except ValueError as exc:
                raise RawResultQuarantineError("durable stream metadata is invalid") from exc
        self._chunks.sort(key=lambda item: item[0].sequence_number)
        if tuple(item.sequence_number for item, _ in self._chunks) != tuple(
            range(len(self._chunks))
        ):
            raise RawResultQuarantineError("durable stream chunk sequence is incomplete")
        if any(
            item.mission_revision != self.binding.mission_revision
            or item.stream_binding_digest != self._binding_digest
            for item, _ in self._chunks
        ):
            raise RawResultQuarantineError("durable stream binding is stale")
        offset = 0
        for item, envelope in self._chunks:
            if not (
                item.plaintext_size == envelope.plaintext_size
                and item.ciphertext_offset == offset
            ):
                raise RawResultQuarantineError("durable stream chunk offset is invalid")
            offset += envelope.plaintext_size
        if self.bytes_received > self.binding.max_result_bytes or len(terminals) > 1:
            raise RawResultQuarantineError("durable stream state conflicts with policy")
        if not terminals:
            return
        terminal, envelope = terminals[0]
        if not (
            terminal.mission_revision == self.binding.mission_revision
            and terminal.stream_binding_digest == self._binding_digest
            and terminal.chunk_count == len(self._chunks)
            and terminal.aggregate_digest == self._aggregate_digest()
        ):
            raise RawResultQuarantineError("durable stream terminal binding is invalid")
        if terminal.record_type == "stream_abort":
            self._aborted = True
            self._terminal_envelope = envelope
            return
        raw, _ = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=envelope.resource_id,
            now=self._clock(),
        )
        try:
            canonical_loads(raw)
            receipt = RawResultReceipt.model_validate_json(raw, strict=True)
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError("durable stream receipt is invalid") from exc
        if not (
            receipt.execution_id == self.execution_id
            and receipt.quarantine_id == self.quarantine_id
            and receipt.sink_id == self.sink_id
            and receipt.ciphertext_digest == terminal.aggregate_digest
            and receipt.receipt_digest == terminal.receipt_digest
            and digest_model(receipt, exclude={"receipt_digest"}) == receipt.receipt_digest
            and (
                receipt.stdout_bytes,
                receipt.stderr_bytes,
                receipt.artifact_count,
            )
            == self._receipt_counts()
        ):
            raise RawResultQuarantineError("durable stream receipt binding is invalid")
        self._receipt = receipt
        self._terminal_envelope = envelope

    def _aggregate_digest(self) -> str:
        return sha256_digest(
            tuple(
                {
                    "binding": binding,
                    "encryption_metadata_id": envelope.encryption_metadata_id,
                    "payload": envelope.payload,
                }
                for binding, envelope in self._chunks
            )
        )

    def _terminal_resource_id(self, state: Literal["commit", "abort"]) -> str:
        return stable_id(
            "streamterminal",
            {
                "schema_version": "stream-terminal-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
                "state": state,
            },
        )

    def _receipt_counts(self) -> tuple[int, int, int]:
        stdout_bytes = sum(
            envelope.plaintext_size
            for binding, envelope in self._chunks
            if binding.channel == "stdout"
        )
        stderr_bytes = sum(
            envelope.plaintext_size
            for binding, envelope in self._chunks
            if binding.channel == "stderr"
        )
        artifact_count = len(
            {
                binding.artifact_sequence
                for binding, _ in self._chunks
                if binding.artifact_sequence is not None
            }
        )
        return stdout_bytes, stderr_bytes, artifact_count

    def _require_live(self, now: datetime) -> None:
        if now >= self.binding.retention_until:
            raise RawResultQuarantineError("raw-result quarantine retention has expired")


class EncryptedRawResultSinkFactory:
    def __init__(
        self,
        *,
        quarantine: EncryptedRawResultQuarantine,
        bindings: QuarantineStreamBindingResolver,
        clock: Callable[[], datetime],
    ) -> None:
        self._quarantine = quarantine
        self._bindings = bindings
        self._clock = clock

    def for_execution(self, execution_id: str) -> EncryptedRawResultSink:
        binding = self._bindings.resolve(execution_id)
        if binding.execution_id != execution_id:
            raise RawResultQuarantineError("stream binding resolver returned another execution")
        return EncryptedRawResultSink(
            quarantine=self._quarantine,
            binding=binding,
            clock=self._clock,
        )
