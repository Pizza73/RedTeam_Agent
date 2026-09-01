"""Executor-compatible encrypted raw-result streaming with durable resume metadata."""

from __future__ import annotations

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
    ArtifactSecurityError,
    AuditIntegrityError,
    DigestIntegrityError,
    EncryptionIntegrityError,
    EncryptionKeyUnavailableError,
    RawResultQuarantineError,
    RawResultStreamingError,
)
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.models.common import UtcDatetime
from redteam_agent.models.execution import (
    ExecutionResult,
    RawArtifactMetadata,
    RawResultReceipt,
    RawResultRecoveryMetadata,
)

from .models import SecureIngestionResult
from .stores import (
    EncryptedRawResultQuarantine,
    _StoredEnvelope,
    _StreamAbortDeletionBinding,
    _StreamDeletionBinding,
    _StreamExpiryDeletionBinding,
    _StreamIngestionAckBinding,
)


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


class _ArtifactTerminalBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_artifact_commit"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    artifact_sequence: int = Field(ge=0)
    artifact_metadata_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    first_chunk_sequence: int = Field(ge=0)
    next_chunk_sequence: int = Field(ge=1)
    chunk_count: int = Field(ge=1)
    chunk_bindings_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class _IngestionResultBinding(StrictImmutableBoundaryModel):
    record_type: Literal["stream_ingestion_result"]
    mission_revision: int = Field(ge=1)
    stream_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_id: str = Field(min_length=1)
    sink_id: str = Field(min_length=1)
    receipt_id: str = Field(min_length=1)
    receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    ingestion_id: str = Field(min_length=1)
    ingestion_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


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
        self._artifact_terminals: dict[
            int, tuple[_ArtifactTerminalBinding, _StoredEnvelope]
        ] = {}
        self._receipt: RawResultReceipt | None = None
        self._ingestion_result: SecureIngestionResult | None = None
        self._ingestion_binding: _IngestionResultBinding | None = None
        self._terminal_envelope: _StoredEnvelope | None = None
        self._aborted = False
        self._recovery_required = False
        self._deleted = False
        self._deleted_bytes_received: int | None = None
        self._deleted_chunk_count: int | None = None
        self.max_observed_chunk_bytes = 0
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._ingestion_ack_resource_id(),
        ):
            self._resume_ingestion_ack()
            return
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        ):
            self._load_ingestion_result()
            self._resume_deletion()
            return
        self._load_durable_state()
        self._load_ingestion_result()
        if self._completed_terminal_deletion():
            return
        if self._aborted:
            self._delete_aborted(now=self._clock())
            return
        if self._clock() >= self.binding.retention_until:
            if self._receipt is not None and self._ingestion_result is not None:
                self._delete_committed(now=self._clock())
            else:
                self._delete_expired(now=self._clock())
            return
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
        if self._deleted_bytes_received is not None:
            return self._deleted_bytes_received
        return sum(envelope.plaintext_size for _, envelope in self._chunks)

    @property
    def committed(self) -> bool:
        return self._receipt is not None

    def mark_recovery_required(self) -> None:
        if self._receipt is None and not self._aborted:
            self._recovery_required = True

    async def write_stdout(self, chunk: bytes) -> None:
        failure = self._capture_write_failure(channel="stdout", chunk=chunk)
        del chunk
        if failure is not None:
            raise failure from None

    async def write_stderr(self, chunk: bytes) -> None:
        failure = self._capture_write_failure(channel="stderr", chunk=chunk)
        del chunk
        if failure is not None:
            raise failure from None

    async def write_artifact(
        self,
        metadata: RawArtifactMetadata,
        chunks: AsyncIterator[bytes],
    ) -> None:
        metadata_digest = digest_model(metadata)
        existing = [
            item
            for item, _ in self._chunks
            if item.artifact_sequence == metadata.artifact_sequence
        ]
        terminal = self._artifact_terminals.get(metadata.artifact_sequence)
        replaying_same = bool(existing) and (
            self._input_sequence < len(self._chunks)
            and self._chunks[self._input_sequence][0].artifact_sequence
            == metadata.artifact_sequence
        )
        continuing_open = bool(existing) and (
            self._input_sequence == len(self._chunks)
            and terminal is None
            and self._chunks[-1][0].artifact_sequence == metadata.artifact_sequence
        )
        if not existing and metadata.artifact_sequence != len(
            self._artifact_terminals
        ):
            raise RawResultStreamingError("artifact sequence is not monotonic")
        if existing and not (replaying_same or continuing_open):
            raise RawResultStreamingError("artifact sequence was reused")
        if terminal is not None and not replaying_same:
            raise RawResultStreamingError("completed artifact sequence was reused")
        if any(item.artifact_metadata_digest != metadata_digest for item in existing):
            raise DigestIntegrityError("resumed artifact metadata differs from durable content")
        wrote = False
        async for chunk in chunks:
            wrote = True
            failure = self._capture_write_failure(
                channel="artifact",
                chunk=chunk,
                artifact_sequence=metadata.artifact_sequence,
                artifact_metadata_digest=metadata_digest,
            )
            del chunk
            if failure is not None:
                raise failure from None
        if not wrote and not existing:
            failure = self._capture_write_failure(
                channel="artifact",
                chunk=b"",
                artifact_sequence=metadata.artifact_sequence,
                artifact_metadata_digest=metadata_digest,
            )
            if failure is not None:
                raise failure from None
        self._commit_artifact(metadata, metadata_digest=metadata_digest)

    async def commit(self) -> RawResultReceipt:
        try:
            return self._commit_terminal()
        except (RawResultQuarantineError, RawResultStreamingError):
            raise
        except Exception as failure:
            failure.__traceback__ = None
        raise RawResultQuarantineError(
            "raw-result terminal persistence failed closed"
        ) from None

    def _commit_terminal(self) -> RawResultReceipt:
        if self._receipt is not None:
            return self._receipt
        if self._deleted:
            raise RawResultQuarantineError("deleted quarantine cannot be committed")
        if self._aborted:
            raise RawResultQuarantineError("aborted quarantine cannot be committed")
        if self._input_sequence < len(self._chunks):
            raise RawResultQuarantineError("stream replay did not verify every durable chunk")
        incomplete_artifacts = {
            binding.artifact_sequence
            for binding, _ in self._chunks
            if binding.artifact_sequence is not None
        } - set(self._artifact_terminals)
        if incomplete_artifacts:
            raise RawResultQuarantineError("artifact stream is not durably complete")
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
            operation_id=self._audit_operation_id("commit", "terminal"),
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
        try:
            self._abort_terminal()
            return
        except (RawResultQuarantineError, RawResultStreamingError):
            raise
        except Exception as failure:
            failure.__traceback__ = None
        raise RawResultQuarantineError(
            "raw-result terminal persistence failed closed"
        ) from None

    def _abort_terminal(self) -> None:
        if self._deleted:
            raise RawResultQuarantineError("deleted quarantine cannot be aborted")
        if self._receipt is not None:
            return
        now = self._clock()
        if self._aborted:
            self._delete_aborted(now=now)
            return
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
            operation_id=self._audit_operation_id("abort", "terminal"),
            metadata_digest=terminal.aggregate_digest,
            occurred_at=now,
        )
        self._aborted = True
        self._terminal_envelope = next(
            item
            for item in self._store.envelopes_for(self.binding.mission_id)
            if item.resource_id == self._terminal_resource_id("abort")
        )
        self._delete_aborted(now=now)

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
            last_chunk_sequence=(
                self._deleted_chunk_count - 1
                if self._deleted_chunk_count is not None
                else len(self._chunks) - 1
            ),
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
            if self._deleted or self._receipt is None or receipt != self._receipt:
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
                if (
                    self._store._content_digest(
                        content,
                        metadata=envelope.payload.metadata,
                    )
                    != binding.chunk_digest
                ):
                    raise DigestIntegrityError("committed stream chunk integrity failed")
                yield content

        return iterate()

    def _durable_ingestion_result(
        self, receipt: RawResultReceipt
    ) -> SecureIngestionResult | None:
        if self._ingestion_result is None or self._ingestion_binding is None:
            return None
        if not (
            self._ingestion_binding.receipt_id == receipt.receipt_id
            and self._ingestion_binding.receipt_digest == receipt.receipt_digest
            and receipt.execution_id == self.execution_id
            and receipt.quarantine_id == self.quarantine_id
            and receipt.sink_id == self.sink_id
        ):
            raise RawResultQuarantineError(
                "durable ingestion result is bound to another receipt"
            )
        return self._ingestion_result

    def _commit_ingestion_result(
        self,
        receipt: RawResultReceipt,
        result: SecureIngestionResult,
        *,
        now: datetime,
    ) -> None:
        if self._receipt is None or receipt != self._receipt or self._deleted:
            raise RawResultQuarantineError(
                "ingestion result requires a live committed quarantine"
            )
        binding = _IngestionResultBinding(
            record_type="stream_ingestion_result",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            receipt_id=receipt.receipt_id,
            receipt_digest=receipt.receipt_digest,
            ingestion_id=result.ingestion_id,
            ingestion_digest=result.ingestion_digest,
        )
        self._store.write(
            mission_id=self.binding.mission_id,
            resource_id=self._ingestion_result_resource_id(),
            content=canonicalize(result.model_dump(mode="python")),
            binding=binding.model_dump(mode="python"),
            created_at=now,
            retention_until=None,
        )
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="commit",
            operation_id=self._audit_operation_id("commit", "ingestion-result"),
            metadata_digest=result.ingestion_digest,
            occurred_at=now,
        )
        self._ingestion_binding = binding
        self._ingestion_result = result

    def _load_ingestion_result(self) -> None:
        resource_id = self._ingestion_result_resource_id()
        if not self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=resource_id,
        ):
            return
        raw, envelope = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=resource_id,
            now=None,
        )
        try:
            canonical_loads(raw)
            result = SecureIngestionResult.model_validate_json(raw, strict=True)
            binding = _IngestionResultBinding.model_validate(
                envelope.binding.to_dict()
            )
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError(
                "durable ingestion result is invalid"
            ) from exc
        expected_digest = sha256_digest(
            {
                "ingestion_id": result.ingestion_id,
                "redacted_artifacts": result.redacted_artifacts,
                "encrypted_raw_artifacts": result.encrypted_raw_artifacts,
                "detected_secrets": result.detected_secrets,
                "redaction_metadata": result.redaction_metadata,
            }
        )
        if not (
            binding.mission_revision == self.binding.mission_revision
            and binding.stream_binding_digest == self._binding_digest
            and binding.execution_id == self.execution_id
            and binding.sink_id == self.sink_id
            and binding.ingestion_id == result.ingestion_id
            and binding.ingestion_digest
            == result.ingestion_digest
            == expected_digest
        ):
            raise RawResultQuarantineError(
                "durable ingestion result binding is invalid"
            )
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="commit",
            operation_id=self._audit_operation_id("commit", "ingestion-result"),
            metadata_digest=result.ingestion_digest,
            occurred_at=envelope.created_at,
        )
        self._ingestion_binding = binding
        self._ingestion_result = result

    def _delete_committed(self, *, now: datetime) -> None:
        if self._deleted:
            return
        if (
            self._receipt is None
            or self._terminal_envelope is None
            or self._ingestion_result is None
        ):
            raise RawResultQuarantineError("raw-result stream is not committed")
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        ):
            self._resume_deletion()
            return
        terminal = _TerminalBinding.model_validate(
            self._terminal_envelope.binding.to_dict()
        )
        intent = _StreamDeletionBinding(
            record_type="stream_delete_intent",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            chunk_count=len(self._chunks),
            artifact_sequences=tuple(sorted(self._artifact_terminals)),
            bytes_received=self.bytes_received,
            aggregate_digest=terminal.aggregate_digest,
            receipt_digest=self._receipt.receipt_digest,
            ingestion_id=self._ingestion_result.ingestion_id,
            ingestion_digest=self._ingestion_result.ingestion_digest,
        )
        self._store.write_quarantine_cleanup_intent(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
            binding=intent.model_dump(mode="json"),
            created_at=now,
        )
        self._resume_deletion()

    def _acknowledge_persisted(
        self,
        receipt: RawResultReceipt,
        result: ExecutionResult,
        *,
        now: datetime,
    ) -> None:
        """Reclaim replay metadata only after the Executor persisted its result."""

        if not (
            receipt.execution_id == self.execution_id
            and receipt.quarantine_id == self.quarantine_id
            and receipt.sink_id == self.sink_id
            and result.execution_id == self.execution_id
        ):
            raise RawResultQuarantineError(
                "execution-result acknowledgment binding is invalid"
            )
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._ingestion_ack_resource_id(),
        ):
            self._resume_ingestion_ack()
            return
        if not self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        ):
            if not self._audit.operation_recorded(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="delete",
                operation_id=self._audit_operation_id("delete", "intent"),
                metadata_digest=receipt.receipt_digest,
            ):
                raise RawResultQuarantineError(
                    "execution-result acknowledgment is unavailable"
                )
            self._deleted = True
            return
        if not self._deleted:
            self._resume_deletion()
        if (
            self._receipt is None
            or self._ingestion_result is None
            or self._terminal_envelope is None
        ):
            raise RawResultQuarantineError(
                "execution-result acknowledgment source is unavailable"
            )
        if not (
            self._receipt == receipt
            and self._ingestion_result.ingestion_id == result.secure_ingestion_id
        ):
            raise RawResultQuarantineError(
                "execution-result acknowledgment binding is invalid"
            )
        terminal = _TerminalBinding.model_validate(
            self._terminal_envelope.binding.to_dict()
        )
        intent_raw, _ = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
            now=None,
        )
        if intent_raw:
            raise RawResultQuarantineError("deletion intent content is invalid")
        deletion_intent = _StreamDeletionBinding.model_validate_json(
            canonicalize(
                self._store.verified_envelope(
                    mission_id=self.binding.mission_id,
                    resource_id=self._deletion_resource_id(),
                    now=None,
                ).binding.to_dict()
            ),
            strict=True,
        )
        acknowledgment = _StreamIngestionAckBinding(
            record_type="stream_ingestion_ack",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            chunk_count=deletion_intent.chunk_count,
            artifact_sequences=deletion_intent.artifact_sequences,
            aggregate_digest=terminal.aggregate_digest,
            receipt_id=receipt.receipt_id,
            receipt_digest=receipt.receipt_digest,
            ingestion_id=self._ingestion_result.ingestion_id,
            ingestion_digest=self._ingestion_result.ingestion_digest,
            execution_result_id=result.result_id,
            execution_result_digest=result.result_digest,
        )
        self._store.write_quarantine_cleanup_intent(
            mission_id=self.binding.mission_id,
            resource_id=self._ingestion_ack_resource_id(),
            binding=acknowledgment.model_dump(mode="json"),
            created_at=now,
        )
        self._resume_ingestion_ack()

    def _capture_write_failure(
        self,
        *,
        channel: Literal["stdout", "stderr", "artifact"],
        chunk: bytes,
        artifact_sequence: int | None = None,
        artifact_metadata_digest: str | None = None,
    ) -> RawResultStreamingError | None:
        """Return a sanitized failure after the secret-bearing frame has unwound."""

        try:
            self._write(
                channel=channel,
                chunk=chunk,
                artifact_sequence=artifact_sequence,
                artifact_metadata_digest=artifact_metadata_digest,
            )
        except Exception as failure:
            failure.__traceback__ = None
            del failure
            return RawResultStreamingError("raw-result streaming failed closed")
        return None

    def _write(
        self,
        *,
        channel: Literal["stdout", "stderr", "artifact"],
        chunk: bytes,
        artifact_sequence: int | None = None,
        artifact_metadata_digest: str | None = None,
    ) -> None:
        if self._deleted or self._receipt is not None or self._aborted:
            raise RawResultStreamingError("raw-result sink is no longer writable")
        if not isinstance(chunk, bytes):
            raise RawResultStreamingError("raw-result chunks must be bytes")
        self.max_observed_chunk_bytes = max(self.max_observed_chunk_bytes, len(chunk))
        sequence = self._input_sequence
        durable_envelope = (
            self._chunks[sequence][1] if sequence < len(self._chunks) else None
        )
        digest = self._store._content_digest(
            chunk,
            metadata=(
                None if durable_envelope is None else durable_envelope.payload.metadata
            ),
        )
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
        resource_id = self._chunk_resource_id(sequence)
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
            operation_id=self._audit_operation_id("write_chunk", str(sequence)),
            metadata_digest=digest,
            occurred_at=now,
        )
        self._chunks.append((expected, envelope))
        self._input_sequence += 1

    def _commit_artifact(
        self,
        metadata: RawArtifactMetadata,
        *,
        metadata_digest: str,
    ) -> None:
        chunks = [
            binding
            for binding, _ in self._chunks
            if binding.artifact_sequence == metadata.artifact_sequence
        ]
        if not chunks or self._input_sequence <= chunks[-1].sequence_number:
            raise RawResultQuarantineError("artifact replay did not verify durable chunks")
        artifact_size = sum(item.plaintext_size for item in chunks)
        if metadata.declared_size is not None and metadata.declared_size != artifact_size:
            raise RawResultQuarantineError("artifact declared size differs from durable chunks")
        expected = _ArtifactTerminalBinding(
            record_type="stream_artifact_commit",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            artifact_sequence=metadata.artifact_sequence,
            artifact_metadata_digest=metadata_digest,
            first_chunk_sequence=chunks[0].sequence_number,
            next_chunk_sequence=chunks[-1].sequence_number + 1,
            chunk_count=len(chunks),
            chunk_bindings_digest=sha256_digest(tuple(chunks)),
        )
        durable = self._artifact_terminals.get(metadata.artifact_sequence)
        if durable is not None:
            if durable[0] != expected:
                raise DigestIntegrityError("durable artifact completion binding differs")
            return
        now = self._clock()
        self._require_live(now)
        resource_id = self._artifact_terminal_resource_id(metadata.artifact_sequence)
        self._store.write(
            mission_id=self.binding.mission_id,
            resource_id=resource_id,
            content=b"",
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
            operation="commit_artifact",
            operation_id=self._audit_operation_id(
                "commit_artifact", str(metadata.artifact_sequence)
            ),
            metadata_digest=expected.chunk_bindings_digest,
            occurred_at=now,
        )
        self._artifact_terminals[metadata.artifact_sequence] = (expected, envelope)

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
                elif record_type == "stream_artifact_commit":
                    artifact = _ArtifactTerminalBinding.model_validate(value)
                    if artifact.artifact_sequence in self._artifact_terminals:
                        raise ValueError("duplicate artifact completion")
                    self._artifact_terminals[artifact.artifact_sequence] = (
                        artifact,
                        envelope,
                    )
                elif record_type in {"stream_commit", "stream_abort"}:
                    terminals.append((_TerminalBinding.model_validate(value), envelope))
                elif record_type in {
                    "stream_ingestion_result",
                    "stream_delete_intent",
                }:
                    continue
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
        for sequence, (artifact, _) in self._artifact_terminals.items():
            chunks = [
                item
                for item, _ in self._chunks
                if item.artifact_sequence == sequence
            ]
            if not (
                chunks
                and artifact.mission_revision == self.binding.mission_revision
                and artifact.stream_binding_digest == self._binding_digest
                and all(
                    item.artifact_metadata_digest
                    == artifact.artifact_metadata_digest
                    for item in chunks
                )
                and artifact.first_chunk_sequence == chunks[0].sequence_number
                and artifact.next_chunk_sequence == chunks[-1].sequence_number + 1
                and artifact.chunk_count == len(chunks)
                and artifact.chunk_bindings_digest == sha256_digest(tuple(chunks))
            ):
                raise RawResultQuarantineError(
                    "durable artifact completion binding is invalid"
                )
        self._reconcile_nonterminal_audits()
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
            self._audit.record(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="abort",
                operation_id=self._audit_operation_id("abort", "terminal"),
                metadata_digest=terminal.aggregate_digest,
                occurred_at=envelope.created_at,
            )
            self._aborted = True
            self._terminal_envelope = envelope
            return
        raw, _ = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=envelope.resource_id,
            now=None,
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
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="commit",
            operation_id=self._audit_operation_id("commit", "terminal"),
            metadata_digest=receipt.receipt_digest,
            occurred_at=envelope.created_at,
        )
        self._receipt = receipt
        self._terminal_envelope = envelope

    def _aggregate_digest(self) -> str:
        return sha256_digest(
            {
                "chunks": tuple(
                    {
                        "binding": binding,
                        "encryption_metadata_id": envelope.encryption_metadata_id,
                        "payload": envelope.payload,
                    }
                    for binding, envelope in self._chunks
                ),
                "artifact_completions": tuple(
                    {
                        "binding": binding,
                        "encryption_metadata_id": envelope.encryption_metadata_id,
                        "payload": envelope.payload,
                    }
                    for _, (binding, envelope) in sorted(
                        self._artifact_terminals.items()
                    )
                ),
            }
        )

    def _reconcile_nonterminal_audits(self) -> None:
        for chunk_binding, envelope in self._chunks:
            self._audit.record(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="write_chunk",
                operation_id=self._audit_operation_id(
                    "write_chunk", str(chunk_binding.sequence_number)
                ),
                metadata_digest=chunk_binding.chunk_digest,
                occurred_at=envelope.created_at,
            )
        for artifact_binding, envelope in self._artifact_terminals.values():
            self._audit.record(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="commit_artifact",
                operation_id=self._audit_operation_id(
                    "commit_artifact", str(artifact_binding.artifact_sequence)
                ),
                metadata_digest=artifact_binding.chunk_bindings_digest,
                occurred_at=envelope.created_at,
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

    def _artifact_terminal_resource_id(self, artifact_sequence: int) -> str:
        return stable_id(
            "streamartifact",
            {
                "schema_version": "stream-artifact-terminal-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
                "artifact_sequence": artifact_sequence,
            },
        )

    def _chunk_resource_id(self, sequence: int) -> str:
        return stable_id(
            "streamchunk",
            {
                "schema_version": "stream-chunk-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
                "sequence_number": sequence,
            },
        )

    def _deletion_resource_id(self) -> str:
        return stable_id(
            "streamdeletion",
            {
                "schema_version": "stream-deletion-intent-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
            },
        )

    def _ingestion_ack_resource_id(self) -> str:
        return stable_id(
            "streamack",
            {
                "schema_version": "stream-ingestion-ack-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
            },
        )

    def _ingestion_result_resource_id(self) -> str:
        return stable_id(
            "streamingestion",
            {
                "schema_version": "stream-ingestion-result-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
            },
        )

    def _audit_operation_id(self, operation: str, identity: str) -> str:
        return stable_id(
            "auditop",
            {
                "schema_version": "stream-audit-operation-v1",
                "execution_id": self.execution_id,
                "sink_id": self.sink_id,
                "operation": operation,
                "identity": identity,
            },
        )

    def _completed_terminal_deletion(self) -> bool:
        if (
            self._chunks
            or self._artifact_terminals
            or self._terminal_envelope is not None
            or self._ingestion_result is not None
        ):
            return False
        completed = tuple(
            identity
            for identity in ("abort-intent", "expiry-intent")
            if self._audit.operation_metadata_digest(
                mission_id=self.binding.mission_id,
                resource_type="raw_result_quarantine",
                resource_id=self.quarantine_id,
                operation="delete",
                operation_id=self._audit_operation_id("delete", identity),
            )
            is not None
        )
        if len(completed) > 1:
            raise AuditIntegrityError(
                "terminal stream deletion completion is ambiguous"
            )
        if not completed:
            return False
        self._aborted = completed[0] == "abort-intent"
        self._deleted = True
        return True

    def _resume_deletion(self) -> None:
        raw, envelope = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
            now=None,
        )
        if raw:
            raise RawResultQuarantineError("deletion intent content is invalid")
        value = envelope.binding.to_dict()
        if value.get("record_type") == "stream_abort_delete_intent":
            self._resume_abort_deletion(value, envelope=envelope)
            return
        if value.get("record_type") == "stream_expiry_delete_intent":
            self._resume_expiry_deletion(value, envelope=envelope)
            return
        if self._ingestion_result is None or self._ingestion_binding is None:
            raise RawResultQuarantineError(
                "deletion intent lacks a durable ingestion result"
            )
        try:
            intent = _StreamDeletionBinding.model_validate_json(
                canonicalize(value),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError("deletion intent is invalid") from exc
        terminal_raw, terminal_envelope = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=self._terminal_resource_id("commit"),
            now=None,
        )
        try:
            canonical_loads(terminal_raw)
            terminal = _TerminalBinding.model_validate(
                terminal_envelope.binding.to_dict()
            )
            receipt = RawResultReceipt.model_validate_json(
                terminal_raw,
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError("deletion terminal is invalid") from exc
        if not (
            intent.mission_revision == self.binding.mission_revision
            and intent.stream_binding_digest == self._binding_digest
            and intent.execution_id == self.execution_id
            and intent.sink_id == self.sink_id
            and intent.artifact_sequences
            == tuple(sorted(set(intent.artifact_sequences)))
            and all(sequence >= 0 for sequence in intent.artifact_sequences)
            and terminal.record_type == "stream_commit"
            and terminal.chunk_count == intent.chunk_count
            and intent.bytes_received <= self.binding.max_result_bytes
            and receipt.stdout_bytes + receipt.stderr_bytes
            <= intent.bytes_received
            and receipt.artifact_count <= intent.chunk_count
            and terminal.aggregate_digest == intent.aggregate_digest
            and terminal.receipt_digest == intent.receipt_digest
            and receipt.execution_id == self.execution_id
            and receipt.quarantine_id == self.quarantine_id
            and receipt.sink_id == self.sink_id
            and receipt.ciphertext_digest == terminal.aggregate_digest
            and receipt.receipt_digest == terminal.receipt_digest
            and digest_model(receipt, exclude={"receipt_digest"})
            == receipt.receipt_digest
            and self._ingestion_binding.receipt_id == receipt.receipt_id
            and self._ingestion_binding.receipt_digest
            == receipt.receipt_digest
            and intent.ingestion_id == self._ingestion_result.ingestion_id
            and intent.ingestion_digest == self._ingestion_result.ingestion_digest
        ):
            raise RawResultQuarantineError("deletion intent binding is invalid")
        self._receipt = receipt
        self._terminal_envelope = terminal_envelope
        self._deleted_bytes_received = intent.bytes_received
        self._deleted_chunk_count = intent.chunk_count
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="delete",
            operation_id=self._audit_operation_id("delete", "intent"),
            metadata_digest=intent.receipt_digest,
            occurred_at=envelope.created_at,
        )
        for sequence in range(intent.chunk_count):
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._chunk_resource_id(sequence),
            )
        self._deleted = True

    def _resume_ingestion_ack(self) -> None:
        raw, envelope = self._store.read_bound(
            mission_id=self.binding.mission_id,
            resource_id=self._ingestion_ack_resource_id(),
            now=None,
        )
        if raw:
            raise RawResultQuarantineError(
                "execution-result acknowledgment content is invalid"
            )
        try:
            acknowledgment = _StreamIngestionAckBinding.model_validate_json(
                canonicalize(envelope.binding.to_dict()),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError(
                "execution-result acknowledgment is invalid"
            ) from exc
        if not (
            acknowledgment.mission_revision == self.binding.mission_revision
            and acknowledgment.stream_binding_digest == self._binding_digest
            and acknowledgment.execution_id == self.execution_id
            and acknowledgment.sink_id == self.sink_id
            and acknowledgment.artifact_sequences
            == tuple(sorted(set(acknowledgment.artifact_sequences)))
            and all(
                sequence >= 0
                for sequence in acknowledgment.artifact_sequences
            )
        ):
            raise RawResultQuarantineError(
                "execution-result acknowledgment binding is invalid"
            )
        deletion_resource_id = self._deletion_resource_id()
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=deletion_resource_id,
        ):
            deletion_raw, deletion_envelope = self._store.read_bound(
                mission_id=self.binding.mission_id,
                resource_id=deletion_resource_id,
                now=None,
            )
            if deletion_raw:
                raise RawResultQuarantineError("deletion intent content is invalid")
            try:
                deletion = _StreamDeletionBinding.model_validate_json(
                    canonicalize(deletion_envelope.binding.to_dict()),
                    strict=True,
                )
            except (TypeError, ValueError) as exc:
                raise RawResultQuarantineError("deletion intent is invalid") from exc
            if not (
                deletion.mission_revision == acknowledgment.mission_revision
                and deletion.stream_binding_digest
                == acknowledgment.stream_binding_digest
                and deletion.execution_id == acknowledgment.execution_id
                and deletion.sink_id == acknowledgment.sink_id
                and deletion.chunk_count == acknowledgment.chunk_count
                and deletion.artifact_sequences
                == acknowledgment.artifact_sequences
                and deletion.aggregate_digest == acknowledgment.aggregate_digest
                and deletion.receipt_digest == acknowledgment.receipt_digest
                and deletion.ingestion_id == acknowledgment.ingestion_id
                and deletion.ingestion_digest == acknowledgment.ingestion_digest
            ):
                raise RawResultQuarantineError(
                    "execution-result acknowledgment binding is invalid"
                )
        if not self._audit.operation_recorded(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="delete",
            operation_id=self._audit_operation_id("delete", "intent"),
            metadata_digest=acknowledgment.receipt_digest,
        ):
            raise RawResultQuarantineError(
                "execution-result acknowledgment lacks deletion evidence"
            )
        for sequence in range(acknowledgment.chunk_count):
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._chunk_resource_id(sequence),
            )
        for artifact_sequence in acknowledgment.artifact_sequences:
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._artifact_terminal_resource_id(
                    artifact_sequence
                ),
            )
        for resource_id in (
            self._terminal_resource_id("commit"),
            self._ingestion_result_resource_id(),
            deletion_resource_id,
        ):
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=resource_id,
            )
        self._store.erase_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._ingestion_ack_resource_id(),
        )
        self._chunks.clear()
        self._artifact_terminals.clear()
        self._receipt = None
        self._ingestion_result = None
        self._ingestion_binding = None
        self._terminal_envelope = None
        self._deleted = True

    def _delete_expired(self, *, now: datetime) -> None:
        if self._deleted:
            return
        if now < self.binding.retention_until:
            raise RawResultQuarantineError("raw-result quarantine retention is live")
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        ):
            self._resume_deletion()
            return
        intent = _StreamExpiryDeletionBinding(
            record_type="stream_expiry_delete_intent",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            terminal_state=(
                "committed" if self._receipt is not None else "abandoned"
            ),
            chunk_count=len(self._chunks),
            artifact_sequences=tuple(sorted(self._artifact_terminals)),
            aggregate_digest=self._aggregate_digest(),
            receipt_digest=(
                None if self._receipt is None else self._receipt.receipt_digest
            ),
        )
        self._store.write_quarantine_cleanup_intent(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
            binding=intent.model_dump(mode="json"),
            created_at=now,
        )
        self._resume_deletion()

    def _resume_expiry_deletion(
        self,
        value: dict[str, object],
        *,
        envelope: _StoredEnvelope,
    ) -> None:
        try:
            intent = _StreamExpiryDeletionBinding.model_validate_json(
                canonicalize(value),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError("expiry deletion intent is invalid") from exc
        if not (
            intent.mission_revision == self.binding.mission_revision
            and intent.stream_binding_digest == self._binding_digest
            and intent.execution_id == self.execution_id
            and intent.sink_id == self.sink_id
            and intent.artifact_sequences
            == tuple(sorted(set(intent.artifact_sequences)))
            and all(sequence >= 0 for sequence in intent.artifact_sequences)
            and (
                (intent.terminal_state == "committed" and intent.receipt_digest)
                or (
                    intent.terminal_state == "abandoned"
                    and intent.receipt_digest is None
                )
            )
        ):
            raise RawResultQuarantineError("expiry deletion intent binding is invalid")
        terminal_resource_id = self._terminal_resource_id("commit")
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=terminal_resource_id,
        ):
            terminal_envelope = self._store.verified_envelope(
                mission_id=self.binding.mission_id,
                resource_id=terminal_resource_id,
                now=None,
            )
            try:
                terminal = _TerminalBinding.model_validate(
                    terminal_envelope.binding.to_dict()
                )
            except ValueError as exc:
                raise RawResultQuarantineError(
                    "expiry deletion terminal is invalid"
                ) from exc
            if not (
                intent.terminal_state == "committed"
                and terminal.record_type == "stream_commit"
                and terminal.chunk_count == intent.chunk_count
                and terminal.aggregate_digest == intent.aggregate_digest
                and terminal.receipt_digest == intent.receipt_digest
            ):
                raise RawResultQuarantineError(
                    "expiry deletion terminal binding is invalid"
                )
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="delete",
            operation_id=self._audit_operation_id("delete", "expiry-intent"),
            metadata_digest=intent.receipt_digest or intent.aggregate_digest,
            occurred_at=envelope.created_at,
        )
        for sequence in range(intent.chunk_count):
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._chunk_resource_id(sequence),
            )
        for artifact_sequence in intent.artifact_sequences:
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._artifact_terminal_resource_id(artifact_sequence),
            )
        self._store.erase_resource(
            mission_id=self.binding.mission_id,
            resource_id=terminal_resource_id,
        )
        self._store.erase_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        )
        self._chunks.clear()
        self._artifact_terminals.clear()
        self._receipt = None
        self._terminal_envelope = None
        self._deleted = True

    def _delete_aborted(self, *, now: datetime) -> None:
        if self._deleted:
            return
        if not self._aborted or self._terminal_envelope is None:
            raise RawResultQuarantineError("raw-result stream is not aborted")
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        ):
            self._resume_deletion()
            return
        terminal = _TerminalBinding.model_validate(
            self._terminal_envelope.binding.to_dict()
        )
        intent = _StreamAbortDeletionBinding(
            record_type="stream_abort_delete_intent",
            mission_revision=self.binding.mission_revision,
            stream_binding_digest=self._binding_digest,
            execution_id=self.execution_id,
            sink_id=self.sink_id,
            chunk_count=len(self._chunks),
            artifact_sequences=tuple(sorted(self._artifact_terminals)),
            aggregate_digest=terminal.aggregate_digest,
        )
        self._store.write_quarantine_cleanup_intent(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
            binding=intent.model_dump(mode="json"),
            created_at=now,
        )
        self._resume_deletion()

    def _resume_abort_deletion(
        self,
        value: dict[str, object],
        *,
        envelope: _StoredEnvelope,
    ) -> None:
        try:
            intent = _StreamAbortDeletionBinding.model_validate_json(
                canonicalize(value),
                strict=True,
            )
        except (TypeError, ValueError) as exc:
            raise RawResultQuarantineError("abort deletion intent is invalid") from exc
        terminal_envelope: _StoredEnvelope | None = None
        terminal: _TerminalBinding | None = None
        if self._store.has_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._terminal_resource_id("abort"),
        ):
            terminal_envelope = self._store.verified_envelope(
                mission_id=self.binding.mission_id,
                resource_id=self._terminal_resource_id("abort"),
                now=None,
            )
            try:
                terminal = _TerminalBinding.model_validate(
                    terminal_envelope.binding.to_dict()
                )
            except ValueError as exc:
                raise RawResultQuarantineError(
                    "abort deletion terminal is invalid"
                ) from exc
        if not (
            intent.mission_revision == self.binding.mission_revision
            and intent.stream_binding_digest == self._binding_digest
            and intent.execution_id == self.execution_id
            and intent.sink_id == self.sink_id
            and intent.artifact_sequences
            == tuple(sorted(set(intent.artifact_sequences)))
            and all(sequence >= 0 for sequence in intent.artifact_sequences)
            and (
                terminal is None
                or (
                    terminal.record_type == "stream_abort"
                    and terminal.chunk_count == intent.chunk_count
                    and terminal.aggregate_digest == intent.aggregate_digest
                )
            )
        ):
            raise RawResultQuarantineError("abort deletion intent binding is invalid")
        self._audit.record(
            mission_id=self.binding.mission_id,
            resource_type="raw_result_quarantine",
            resource_id=self.quarantine_id,
            operation="delete",
            operation_id=self._audit_operation_id("delete", "abort-intent"),
            metadata_digest=intent.aggregate_digest,
            occurred_at=envelope.created_at,
        )
        for sequence in range(intent.chunk_count):
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._chunk_resource_id(sequence),
            )
        for artifact_sequence in intent.artifact_sequences:
            self._store.erase_resource(
                mission_id=self.binding.mission_id,
                resource_id=self._artifact_terminal_resource_id(artifact_sequence),
            )
        self._store.erase_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._terminal_resource_id("abort"),
        )
        self._store.erase_resource(
            mission_id=self.binding.mission_id,
            resource_id=self._deletion_resource_id(),
        )
        self._chunks.clear()
        self._artifact_terminals.clear()
        self._aborted = True
        self._terminal_envelope = None
        self._deleted = True

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
        artifact_count = len(self._artifact_terminals)
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
        try:
            binding = self._bindings.resolve(execution_id)
            if binding.execution_id != execution_id:
                raise RawResultQuarantineError(
                    "stream binding resolver returned another execution"
                )
            return EncryptedRawResultSink(
                quarantine=self._quarantine,
                binding=binding,
                clock=self._clock,
            )
        except (
            ArtifactSecurityError,
            AuditIntegrityError,
            DigestIntegrityError,
            EncryptionIntegrityError,
            EncryptionKeyUnavailableError,
            RawResultQuarantineError,
            RawResultStreamingError,
        ):
            raise RawResultQuarantineError(
                "encrypted raw-result sink reconstruction failed"
            ) from None

    def recovery_metadata_for_failure(
        self,
        execution_id: str,
        *,
        updated_at: datetime,
    ) -> RawResultRecoveryMetadata:
        quarantine_id = stable_id(
            "quarantine",
            {"schema_version": "encrypted-stream-v1", "execution_id": execution_id},
        )
        sink_id = stable_id(
            "sink",
            {"schema_version": "encrypted-stream-v1", "execution_id": execution_id},
        )
        provisional = RawResultRecoveryMetadata(
            recovery_id=stable_id(
                "recovery",
                {
                    "schema_version": "raw-result-recovery-v1",
                    "execution_id": execution_id,
                    "quarantine_id": quarantine_id,
                },
            ),
            recovery_digest="pending",
            execution_id=execution_id,
            quarantine_id=quarantine_id,
            sink_id=sink_id,
            state="RECOVERY_REQUIRED",
            bytes_received=0,
            last_chunk_sequence=-1,
            receipt_id=None,
            updated_at=updated_at,
        )
        return provisional.model_copy(
            update={
                "recovery_digest": digest_model(
                    provisional,
                    exclude={"recovery_digest"},
                )
            }
        )
