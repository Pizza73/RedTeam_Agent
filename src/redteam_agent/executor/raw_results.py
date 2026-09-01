"""Raw-result streaming boundary and metadata-only mock quarantine sink."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Literal, Protocol

from redteam_agent.canonical import digest_model, stable_id
from redteam_agent.errors import RawResultQuarantineError, RawResultStreamingError
from redteam_agent.models.execution import (
    RawArtifactMetadata,
    RawResultReceipt,
    RawResultRecoveryMetadata,
)


class RawResultSink(Protocol):
    """Quarantine-owned stream; implementations must never expose accumulated raw bytes."""

    @property
    def committed(self) -> bool: ...

    async def write_stdout(self, chunk: bytes) -> None: ...

    async def write_stderr(self, chunk: bytes) -> None: ...

    async def write_artifact(
        self,
        metadata: RawArtifactMetadata,
        chunks: AsyncIterator[bytes],
    ) -> None: ...

    async def commit(self) -> RawResultReceipt: ...

    async def abort(self) -> None: ...

    def mark_recovery_required(self) -> None: ...

    def recovery_metadata(self, *, updated_at: datetime) -> RawResultRecoveryMetadata: ...


class RawResultSinkFactory(Protocol):
    def for_execution(self, execution_id: str) -> RawResultSink: ...

    def recovery_metadata_for_failure(
        self,
        execution_id: str,
        *,
        updated_at: datetime,
    ) -> RawResultRecoveryMetadata: ...


class MockRawResultSink:
    """Metadata-only sink used by tests; bytes are incrementally hashed then discarded."""

    def __init__(
        self,
        *,
        execution_id: str,
        sink_id: str,
        committed_at: datetime,
        max_bytes: int,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("raw-result size limit must be positive")
        self.execution_id = execution_id
        self.sink_id = sink_id
        self.quarantine_id = stable_id(
            "quarantine",
            {"schema_version": "mock-quarantine-v1", "execution_id": execution_id},
        )
        self._committed_at = committed_at
        self._max_bytes = max_bytes
        self._hasher = hashlib.sha256(b"redteam-agent:mock-quarantine:v1\x00")
        self._stdout_bytes = 0
        self._stderr_bytes = 0
        self._artifact_count = 0
        self._artifact_sequences: set[int] = set()
        self._bytes_received = 0
        self._chunk_sequence = -1
        self._receipt: RawResultReceipt | None = None
        self._aborted = False
        self._recovery_required = False
        self.max_observed_chunk_bytes = 0

    @property
    def committed(self) -> bool:
        return self._receipt is not None

    @property
    def bytes_received(self) -> int:
        return self._bytes_received

    def _write(self, channel: bytes, chunk: bytes) -> None:
        if self._receipt is not None or self._aborted:
            raise RawResultStreamingError("raw-result sink is no longer writable")
        if not isinstance(chunk, bytes):
            raise RawResultStreamingError("raw-result chunks must be bytes")
        next_size = self._bytes_received + len(chunk)
        if next_size > self._max_bytes:
            raise RawResultQuarantineError("raw-result quarantine size limit exceeded")
        self._chunk_sequence += 1
        self._hasher.update(channel)
        self._hasher.update(self._chunk_sequence.to_bytes(8, "big", signed=False))
        self._hasher.update(len(chunk).to_bytes(8, "big", signed=False))
        self._hasher.update(chunk)
        self._bytes_received = next_size
        self.max_observed_chunk_bytes = max(self.max_observed_chunk_bytes, len(chunk))

    async def write_stdout(self, chunk: bytes) -> None:
        self._write(b"stdout\x00", chunk)
        self._stdout_bytes += len(chunk)

    async def write_stderr(self, chunk: bytes) -> None:
        self._write(b"stderr\x00", chunk)
        self._stderr_bytes += len(chunk)

    async def write_artifact(
        self,
        metadata: RawArtifactMetadata,
        chunks: AsyncIterator[bytes],
    ) -> None:
        if metadata.artifact_sequence in self._artifact_sequences:
            raise RawResultStreamingError("artifact sequence was reused")
        self._artifact_sequences.add(metadata.artifact_sequence)
        self._hasher.update(b"artifact-metadata\x00")
        self._hasher.update(digest_model(metadata).encode("ascii"))
        async for chunk in chunks:
            self._write(b"artifact\x00", chunk)
        self._artifact_count += 1

    async def commit(self) -> RawResultReceipt:
        if self._aborted:
            raise RawResultQuarantineError("aborted quarantine cannot be committed")
        if self._receipt is not None:
            return self._receipt
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
            stdout_bytes=self._stdout_bytes,
            stderr_bytes=self._stderr_bytes,
            artifact_count=self._artifact_count,
            ciphertext_digest="sha256:" + self._hasher.hexdigest(),
            committed_at=self._committed_at,
        )
        self._receipt = provisional.model_copy(
            update={
                "receipt_digest": digest_model(
                    provisional, exclude={"receipt_digest"}
                )
            }
        )
        return self._receipt

    async def abort(self) -> None:
        if self._receipt is None:
            self._aborted = True

    def mark_recovery_required(self) -> None:
        if self._receipt is None:
            self._recovery_required = True

    def recovery_metadata(self, *, updated_at: datetime) -> RawResultRecoveryMetadata:
        state: Literal["OPEN", "COMMITTED", "RECOVERY_REQUIRED", "ABORTED"] = (
            "COMMITTED"
            if self._receipt is not None
            else "RECOVERY_REQUIRED"
            if self._recovery_required or self._bytes_received
            else "ABORTED"
            if self._aborted
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
            bytes_received=self._bytes_received,
            last_chunk_sequence=self._chunk_sequence,
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


class MockQuarantineStore:
    """Durable test-double boundary shared by factories across Executor restarts."""

    def __init__(self) -> None:
        self.sinks: dict[str, MockRawResultSink] = {}


class MockRawResultSinkFactory:
    """Returns the same bound sink when result collection resumes after a crash."""

    def __init__(
        self,
        *,
        now: datetime,
        max_bytes: int = 16 * 1024 * 1024,
        store: MockQuarantineStore | None = None,
    ) -> None:
        self._now = now
        self._max_bytes = max_bytes
        self.store = store or MockQuarantineStore()

    def for_execution(self, execution_id: str) -> MockRawResultSink:
        sink = self.store.sinks.get(execution_id)
        if sink is None:
            sink = MockRawResultSink(
                execution_id=execution_id,
                sink_id=stable_id(
                    "sink",
                    {"schema_version": "mock-sink-v1", "execution_id": execution_id},
                ),
                committed_at=self._now,
                max_bytes=self._max_bytes,
            )
            self.store.sinks[execution_id] = sink
        return sink

    def recovery_metadata_for_failure(
        self,
        execution_id: str,
        *,
        updated_at: datetime,
    ) -> RawResultRecoveryMetadata:
        sink = self.store.sinks.get(execution_id)
        if sink is not None:
            sink.mark_recovery_required()
            return sink.recovery_metadata(updated_at=updated_at)
        quarantine_id = stable_id(
            "quarantine",
            {"schema_version": "mock-quarantine-v1", "execution_id": execution_id},
        )
        sink_id = stable_id(
            "sink",
            {"schema_version": "mock-sink-v1", "execution_id": execution_id},
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

    def mock_sink(self, execution_id: str) -> MockRawResultSink | None:
        return self.store.sinks.get(execution_id)
