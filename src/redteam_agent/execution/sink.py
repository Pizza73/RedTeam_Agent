"""Chunk-streaming raw-result sink (SystemDesign §10).

Raw provider content is streamed to the sink chunk-by-chunk. The sink applies a
cumulative size cap and updates a running integrity digest per chunk; it never
accumulates the whole result in memory (``max_single_chunk_bytes`` stays far
below the total). ``commit()`` returns a receipt only after finalizing and is
idempotent (a re-call returns the same receipt); ``abort()`` moves the sink to a
terminal state and never falls back to a normal artifact.

Phase 0B has no production encryption or quarantine store (that is Phase 0C), so
the sink hashes-and-discards plaintext after updating the running digest: it
proves streaming + integrity + no whole-result buffering without persisting raw
bytes. The composition owns the sink; a caller never supplies or selects one.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime
from typing import Protocol

from redteam_agent.errors import ResultCollectionError
from redteam_agent.execution.models import RawArtifactMetadata, RawResultReceipt

_CIPHERTEXT_DOMAIN = b"phase0b-quarantine-stream-v1"


class RawResultSink(Protocol):
    @property
    def sink_id(self) -> str: ...
    def write_stdout(self, chunk: bytes) -> None: ...
    def write_stderr(self, chunk: bytes) -> None: ...
    def write_artifact(self, metadata: RawArtifactMetadata, chunks: Iterable[bytes]) -> None: ...
    def commit(self) -> RawResultReceipt: ...
    def abort(self) -> None: ...


class StreamingQuarantineSink:
    """A bounded-memory, hash-and-discard sink for Phase 0B collection."""

    def __init__(
        self,
        *,
        sink_id: str,
        execution_id: str,
        quarantine_id: str,
        task_binding_digest: str,
        max_output_bytes: int,
        committed_at: datetime,
    ) -> None:
        self._sink_id = sink_id
        self._execution_id = execution_id
        self._quarantine_id = quarantine_id
        self._task_binding_digest = task_binding_digest
        self._max_output_bytes = max_output_bytes
        self._committed_at = committed_at
        self._hasher = hashlib.sha256(_CIPHERTEXT_DOMAIN)
        self._stdout_bytes = 0
        self._stderr_bytes = 0
        self._artifact_count = 0
        self._total_bytes = 0
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
            raise ResultCollectionError(f"sink is not open (state={self._state})")

    def _account(self, chunk: bytes) -> None:
        self.max_single_chunk_bytes = max(self.max_single_chunk_bytes, len(chunk))
        self._total_bytes += len(chunk)
        if self._total_bytes > self._max_output_bytes:
            self._state = "RECOVERY_REQUIRED"
            raise ResultCollectionError("raw result exceeded the tool output cap")
        # Update the running digest and discard the plaintext immediately; no
        # attribute accumulates the concatenated bytes.
        self._hasher.update(chunk)

    def write_stdout(self, chunk: bytes) -> None:
        self._require_open()
        self._account(chunk)
        self._stdout_bytes += len(chunk)

    def write_stderr(self, chunk: bytes) -> None:
        self._require_open()
        self._account(chunk)
        self._stderr_bytes += len(chunk)

    def write_artifact(self, metadata: RawArtifactMetadata, chunks: Iterable[bytes]) -> None:
        self._require_open()
        self._hasher.update(f"artifact:{metadata.artifact_sequence}".encode())
        for chunk in chunks:
            self._account(chunk)
        self._artifact_count += 1

    def commit(self) -> RawResultReceipt:
        if self._receipt is not None:
            return self._receipt  # idempotent
        self._require_open()
        ciphertext_digest = self._hasher.hexdigest()
        self._receipt = RawResultReceipt(
            receipt_id=f"receipt-{self._execution_id}",
            execution_id=self._execution_id,
            quarantine_id=self._quarantine_id,
            task_binding_digest=self._task_binding_digest,
            stdout_bytes=self._stdout_bytes,
            stderr_bytes=self._stderr_bytes,
            artifact_count=self._artifact_count,
            ciphertext_digest=ciphertext_digest,
            committed_at=self._committed_at,
        )
        self._state = "COMMITTED"
        return self._receipt

    def abort(self) -> None:
        if self._state == "COMMITTED":
            raise ResultCollectionError("cannot abort a committed sink")
        self._state = "ABORTED"
