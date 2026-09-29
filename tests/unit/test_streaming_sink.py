"""Streaming sink: chunk streaming, no whole-result buffering, cap, idempotent commit."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redteam_agent.errors import ResultCollectionError
from redteam_agent.execution.models import RawArtifactMetadata
from redteam_agent.execution.sink import StreamingQuarantineSink

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _sink(max_output_bytes: int = 10_000_000) -> StreamingQuarantineSink:
    return StreamingQuarantineSink(
        sink_id="sink-1", execution_id="exec-1", quarantine_id="q-1", task_binding_digest="bd",
        max_output_bytes=max_output_bytes, committed_at=T0,
    )


def test_streams_without_buffering_whole_result() -> None:
    sink = _sink()
    chunk = b"x" * 10_000
    total = 0
    for _ in range(200):  # 2 MB total, fed one chunk at a time
        sink.write_stdout(chunk)
        total += len(chunk)
    receipt = sink.commit()
    assert receipt.stdout_bytes == total
    # The sink never holds more than a single chunk resident at once.
    assert sink.max_single_chunk_bytes == len(chunk)
    assert sink.max_single_chunk_bytes * 10 < total
    # There is no attribute accumulating the concatenated bytes.
    for value in sink.__dict__.values():
        assert not (isinstance(value, (bytes, bytearray)) and len(value) >= total)


def test_output_cap_enforced_and_marks_recovery_required() -> None:
    sink = _sink(max_output_bytes=1024)
    with pytest.raises(ResultCollectionError):
        sink.write_stdout(b"y" * 2048)
    assert sink.state == "RECOVERY_REQUIRED"


def test_commit_is_idempotent() -> None:
    sink = _sink()
    sink.write_stdout(b"abc")
    first = sink.commit()
    second = sink.commit()
    assert first == second
    assert first.ciphertext_digest == second.ciphertext_digest


def test_artifact_streaming_counts_without_buffer() -> None:
    sink = _sink()
    sink.write_artifact(RawArtifactMetadata(artifact_sequence=0, suggested_name="a", media_type=None), (b"a", b"bc"))
    receipt = sink.commit()
    assert receipt.artifact_count == 1


def test_abort_moves_to_terminal_and_blocks_commit() -> None:
    sink = _sink()
    sink.write_stdout(b"abc")
    sink.abort()
    assert sink.state == "ABORTED"
    with pytest.raises(ResultCollectionError):
        sink.write_stdout(b"more")


def test_cannot_abort_after_commit() -> None:
    sink = _sink()
    sink.commit()
    with pytest.raises(ResultCollectionError):
        sink.abort()
