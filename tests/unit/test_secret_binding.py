"""Ephemeral secret binding: non-serializable, redacting, zeroizing (SystemDesign §10.2)."""

from __future__ import annotations

import copy
import pickle

import pytest

from redteam_agent.execution.secret_binding import EphemeralSecretBinding, _EphemeralSecretBinding


def _binding() -> _EphemeralSecretBinding:
    return _EphemeralSecretBinding(
        secret_argument_path="/credential", secret_version_id="sv-1", buffer=bytearray(b"s3cret")
    )


def test_length_is_the_only_value_metadata() -> None:
    binding = _binding()
    assert binding.length() == 6
    assert binding.secret_version_id == "sv-1"
    assert binding.secret_argument_path == "/credential"


def test_repr_redacts_value() -> None:
    assert "s3cret" not in repr(_binding())


def test_not_picklable() -> None:
    with pytest.raises(TypeError):
        pickle.dumps(_binding())


def test_not_copyable() -> None:
    with pytest.raises(TypeError):
        copy.copy(_binding())
    with pytest.raises(TypeError):
        copy.deepcopy(_binding())


def test_zeroize_clears_buffer_and_invalidates() -> None:
    buffer = bytearray(b"s3cret")
    binding = _EphemeralSecretBinding(secret_argument_path="/c", secret_version_id="sv-1", buffer=buffer)
    binding.zeroize()
    assert bytes(buffer) == b"\x00" * 6
    assert binding.length() == 0
    with pytest.raises(RuntimeError):
        binding.consume()


def test_satisfies_protocol() -> None:
    assert isinstance(_binding(), EphemeralSecretBinding)
