"""Trusted target extractor tests (B-02: no hidden destinations)."""

from __future__ import annotations

import pytest

from redteam_agent.errors import TargetExtractorResolutionError
from redteam_agent.policy.scope_models import IpTargetReference, SessionTargetReference
from redteam_agent.tools.target_extractors import (
    DEFAULT_TARGET_EXTRACTOR_REGISTRY,
    TargetExtractionInput,
)

REG = DEFAULT_TARGET_EXTRACTOR_REGISTRY


def test_network_enumerates_argument_destinations() -> None:
    data = TargetExtractionInput(
        requested_targets=(), arguments={"destinations": ["10.1.2.3", "10.1.2.4"], "port": 443, "protocol": "tcp"},
        session_id=None,
    )
    targets = REG.extract("network_target_v1", data)
    values = {t.canonical_value for t in targets}
    assert values == {"10.1.2.3", "10.1.2.4"}
    assert all(t.port == 443 and t.protocol == "tcp" for t in targets)


def test_network_unions_requested_and_argument_targets() -> None:
    data = TargetExtractionInput(
        requested_targets=(IpTargetReference(type="ip", address="10.9.9.9"),),
        arguments={"destinations": ["10.1.2.3"]},
        session_id=None,
    )
    targets = REG.extract("network_target_v1", data)
    assert {t.canonical_value for t in targets} == {"10.1.2.3", "10.9.9.9"}


def test_hidden_destination_in_undeclared_field_is_rejected() -> None:
    # An out-of-scope destination hidden in an undeclared argument field must not
    # be silently ignored: the closed schema rejects the whole extraction.
    data = TargetExtractionInput(
        requested_targets=(), arguments={"destinations": ["10.1.2.3"], "secret_dest": "8.8.8.8"}, session_id=None
    )
    with pytest.raises(TargetExtractorResolutionError):
        REG.extract("network_target_v1", data)


def test_out_of_scope_argument_destination_is_enumerated() -> None:
    # The extractor surfaces every argument destination so scope can deny it,
    # even when requested_targets look in-scope.
    data = TargetExtractionInput(
        requested_targets=(IpTargetReference(type="ip", address="10.0.0.1"),),
        arguments={"destinations": ["8.8.8.8"]},
        session_id=None,
    )
    targets = REG.extract("network_target_v1", data)
    assert "8.8.8.8" in {t.canonical_value for t in targets}


def test_ipv4_mapped_destination_is_canonicalized() -> None:
    data = TargetExtractionInput(requested_targets=(), arguments={"destinations": ["::ffff:10.1.2.3"]}, session_id=None)
    targets = REG.extract("network_target_v1", data)
    assert targets[0].canonical_value == "10.1.2.3"


def test_session_extractor_includes_execution_session() -> None:
    data = TargetExtractionInput(
        requested_targets=(SessionTargetReference(type="session", session_id="s2"),),
        arguments={},
        session_id="s1",
    )
    targets = REG.extract("session_target_v1", data)
    assert {t.canonical_value for t in targets} == {"s1", "s2"}


def test_artifact_extractor_has_no_external_target() -> None:
    data = TargetExtractionInput(requested_targets=(), arguments={"artifact_ids": ["a1"]}, session_id=None)
    assert REG.extract("artifact_target_v1", data) == ()


def test_artifact_extractor_rejects_external_targets() -> None:
    data = TargetExtractionInput(
        requested_targets=(IpTargetReference(type="ip", address="10.0.0.1"),), arguments={}, session_id=None
    )
    with pytest.raises(TargetExtractorResolutionError):
        REG.extract("artifact_target_v1", data)


def test_empty_network_extraction_is_error_not_empty_success() -> None:
    data = TargetExtractionInput(requested_targets=(), arguments={"destinations": []}, session_id=None)
    with pytest.raises(TargetExtractorResolutionError):
        REG.extract("network_target_v1", data)


def test_unregistered_extractor_fails_closed() -> None:
    data = TargetExtractionInput(requested_targets=(), arguments={}, session_id=None)
    with pytest.raises(TargetExtractorResolutionError):
        REG.extract("dynamic_import_v1", data)
