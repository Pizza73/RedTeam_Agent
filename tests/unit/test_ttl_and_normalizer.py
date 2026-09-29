"""TTL invariants and target-normalizer failure paths."""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.errors import AuthorizationTtlError, TargetExtractorResolutionError
from redteam_agent.policy.target_normalizer import canonicalize_ip, normalize_port, normalize_protocol
from redteam_agent.policy.ttl import enforce_ttl


def test_ttl_ok_within_bounds() -> None:
    enforce_ttl(
        label="x", issued_at=support.T0, expires_at=support.T0 + timedelta(minutes=5),
        mission_valid_until=support.T0 + timedelta(days=1),
    )


def test_ttl_non_positive_rejected() -> None:
    with pytest.raises(AuthorizationTtlError):
        enforce_ttl(label="x", issued_at=support.T0, expires_at=support.T0, mission_valid_until=support.T0 + timedelta(days=1))


def test_ttl_exceeds_mission_validity_rejected() -> None:
    with pytest.raises(AuthorizationTtlError):
        enforce_ttl(
            label="x", issued_at=support.T0, expires_at=support.T0 + timedelta(days=2),
            mission_valid_until=support.T0 + timedelta(days=1),
        )


def test_ttl_exceeds_parent_rejected() -> None:
    with pytest.raises(AuthorizationTtlError):
        enforce_ttl(
            label="x", issued_at=support.T0, expires_at=support.T0 + timedelta(hours=2),
            mission_valid_until=support.T0 + timedelta(days=1),
            parent_expires_at=support.T0 + timedelta(hours=1),
        )


def test_canonicalize_ip_rejects_garbage() -> None:
    with pytest.raises(TargetExtractorResolutionError):
        canonicalize_ip("not-an-ip")


def test_canonicalize_ip_unmaps_ipv4_in_ipv6() -> None:
    assert canonicalize_ip("::ffff:10.1.2.3") == "10.1.2.3"


def test_normalize_port_rejects_out_of_range_and_bool() -> None:
    with pytest.raises(TargetExtractorResolutionError):
        normalize_port(0)
    with pytest.raises(TargetExtractorResolutionError):
        normalize_port(70000)
    with pytest.raises(TargetExtractorResolutionError):
        normalize_port(True)


def test_normalize_protocol_rejects_empty_and_nonstring() -> None:
    with pytest.raises(TargetExtractorResolutionError):
        normalize_protocol("")
    with pytest.raises(TargetExtractorResolutionError):
        normalize_protocol(3)
    assert normalize_protocol("TCP") == "tcp"
