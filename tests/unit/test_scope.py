from __future__ import annotations

import pytest

from redteam_agent.models.scope import (
    CidrTargetReference,
    HostScopeRule,
    HostTargetReference,
    IpTargetReference,
    NetworkScopeRule,
    SessionScopeRule,
    SessionTargetReference,
)
from redteam_agent.policy.scope import ScopeEvaluator, TargetNormalizer, UnsupportedScopeTypeError


@pytest.mark.parametrize(
    ("target", "allowed", "prohibited", "expected"),
    [
        (
            IpTargetReference(type="ip", address="10.0.0.10"),
            (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),),
            (),
            True,
        ),
        (
            IpTargetReference(type="ip", address="2001:db8::1"),
            (NetworkScopeRule(type="network", cidrs=("2001:db8::/64",)),),
            (),
            True,
        ),
        (
            CidrTargetReference(type="cidr", cidr="10.0.0.0/25"),
            (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),),
            (),
            True,
        ),
        (
            HostTargetReference(type="host", host_id="host-1"),
            (HostScopeRule(type="host", host_id="host-1"),),
            (),
            True,
        ),
        (
            SessionTargetReference(type="session", session_id="session-1"),
            (SessionScopeRule(type="session", session_id="session-1"),),
            (),
            True,
        ),
    ],
)
def test_basic_typed_scope(target, allowed, prohibited, expected: bool) -> None:
    normalized = TargetNormalizer().normalize(target)
    assert ScopeEvaluator().evaluate(normalized, allowed, prohibited).allowed is expected


def test_prohibited_scope_wins_over_allowed() -> None:
    target = TargetNormalizer().normalize(IpTargetReference(type="ip", address="10.0.0.200"))
    result = ScopeEvaluator().evaluate(
        target,
        (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),),
        (NetworkScopeRule(type="network", cidrs=("10.0.0.128/25",)),),
    )
    assert result.allowed is False
    assert result.reason_code == "PROHIBITED_SCOPE_MATCH"


def test_cidr_overlap_with_prohibited_is_denied_as_a_whole() -> None:
    target = TargetNormalizer().normalize(CidrTargetReference(type="cidr", cidr="10.0.0.0/24"))
    result = ScopeEvaluator().evaluate(
        target,
        (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),),
        (NetworkScopeRule(type="network", cidrs=("10.0.0.64/26",)),),
    )
    assert not result.allowed


def test_unimplemented_scope_is_not_normalized() -> None:
    from redteam_agent.models.scope import NamedTargetReference

    with pytest.raises(UnsupportedScopeTypeError):
        TargetNormalizer().normalize(NamedTargetReference(type="hostname", value="example.test"))


def test_ipv4_mapped_ipv6_alias_is_rejected() -> None:
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(IpTargetReference(type="ip", address="::ffff:10.0.0.1"))

