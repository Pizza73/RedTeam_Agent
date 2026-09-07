"""Concrete scope evaluation tests (B-01, Scope False-Allow = 0)."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from redteam_agent.errors import ScopeEvaluationError
from redteam_agent.policy.scope_engine import (
    assert_scope_rules_interpretable,
    evaluate_target,
    evaluate_targets,
)
from redteam_agent.policy.scope_models import (
    HostScopeRule,
    NetworkScopeRule,
    NormalizedTarget,
    SessionScopeRule,
)

ALLOW_NET = (NetworkScopeRule(type="network", cidrs=("10.0.0.0/8",), ports=(443,), protocols=("tcp",)),)


def _ip(value: str, *, port: int | None = 443, protocol: str | None = "tcp") -> NormalizedTarget:
    return NormalizedTarget(type="ip", canonical_value=value, port=port, protocol=protocol, source="argument")


def test_in_scope_ip_port_protocol_allowed() -> None:
    assert evaluate_target(ALLOW_NET, (), _ip("10.1.2.3")).allowed


def test_out_of_scope_ip_denied() -> None:
    decision = evaluate_target(ALLOW_NET, (), _ip("192.168.0.1"))
    assert not decision.allowed
    assert decision.reason_code == "OUT_OF_SCOPE"


def test_port_not_in_rule_is_denied() -> None:
    assert not evaluate_target(ALLOW_NET, (), _ip("10.1.2.3", port=22)).allowed


def test_unknown_port_cannot_satisfy_constrained_rule() -> None:
    assert not evaluate_target(ALLOW_NET, (), _ip("10.1.2.3", port=None)).allowed


def test_protocol_mismatch_denied() -> None:
    assert not evaluate_target(ALLOW_NET, (), _ip("10.1.2.3", protocol="udp")).allowed


def test_prohibited_precedence() -> None:
    prohibited = (NetworkScopeRule(type="network", cidrs=("10.1.2.0/24",), ports=None, protocols=None),)
    decision = evaluate_target(ALLOW_NET, prohibited, _ip("10.1.2.3"))
    assert not decision.allowed
    assert decision.reason_code == "PROHIBITED"


def test_ipv4_mapped_ipv6_prohibition_is_not_bypassed() -> None:
    # Regression: a prohibition written in IPv4-mapped IPv6 form must still match
    # an IPv4 target (and vice versa), never silently ignored (Codex B-01).
    prohibited = (NetworkScopeRule(type="network", cidrs=("::ffff:10.1.2.3/128",), ports=None, protocols=None),)
    assert not evaluate_target(ALLOW_NET, prohibited, _ip("10.1.2.3")).allowed
    assert not evaluate_target(ALLOW_NET, prohibited, _ip("::ffff:10.1.2.3")).allowed


def test_adjacent_ip_still_allowed_under_specific_prohibition() -> None:
    prohibited = (NetworkScopeRule(type="network", cidrs=("::ffff:10.1.2.3/128",), ports=None, protocols=None),)
    assert evaluate_target(ALLOW_NET, prohibited, _ip("10.1.2.4")).allowed


def test_unimplemented_target_type_denied() -> None:
    target = NormalizedTarget(type="hostname", canonical_value="example.com", source="plan")
    decision = evaluate_target(ALLOW_NET, (), target)
    assert not decision.allowed
    assert decision.reason_code == "SCOPE_TYPE_NOT_IMPLEMENTED"


def test_host_and_session_scope() -> None:
    host_allow = (HostScopeRule(type="host", host_id="h1"),)
    session_allow = (SessionScopeRule(type="session", session_id="s1"),)
    assert evaluate_target(host_allow, (), NormalizedTarget(type="host", canonical_value="h1", source="plan")).allowed
    assert not evaluate_target(host_allow, (), NormalizedTarget(type="host", canonical_value="h2", source="plan")).allowed
    assert evaluate_target(
        session_allow, (), NormalizedTarget(type="session", canonical_value="s1", source="session")
    ).allowed


def test_no_targets_is_default_deny() -> None:
    assert not evaluate_targets(ALLOW_NET, (), ()).allowed


def test_uninterpretable_cidr_rejected_at_validation() -> None:
    bad = (NetworkScopeRule(type="network", cidrs=("not-an-ip",), ports=None, protocols=None),)
    with pytest.raises(ScopeEvaluationError):
        assert_scope_rules_interpretable(bad)


@given(octets=st.tuples(*[st.integers(min_value=0, max_value=255) for _ in range(4)]))
def test_property_no_false_allow_outside_cidr(octets: tuple[int, int, int, int]) -> None:
    # With an any-port/any-protocol allow of 10.0.0.0/8, a target is allowed iff
    # it is actually inside that network. Never a false allow.
    allow = (NetworkScopeRule(type="network", cidrs=("10.0.0.0/8",), ports=None, protocols=None),)
    address = ".".join(str(o) for o in octets)
    target = _ip(address, port=None, protocol=None)
    decision = evaluate_target(allow, (), target)
    inside = ipaddress.ip_address(address) in ipaddress.ip_network("10.0.0.0/8")
    assert decision.allowed == inside
