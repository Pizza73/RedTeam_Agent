"""Deterministic concrete scope evaluation (SystemDesign §21 / §22).

MVP implements IP/CIDR (network), Host ID (host) and Session ID (session). Every
other scope/target type is Default Deny even when its schema exists. Prohibited
rules always win over allowed rules, and matching is fail-closed: prohibition is
evaluated conservatively (an unknown port/protocol cannot escape a prohibition),
while allow is evaluated strictly (an unknown port/protocol cannot satisfy a
port/protocol-constrained allow). This guarantees Scope False-Allow = 0 (B-01).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

from redteam_agent.errors import ScopeEvaluationError
from redteam_agent.policy.scope_models import (
    ExecutionScopeRule,
    HostScopeRule,
    NetworkScopeRule,
    NormalizedTarget,
    SessionScopeRule,
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

IMPLEMENTED_SCOPE_TYPES: frozenset[str] = frozenset({"network", "host", "session"})
IMPLEMENTED_TARGET_TYPES: frozenset[str] = frozenset({"ip", "host", "session"})

ScopeReason = Literal[
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "PROHIBITED",
    "SCOPE_TYPE_NOT_IMPLEMENTED",
    "SCOPE_INDETERMINATE",
]


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason_code: ScopeReason


def _canonical_ip(value: str) -> IPAddress:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # Prevent IPv4-mapped IPv6 (``::ffff:a.b.c.d``) scope evasion.
        return address.ipv4_mapped
    return address


def _canonical_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Canonicalize a CIDR, unmapping IPv4-mapped IPv6 networks symmetrically.

    ``::ffff:10.1.2.3/128`` becomes ``10.1.2.3/32`` so a prohibited rule written
    in mapped form matches an IPv4 target. This mirrors :func:`_canonical_ip`,
    preventing a mapped rule from being silently ignored as a version mismatch.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if isinstance(network, ipaddress.IPv6Network):
        mapped = network.network_address.ipv4_mapped
        if mapped is not None and network.prefixlen >= 96:
            return ipaddress.ip_network(f"{mapped}/{network.prefixlen - 96}", strict=False)
    return network


def _ip_in_cidr(address: IPAddress, cidr: str) -> bool:
    network = _canonical_network(cidr)
    if address.version != network.version:
        # Version mismatch never matches; a target canonicalized to IPv4 will
        # not silently satisfy an IPv6 rule (or vice versa). Fail closed.
        return False
    if isinstance(address, ipaddress.IPv4Address) and isinstance(network, ipaddress.IPv4Network):
        return address in network
    if isinstance(address, ipaddress.IPv6Address) and isinstance(network, ipaddress.IPv6Network):
        return address in network
    return False


def _network_allow_match(rule: NetworkScopeRule, target: NormalizedTarget) -> bool:
    if target.type != "ip":
        return False
    try:
        address = _canonical_ip(target.canonical_value)
    except ValueError:
        return False
    if not any(_safe_in_cidr(address, cidr) for cidr in rule.cidrs):
        return False
    # Strict port/protocol enforcement: a constrained rule requires a known,
    # in-set value on the target.
    if rule.ports is not None and (target.port is None or target.port not in rule.ports):
        return False
    return not (rule.protocols is not None and (target.protocol is None or target.protocol not in rule.protocols))


def _network_prohibit_match(rule: NetworkScopeRule, target: NormalizedTarget) -> bool:
    if target.type != "ip":
        return False
    try:
        address = _canonical_ip(target.canonical_value)
    except ValueError:
        # An unparseable target inside a prohibition context is treated as a
        # non-match here; the overall evaluation still denies it below.
        return False
    if not any(_safe_in_cidr(address, cidr) for cidr in rule.cidrs):
        return False
    # Conservative: a prohibition covers the target unless we can positively
    # rule it out. Unknown port/protocol therefore cannot escape prohibition.
    if rule.ports is not None and target.port is not None and target.port not in rule.ports:
        return False
    return not (
        rule.protocols is not None and target.protocol is not None and target.protocol not in rule.protocols
    )


def _safe_in_cidr(address: IPAddress, cidr: str) -> bool:
    try:
        return _ip_in_cidr(address, cidr)
    except ValueError:
        return False


def _host_match(rule: HostScopeRule, target: NormalizedTarget) -> bool:
    return target.type == "host" and target.canonical_value == rule.host_id


def _session_match(rule: SessionScopeRule, target: NormalizedTarget) -> bool:
    return target.type == "session" and target.canonical_value == rule.session_id


def _rule_matches_allow(rule: ExecutionScopeRule, target: NormalizedTarget) -> bool:
    if isinstance(rule, NetworkScopeRule):
        return _network_allow_match(rule, target)
    if isinstance(rule, HostScopeRule):
        return _host_match(rule, target)
    if isinstance(rule, SessionScopeRule):
        return _session_match(rule, target)
    return False  # unimplemented scope type never grants


def _rule_matches_prohibit(rule: ExecutionScopeRule, target: NormalizedTarget) -> bool:
    if isinstance(rule, NetworkScopeRule):
        return _network_prohibit_match(rule, target)
    if isinstance(rule, HostScopeRule):
        return _host_match(rule, target)
    if isinstance(rule, SessionScopeRule):
        return _session_match(rule, target)
    return False


def evaluate_target(
    allowed: tuple[ExecutionScopeRule, ...],
    prohibited: tuple[ExecutionScopeRule, ...],
    target: NormalizedTarget,
) -> ScopeDecision:
    """Decide whether a single normalized target is in scope."""
    if target.type not in IMPLEMENTED_TARGET_TYPES:
        return ScopeDecision(allowed=False, reason_code="SCOPE_TYPE_NOT_IMPLEMENTED")

    if target.type == "ip":
        try:
            _canonical_ip(target.canonical_value)
        except ValueError:
            return ScopeDecision(allowed=False, reason_code="SCOPE_INDETERMINATE")

    if any(_rule_matches_prohibit(rule, target) for rule in prohibited):
        return ScopeDecision(allowed=False, reason_code="PROHIBITED")

    if any(_rule_matches_allow(rule, target) for rule in allowed):
        return ScopeDecision(allowed=True, reason_code="IN_SCOPE")

    return ScopeDecision(allowed=False, reason_code="OUT_OF_SCOPE")


def evaluate_targets(
    allowed: tuple[ExecutionScopeRule, ...],
    prohibited: tuple[ExecutionScopeRule, ...],
    targets: tuple[NormalizedTarget, ...],
) -> ScopeDecision:
    """All targets must be in scope; the first failure decides the result."""
    if not targets:
        # A tool that requires a target but resolves none is Default Deny.
        return ScopeDecision(allowed=False, reason_code="OUT_OF_SCOPE")
    for target in targets:
        decision = evaluate_target(allowed, prohibited, target)
        if not decision.allowed:
            return decision
    return ScopeDecision(allowed=True, reason_code="IN_SCOPE")


def assert_scope_rules_interpretable(rules: tuple[ExecutionScopeRule, ...]) -> None:
    """Reject uninterpretable rules for implemented types (fail closed).

    A network rule with an unparseable CIDR, an out-of-range port, or an empty
    protocol is rejected here rather than being silently ignored during matching
    (which could bypass a prohibition).
    """
    for rule in rules:
        if isinstance(rule, NetworkScopeRule):
            for cidr in rule.cidrs:
                try:
                    _canonical_network(cidr)
                except ValueError as exc:
                    raise ScopeEvaluationError(f"uninterpretable CIDR in scope rule: {cidr!r}") from exc
            if rule.ports is not None:
                for port in rule.ports:
                    if not 0 < port < 65536:
                        raise ScopeEvaluationError(f"port out of range in scope rule: {port}")
            if rule.protocols is not None:
                for protocol in rule.protocols:
                    if protocol == "":
                        raise ScopeEvaluationError("empty protocol in scope rule")


def mission_supports_scope_type(scope_type: str, allowed: tuple[ExecutionScopeRule, ...]) -> bool:
    """Whether at least one implemented allowed rule of ``scope_type`` exists."""
    if scope_type not in IMPLEMENTED_SCOPE_TYPES:
        return False
    return any(rule.type == scope_type for rule in allowed)
