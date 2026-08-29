"""Deterministic Basic Typed Scope normalization and evaluation."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from redteam_agent.models.scope import (
    CidrTargetReference,
    HostScopeRule,
    HostTargetReference,
    IpTargetReference,
    NetworkScopeRule,
    NormalizedTarget,
    SessionScopeRule,
    SessionTargetReference,
    TargetReference,
)


class TargetNormalizationError(ValueError):
    pass


class UnsupportedScopeTypeError(TargetNormalizationError):
    pass


class TargetNormalizer:
    """Supports only IP/CIDR, Host ID and Session ID in Phase 0A."""

    implemented_target_types = frozenset({"ip", "cidr", "host", "session"})

    def normalize(self, target: TargetReference) -> NormalizedTarget:
        if isinstance(target, IpTargetReference):
            try:
                address = ipaddress.ip_address(target.address)
            except ValueError as exc:
                raise TargetNormalizationError("invalid IP address") from exc
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                raise TargetNormalizationError("IPv4-mapped IPv6 is rejected to prevent aliasing")
            return NormalizedTarget(
                type="ip",
                canonical_value=str(address),
                port=target.port,
                protocol=target.protocol,
                source="plan",
            )
        if isinstance(target, CidrTargetReference):
            try:
                network = ipaddress.ip_network(target.cidr, strict=False)
            except ValueError as exc:
                raise TargetNormalizationError("invalid CIDR") from exc
            return NormalizedTarget(
                type="cidr",
                canonical_value=str(network),
                port=target.port,
                protocol=target.protocol,
                source="plan",
            )
        if isinstance(target, HostTargetReference):
            return NormalizedTarget(type="host", canonical_value=target.host_id, source="plan")
        if isinstance(target, SessionTargetReference):
            return NormalizedTarget(
                type="session", canonical_value=target.session_id, source="plan"
            )
        raise UnsupportedScopeTypeError(f"scope type {target.type} is not implemented in Phase 0A")


@dataclass(frozen=True)
class ScopeEvaluation:
    allowed: bool
    reason_code: str


class ScopeEvaluator:
    """Allowed is necessary; a matching prohibited rule always wins."""

    def evaluate(
        self,
        target: NormalizedTarget,
        allowed_rules: tuple[object, ...],
        prohibited_rules: tuple[object, ...],
    ) -> ScopeEvaluation:
        if target.type not in TargetNormalizer.implemented_target_types:
            return ScopeEvaluation(False, "SCOPE_TYPE_NOT_IMPLEMENTED")
        if any(self._matches(target, rule, prohibited=True) for rule in prohibited_rules):
            return ScopeEvaluation(False, "PROHIBITED_SCOPE_MATCH")
        if any(self._matches(target, rule, prohibited=False) for rule in allowed_rules):
            return ScopeEvaluation(True, "SCOPE_ALLOWED")
        return ScopeEvaluation(False, "NO_ALLOWED_SCOPE_MATCH")

    @staticmethod
    def _network_matches(
        target_network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        scope_network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        *,
        prohibited: bool,
    ) -> bool:
        if isinstance(target_network, ipaddress.IPv4Network):
            if not isinstance(scope_network, ipaddress.IPv4Network):
                return False
            return (
                target_network.overlaps(scope_network)
                if prohibited
                else target_network.subnet_of(scope_network)
            )
        if not isinstance(scope_network, ipaddress.IPv6Network):
            return False
        return (
            target_network.overlaps(scope_network)
            if prohibited
            else target_network.subnet_of(scope_network)
        )

    @staticmethod
    def _matches(target: NormalizedTarget, rule: object, *, prohibited: bool) -> bool:
        if target.type in {"ip", "cidr"} and isinstance(rule, NetworkScopeRule):
            target_network = (
                ipaddress.ip_network(target.canonical_value, strict=False)
                if target.type == "cidr"
                else ipaddress.ip_network(f"{target.canonical_value}/32", strict=False)
                if ipaddress.ip_address(target.canonical_value).version == 4
                else ipaddress.ip_network(f"{target.canonical_value}/128", strict=False)
            )
            network_matches = any(
                ScopeEvaluator._network_matches(
                    target_network, scope_network, prohibited=prohibited
                )
                for scope_network in (
                    ipaddress.ip_network(cidr, strict=False) for cidr in rule.cidrs
                )
            )
            if not network_matches:
                return False
            if rule.ports is not None:
                if target.port is None:
                    # An unknown endpoint may intersect a prohibited rule, but cannot
                    # satisfy a restricted allow rule.
                    return prohibited
                if target.port not in rule.ports:
                    return False
            if rule.protocols is not None:
                if target.protocol is None:
                    return prohibited
                if target.protocol not in rule.protocols:
                    return False
            return True
        if target.type == "host" and isinstance(rule, HostScopeRule):
            return target.canonical_value == rule.host_id
        if target.type == "session" and isinstance(rule, SessionScopeRule):
            return target.canonical_value == rule.session_id
        return False
