"""Deterministic target normalization helpers (SystemDesign §21 / §22).

Normalization is where scope-evasion tricks are neutralized before scope
evaluation: IPv4-mapped IPv6, non-canonical IP forms, and case differences.
Only IP/host/session are implemented for Phase 0A; other forms are rejected.
"""

from __future__ import annotations

import ipaddress

from redteam_agent.errors import TargetExtractorResolutionError


def canonicalize_ip(value: str) -> str:
    """Return the canonical string form of an IP address, unmapping IPv4-in-IPv6."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TargetExtractorResolutionError(f"unparseable IP target: {value!r}") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TargetExtractorResolutionError(f"port must be an integer, got {value!r}")
    if not 0 < value < 65536:
        raise TargetExtractorResolutionError(f"port out of range: {value}")
    return value


def normalize_protocol(value: object) -> str:
    if not isinstance(value, str) or value == "":
        raise TargetExtractorResolutionError(f"protocol must be a non-empty string, got {value!r}")
    return value.lower()
