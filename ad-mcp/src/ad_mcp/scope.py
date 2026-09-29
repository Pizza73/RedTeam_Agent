"""Scope checks performed before command construction."""

from __future__ import annotations

import ipaddress
import re

from ad_mcp.config import ScopeConfig
from ad_mcp.errors import ScopeError

_DNS = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)


class ScopePolicy:
    def __init__(self, config: ScopeConfig) -> None:
        try:
            self._networks = tuple(
                ipaddress.ip_network(value, strict=True) for value in config.cidrs
            )
        except ValueError as exc:
            raise ScopeError("SCOPE_CIDR_INVALID") from exc
        self._domains = tuple(self._normalize_dns(value) for value in config.domains)
        self._hosts = frozenset(self._normalize_dns(value) for value in config.hosts)

    @staticmethod
    def _normalize_dns(value: str) -> str:
        normalized = value.rstrip(".").lower()
        if not normalized or _DNS.fullmatch(normalized) is None:
            raise ScopeError("SCOPE_DNS_INVALID")
        return normalized

    def authorize_targets(
        self, targets: tuple[str, ...], *, required: bool, maximum: int
    ) -> tuple[str, ...]:
        if required and not targets:
            raise ScopeError("TARGET_REQUIRED")
        if len(targets) > maximum:
            raise ScopeError("TARGET_LIMIT_EXCEEDED")
        approved: list[str] = []
        for target in targets:
            try:
                address = ipaddress.ip_address(target)
            except ValueError as exc:
                raise ScopeError("TARGET_IP_REQUIRED") from exc
            if str(address) != target or not any(address in network for network in self._networks):
                raise ScopeError("TARGET_OUT_OF_SCOPE")
            approved.append(target)
        return tuple(approved)

    def authorize_domain(self, domain: str | None) -> str | None:
        if domain is None:
            return None
        normalized = self._normalize_dns(domain)
        if normalized not in self._hosts and not any(
            normalized == allowed or normalized.endswith(f".{allowed}")
            for allowed in self._domains
        ):
            raise ScopeError("DOMAIN_OUT_OF_SCOPE")
        return normalized
