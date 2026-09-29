"""Stable public error codes for the AD MCP boundary."""

from __future__ import annotations


class AdMcpError(Exception):
    """An expected failure that is safe to report by code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AuthorizationError(AdMcpError):
    pass


class ConfigurationError(AdMcpError):
    pass


class ScopeError(AdMcpError):
    pass


class ValidationError(AdMcpError):
    pass
