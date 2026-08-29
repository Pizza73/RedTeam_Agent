"""Phase 0A contains only the authorization gate, never dispatch."""

from .authorization_gate import AuthorizationGateResult, authorize_execution

__all__ = ["AuthorizationGateResult", "authorize_execution"]

