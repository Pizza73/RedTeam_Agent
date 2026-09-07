"""Production composition root — not available in Phase 0A.

The production root (SystemDesign §35.2) requires the single-host TPM 2.0 NV
witness, the production key provider with domain/resource key separation, and
approved real adapters. None of that exists in Phase 0A, so building a
production root fails closed rather than presenting test doubles as production.
"""

from __future__ import annotations

from redteam_agent.errors import AuthorizationKernelError


class ProductionCompositionUnavailableError(AuthorizationKernelError):
    """Raised because the production composition root is a later-phase concern."""


def build_production_root() -> None:
    raise ProductionCompositionUnavailableError(
        "production composition (TPM witness, production key provider, real adapters) "
        "is not implemented in Phase 0A"
    )
