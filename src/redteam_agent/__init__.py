"""RedTeam Agent — Phase 0A: Core Models / Authorization Kernel.

This package implements the deterministic authorization kernel described in
``SystemDesign.md`` §36 Phase 0A and the accompanying acceptance criteria.

Phase 0A performs **no external dispatch**. The Executor authorization gate
validates a ``PolicyDecision`` and stops; it never calls an adapter. Later-phase
capabilities (execution state machine, secret injection, production crypto/TPM,
real adapters) are intentionally out of scope and are not faked here.
"""

__all__ = ["__version__"]

__version__ = "0.0.0a1"
