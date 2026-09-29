"""Write-capability guard for authorization-artifact repositories.

An authorization artifact (mission state, policy decision, available-tool
snapshot, approval request/record, context grant, lifecycle event) may only be
persisted by its owning application service. Each such repository is bound once
to a single :class:`WriteGuard` created by the composition root and held only by
the owner services. A caller that holds a repository reference cannot persist a
forged artifact because it does not hold the guard. This is a wiring control,
not a cryptographic one; it closes the public raw-save bypass without adding a
new persistent authorization record.
"""

from __future__ import annotations


class WriteGuard:
    """An opaque, unforgeable-by-value capability token (identity-compared)."""

    __slots__ = ()
