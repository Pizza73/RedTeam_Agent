"""Trusted resource metadata read boundaries (SystemDesign §22 / §34).

Phase 0A models the *metadata* source of truth used to bind a data-access grant
to an exact resource version, metadata digest and lifecycle state. No secret
value is ever read here; secret resolution and dispatch are later phases. A
fixed test-double store stands in for the production metadata repositories.
"""
