"""Sandbox interface/capability models (SystemDesign §19.3).

Phase 0A models the sandbox *requirement/capability contract* only. No isolation
mechanism is implemented; unimplemented capabilities are never treated as
available (Default Deny).
"""
