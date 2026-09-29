"""Session runtime state models (SystemDesign §14 / §20.1).

Phase 0A models the security-relevant session context and the freshness bound
used by snapshot revalidation. It does not connect to any live session provider.
"""
