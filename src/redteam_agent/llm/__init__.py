"""LLM profile registration (SystemDesign §7 / §21).

Phase 0A only needs the profile record that mission validation binds to. No
LLM is invoked. A Mock profile is registered explicitly; empty or unregistered
profiles cannot bypass validation.
"""
