"""Composition roots (SystemDesign §35.2).

Phase 0A provides a test/local composition only. The production composition root
(single-host TPM witness, production key provider, real adapters) is a later
phase and must not be faked; see :mod:`redteam_agent.composition.production`.
"""
