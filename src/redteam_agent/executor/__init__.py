"""Executor authorization gate (SystemDesign §36 Phase 0A).

Phase 0A implements the gate only: it validates a PolicyDecision and stops. It
never resolves secrets, never builds an ExecutionRequest and never calls an
adapter (External Tool Dispatch = 0). The full dispatching executor is Phase 0B.
"""
