"""Policy engine: scope, data access, risk, target binding and PolicyDecision.

The policy engine is the *only* component that authorizes a concrete action
(SystemDesign §22, safety-invariants Authorization). It never fetches context
bodies, decides human approval, or dispatches.
"""
