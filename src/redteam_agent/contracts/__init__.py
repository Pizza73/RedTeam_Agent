"""Registered action-contract catalog (SystemDesign AI-control §5.3).

Phase 0A binds each tool to a fixed, registered action contract keyed by exact
ToolRef. The contract records the tool's parameter-schema digest, target
extractor, evidence rules, risk/side-effect floor and publication rule. Tool
registry validation rejects a tool whose ``action_contract_ref`` does not
resolve to a registered contract that matches the tool. The full prerequisite
search / current-evidence evaluation is a later phase; this is the closed
type + registration only.
"""
