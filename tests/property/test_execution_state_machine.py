"""Property / state-machine evidence for Phase 0B execution safety.

The oracles here are independent re-statements of the SystemDesign §10 state
machines, hard-coded in this test rather than imported from the product, so the
comparison is not tautological. Random dispatch scenarios assert the executor's
safety invariants (single attempt, fail-closed block, no provider call on block).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

import support
import support_phase0b as p0b
from redteam_agent.execution.state_machine import (
    RESULT_COLLECTION_EDGES,
    RESULT_INGESTION_EDGES,
    is_legal_provider_edge,
)

# Independent oracle: provider edges that must be legal (subset re-stated from §10.1).
_ORACLE_PROVIDER_LEGAL = frozenset(
    {
        ("PLANNED", "AUTHORIZED"),
        ("AUTHORIZED", "BLOCKED"),
        ("AUTHORIZED", "DISPATCH_CLAIMED"),
        ("DISPATCH_CLAIMED", "BLOCKED"),
        ("DISPATCH_CLAIMED", "DISPATCHED"),
        ("DISPATCH_CLAIMED", "RECONCILING"),
        ("DISPATCHED", "RUNNING"),
        ("RUNNING", "SUCCEEDED"),
        ("RUNNING", "OUTCOME_UNKNOWN"),
        ("RECONCILING", "OUTCOME_UNKNOWN"),
    }
)
# Independent oracle: transitions that must be illegal (no shortcut / no revive).
_ORACLE_PROVIDER_ILLEGAL = frozenset(
    {
        ("PLANNED", "DISPATCHED"),
        ("AUTHORIZED", "DISPATCHED"),
        ("AUTHORIZED", "SUCCEEDED"),
        ("BLOCKED", "AUTHORIZED"),
        ("BLOCKED", "DISPATCH_CLAIMED"),
        ("SUCCEEDED", "RUNNING"),
        ("OUTCOME_UNKNOWN", "DISPATCHED"),
    }
)


def test_provider_edges_match_independent_oracle() -> None:
    for edge in _ORACLE_PROVIDER_LEGAL:
        assert is_legal_provider_edge(*edge), f"expected legal edge {edge}"
    for edge in _ORACLE_PROVIDER_ILLEGAL:
        assert not is_legal_provider_edge(*edge), f"expected illegal edge {edge}"


def test_collection_and_ingestion_have_no_revive_edges() -> None:
    # A terminal collection state never returns to an active one.
    for terminal in ("COMPLETE", "ABANDONED"):
        assert not any(src == terminal for src, _ in RESULT_COLLECTION_EDGES)
    # Ingestion never returns from an erased/succeeded state to processing.
    for terminal in ("QUARANTINE_ERASED", "SUCCEEDED", "ERASURE_COMPLETED_UNRESOLVED"):
        assert not any(src == terminal and dst in ("PENDING", "INGESTING") for src, dst in RESULT_INGESTION_EDGES)


@settings(max_examples=25, deadline=None)
@given(perturbation=st.sampled_from(["none", "pause", "invalidate"]))
def test_dispatch_invariants_hold_under_perturbation(perturbation: str) -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel)
    p0b.authorize(seeded)
    mm = kernel.phase0a.mission_manager
    version = seeded.seeded.running_state.mission_state_version
    if perturbation == "pause":
        mm.pause_mission(support.MISSION_ID, expected_version=version, actor_token=support.OPERATOR_ACTOR_TOKEN)
    elif perturbation == "invalidate":
        mm.invalidate_authorization(
            support.MISSION_ID, expected_version=version, actor_token=support.OPERATOR_ACTOR_TOKEN
        )

    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)

    # Global invariants.
    assert out.dispatch_attempts in (0, 1)
    record = kernel.execution_repository.get("exec-1")
    assert record is not None

    if perturbation == "none":
        assert out.provider_execution_state == "DISPATCHED"
        assert out.dispatch_attempts == 1
        assert kernel.mock_adapter.submit_calls == 1
        claim = kernel.claim_repository.get("claim-exec-1")
        assert claim is not None and claim.claim_state == "consumed"
    else:
        # Pre-dispatch mismatch: fail closed with no provider call and no claim.
        assert out.provider_execution_state == "BLOCKED"
        assert out.pre_dispatch_block_reason is not None
        assert out.dispatch_attempts == 0
        assert kernel.mock_adapter.submit_calls == 0
        assert kernel.claim_repository.get("claim-exec-1") is None
        assert kernel.result_repository.get("exec-1") is None
