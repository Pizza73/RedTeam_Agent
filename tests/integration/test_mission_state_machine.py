"""Property/state-machine test for mission lifecycle transitions (B-03).

The reference model here is an *independent* re-statement of the lifecycle from
SystemDesign §21.1, hard-coded in this test. It deliberately does not import the
product's ``LEGAL_LIFECYCLE_EDGES`` / ``EPOCH_ROTATING_EDGES`` sets: comparing the
implementation against a copy of its own tables would be tautological. Instead
the expected next state, version and epoch are computed from this test-local
oracle and asserted against the Mission Manager's behaviour (R19).
"""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import given, settings
from hypothesis import strategies as st

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import AuthorizationKernelError
from redteam_agent.runtime.clock import ManualClock

_OPS = ["pause", "resume", "finalize", "complete", "abort", "invalidate"]

# Independent oracle: the legal lifecycle edges reachable via these operations,
# re-stated from the design diagram rather than imported from the product.
_REF_LEGAL_EDGES = frozenset(
    {
        ("RUNNING", "PAUSED"),
        ("PAUSED", "RUNNING"),
        ("RUNNING", "FINALIZING"),
        ("PAUSED", "FINALIZING"),
        ("FINALIZING", "COMPLETED"),
        ("FINALIZING", "ABORTED"),
    }
)
# Edges that additionally rotate the authorization epoch (a revocation boundary).
_REF_EPOCH_ROTATING_EDGES = frozenset(
    {
        ("RUNNING", "PAUSED"),
        ("PAUSED", "RUNNING"),
        ("RUNNING", "FINALIZING"),
        ("PAUSED", "FINALIZING"),
    }
)
_TARGET = {
    "pause": "PAUSED",
    "resume": "RUNNING",
    "finalize": "FINALIZING",
    "complete": "COMPLETED",
    "abort": "ABORTED",
}


@dataclass
class _Ref:
    state: str
    version: int
    epoch: int


def _apply_ref(ref: _Ref, op: str) -> _Ref | None:
    """Return the expected next reference state, or None if the op is illegal."""
    if op == "invalidate":
        if ref.state not in ("RUNNING", "PAUSED"):
            return None
        return _Ref(ref.state, ref.version + 1, ref.epoch + 1)
    target = _TARGET[op]
    edge = (ref.state, target)
    if edge not in _REF_LEGAL_EDGES:
        return None
    epoch = ref.epoch + (1 if edge in _REF_EPOCH_ROTATING_EDGES else 0)
    return _Ref(target, ref.version + 1, epoch)


def _invoke(kernel, op: str, version: int):
    mm = kernel.mission_manager
    mid = support.MISSION_ID
    token = support.OPERATOR_ACTOR_TOKEN
    if op == "pause":
        return mm.pause_mission(mid, version, actor_token=token)
    if op == "resume":
        return mm.resume_mission(mid, version, actor_token=token)
    if op == "finalize":
        return mm.begin_finalization(mid, version, actor_token=token)
    if op == "complete":
        return mm.complete_mission(mid, version, actor_token=token)
    if op == "abort":
        return mm.abort_mission(mid, version, actor_token=token)
    return mm.invalidate_authorization(mid, version, actor_token=token)


@settings(max_examples=60, deadline=None)
@given(ops=st.lists(st.sampled_from(_OPS), max_size=8))
def test_lifecycle_matches_reference_model(ops: list[str]) -> None:
    kernel = build_test_kernel(clock=ManualClock(support.T0))
    profile = support.make_profile(kernel.digest_service)
    kernel.profile_repository.save(profile)
    revision = support.mission_revision(kernel.digest_service, profile=profile)
    support.provision_lifecycle_roles(kernel)
    kernel.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    kernel.mission_manager.validate_mission(
        support.MISSION_ID, expected_version=0, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    running = kernel.mission_manager.start_mission(
        support.MISSION_ID, expected_version=1, actor_token=support.OPERATOR_ACTOR_TOKEN
    )
    ref = _Ref(state=running.state, version=running.mission_state_version, epoch=running.authorization_epoch)

    for op in ops:
        expected = _apply_ref(ref, op)
        if expected is None:
            try:
                _invoke(kernel, op, ref.version)
            except AuthorizationKernelError:
                continue
            raise AssertionError(f"illegal op {op} from {ref.state} was accepted")
        result = _invoke(kernel, op, ref.version)
        assert result.state == expected.state
        assert result.mission_state_version == expected.version
        assert result.authorization_epoch == expected.epoch
        ref = expected
        # Version strictly increases; epoch never decreases.
        assert ref.version >= 3
        assert ref.epoch >= 0
