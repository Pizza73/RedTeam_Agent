"""Current Authorization Runtime Context resolution tests (H-01)."""

from __future__ import annotations

import pytest

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import RepositoryIntegrityError
from redteam_agent.runtime.clock import ManualClock


def _kernel():
    return build_test_kernel(clock=ManualClock(support.T0))


def _seed(kernel):
    tool = support.network_tool()
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    return support.seed_running_mission(kernel, tool=tool, revision=revision)


def test_resolves_current_running_mission() -> None:
    kernel = _kernel()
    seeded = _seed(kernel)
    runtime = kernel.context_resolver.resolve(support.MISSION_ID, now=support.T0)
    assert runtime.mission.state == "RUNNING"
    assert runtime.mission.mission_revision == seeded.revision.mission_revision
    assert runtime.registry_digest == seeded.registry.registry_digest
    assert runtime.policy_version == kernel.policy_version


def test_reflects_epoch_rotation() -> None:
    kernel = _kernel()
    _seed(kernel)
    kernel.mission_manager.invalidate_authorization(support.MISSION_ID, expected_version=2)
    runtime = kernel.context_resolver.resolve(support.MISSION_ID, now=support.T0)
    assert runtime.mission.authorization_epoch == 1
    assert runtime.bindings.authorization_epoch == 1


def test_missing_mission_fails_closed() -> None:
    kernel = _kernel()
    with pytest.raises(RepositoryIntegrityError):
        kernel.context_resolver.resolve("no-such-mission", now=support.T0)
