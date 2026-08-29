from __future__ import annotations

from datetime import timedelta

import pytest

from redteam_agent.errors import MissionTTLExceededError
from redteam_agent.policy.approval import create_approval_request
from redteam_agent.seeds import FIXED_TIME
from tests.helpers import build_environment


def test_policy_ttl_cannot_outlive_mission() -> None:
    environment = build_environment()
    from redteam_agent.policy.engine import PolicyEngine

    with pytest.raises(MissionTTLExceededError):
        PolicyEngine(policy_version="policy-v1", extractors=environment.extractors).authorize(
            mission=environment.mission,
            plan=environment.plan,
            snapshot=environment.snapshot,
            registry=environment.registry,
            issued_at=FIXED_TIME + timedelta(minutes=1),
            expires_at=environment.mission.valid_until + timedelta(seconds=1),
        )


def test_approval_request_cannot_outlive_decision() -> None:
    environment = build_environment(approval_rule="always")
    with pytest.raises(MissionTTLExceededError):
        create_approval_request(
            mission=environment.mission,
            decision=environment.decision,
            plan=environment.plan,
            tool=environment.tool,
            issued_at=FIXED_TIME + timedelta(minutes=2),
            expires_at=environment.decision.expires_at + timedelta(seconds=1),
        )
