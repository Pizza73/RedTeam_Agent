from __future__ import annotations

import math
from datetime import datetime, timezone

import pytest

from redteam_agent.canonical import canonical_loads, canonicalize, sha256_digest
from redteam_agent.models.common import OperationalPhase
from redteam_agent.models.plans import ExecutionPlanProposal
from redteam_agent.models.scope import IpTargetReference
from redteam_agent.models.tools import ToolRef
from redteam_agent.canonical.models import CanonicalJsonObject
from redteam_agent.policy.digests import proposal_digest


def test_canonical_object_key_order_is_stable() -> None:
    assert canonicalize({"b": 2, "a": 1}) == canonicalize({"a": 1, "b": 2})
    assert sha256_digest({"b": 2, "a": 1}) == sha256_digest({"a": 1, "b": 2})


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(ValueError):
        canonicalize(value)


@pytest.mark.parametrize("value", [b"secret", object(), {1, 2}])
def test_non_json_python_objects_are_rejected(value: object) -> None:
    with pytest.raises(TypeError):
        canonicalize(value)


def test_duplicate_json_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        canonical_loads('{"a":1,"a":2}')


def test_canonical_json_ingress_is_utf8_only() -> None:
    with pytest.raises(UnicodeDecodeError):
        canonical_loads('{"a":1}'.encode("utf-16"))


def test_datetime_is_utc_canonical() -> None:
    value = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert canonicalize(value) == b'"2026-01-01T00:00:00Z"'


def proposal(targets, arguments) -> ExecutionPlanProposal:
    return ExecutionPlanProposal(
        objective="x",
        phase=OperationalPhase.DISCOVERY,
        tool_ref=ToolRef(tool_id="tool", registry_revision=1),
        requested_targets=targets,
        session_id=None,
        arguments=CanonicalJsonObject(arguments),
    )


def test_unordered_targets_do_not_change_proposal_digest() -> None:
    a = IpTargetReference(type="ip", address="10.0.0.1")
    b = IpTargetReference(type="ip", address="10.0.0.2")
    assert proposal_digest(proposal((a, b), {})) == proposal_digest(proposal((b, a), {}))


def test_ordered_argument_list_changes_proposal_digest() -> None:
    assert proposal_digest(proposal((), {"steps": [1, 2]})) != proposal_digest(
        proposal((), {"steps": [2, 1]})
    )
