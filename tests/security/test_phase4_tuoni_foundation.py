"""Security probes for the non-networking Tuoni adapter foundation."""

from __future__ import annotations

from typing import Any, cast

import pytest

from redteam_agent.adapters.tuoni import TuoniAdapterFoundation, build_tuoni_foundation_profile
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import C2AdapterUnavailableError
from redteam_agent.execution.adapter import ExecutionRequest
from redteam_agent.execution.capture import DispatchResultCapture
from redteam_agent.execution.models import ResultTaskBinding
from redteam_agent.execution.secret_binding import EphemeralSecretBinding
from redteam_agent.execution.sink import RawResultSink


class _SecretProbe:
    secret_argument_path = "/credential"
    secret_version_id = "tuoni-credential#v1"

    def __init__(self) -> None:
        self.consume_calls = 0

    def length(self) -> int:
        return 12

    def consume(self) -> bytes:
        self.consume_calls += 1
        return b"must-not-be-read"


class _SinkProbe:
    sink_id = "sink-probe"

    def __init__(self) -> None:
        self.write_calls = 0

    def __getattr__(self, _name: str) -> Any:
        def called(*_args: object, **_kwargs: object) -> None:
            self.write_calls += 1

        return called


def _adapter() -> TuoniAdapterFoundation:
    ds = DigestService()
    return TuoniAdapterFoundation(build_tuoni_foundation_profile(digest_service=ds), ds)


def test_submit_fails_before_secret_access() -> None:
    adapter = _adapter()
    secret = _SecretProbe()

    with pytest.raises(C2AdapterUnavailableError):
        adapter.submit(
            cast(ExecutionRequest, object()),
            (cast(EphemeralSecretBinding, secret),),
            cast(DispatchResultCapture, object()),
            "idempotency-key",
        )

    assert secret.consume_calls == 0


def test_result_collection_fails_before_sink_access() -> None:
    adapter = _adapter()
    sink = _SinkProbe()

    with pytest.raises(C2AdapterUnavailableError):
        adapter.collect_result(
            "execution-1",
            cast(ResultTaskBinding, object()),
            cast(RawResultSink, sink),
        )

    assert sink.write_calls == 0


@pytest.mark.parametrize(
    "operation",
    [
        lambda adapter: adapter.get_capabilities(),
        lambda adapter: adapter.get_session("provider-session-1"),
        lambda adapter: adapter.reconcile("execution-1", None),
        lambda adapter: adapter.cancel("execution-1", "provider-task-1"),
        lambda adapter: adapter.get_task_control(
            "execution-1", cast(ResultTaskBinding, object())
        ),
    ],
)
def test_every_other_provider_operation_is_unavailable(operation: Any) -> None:
    with pytest.raises(C2AdapterUnavailableError):
        operation(_adapter())


def test_profile_serialization_contains_only_credential_reference() -> None:
    raw = build_tuoni_foundation_profile(digest_service=DigestService()).model_dump_json()

    assert '"password":' not in raw.lower()
    assert '"jwt_token":' not in raw.lower()
