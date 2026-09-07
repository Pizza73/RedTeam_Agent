"""Dispatch result capture capability (SystemDesign §10.2 / §10.5).

``DispatchResultCapture`` is a Root-generated, non-serializable TCB capability;
Planner/Operator/Plugin code cannot inject an arbitrary object, callback or sink.
For a ``local_result`` submit it carries the composition-owned sink the adapter
streams into and receives the adapter's control metadata exactly once. It lives
in its own module so both the adapter contract and the dispatch port can depend
on it without an import cycle.
"""

from __future__ import annotations

from typing import NoReturn

from redteam_agent.errors import SecretInjectionError
from redteam_agent.execution.models import AdapterCollectionControl, ResultDeliveryMode
from redteam_agent.execution.sink import RawResultSink


class DispatchResultCapture:
    __slots__ = ("_capture_id", "_committed", "_control", "_mode", "_sink")

    def __init__(self, *, mode: ResultDeliveryMode, capture_id: str, sink: RawResultSink | None) -> None:
        if mode == "local_result" and sink is None:
            raise SecretInjectionError("local_result capture requires a composition-owned sink")
        if mode == "provider_task" and sink is not None:
            raise SecretInjectionError("provider_task capture must not carry a sink")
        self._mode = mode
        self._capture_id = capture_id
        self._sink = sink
        self._control: AdapterCollectionControl | None = None
        self._committed = False

    @property
    def mode(self) -> ResultDeliveryMode:
        return self._mode

    @property
    def capture_id(self) -> str:
        return self._capture_id

    @property
    def sink(self) -> RawResultSink | None:
        return self._sink

    def commit_control_metadata(self, control: AdapterCollectionControl) -> None:
        """Called once by a local adapter after streaming into the sink."""
        if self._mode != "local_result":
            raise SecretInjectionError("control metadata capture is only valid for local_result")
        if self._committed:
            raise SecretInjectionError("control metadata already committed")
        self._control = control
        self._committed = True

    def control(self) -> AdapterCollectionControl | None:
        return self._control

    def __reduce__(self) -> NoReturn:
        raise TypeError("DispatchResultCapture is not serializable")
