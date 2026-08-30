from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import pytest

from automation.transition_phase import (
    IMPLEMENTATION_LABEL,
    TRANSITION_MARKER,
    PhaseTransitionEvidenceError,
    TransitionRequest,
    decode_transition_request,
    transition_automatic_phase,
)

HEAD_SHA = "a" * 40


def request_payload(**overrides: Any) -> dict[str, Any]:
    marker = {
        "schema_version": "1.0",
        "action": "IMPLEMENT_PHASE",
        "trigger": "PHASE_START",
        "phase": "phase-0b",
        "head_sha": HEAD_SHA,
        "phase_prompt": "prompts/phases/phase-0b-security-fix.md",
    }
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "owner": "owner",
        "repo": "repo",
        "pull_number": 3,
        "reviewed_sha": HEAD_SHA,
        "current_phase": "phase-0a",
        "next_phase": "phase-0b",
        "request_body": (
            "phase transition\n\n<!-- redteam-implementation-request\n"
            f"{json.dumps(marker, separators=(',', ':'))}\n-->"
        ),
    }
    payload.update(overrides)
    return payload


def transition_request(**overrides: Any) -> TransitionRequest:
    return TransitionRequest.from_payload(request_payload(**overrides))


class FakeTransitionClient:
    def __init__(
        self,
        labels: set[str],
        hook: Callable[[str, str | None, set[str]], None] | None = None,
    ) -> None:
        self.labels = labels
        self.hook = hook or (lambda _operation, _label, _labels: None)
        self.history: list[tuple[str, tuple[str, ...]]] = []
        self.statuses: list[str] = []
        self.comments: list[str] = []

    def _snapshot(self) -> list[dict[str, str]]:
        return [{"name": name} for name in sorted(self.labels)]

    def _mutate(self, operation: str, label: str, callback: Callable[[], None]) -> list[Any]:
        self.hook(operation, label, self.labels)
        callback()
        self.history.append((operation, tuple(sorted(self.labels))))
        return self._snapshot()

    def get_pull_request(self, _request: TransitionRequest) -> dict[str, Any]:
        self.hook("get", None, self.labels)
        return {"state": "open", "head": {"sha": HEAD_SHA}, "labels": self._snapshot()}

    def add_label(self, _request: TransitionRequest, label: str) -> list[Any]:
        return self._mutate("add", label, lambda: self.labels.add(label))

    def remove_label(self, _request: TransitionRequest, label: str) -> list[Any]:
        def remove() -> None:
            if label not in self.labels:
                raise AssertionError(f"missing label: {label}")
            self.labels.remove(label)

        return self._mutate("remove", label, remove)

    def set_pending_status(self, request: TransitionRequest) -> None:
        self.hook("status", None, self.labels)
        self.statuses.append(request.reviewed_sha)

    def create_request_comment(self, request: TransitionRequest) -> None:
        self.hook("comment", None, self.labels)
        self.comments.append(request.request_body)


def test_transition_preserves_unrelated_concurrent_labels_and_never_has_zero_phase() -> None:
    def hook(operation: str, label: str | None, labels: set[str]) -> None:
        if operation == "add" and label == "phase-0b":
            labels.add("concurrent-unrelated")

    client = FakeTransitionClient(
        {"ai-loop", TRANSITION_MARKER, "phase-0a", "unrelated"}, hook
    )

    transition_automatic_phase(client, transition_request())

    assert client.labels == {
        "ai-loop",
        IMPLEMENTATION_LABEL,
        "phase-0b",
        "unrelated",
        "concurrent-unrelated",
    }
    assert all(any(label.startswith("phase-") for label in labels) for _, labels in client.history)
    dual = next(labels for _, labels in client.history if {"phase-0a", "phase-0b"} <= set(labels))
    assert TRANSITION_MARKER in dual
    assert client.statuses == [HEAD_SHA]
    assert len(client.comments) == 1
    assert client.history[-1][0] == "remove"


@pytest.mark.parametrize(
    ("race", "message"),
    [
        ("conflicting-phase", "adjacent dual-Phase transition"),
        ("marker-removal", "adjacent dual-Phase transition"),
    ],
)
def test_early_transition_races_fail_before_status_and_request(
    race: str, message: str
) -> None:
    def hook(operation: str, label: str | None, labels: set[str]) -> None:
        if operation == "add" and label == "phase-0b":
            if race == "conflicting-phase":
                labels.add("phase-2")
            else:
                labels.remove(TRANSITION_MARKER)

    client = FakeTransitionClient({"ai-loop", TRANSITION_MARKER, "phase-0a"}, hook)

    with pytest.raises(PhaseTransitionEvidenceError, match=message):
        transition_automatic_phase(client, transition_request())

    assert client.statuses == []
    assert client.comments == []


def test_same_label_concurrent_add_is_idempotent() -> None:
    def hook(operation: str, label: str | None, labels: set[str]) -> None:
        if operation == "add" and label == "phase-0b":
            labels.add("phase-0b")

    client = FakeTransitionClient({"ai-loop", TRANSITION_MARKER, "phase-0a"}, hook)

    transition_automatic_phase(client, transition_request())

    assert client.labels == {"ai-loop", IMPLEMENTATION_LABEL, "phase-0b"}


def test_conflicting_phase_at_marker_release_is_rejected_from_mutation_response() -> None:
    def hook(operation: str, label: str | None, labels: set[str]) -> None:
        if operation == "remove" and label == TRANSITION_MARKER:
            labels.add("phase-3")

    client = FakeTransitionClient({"ai-loop", TRANSITION_MARKER, "phase-0a"}, hook)

    with pytest.raises(PhaseTransitionEvidenceError, match="atomic Phase transition release"):
        transition_automatic_phase(client, transition_request())

    assert "phase-3" in client.labels
    assert TRANSITION_MARKER not in client.labels


@pytest.mark.parametrize(
    "override",
    [
        {"unexpected": True},
        {"current_phase": "phase-0a", "next_phase": "phase-1"},
        {"reviewed_sha": "bad"},
        {"pull_number": True},
        {"request_body": "missing marker"},
    ],
)
def test_transition_payload_rejects_unknown_malformed_or_unbound_input(
    override: dict[str, Any],
) -> None:
    payload = request_payload()
    payload.update(override)

    with pytest.raises(PhaseTransitionEvidenceError):
        TransitionRequest.from_payload(payload)


def test_base64url_transition_payload_is_strictly_decoded() -> None:
    encoded = base64.urlsafe_b64encode(
        json.dumps(request_payload(), separators=(",", ":")).encode()
    ).decode().rstrip("=")

    assert decode_transition_request(encoded) == transition_request()
    with pytest.raises(PhaseTransitionEvidenceError):
        decode_transition_request("%%%")
