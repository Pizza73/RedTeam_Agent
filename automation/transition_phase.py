#!/usr/bin/env python3
"""Perform a marked adjacent-Phase label transition without stale label replacement."""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Protocol

PHASES = (
    "phase-0a",
    "phase-0b",
    "phase-0c",
    "phase-1",
    "phase-2",
    "phase-3",
    "phase-4",
    "phase-5",
)
TRANSITION_MARKER = "ai-review-passed"
IMPLEMENTATION_LABEL = "ai-needs-implementation"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PART_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
REQUEST_MARKER_PATTERN = re.compile(
    r"<!--\s*redteam-implementation-request\s*([\s\S]*?)-->",
)


class PhaseTransitionError(RuntimeError):
    """Base typed error for a fail-closed Phase transition."""


class PhaseTransitionEvidenceError(PhaseTransitionError):
    """Raised when transition input or live GitHub state is invalid."""


class PhaseTransitionApiError(PhaseTransitionError):
    """Raised when GitHub does not confirm a required API operation."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhaseTransitionEvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json_object(raw: str, description: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PhaseTransitionEvidenceError(f"{description} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PhaseTransitionEvidenceError(f"{description} must be a JSON object")
    return value


@dataclass(frozen=True)
class TransitionRequest:
    owner: str
    repo: str
    pull_number: int
    reviewed_sha: str
    current_phase: str
    next_phase: str
    request_body: str

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> TransitionRequest:
        expected_keys = {
            "schema_version",
            "owner",
            "repo",
            "pull_number",
            "reviewed_sha",
            "current_phase",
            "next_phase",
            "request_body",
        }
        if set(payload) != expected_keys or payload.get("schema_version") != "1.0":
            raise PhaseTransitionEvidenceError(
                "transition payload has missing, unknown, or unsupported fields"
            )
        owner = payload.get("owner")
        repo = payload.get("repo")
        pull_number = payload.get("pull_number")
        reviewed_sha = payload.get("reviewed_sha")
        current_phase = payload.get("current_phase")
        next_phase = payload.get("next_phase")
        request_body = payload.get("request_body")
        if not isinstance(owner, str) or not REPOSITORY_PART_PATTERN.fullmatch(owner):
            raise PhaseTransitionEvidenceError("transition owner is invalid")
        if not isinstance(repo, str) or not REPOSITORY_PART_PATTERN.fullmatch(repo):
            raise PhaseTransitionEvidenceError("transition repository is invalid")
        if not isinstance(pull_number, int) or isinstance(pull_number, bool) or pull_number < 1:
            raise PhaseTransitionEvidenceError("transition pull request number is invalid")
        if not isinstance(reviewed_sha, str) or not SHA_PATTERN.fullmatch(reviewed_sha):
            raise PhaseTransitionEvidenceError("transition reviewed SHA is invalid")
        if not isinstance(current_phase, str) or current_phase not in PHASES:
            raise PhaseTransitionEvidenceError("transition current Phase is invalid")
        if not isinstance(next_phase, str) or next_phase not in PHASES:
            raise PhaseTransitionEvidenceError("transition next Phase is invalid")
        current_index = PHASES.index(current_phase)
        if current_index + 1 >= len(PHASES) or PHASES[current_index + 1] != next_phase:
            raise PhaseTransitionEvidenceError("transition Phases are not adjacent")
        if not isinstance(request_body, str) or not request_body or len(request_body) > 10_000:
            raise PhaseTransitionEvidenceError("transition request body is invalid")
        cls._validate_request_marker(request_body, reviewed_sha, next_phase)
        return cls(
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            reviewed_sha=reviewed_sha,
            current_phase=current_phase,
            next_phase=next_phase,
            request_body=request_body,
        )

    @staticmethod
    def _validate_request_marker(body: str, reviewed_sha: str, next_phase: str) -> None:
        matches = REQUEST_MARKER_PATTERN.findall(body)
        if len(matches) != 1:
            raise PhaseTransitionEvidenceError(
                "transition body must contain exactly one implementation request marker"
            )
        marker = _strict_json_object(matches[0].strip(), "implementation request marker")
        expected_keys = {
            "schema_version",
            "action",
            "trigger",
            "phase",
            "head_sha",
            "phase_prompt",
        }
        if set(marker) != expected_keys:
            raise PhaseTransitionEvidenceError(
                "implementation request marker has missing or unknown fields"
            )
        if (
            marker.get("schema_version") != "1.0"
            or marker.get("action") != "IMPLEMENT_PHASE"
            or marker.get("trigger") != "PHASE_START"
            or marker.get("phase") != next_phase
            or marker.get("head_sha") != reviewed_sha
        ):
            raise PhaseTransitionEvidenceError(
                "implementation request marker is not bound to the transition"
            )
        prompt = marker.get("phase_prompt")
        if not isinstance(prompt, str) or not prompt.startswith("prompts/phases/"):
            raise PhaseTransitionEvidenceError("implementation request Phase prompt is invalid")


class TransitionClient(Protocol):
    def get_pull_request(self, request: TransitionRequest) -> dict[str, Any]: ...

    def add_label(self, request: TransitionRequest, label: str) -> list[Any]: ...

    def remove_label(self, request: TransitionRequest, label: str) -> list[Any]: ...

    def set_pending_status(self, request: TransitionRequest) -> None: ...

    def create_request_comment(self, request: TransitionRequest) -> None: ...


def _label_names(source: Any) -> tuple[str, ...]:
    if not isinstance(source, list):
        raise PhaseTransitionEvidenceError("Phase transition labels are unavailable")
    names: list[str] = []
    for item in source:
        if isinstance(item, str):
            name = item
        else:
            name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name:
            raise PhaseTransitionEvidenceError("Phase transition labels are malformed")
        names.append(name)
    if len(names) != len(set(names)):
        raise PhaseTransitionEvidenceError("Phase transition labels contain duplicates")
    return tuple(sorted(names))


def _assert_labels(
    labels: tuple[str, ...],
    *,
    phases: tuple[str, ...],
    required: tuple[str, ...] = (),
    forbidden: tuple[str, ...] = (),
    stage: str,
) -> None:
    actual_phases = tuple(name for name in labels if name in PHASES)
    if (
        actual_phases != tuple(sorted(phases, key=PHASES.index))
        or any(name not in labels for name in required)
        or any(name in labels for name in forbidden)
    ):
        raise PhaseTransitionEvidenceError(f"pull request labels changed during {stage}")


def _assert_pull_request(
    pull_request: dict[str, Any],
    request: TransitionRequest,
    *,
    phases: tuple[str, ...],
    required: tuple[str, ...] = (),
    forbidden: tuple[str, ...] = (),
    stage: str,
) -> None:
    head = pull_request.get("head")
    if (
        pull_request.get("state") != "open"
        or not isinstance(head, dict)
        or head.get("sha") != request.reviewed_sha
    ):
        raise PhaseTransitionEvidenceError(f"pull request changed during {stage}")
    _assert_labels(
        _label_names(pull_request.get("labels")),
        phases=phases,
        required=required,
        forbidden=forbidden,
        stage=stage,
    )


def transition_automatic_phase(client: TransitionClient, request: TransitionRequest) -> None:
    def validate(
        stage: str,
        phases: tuple[str, ...],
        required: tuple[str, ...],
        forbidden: tuple[str, ...] = (),
    ) -> None:
        _assert_pull_request(
            client.get_pull_request(request),
            request,
            phases=phases,
            required=required,
            forbidden=forbidden,
            stage=stage,
        )

    validate(
        "the marked Phase transition snapshot",
        (request.current_phase,),
        (TRANSITION_MARKER,),
        (IMPLEMENTATION_LABEL,),
    )
    client.add_label(request, request.next_phase)
    validate(
        "the adjacent dual-Phase transition",
        (request.current_phase, request.next_phase),
        (TRANSITION_MARKER,),
        (IMPLEMENTATION_LABEL,),
    )
    client.remove_label(request, request.current_phase)
    validate(
        "the current-Phase removal",
        (request.next_phase,),
        (TRANSITION_MARKER,),
        (IMPLEMENTATION_LABEL,),
    )
    client.add_label(request, IMPLEMENTATION_LABEL)
    validate(
        "the next-Phase implementation preparation",
        (request.next_phase,),
        (TRANSITION_MARKER, IMPLEMENTATION_LABEL),
    )
    client.set_pending_status(request)
    client.create_request_comment(request)
    validate(
        "the Phase transition release",
        (request.next_phase,),
        (TRANSITION_MARKER, IMPLEMENTATION_LABEL),
    )
    released_labels = _label_names(client.remove_label(request, TRANSITION_MARKER))
    _assert_labels(
        released_labels,
        phases=(request.next_phase,),
        required=(IMPLEMENTATION_LABEL,),
        forbidden=(TRANSITION_MARKER, request.current_phase),
        stage="the atomic Phase transition release",
    )


class GitHubTransitionClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise PhaseTransitionEvidenceError("GITHUB_TOKEN is not configured")
        self._token = token

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        connection = http.client.HTTPSConnection("api.github.com", timeout=30)
        try:
            connection.request(
                method,
                path,
                body=data,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "redteam-agent-phase-transition",
                },
            )
            response = connection.getresponse()
            response_body = response.read()
            if not 200 <= response.status < 300:
                raise PhaseTransitionApiError(
                    f"GitHub rejected {method} {path} with status {response.status}"
                )
            return json.loads(response_body.decode("utf-8"))
        except PhaseTransitionApiError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException, json.JSONDecodeError) as exc:
            raise PhaseTransitionApiError(
                f"GitHub did not confirm {method} {path}"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _base_path(request: TransitionRequest) -> str:
        owner = urllib.parse.quote(request.owner, safe="")
        repo = urllib.parse.quote(request.repo, safe="")
        return f"/repos/{owner}/{repo}"

    def get_pull_request(self, request: TransitionRequest) -> dict[str, Any]:
        result = self._request(
            "GET", f"{self._base_path(request)}/pulls/{request.pull_number}"
        )
        if not isinstance(result, dict):
            raise PhaseTransitionApiError("GitHub returned a malformed pull request")
        return result

    def add_label(self, request: TransitionRequest, label: str) -> list[Any]:
        result = self._request(
            "POST",
            f"{self._base_path(request)}/issues/{request.pull_number}/labels",
            {"labels": [label]},
        )
        if not isinstance(result, list):
            raise PhaseTransitionApiError("GitHub returned malformed labels after add")
        return result

    def remove_label(self, request: TransitionRequest, label: str) -> list[Any]:
        encoded_label = urllib.parse.quote(label, safe="")
        result = self._request(
            "DELETE",
            f"{self._base_path(request)}/issues/{request.pull_number}/labels/{encoded_label}",
        )
        if not isinstance(result, list):
            raise PhaseTransitionApiError("GitHub returned malformed labels after removal")
        return result

    def set_pending_status(self, request: TransitionRequest) -> None:
        result = self._request(
            "POST",
            f"{self._base_path(request)}/statuses/{request.reviewed_sha}",
            {
                "state": "pending",
                "context": "redteam/phase-review",
                "description": f"{request.next_phase}: implementation pending",
            },
        )
        if not isinstance(result, dict) or result.get("state") != "pending":
            raise PhaseTransitionApiError("GitHub did not confirm the pending Phase status")

    def create_request_comment(self, request: TransitionRequest) -> None:
        result = self._request(
            "POST",
            f"{self._base_path(request)}/issues/{request.pull_number}/comments",
            {"body": request.request_body},
        )
        if not isinstance(result, dict) or not isinstance(result.get("html_url"), str):
            raise PhaseTransitionApiError("GitHub did not confirm the implementation request")


def decode_transition_request(encoded: str) -> TransitionRequest:
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise PhaseTransitionEvidenceError("transition payload is not valid base64url") from exc
    return TransitionRequest.from_payload(_strict_json_object(raw, "transition payload"))


def main() -> int:
    encoded = os.environ.get("REDTEAM_PHASE_TRANSITION", "")
    request = decode_transition_request(encoded)
    client = GitHubTransitionClient(os.environ.get("GITHUB_TOKEN", ""))
    transition_automatic_phase(client, request)
    print("PHASE_TRANSITION=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
