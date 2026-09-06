"""Trusted local supervisor: workers propose; this process validates and publishes.

Run only from the checked, clean current-main launcher. GitHub claims are permanent
single-attempt latches. An interrupted/uncertain run requires reconciliation, never
an automatic second model run, push, or partial review publication.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator

from automation.local_worker import (
    NODE_DIRECTORY,
    LocalWorkerConfig,
    LocalWorkerError,
    preflight_local_worker,
    run_local_validation,
    run_local_worker,
)
from automation.run_phase_loop import (
    INVARIANT_FAMILIES,
    REQUIRED_CHECK_ORDER,
    TRUSTED_WORKFLOW_LOGIN,
    LoopBlockedError,
    MarkerEvidence,
    PhaseLoop,
    PhaseLoopError,
    PullRequestState,
    ReviewEvidence,
    canonical_digest,
    evaluate_native_review,
    invariant_audit_from_ready,
    marker_payloads,
    native_finding_key,
    native_invariant_family,
    review_trigger_source,
    strict_json_loads,
    trusted_gate_evidence,
    validate_review_result,
)
from scripts.ci.validate_invariant_audit import InvariantAuditError, validate_invariant_audit

MAX_COMMENT_BYTES = 60000
IMPLEMENTATION_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "enum": ["READY", "BLOCKED"]},
        "summary": {"type": "string", "minLength": 1, "maxLength": 4000},
    },
    "required": ["status", "summary"],
}


class LocalExecutionBlocked(LoopBlockedError):
    """A local worker or its exact-input authority could not be verified."""


class LocalReconciliationRequired(LocalExecutionBlocked):
    """A permanent claim exists or an external write has an uncertain outcome."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def trusted_model_settings() -> dict[str, str]:
    """Read only model-selection scalars; never import host plugins/providers/secrets.

    The native CLI login remains owned by Codex. Do not log or copy the config.
    Profile/provider/tool settings are intentionally not forwarded to a worker.
    """
    config_dir = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    if not config_dir.is_absolute():
        raise LocalExecutionBlocked("LOCAL_HOST_CONFIG_PATH_INVALID")
    try:
        with (config_dir / "config.toml").open("rb") as stream:
            config = tomllib.load(stream)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError):
        raise LocalExecutionBlocked("LOCAL_HOST_MODEL_CONFIG_INVALID") from None
    result = {}
    for key, destination in (("model", "model"), ("model_reasoning_effort", "reasoning_effort")):
        if key in config:
            if not isinstance(config[key], str):
                raise LocalExecutionBlocked("LOCAL_HOST_MODEL_SELECTION_INVALID")
            result[destination] = config[key]
    return result


def marker_body(name: str, payload: dict[str, Any]) -> str:
    body = f"<!-- {name}\n{canonical_json(payload)}\n-->"
    if len(body.encode("utf-8")) > MAX_COMMENT_BYTES or "-->" in canonical_json(payload):
        raise LocalExecutionBlocked("LOCAL_EVIDENCE_NOT_PUBLISHABLE")
    return body


def allowed_product_path(value: str) -> bool:
    path = Path(value)
    return (
        bool(value) and not path.is_absolute() and "\\" not in value
        and all(part not in {"", ".", "..", ".git", ".codex", ".agents"}
                for part in value.split("/"))
        and any(value.startswith(prefix) for prefix in ("src/", "tests/", "docs/review/"))
    )


def git(workspace: Path, *arguments: str, timeout: int = 60) -> str:
    """No checkout-controlled hooks, filters, aliases, pagers or inherited Git config."""
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("GIT_", "LD_", "PYTHON"))
    }
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                        "GIT_TERMINAL_PROMPT": "0"})
    executable = shutil.which("git")
    if executable is None:
        raise LocalExecutionBlocked("LOCAL_GIT_EXECUTABLE_REQUIRED")
    try:
        result = subprocess.run(  # noqa: S603
            [executable, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false",
             "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
             "-C", str(workspace), *arguments],
            env=environment, capture_output=True, text=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise LocalExecutionBlocked("LOCAL_GIT_COMMAND_UNCONFIRMED") from None
    if result.returncode:
        raise LocalExecutionBlocked("LOCAL_GIT_COMMAND_REJECTED")
    return result.stdout.strip()


class LocalExecution:
    def __init__(self, repo_root: Path) -> None:
        self.root = repo_root.resolve()
        self.policy = strict_json_loads(
            (self.root / "automation/local-execution-policy.json").read_text()
        )
        schema = strict_json_loads(
            (self.root / "automation/schemas/local-execution-policy.schema.json").read_text()
        )
        if not Draft202012Validator(schema).is_valid(self.policy):
            raise LocalExecutionBlocked("LOCAL_EXECUTION_POLICY_REJECTED")
        self.policy_digest = canonical_digest(self.policy)
        self._input_digests: dict[str, str] = {}
        self.model_settings = trusted_model_settings()

    def _configuration(self, loop: PhaseLoop, workspace: Path, role: str,
                       inputs: Path) -> LocalWorkerConfig:
        remaining = int(loop.deadline - time.monotonic())
        if remaining < 60:
            raise LocalExecutionBlocked("LOCAL_WORKER_RUNTIME_EXHAUSTED")
        return LocalWorkerConfig(
            workspace=workspace, role=role,  # type: ignore[arg-type]
            timeout_seconds=min(remaining, self.policy["max_worker_seconds"]),
            max_output_bytes=self.policy["max_output_bytes"], input_dir=inputs,
            dependency_env=self.root / ".venv",
            **self.model_settings,
        )

    def _current(self, loop: PhaseLoop, state: PullRequestState,
                 evidence: MarkerEvidence, kind: str) -> list[dict[str, Any]]:
        loop.fail_if_expired()
        loop.current_default_branch_sha()
        fresh = loop.pr_state()
        if (replace(fresh, labels=frozenset()) != replace(state, labels=frozenset())
                or {"ai-loop-blocked", "ai-human-gate", "ai-project-complete", "ai-review-passed"}
                .intersection(fresh.labels)):
            raise LocalExecutionBlocked("LOCAL_INPUT_STATE_CHANGED")
        comments = loop.comments()
        marker = ("redteam-implementation-request" if kind == "implementation"
                  else "redteam-ready-for-review")
        records = loop.trusted_markers(comments, marker)
        current = [record for record in records
                   if record.payload.get("phase") == state.phase
                   and record.payload.get("head_sha") == state.head_sha]
        if (not current or current[-1].url != evidence.url
                or current[-1].payload != evidence.payload or current[-1].body != evidence.body):
            raise LocalExecutionBlocked("LOCAL_AUTHORITY_CHANGED")
        raw = [comment for comment in comments if comment.get("html_url") == evidence.url]
        if (len(raw) != 1 or raw[0].get("created_at") != raw[0].get("updated_at")
                or not raw[0].get("created_at")):
            raise LocalExecutionBlocked("LOCAL_AUTHORITY_EDITED_OR_MISSING")
        if kind == "review" and loop.check_state(state.head_sha) != "success":
            raise LocalExecutionBlocked("LOCAL_REVIEW_CI_NOT_PASSING")
        if kind == "implementation":
            loop.validate_design_resume_authority(
                state, evidence, comments=comments,
                default_branch_sha=loop.current_default_branch_sha(),
            )
            findings = self._fix_findings(loop, state, evidence, comments)
            digest = canonical_digest({"findings": findings})
            if self._input_digests.setdefault(evidence.url, digest) != digest:
                raise LocalExecutionBlocked("LOCAL_FINDING_INPUT_CHANGED")
        return comments

    def _fix_findings(
        self, loop: PhaseLoop, state: PullRequestState,
        request: MarkerEvidence, comments: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if request.payload.get("action") != "FIX_REVIEW_FINDINGS":
            return []
        review = request.payload["review"]
        gates = [record for record in loop.trusted_markers(comments, "redteam-phase-gate")
                 if record.payload.get("phase") == state.phase
                 and record.payload.get("reviewed_sha") == state.head_sha
                 and record.payload.get("review_reference") == review["review_reference"]]
        if (review["reviewed_sha"] != state.head_sha or len(gates) != 1
                or gates[0].payload.get("verdict") != "CHANGES_REQUESTED"
                or gates[0].payload.get("recorded_by") != loop.actor_login
                or not trusted_gate_evidence(gates[0].payload, loop.reviewer_login,
                                             loop.actor_login)):
            raise LocalExecutionBlocked("LOCAL_FIX_GATE_NOT_BOUND")
        gate = gates[0].payload
        ready_records = [record for record in loop.trusted_markers(comments,
                          "redteam-ready-for-review") if record.url == gate["ready_reference"]]
        if len(ready_records) != 1:
            raise LocalExecutionBlocked("LOCAL_FIX_READY_NOT_BOUND")
        if gate["evidence_format"] == "local-review-v1":
            expected = self._expected_review(loop, state, ready_records[0],
                                             gate["base_sha"], comments)
            expected.update({"startReference": gate["review_trigger_reference"],
                             "reportReference": review["review_reference"]})
            verified = self._evaluate(expected)
            findings = [{"finding_key": item["finding_key"],
                         "finding_reference": item["html_url"],
                         "invariant_family": item["invariant_family"],
                         "untrusted_finding": item}
                        for item in verified["currentFindings"]]
        else:
            raw_findings = loop.github.review_comments(state.number)
            verified_native = evaluate_native_review(
                phase=state.phase, head_sha=state.head_sha, base_sha=gate["base_sha"],
                ready=ready_records[0], actor_login=loop.actor_login,
                reviewer_login=loop.reviewer_login, comments=comments,
                reviews=loop.github.reviews(state.number), review_comments=raw_findings,
                reactions=loop.github.issue_reactions(state.number),
                timeline=loop.github.timeline(state.number),
            )
            if (verified_native is None or verified_native.url != review["review_reference"]
                    or verified_native.result["verdict"] != "CHANGES_REQUESTED"):
                raise LocalExecutionBlocked("LOCAL_FIX_NATIVE_REVIEW_NOT_BOUND")
            requested_references = {item["finding_reference"] for item in review["findings"]}
            findings = []
            for item in raw_findings:
                if item.get("html_url") not in requested_references:
                    continue
                if (item.get("user", {}).get("login") != loop.reviewer_login
                        or item.get("commit_id") != state.head_sha
                        or item.get("created_at") != item.get("updated_at")):
                    raise LocalExecutionBlocked("LOCAL_FIX_NATIVE_FINDING_CHANGED")
                findings.append({"finding_key": native_finding_key(item),
                                 "finding_reference": item["html_url"],
                                 "invariant_family": native_invariant_family(item),
                                 "untrusted_finding": {"body": item["body"],
                                                       "path": item["path"],
                                                       "line": item.get("line")}})
            if len(findings) != len(verified_native.result["findings"]):
                raise LocalExecutionBlocked("LOCAL_FIX_NATIVE_FINDINGS_INCOMPLETE")
        by_reference = {item["finding_reference"]: item for item in findings}
        projected = [{key: item[key] for key in (
            "finding_key", "finding_reference", "invariant_family")}
            for item in findings]
        if (len(findings) != review["finding_count"] or len(by_reference) != len(findings)
                or sorted(projected, key=canonical_json)
                != sorted(review["findings"], key=canonical_json)):
            raise LocalExecutionBlocked("LOCAL_FIX_FINDINGS_DO_NOT_MATCH_REQUEST")
        return [by_reference[item["finding_reference"]] for item in review["findings"]]

    @staticmethod
    def _cutover_check(loop: PhaseLoop, state: PullRequestState,
                       comments: list[dict[str, Any]], kind: str) -> None:
        from automation.local_attempt_reconciliation import assert_attempts_resolved

        # Advancing the input HEAD must not hide a previous unresolved local attempt.
        assert_attempts_resolved(loop, state, comments)
        for item in comments:
            if item.get("user", {}).get("login") != loop.actor_login:
                continue
            for value in marker_payloads(str(item.get("body", "")),
                                         "redteam-local-codex-trigger"):
                if value.get("head_sha") == state.head_sha and value.get("kind") == kind:
                    raise LocalReconciliationRequired(
                        "LEGACY_CLOUD_ATTEMPT_REQUIRES_RECONCILIATION"
                    )
            for value in marker_payloads(str(item.get("body", "")),
                                         f"redteam-local-{kind}-start"):
                if value.get("head_sha") == state.head_sha and value.get("phase") == state.phase:
                    raise LocalReconciliationRequired("LOCAL_ATTEMPT_REQUIRES_RECONCILIATION")

    def _claim(self, loop: PhaseLoop, state: PullRequestState, kind: str,
               digest: str) -> str:
        reference = (f"{self.policy['claim_ref_prefix']}/pr-{state.number}/{state.phase}/"
                     f"{kind}/{state.head_sha}/{digest}")
        try:
            raw = loop.github.command.run([
                "api", "--method", "POST", f"repos/{loop.github.repository}/git/refs",
                "--raw-field", f"ref={reference}", "--raw-field", f"sha={state.head_sha}",
            ])
            value = strict_json_loads(raw)
            if (not isinstance(value, dict) or value.get("ref") != reference
                    or value.get("object", {}).get("sha") != state.head_sha
                    or value.get("object", {}).get("type") != "commit"):
                raise ValueError
        except (PhaseLoopError, ValueError, TypeError):
            raise LocalReconciliationRequired("LOCAL_CLAIM_EXISTS_OR_UNCONFIRMED") from None
        return reference

    @staticmethod
    def _journal(directory: Path, event: str, payload: dict[str, Any]) -> None:
        # Exclusive, immutable entries; parent directory is outside the worker namespace.
        path = directory / f"{event}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(canonical_json(payload) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _post(self, loop: PhaseLoop, state: PullRequestState, name: str,
              payload: dict[str, Any]) -> dict[str, Any]:
        body = marker_body(name, payload)
        try:
            result = loop.github.post_comment(state.number, body)
            prefix = f"https://github.com/{loop.github.repository}/pull/{state.number}#issuecomment-"
            reference = result.get("html_url", "")
            if (result.get("body") != body
                    or result.get("user", {}).get("login") != loop.actor_login
                    or not reference.startswith(prefix)
                    or not re.fullmatch(r"[1-9][0-9]*", reference[len(prefix):])
                    or not result.get("created_at")
                    or result.get("created_at") != result.get("updated_at")):
                raise ValueError
            return result
        except (PhaseLoopError, ValueError, TypeError):
            raise LocalReconciliationRequired("LOCAL_PUBLICATION_UNCONFIRMED") from None

    def _snapshot(self, loop: PhaseLoop, state: PullRequestState,
                  directory: Path) -> tuple[Path, str]:
        raw = loop.github.pull_request(state.number)
        branch = raw.get("head", {}).get("ref", "")
        if (raw.get("head", {}).get("sha") != state.head_sha
                or not isinstance(branch, str) or branch.startswith("-")
                or branch in {"main", "HEAD"}):
            raise LocalExecutionBlocked("LOCAL_BRANCH_BINDING_INVALID")
        git(self.root, "check-ref-format", "--branch", branch)
        # A clean clone copies objects, never .git config or linked worktree metadata.
        git(self.root, "fetch", "--no-tags", "origin", state.head_sha, timeout=180)
        workspace = directory / "workspace"
        git(self.root, "clone", "--no-hardlinks", "--no-checkout", "--", str(self.root),
            str(workspace), timeout=180)
        git(workspace, "remote", "remove", "origin")
        tree = git(workspace, "ls-tree", "-rz", state.head_sha)
        if any(entry and not entry.startswith(("100644 ", "100755 "))
               for entry in tree.split("\x00")):
            raise LocalExecutionBlocked("LOCAL_SNAPSHOT_LINK_OR_SPECIAL_FILE")
        git(workspace, "checkout", "-b", branch, state.head_sha)
        (workspace / ".venv").mkdir(exist_ok=True)
        if not loop.github.is_ancestor(loop.current_default_branch_sha(), state.head_sha):
            raise LocalExecutionBlocked("LOCAL_GOVERNANCE_REFRESH_REQUIRED")
        # No PR-controlled governance (including trusted files introduced on main).
        controls = git(workspace, "diff", "--name-only", "-z",
                       loop.current_default_branch_sha(), state.head_sha, "--")
        if any(path and not allowed_product_path(path) for path in controls.split("\x00")):
            raise LocalExecutionBlocked("LOCAL_UNAPPROVED_CONTROL_DIFF")
        return workspace, branch

    def _inputs(self, loop: PhaseLoop, state: PullRequestState, evidence: MarkerEvidence,
                base_sha: str, directory: Path, start: dict[str, Any]) -> Path:
        # These identities come from independently validated repository configuration,
        # never from approved_by (or another field) inside a worker/PR supplied record.
        approver = getattr(loop, "approver_login", None)
        if (not isinstance(approver, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", approver) is None
                or approver != loop.actor_login):
            raise LocalExecutionBlocked("LOCAL_CONFIGURED_APPROVER_INVALID")
        inputs = directory / "inputs"
        inputs.mkdir(mode=0o700)
        comments = loop.comments()
        payload = {
            "phase": state.phase, "head_sha": state.head_sha, "base_sha": base_sha,
            "labels": sorted(state.labels), "repository": loop.github.repository,
            "pull_request_number": state.number, "source": {
                "reference": evidence.url, "author": evidence.author,
                "payload": evidence.payload, "body": evidence.body,
            },
            "start": start, "policy_digest": self.policy_digest,
            "configured_authorities": {
                "approver_login": approver,
                "workflow_login": TRUSTED_WORKFLOW_LOGIN,
            },
            "fix_findings": self._fix_findings(loop, state, evidence, comments),
            "required_checks": [
                {"name": name, "status": "PASS" if loop.check_state(state.head_sha)
                 == "success" else "MISSING"} for name in REQUIRED_CHECK_ORDER
            ],
            "authority_records": [
                {"reference": item.get("html_url"), "body": item.get("body"),
                 "author": TRUSTED_WORKFLOW_LOGIN}
                for item in comments if item.get("user", {}).get("login") == TRUSTED_WORKFLOW_LOGIN
                and any(marker in str(item.get("body", "")) for marker in (
                    "redteam-phase-gate", "redteam-implementation-request",
                    "redteam-design-approval", "redteam-invariant-family-review"))
            ],
        }
        (inputs / "evidence.json").write_text(canonical_json(payload), encoding="utf-8")
        if "action" in evidence.payload:
            (inputs / "request.json").write_text(canonical_json(evidence.payload), encoding="utf-8")
        return inputs

    def implementation_prompt(self, state: PullRequestState, request: MarkerEvidence) -> str:
        return (
            (self.root / ".github/prompts/implement.md").read_text()
            + f"\nBound Phase: {state.phase}; input HEAD: {state.head_sha}; "
            + f"request: {request.url}.\n"
            + "Read /run/redteam-input/evidence.json and /tmp/redteam-loop-request.json. "
            + "Apply SystemDesign Section 38: reuse/replace/new, storage/recovery, "
            + "implementation_strategy and before/after. Do not infer current authority from "
            + "archived designs or erase existing state. Run the complete phase gate. "
            + "Return only the supplied JSON schema: status READY or BLOCKED, and summary. "
            + "Include the detailed required report in docs/review/; leave changes uncommitted.\n"
        )

    def review_prompt(self, state: PullRequestState, base_sha: str) -> str:
        return (
            (self.root / "automation/chatgpt-event-task-prompt.md").read_text()
            + f"\nBound Phase: {state.phase}; full HEAD: {state.head_sha}; "
            + f"phase base: {base_sha}.\n"
            + "Read /run/redteam-input/evidence.json. Perform one exhaustive independent review; "
            + "this applies identically to every Phase. Retain every consequential finding in "
            + "this single structured review. Independently verify reuse/replace/new and "
            + "migration/recovery; the pre-review audit is a checklist, not proof. "
            + "Return the closed review-result schema only. No comments, edits, or publication.\n"
        )

    def implement(self, loop: PhaseLoop, state: PullRequestState, request: MarkerEvidence,
                  comments: list[dict[str, Any]]) -> None:
        self._cutover_check(loop, state, comments, "implementation")
        if loop.dry_run:
            loop.log(f"would run local implementation: {state.phase} {state.head_sha}")
            return
        comments = self._current(loop, state, request, "implementation")
        self._cutover_check(loop, state, comments, "implementation")
        phase_records = loop.trusted_markers(comments, "redteam-phase-gate")
        base_sha = loop.expected_base_sha(
            state, phase_records, loop.trusted_base_refresh_statuses(state, phase_records),
            loop.current_default_branch_sha(),
        )
        directory = Path(tempfile.mkdtemp(prefix="redteam-local-implementation-"))
        workspace, branch = self._snapshot(loop, state, directory)
        run_id = str(uuid4())
        digest = canonical_digest({"request_url": request.url, "request": request.payload})
        start = {"schema_version": "1.0", "phase": state.phase, "head_sha": state.head_sha,
                 "base_sha": base_sha, "request_reference": request.url,
                 "source_digest": digest, "policy_digest": self.policy_digest,
                 "run_id": run_id, "started_at": utc_now()}
        inputs = self._inputs(loop, state, request, base_sha, directory, start)
        config = self._configuration(loop, workspace, "implementation", inputs)
        try:
            preflight_local_worker(config)
            self._current(loop, state, request, "implementation")
            claim = self._claim(loop, state, "implementation", digest)
            self._journal(directory, "01-claimed", {**start, "claim_reference": claim})
            start_comment = self._post(loop, state, "redteam-local-implementation-start", start)
            self._journal(directory, "02-started", {"reference": start_comment["html_url"]})
            self._current(loop, state, request, "implementation")
            loop.log(f"starting isolated local implementation: {state.phase} {state.head_sha}")
            worker = run_local_worker(config, self.implementation_prompt(state, request),
                                      IMPLEMENTATION_SCHEMA)
            self._journal(directory, "03-worker", {"session_id": worker.session_id,
                          "transcript_sha256": worker.transcript_sha256,
                          "result": worker.final_json})
            if worker.final_json["status"] != "READY":
                from automation.local_attempt_reconciliation import publish_blocked_terminal

                publish_blocked_terminal(loop, state, directory)
                raise LocalExecutionBlocked("LOCAL_IMPLEMENTER_REPORTED_BLOCKED")
            paths = self._changed_paths(workspace, state.head_sha)
            diff_digest = self._diff_digest(workspace, paths)
            self._current(loop, state, request, "implementation")
            loop.log(f"validating local implementation: {state.phase} {state.head_sha}")
            validation = run_local_validation(
                self._configuration(loop, workspace, "implementation", inputs), state.phase
            )
            if (paths != self._changed_paths(workspace, state.head_sha)
                    or diff_digest != self._diff_digest(workspace, paths)):
                raise LocalExecutionBlocked("LOCAL_VALIDATION_CHANGED_SOURCES")
            if request.payload.get("invariant_audit", {}).get("required") is True:
                try:
                    validate_invariant_audit(
                        workspace, state.phase, expected_request_head=state.head_sha,
                        expected_request_action=request.payload["action"],
                        expected_request_reference=request.url,
                        require_implementation_strategy=True,
                    )
                except InvariantAuditError:
                    raise LocalExecutionBlocked("LOCAL_STRICT_INVARIANT_AUDIT_FAILED") from None
            self._journal(directory, "04-validated", {
                "command": f"bash scripts/ci/run_phase_gate.sh {state.phase}",
                "transcript_sha256": validation.transcript_sha256, "result": "PASS",
            })
            git(workspace, "diff", "--check")
            git(workspace, "add", "--", *paths)
            git(workspace, "-c", "user.name=RedTeam Local Runner", "-c",
                "user.email=redteam-local-runner@users.noreply.github.com", "commit", "-m",
                f"{state.phase}: local implementation ({run_id})")
            output_sha = git(workspace, "rev-parse", "HEAD")
            if git(workspace, "rev-list", "--parents", "-n", "1", "HEAD") != (
                f"{output_sha} {state.head_sha}"
            ):
                raise LocalExecutionBlocked("LOCAL_OUTPUT_NOT_SINGLE_CHILD")
            self._current(loop, state, request, "implementation")
            self._journal(directory, "05-push-attempt", {"input_sha": state.head_sha,
                          "output_sha": output_sha, "branch": branch})
            try:
                # gh owns credentials in the parent only; never change global Git config.
                git(workspace, "-c", "credential.helper=!gh auth git-credential", "push",
                    f"https://github.com/{loop.github.repository}.git",
                    f"{output_sha}:refs/heads/{branch}", timeout=180)
                actual = loop.github.pull_request(state.number)
                if actual.get("head", {}).get("sha") != output_sha:
                    raise ValueError
            except (PhaseLoopError, ValueError):
                raise LocalReconciliationRequired(
                    "LOCAL_PUSH_OUTCOME_REQUIRES_RECONCILIATION"
                ) from None
            result = {**start, "start_reference": start_comment["html_url"],
                      "implementation_session_id": worker.session_id, "output_sha": output_sha,
                      "completed_at": utc_now(), "validation": "PASS"}
            self._post(loop, state, "redteam-local-implementation-result", result)
            self._journal(directory, "06-published", result)
            loop.log(f"local implementation published: {state.phase} {output_sha}")
        except LocalWorkerError:
            raise LocalExecutionBlocked("LOCAL_WORKER_OR_VALIDATION_FAILED") from None

    @staticmethod
    def _changed_paths(workspace: Path, input_sha: str) -> list[str]:
        if git(workspace, "rev-parse", "HEAD") != input_sha:
            raise LocalExecutionBlocked("LOCAL_WORKER_CHANGED_GIT_HEAD")
        # Include staged, unstaged, and untracked paths; do not allow symlink/submodule output.
        paths = sorted(set(filter(None, (
            git(workspace, "diff", "--name-only", "-z", input_sha, "--") + "\x00"
            + git(workspace, "ls-files", "--others", "--exclude-standard", "-z")
        ).split("\x00"))))
        if not paths or any(not allowed_product_path(path) for path in paths):
            raise LocalExecutionBlocked("LOCAL_DIFF_EMPTY_OR_OUT_OF_SCOPE")
        for path in paths:
            target = workspace / path
            if (target.is_symlink() or not target.resolve().is_relative_to(workspace.resolve())
                    or (target.exists() and not target.is_file())
                    or any(parent.is_symlink() for parent in target.parents
                           if parent.is_relative_to(workspace))):
                raise LocalExecutionBlocked("LOCAL_OUTPUT_LINK_OR_SPECIAL_FILE")
        return paths

    @staticmethod
    def _diff_digest(workspace: Path, paths: list[str]) -> str:
        contents = {
            path: {"digest": hashlib.sha256((workspace / path).read_bytes()).hexdigest(),
                   "mode": (workspace / path).stat().st_mode}
            if (workspace / path).exists() else None for path in paths
        }
        return canonical_digest(contents)

    def _expected_review(self, loop: PhaseLoop, state: PullRequestState,
                         ready: MarkerEvidence, base_sha: str,
                         comments: list[dict[str, Any]]) -> dict[str, Any]:
        raw = [item for item in comments if item.get("html_url") == ready.url]
        if len(raw) != 1 or invariant_audit_from_ready(
            ready, phase=state.phase, head_sha=state.head_sha
        ) is None:
            raise LocalExecutionBlocked("LOCAL_REVIEW_READY_AUDIT_REQUIRED")
        return {
            "comments": comments, "timeline": loop.github.timeline(state.number),
            "operatorLogin": loop.actor_login, "phase": state.phase,
            "headSha": state.head_sha, "baseSha": base_sha, "readyReference": ready.url,
            "readyCreatedAt": raw[0]["created_at"],
            "sourceDigest": canonical_digest(review_trigger_source(
                ready=ready, phase=state.phase, head_sha=state.head_sha, base_sha=base_sha)),
            "policyDigest": self.policy_digest, "familyIds": list(INVARIANT_FAMILIES),
            "requiredCheckNames": list(REQUIRED_CHECK_ORDER),
            "pullRequestUrl": f"https://github.com/{loop.github.repository}/pull/{state.number}",
        }

    def _evaluate(self, expected: dict[str, Any]) -> dict[str, Any]:
        bundled_node = Path(NODE_DIRECTORY) / "node"
        node = str(bundled_node) if bundled_node.is_file() else shutil.which("node")
        if node is None:
            raise LocalExecutionBlocked("LOCAL_NODE_RUNTIME_REQUIRED")
        program = (
            "const fs=require('fs'); const h=require(process.argv[1]);"
            "try {process.stdout.write(JSON.stringify(h.evaluateLocalReview("
            "JSON.parse(fs.readFileSync(0,'utf8')))));} catch (_) {process.exit(2);}"
        )
        try:
            result = subprocess.run(  # noqa: S603
                [node, "-e", program, str(self.root / "automation/local_review_evidence.js")],
                input=canonical_json(expected), text=True, capture_output=True,
                check=False, timeout=30,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            if result.returncode or len(result.stdout.encode()) > 1024 * 1024:
                raise ValueError
            return strict_json_loads(result.stdout)  # type: ignore[no-any-return]
        except (OSError, subprocess.TimeoutExpired, ValueError, PhaseLoopError):
            raise LocalExecutionBlocked("LOCAL_REVIEW_EVIDENCE_REJECTED") from None

    def find_review(self, loop: PhaseLoop, state: PullRequestState, ready: MarkerEvidence,
                    base_sha: str, comments: list[dict[str, Any]]) -> ReviewEvidence | None:
        reports = []
        for item in comments:
            if item.get("user", {}).get("login") != loop.actor_login:
                continue
            for payload in marker_payloads(str(item.get("body", "")),
                                           "redteam-local-review-result"):
                if (payload.get("phase") == state.phase
                        and payload.get("head_sha") == state.head_sha):
                    reports.append((item, payload))
        if not reports:
            return None
        if len(reports) != 1:
            raise LocalExecutionBlocked("LOCAL_REVIEW_RESULT_AMBIGUOUS")
        comments = self._current(loop, state, ready, "review")
        item, payload = reports[0]
        expected = self._expected_review(loop, state, ready, base_sha, comments)
        expected.update({"startReference": payload.get("start_reference"),
                         "reportReference": item.get("html_url")})
        result = self._evaluate(expected)["result"]
        return ReviewEvidence(result, item["html_url"], loop.actor_login,
                              state.head_sha, ready.url, payload["start_reference"])

    def review(self, loop: PhaseLoop, state: PullRequestState, ready: MarkerEvidence,
               base_sha: str, comments: list[dict[str, Any]]) -> None:
        if self.find_review(loop, state, ready, base_sha, comments) is not None:
            return
        self._cutover_check(loop, state, comments, "review")
        if loop.dry_run:
            loop.log(f"would run independent local review: {state.phase} {state.head_sha}")
            return
        comments = self._current(loop, state, ready, "review")
        self._cutover_check(loop, state, comments, "review")
        expected = self._expected_review(loop, state, ready, base_sha, comments)
        if self.find_review(loop, state, ready, base_sha, comments) is not None:
            return
        directory = Path(tempfile.mkdtemp(prefix="redteam-local-review-"))
        workspace, _branch = self._snapshot(loop, state, directory)
        audit = invariant_audit_from_ready(ready, phase=state.phase, head_sha=state.head_sha)
        if audit is None:
            raise LocalExecutionBlocked("LOCAL_REVIEW_AUDIT_MISSING")
        try:
            audit_value = strict_json_loads((workspace / audit["audit_path"]).read_text())
            if canonical_digest(audit_value) != audit["audit_digest"]:
                raise ValueError
        except (OSError, ValueError, PhaseLoopError):
            raise LocalExecutionBlocked("LOCAL_REVIEW_AUDIT_CONTENT_MISMATCH") from None
        run_id = str(uuid4())
        start = {"schema_version": "1.0", "phase": state.phase, "head_sha": state.head_sha,
                 "base_sha": base_sha, "ready_reference": ready.url,
                 "source_digest": expected["sourceDigest"], "policy_digest": self.policy_digest,
                 "run_id": run_id, "started_at": utc_now()}
        inputs = self._inputs(loop, state, ready, base_sha, directory, start)
        config = self._configuration(loop, workspace, "review", inputs)
        try:
            preflight_local_worker(config)
            self._current(loop, state, ready, "review")
            claim = self._claim(loop, state, "review", expected["sourceDigest"])
            self._journal(directory, "01-claimed", {**start, "claim_reference": claim})
            start_comment = self._post(loop, state, "redteam-local-review-start", start)
            self._journal(directory, "02-started", {"reference": start_comment["html_url"]})
            self._current(loop, state, ready, "review")
            loop.log(f"starting isolated independent local review: {state.phase} {state.head_sha}")
            worker = run_local_worker(config, self.review_prompt(state, base_sha),
                                      loop.review_schema)
            self._journal(directory, "03-worker", {"session_id": worker.session_id,
                          "transcript_sha256": worker.transcript_sha256,
                          "result": worker.final_json})
            if git(workspace, "rev-parse", "HEAD") != state.head_sha or git(
                workspace, "status", "--porcelain", "--untracked-files=all"
            ):
                raise LocalExecutionBlocked("LOCAL_REVIEW_SNAPSHOT_CHANGED")
            validate_review_result(worker.final_json, schema=loop.review_schema, phase=state.phase,
                                   reviewed_sha=state.head_sha, base_sha=base_sha)
            result = {**start, "start_reference": start_comment["html_url"],
                      "reviewer_session_id": worker.session_id, "completed_at": utc_now(),
                      "result": worker.final_json, "finding_references": []}
            # Qualify the complete proposed evidence before publishing ANY finding. Real
            # comment timestamps/URLs are independently verified after actual publication.
            prototype = dict(expected)
            prototype["timeline"] = loop.github.timeline(state.number)
            proposed = list(comments) + [start_comment]
            report_time = datetime.now(UTC).timestamp()
            start_time = datetime.fromisoformat(start_comment["created_at"].replace("Z", "+00:00"))
            if report_time <= start_time.timestamp():
                raise LocalExecutionBlocked("LOCAL_REVIEW_CLOCK_NOT_ADVANCED")
            findings = []
            for finding in worker.final_json["findings"]:
                findings.append({"schema_version": "1.0", "run_id": run_id,
                                 "phase": state.phase, "head_sha": state.head_sha,
                                 "base_sha": base_sha, "finding": finding})
            for index, finding in enumerate(findings):
                reference = expected["pullRequestUrl"] + f"#issuecomment-{9000000000000000 + index}"
                result["finding_references"].append(reference)
                proposed.append({"html_url": reference, "user": {"login": loop.actor_login},
                                 "created_at": result["completed_at"],
                                 "updated_at": result["completed_at"],
                                 "body": marker_body("redteam-local-review-finding", finding)})
            report_reference = expected["pullRequestUrl"] + "#issuecomment-9999999999999999"
            proposed.append({"html_url": report_reference, "user": {"login": loop.actor_login},
                             "created_at": result["completed_at"],
                             "updated_at": result["completed_at"],
                             "body": marker_body("redteam-local-review-result", result)})
            prototype.update({"comments": proposed, "startReference": start_comment["html_url"],
                              "reportReference": report_reference})
            self._evaluate(prototype)
            result["finding_references"] = []
            for finding in findings:
                self._current(loop, state, ready, "review")
                published = self._post(loop, state, "redteam-local-review-finding", finding)
                result["finding_references"].append(published["html_url"])
            self._current(loop, state, ready, "review")
            published = self._post(loop, state, "redteam-local-review-result", result)
            self._journal(directory, "04-published", {"reference": published["html_url"]})
            if self.find_review(loop, state, ready, base_sha, loop.comments()) is None:
                raise LocalReconciliationRequired("LOCAL_REVIEW_PUBLICATION_NOT_VERIFIABLE")
            loop.log(f"local independent review published: {state.phase} {state.head_sha}")
        except LocalWorkerError:
            raise LocalExecutionBlocked("LOCAL_REVIEW_WORKER_FAILED") from None
