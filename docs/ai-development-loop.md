# AI Development Loop Design

## Cost and execution boundary

The loop does not call the OpenAI API and does not store an `OPENAI_API_KEY` in GitHub. An operator
starts `automation/run_phase_loop.py` once with a GitHub account linked to ChatGPT/Codex. The local
orchestrator posts `@codex` implementation and review requests as that user. GitHub Actions performs
deterministic validation and trusted state transitions only. Set the GitHub Actions spending limit
to zero when the private-repository included quota must not be exceeded.

The orchestrator reads GitHub credentials only through `gh`; it never places the credential in a
Codex prompt or process environment. GitHub comments, labels and checks are the durable source of
state, so terminating the local process pauses polling without losing phase progress.

A `governance-change` PR is not a phase implementation and does not receive an AI phase verdict.
CI runs the complete test suite plus control-file validation and marks `redteam/phase-review` as
not applicable only after those deterministic jobs succeed. A human owner review is still a
mandatory operator step, although the current GitHub plan does not enforce `CODEOWNERS`. An
`ai-loop` PR always runs the complete current-phase gate, including Mypy and coverage.

## Repository enforcement boundary

The private repository's current plan does not provide branch protection or repository rulesets.
No empty ruleset is created. Pull-request-only changes, human owner review, conversation
resolution, direct-push prohibition, force-push/deletion prohibition and required checks are
governance requirements, but GitHub does not currently enforce them at the branch boundary.

The local orchestrator, GitHub Actions and Codex never merge or push to `main`. Before a human
merge, the operator must bind the decision to the current 40-character PR head SHA, verify the
complete final diff and all five required checks, verify the current SHA-bound Codex review and
`redteam/phase-review` result, record that evidence on the PR, and merge only through the GitHub UI.
The runbook contains the exact checklist. Direct and force pushes to `main` remain prohibited.

This manual control has a greater account-compromise and operator-error risk than server-enforced
protection. When the repository plan supports protection, the same requirements must be configured
and independently verified before the control is described as enforced.

There is no deployment workflow in Phase 0A through Phase 3. Phase 4 and Phase 5 remain behind
provider-specific Human Gates and CI never connects to a real C2, MCP server or target.

## Roles

| Component | Responsibility | Write access |
|---|---|---|
| Local phase orchestrator | Request implementation/review and record validated evidence | PR comments and approved workflow dispatch |
| Codex Cloud | Current-phase implementation/fix requested through GitHub | PR branch only |
| Codex GitHub Review or ChatGPT | Fresh-context semantic/security review | PR review/comment only |
| CI | Tests, lint, type check, coverage and protected-path enforcement | Check results and ready comment |
| Record AI Phase Review | Revalidate reviewer identity, review SHA, base SHA and actual checks | PR labels/comments/status |
| Human | Start/restart local orchestration, verify manual merge evidence, approve Phase 4/5 and final merge | Explicit approval and GitHub UI merge only |

The implementer and reviewer must use separate runs and contexts. A review result is evidence only
when its GitHub permalink resolves to content authored by `AI_REVIEWER_LOGIN` and it is bound to the
current PR head SHA.

## State machine

```text
IMPLEMENTATION_REQUESTED
  <- local orchestrator dispatches Start AI Loop for a Phase 0A PR and exact HEAD SHA
  -> local orchestrator requests Codex Cloud implementation
  -> CI_RUNNING
       -> CI_FAILED -> FIX_REQUESTED
       -> REVIEW_READY
  -> local orchestrator requests a fresh Codex/ChatGPT review
  -> local orchestrator validates the review and dispatches Record AI Phase Review
       -> CHANGES_REQUESTED -> FIX_REQUESTED
       -> PASS -> NEXT_PHASE_REQUESTED or HUMAN_GATE or PROJECT_COMPLETE
       -> BLOCKED -> HUMAN_GATE
```

`PASS` never starts an AI process inside GitHub Actions. It creates the next SHA-bound
implementation request; the local orchestrator detects the trusted request and asks Codex Cloud to
perform it through the ChatGPT-linked GitHub identity.
`BLOCKED` can be resumed for Phase 0A through Phase 3 only through the approver-restricted
`Resume AI Loop` workflow with a repository-local resolution reference. Phase 4/5 use their
dedicated provider Human Gate and cannot use the generic resume path.

## Machine comments

### Review ready

```html
<!-- redteam-ready-for-review
{"schema_version":"1.0","phase":"phase-0a","head_sha":"<sha>"}
-->
```

### Trusted phase-gate record

This marker is created only by the `Record AI Phase Review` workflow after it re-queries GitHub
checks and validates the reviewer permalink. AI-authored markers are not accepted directly.

```html
<!-- redteam-phase-gate
{"schema_version":"1.0","phase":"phase-0a","reviewed_sha":"<sha>","base_sha":"<sha>","verdict":"PASS","summary":"...","review_reference":"https://github.com/...","reviewer_login":"...","recorded_by":"...","finding_key":null,"required_checks":[],"loop_state":"PASS"}
-->
```

### Phase implementation request

```html
<!-- redteam-implementation-request
{"schema_version":"1.0","action":"IMPLEMENT_PHASE","trigger":"PHASE_START","phase":"phase-0b","head_sha":"<sha>","phase_prompt":"prompts/phases/phase-0b.md"}
-->
```

Only exact markers, trusted workflow authors, the current phase label and the current PR SHA are
accepted. Repository content, PR comments and reviewer output remain untrusted data.

## Review recording

After CI posts the review-ready marker:

1. The local orchestrator posts `@codex review` only after the SHA-bound ready marker exists.
2. Codex independently checks the current phase prompt, acceptance criteria and prior invariants,
   then emits exactly one `redteam-ai-review` marker.
3. The orchestrator validates the JSON Schema, author, current phase, reviewed SHA and phase base
   SHA. For `CHANGES_REQUESTED`, it derives a stable root-cause key from the first finding.
4. The orchestrator dispatches `Record AI Phase Review` as `AI_GATE_APPROVER_LOGIN`.

The workflow rejects a stale SHA, wrong reviewer, wrong phase base, fork PR, missing/failed checks,
review link outside the PR, or orchestrator input that differs from the review's single
`redteam-ai-review` marker. It stops after five change cycles in a phase or three occurrences of the
same root-cause key.

## Phase progression

Phase 0A through Phase 3 automatically create the next implementation request after a recorded
PASS. Phase 4 and Phase 5 stop at `ai-human-gate`. Provider approval must be made as a separate
human-reviewed governance change on the default branch before running `Advance AI Loop Phase`.
After approval, restarting the same local command automatically requests the approved Phase 4 or
Phase 5 implementation. The next provider gate and final merge remain human-only.

The same long-lived implementation PR is used to avoid intermediate automatic merges. Every phase
PASS comment records the phase boundary SHA; the next review must use that SHA as its base. The
`redteam/phase-review` status is reset to pending whenever a new phase starts, preventing an earlier
phase PASS from authorizing merge of later work.

## Completion

`ai-project-complete` means the code and evidence satisfy Phase 0A through Phase 5 on the latest
branch SHA. It does not merge or deploy code and does not authorize actions against a real target.
