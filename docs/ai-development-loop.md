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
`docs/implementation-status.md` is a default-branch/bootstrap snapshot; an active PR's Phase
authority is the exact label plus the trusted current-HEAD implementation request and adjacent
prior-Phase PASS chain.

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

GitHub Actions and Codex never merge or push to `main`. Governance PRs retain the human owner
review and UI-merge checklist. The long-lived `ai-loop` implementation PR has one narrower path:
the local orchestrator may call GitHub's merge endpoint only after `ai-project-complete`, while the
PR remains at Phase 5, and after revalidating the complete exact-SHA Phase chain, five current-head
checks/statuses, stop-label absence and current `main` ancestry. The request includes the current
40-character PR head SHA. Before that request, it atomically creates one repository Git ref claim
for the exact PR/HEAD and persists a claim-bound audit comment. Existing or uncertain claims are
not retried. Direct and force pushes to `main` remain prohibited.

This manual control has a greater account-compromise and operator-error risk than server-enforced
protection. When the repository plan supports protection, the same requirements must be configured
and independently verified before the control is described as enforced.

There is no deployment workflow in Phase 0A through Phase 3. Phase 4 and Phase 5 remain behind
provider-specific Human Gates and CI never connects to a real C2, MCP server or target.

## Roles

| Component | Responsibility | Write access |
|---|---|---|
| Local phase orchestrator | Request implementation/review, record validated evidence, and perform the gated final `ai-loop` merge | PR comments, approved workflow dispatch, one atomic claim ref and one exact-SHA final merge |
| Codex Cloud | Current-phase implementation/fix requested through GitHub | PR branch only |
| Codex GitHub Review or ChatGPT | Fresh-context semantic/security review | PR review/comment only |
| CI | Tests, lint, type check, coverage and protected-path enforcement | Check results and ready comment |
| Record AI Phase Review | Revalidate reviewer identity, review SHA, base SHA and actual checks | PR labels/comments/status |
| Human | Start/restart local orchestration, approve Phase 4/5 provider governance, review/merge governance PRs | Explicit provider approval and governance UI merge |

The implementer and reviewer must use separate runs and contexts. A review result is evidence only
when its GitHub permalink resolves to native Codex content authored by `AI_REVIEWER_LOGIN`. The
full-SHA binding is the validated chain of the current-head CI ready marker, operator-authored
review trigger, unchanged PR timeline, current PR head, native result and required checks. The
shortened commit ID displayed by Codex is corroborating evidence, never the sole binding.

## State machine

```text
IMPLEMENTATION_REQUESTED
  -> DEFAULT_BRANCH_ADVANCED_BEFORE_IMPLEMENTATION
       -> PREVIOUS_PHASE_REVALIDATION_REQUESTED
       -> exact-HEAD update-branch -> CI_RUNNING for the previous phase
  <- local orchestrator dispatches Start AI Loop for a Phase 0A PR and exact HEAD SHA
  -> local orchestrator requests Codex Cloud implementation
  -> CI_RUNNING
       -> CI_FAILED -> FIX_REQUESTED
       -> REVIEW_READY
  -> local orchestrator requests a fresh Codex/ChatGPT review
  -> local orchestrator validates the review and dispatches Record AI Phase Review
       -> CHANGES_REQUESTED -> FIX_REQUESTED
       -> PASS -> NEXT_PHASE_REQUESTED or HUMAN_GATE or PROJECT_COMPLETE
       -> PROJECT_COMPLETE -> LOCAL_EXACT_SHA_MERGE or BLOCKED
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
{"schema_version":"1.0","phase":"phase-0a","reviewed_sha":"<sha>","base_sha":"<sha>","verdict":"PASS","summary":"...","evidence_format":"codex-native-v1","ready_reference":"https://github.com/...","review_trigger_reference":"https://github.com/...","review_reference":"https://github.com/...","reviewer_login":"...","recorded_by":"...","finding_key":null,"required_checks":[],"loop_state":"PASS"}
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

### Base refresh authorization

When `main` has advanced after an adjacent prior-Phase PASS but before Codex has created any
current-Phase commit, the local orchestrator dispatches `Prepare AI Loop Base Refresh`. The workflow
verifies the exact current HEAD, current default-branch SHA, current implementation request and
adjacent prior PASS, then moves the Phase label back exactly one step and emits a commit status:

```text
sha: <old-head>
state: success
context: redteam/base-refresh/phase-0b/phase-0a/<current-main>
description: trusted exact-SHA base refresh authorization
target_url: <trusted-prior-PASS-permalink>
creator: github-actions[bot]
```

The workflow uses `statuses: write` for this evidence and `issues: write` for labels while retaining
only `pull-requests: read`; it does not receive merge authority. Only after validating the status
creator, exact context, state, description, prior PASS link and SHA does the local orchestrator call
GitHub's branch-update endpoint with `expected_head_sha=<old-head>`. A concurrent head change fails
closed. The synchronization is not a final PR merge: it incorporates `main` into the PR branch. CI
then runs the rolled-back Phase on the new HEAD, and every PASS tied to the old HEAD remains stale.

## Review recording

After CI posts the review-ready marker:

1. The local orchestrator posts `@codex review` only after the SHA-bound ready marker exists.
2. Codex independently checks the current phase prompt, acceptance criteria and prior invariants,
   then posts native P0/P1 inline findings or its standard no-major-issues completion and 👍.
3. The orchestrator validates reviewer identity, current phase/head/base, ready/trigger chain,
   native output shape and absence of `synchronize` events during review. For
   `CHANGES_REQUESTED`, it derives a stable root-cause key from priority, path and headline.
4. The orchestrator dispatches `Record AI Phase Review` as `AI_GATE_APPROVER_LOGIN`.

The workflow rejects a stale SHA, wrong reviewer, wrong phase base, fork PR, missing/failed checks,
review link outside the PR, untrusted ready/trigger links, a head change during review, ambiguous
commit evidence, a PASS without the bot 👍, or orchestrator input that differs from the
deterministically derived native result. A formal Codex review without retained P0/P1 comments is
fail-closed. The loop stops after five change cycles in a phase or three occurrences of the same
root-cause key.

## Phase progression

Phase 0A through Phase 3 automatically create the next implementation request after a recorded
PASS. Phase 4 and Phase 5 stop at `ai-human-gate`. Provider approval must be made as a separate
human-reviewed governance change on the default branch before running `Advance AI Loop Phase`.
After approval, restarting the same local command automatically requests the approved Phase 4 or
Phase 5 implementation. Provider choices remain human-only; the final implementation merge uses
the configured local exact-SHA gate.

The same long-lived implementation PR is used to avoid intermediate automatic merges. Every phase
PASS comment records the phase boundary SHA; the next review must use that SHA as its base. The
`redteam/phase-review` status is reset to pending whenever a new phase starts, preventing an earlier
phase PASS from authorizing merge of later work.

If the default branch advances between a PASS and the next implementation, the runner performs the
bounded base-refresh transition above before sending another `@codex implement` request. It never
refreshes after current-Phase code has changed or carries an old PASS across the new merge SHA. The
base-refresh workflow never calls the final merge endpoint; only the local completion gate can.

## Completion

`ai-project-complete` is necessary but not sufficient for merge. The local orchestrator rebuilds
the Phase 0A→5 PASS chain backward from the current Phase 5 HEAD, verifies the latest workflow
status and checks, confirms current `main` is already in the PR ancestry, re-reads the live PR, and
then makes one merge request bound to that exact HEAD. Missing, duplicate, stale, failed or
ambiguous evidence stops the process. Before dispatch it atomically creates
`refs/redteam-final-merge-attempts/pr-<PR>-<HEAD>`, then writes a durable PR comment binding the
attempt to PR, HEAD, current `main`, Phase 5 gate, policy digest, actor and claim ref. Only the
process that successfully created the ref may dispatch. Any existing/uncertain claim or recorded
attempt requires explicit live-outcome reconciliation and cannot be retried by a normal restart.
The runner never automatically deletes a claim. Completion never deploys or authorizes a real
target.
