# AI Development Loop Design

## Cost and execution boundary

The loop does not call the OpenAI API and does not store an `OPENAI_API_KEY` in GitHub. An operator
starts `automation/run_phase_loop.py` once with a GitHub account linked to ChatGPT/Codex. The local
orchestrator posts `@codex` implementation and review requests as that user. GitHub Actions performs
deterministic validation and trusted state transitions only. Set the GitHub Actions spending limit
to zero when the private-repository included quota must not be exceeded.

The orchestrator reads GitHub credentials only through `gh`; it never places the credential in a
Codex prompt or process environment. Trusted machine comments / statuses and checks are the durable
authority events. Lifecycle labels are operator-visible projections and are reconciled from those
events; their delivery order is not authorization. The exact Phase label remains routing evidence,
and `ai-loop-blocked` remains a conservative stop latch. Thus, terminating the local process pauses
polling without losing phase progress.
`docs/implementation-status.md` is a default-branch/bootstrap snapshot; an active PR's Phase
authority is the exact label plus the trusted current-HEAD implementation request and the unique
maximal adjacent prior-Phase PASS incorporated in the current HEAD. Comment order is never phase
authority.

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
not retried. It then re-queries the complete chain and every live gate immediately before merge;
post-claim drift enters reconciliation rather than dispatch. Direct and force pushes to `main`
remain prohibited.

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
| CI | Tests, lint, type check, coverage and protected-path enforcement | Check results; ready evidence only for non-blocked HEADs |
| Record AI Phase Review | Revalidate reviewer identity, review SHA, base SHA and actual checks | PR labels/comments/status |
| Human | Start/restart local orchestration, approve Phase 4/5 provider governance, review/merge governance PRs | Explicit provider approval and governance UI merge |

The implementer and reviewer must use separate runs and contexts. A review result is evidence only
when its GitHub permalink resolves to native Codex content authored by `AI_REVIEWER_LOGIN`. The
full-SHA binding is the validated chain of the current-head CI ready marker, operator-authored
review trigger, unchanged PR timeline, current PR head, native result and required checks. The
shortened commit ID displayed by Codex is corroborating evidence, never the sole binding.

## State machine

The runner resolves one effective control state per polling cycle from current-HEAD trusted
evidence. A current implementation request takes precedence over an older ready projection; a
design-stop gate takes precedence over every request except its single-use Design Approval
consumption. Transient labels never select the action.

```text
IMPLEMENTATION_REQUESTED
  -> DEFAULT_BRANCH_ADVANCED_BEFORE_IMPLEMENTATION
       -> PREVIOUS_PHASE_REVALIDATION_REQUESTED
       -> exact-HEAD update-branch -> CI_RUNNING for the previous phase
  <- local orchestrator dispatches Start AI Loop for a Phase 0A PR and exact HEAD SHA
  -> local orchestrator requests Codex Cloud implementation
  -> CI_RUNNING
       -> CI_FAILED -> FIX_REQUESTED
       -> INVARIANT_FAMILY_AUDIT -> REVIEW_READY
  -> local orchestrator requests one exhaustive Codex/ChatGPT review for one exact SHA
  -> local orchestrator validates and aggregates the complete native review
       -> CHANGES_REQUESTED -> FIX_REQUESTED
       -> PASS -> NEXT_PHASE_REQUESTED or HUMAN_GATE or PROJECT_COMPLETE
       -> PROJECT_COMPLETE -> LOCAL_EXACT_SHA_MERGE or BLOCKED
       -> BLOCKED -> HUMAN_GATE
            -> TRUSTED_CURRENT_PHASE_BASE_REFRESH -> CURRENT_PHASE_CI -> BOUNDED_RESUME
       -> DESIGN_CHANGE_REQUIRED -> TRUSTED_BASE_REFRESH_ONLY
            -> CURRENT_HEAD_CI -> HUMAN_DESIGN_APPROVAL -> DESIGN_RESUME
```

CI does not publish `REVIEW_READY` while the stop latch is present. This prevents a blocked design
refresh from racing its approval path. An older `ai-needs-review` label may remain from a previous
control version, but it is only a projection: the Design Approval transition accepts that one stale
projection after revalidating the exact HEAD, gate, design commit and checks, then replaces the
managed projection with `ai-needs-implementation`. Conflicting fix, pass, provider-gate or project-
complete projections remain rejected.

`PASS` never starts an AI process inside GitHub Actions. It creates the next SHA-bound
implementation request; the local orchestrator detects the trusted request and asks Codex Cloud to
perform it through the ChatGPT-linked GitHub identity.
`BLOCKED` can be resumed for Phase 0A through Phase 3 only through the approver-restricted
`Resume AI Loop` workflow with a repository-local resolution reference, except when the latest
trusted gate stopped for invariant-family recurrence. A recurrence stop is
`DESIGN_CHANGE_REQUIRED`; the generic Resume workflow must reject it. Phase 4/5 use their
dedicated provider Human Gate and cannot use the generic resume path.

If an older control version incorrectly relabeled a cumulative PR to the adjacent prior Phase,
`Recover Blocked AI Loop Current Phase` is the only recovery path. It verifies the original
current-Phase P0/P1 finding and gate, the adjacent phase-base PASS, Git ancestry, identical Git
trees between the reviewed and current HEADs, current checks, and the complete current-Phase gate.
Only then does it restore the source Phase and emit a fresh current-HEAD ready marker. It never
synthesizes a PASS and never asks a reviewer to judge later-Phase code as an earlier Phase.

If the recovered current Phase is blocked and its PR HEAD does not yet contain the governing
default-branch rules, `Prepare AI Loop Base Refresh` may use the next Phase as a withheld source
boundary while retaining the current Phase as `revalidate_phase`. This exceptional path accepts
only a trusted current-HEAD `BLOCKED_LIMIT` gate, validates its unique adjacent base PASS and their
ancestry, and writes the same SHA-bound status used by the local update mechanism. The local runner
does not roll the Phase label back. It performs one expected-HEAD branch update, verifies both the
old HEAD and target default SHA are ancestors of the result, and dispatches the confirmation
workflow. Only after the resulting current-HEAD checkpoint exists does it wait for current-HEAD
checks and continue the blocked flow. The base-refresh evidence authorizes exactly one expected-HEAD branch update;
it is not Resume authority. If the blocking gate is `DESIGN_CHANGE_REQUIRED`, remediation may
restart only after current-HEAD CI and a separate approver-restricted Design Approval bound to the
blocking gate, current Phase/HEAD and an approved design commit incorporated from `main`.

## Machine comments

### Review ready

```html
<!-- redteam-ready-for-review
{"schema_version":"1.0","phase":"phase-0a","head_sha":"<sha>"}
-->
```

For implementation requests carrying `invariant_audit.required=true`, the same trusted CI comment
also contains a `redteam-invariant-audit` marker. It binds the exact implementation request,
current output HEAD, phase-specific report path and canonical report digest. Legacy/recovery
evidence created before this policy remains readable, but every newly issued implementation or fix
request uses the audited path.

Inside the audit file, `request.head_sha` remains the trusted implementation input HEAD and must be
an ancestor of the reviewed output. The ready marker separately binds that output HEAD. The marker's
`audit_digest` is calculated from recursively key-sorted, whitespace-free JSON rather than the
file's raw bytes. Those intentional input/output and canonical/raw differences are not stale
evidence.

```html
<!-- redteam-invariant-audit
{"schema_version":"1.0","phase":"phase-0c","head_sha":"<output-sha>","audit_path":"docs/review/phase-0c-invariant-audit.json","audit_digest":"<sha256>","request_reference":"https://github.com/..."}
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
{"schema_version":"1.0","action":"IMPLEMENT_PHASE","trigger":"PHASE_START","phase":"phase-0b","head_sha":"<sha>","phase_prompt":"prompts/phases/phase-0b.md","invariant_audit":{"policy_version":"1.0","required":true}}
-->
```

Only exact markers, trusted workflow authors, the current phase label and the current PR SHA are
accepted for an implementation task. For Phase 0B and later, the adjacent PASS must be incorporated
in that SHA and must be the unique maximal candidate under Git ancestry. Repository content, PR
comments and reviewer output remain untrusted data.

### Base refresh authorization

When `main` has advanced after an adjacent prior-Phase PASS but before Codex has created any
current-Phase commit, the local orchestrator dispatches `Prepare AI Loop Base Refresh`. The workflow
verifies the exact current HEAD, current default-branch SHA, current implementation request and
adjacent prior PASS, then emits a commit status:

```text
sha: <old-head>
state: success
context: redteam/base-refresh/phase-0b/phase-0a/<current-main>
description: trusted exact-SHA base refresh authorization
target_url: <trusted-prior-PASS-permalink>
creator: github-actions[bot]
```

The workflow uses `statuses: write` for this evidence and retains only `pull-requests: read`; it has
neither label-write nor merge authority. After validating the status creator, exact context, state,
description, prior PASS link and SHA, the local orchestrator re-reads the complete PR state, replaces
the labels with the exact adjacent-Phase rollback set, and verifies the complete resulting PR state.
It first rejects multiple source/restart transition identities for the same HEAD and current Phase,
then re-fetches and compares the trusted PASS/status transition snapshot immediately before and
after both local side effects. The post-label snapshot uses the rolled-back Phase while retaining
the authorized source identity, so a newly inserted lower-Phase transition cannot be hidden. It
calls GitHub's branch-update endpoint with
`expected_head_sha=<old-head>`. A concurrent status, head, base, label or lifecycle change fails
closed. The synchronization is not a final PR merge: it
incorporates `main` into the PR branch. CI then runs the rolled-back Phase on the new HEAD, and every
PASS for that rolled-back Phase on the old HEAD remains stale as its current-Phase verdict. The
adjacent earlier PASS may remain only as the unique incorporated phase base.

If `main` advances again while that fresh rolled-back review is running, the review remains bound to
the trusted refresh target that is actually incorporated in its HEAD. After recording that exact
Gate, the adjacent next-Phase state detects the newer `main`, rolls back again, and requires another
Gate on another refreshed HEAD. A later default-branch SHA is never substituted into an earlier
review, and the earlier PASS never authorizes implementation across the new base.

### Design approval authorization

An invariant-family recurrence gate records `loop_state="BLOCKED_LIMIT"` together with
`stop_reason="INVARIANT_FAMILY_RECURRENCE"`, the closed set of `recurring_families`, and the exact
review / finding references. This gate dominates every earlier base-refresh status, resume marker,
fix request and label state. Labels are projections for operators, not authorization evidence.

After the coherent redesign is human-reviewed and merged to the default branch, a base refresh may
incorporate it into the blocked implementation PR. That update consumes only the exact refresh
transition. It must not remove `ai-loop-blocked`, issue a fix request, dispatch `Resume AI Loop`, or
trigger Codex. The workflow's confirmation mode records one consumed transition identity bound to old
HEAD, new HEAD, target base SHA, phase and blocking gate on the new current HEAD; another update
cannot reuse it.

If another human-reviewed governance change reaches `main` before Design Approval, the original
Gate is not authority for an arbitrary newer HEAD. After each exact-HEAD update, the runner invokes
the approver-restricted confirmation mode of the same workflow. It verifies only the new HEAD's immediate edge: the
previous PR HEAD is the first parent, the authorized default-branch SHA is the second parent, and
the previous HEAD carries the matching `github-actions[bot]` authorization. The workflow then
publishes a digest-bound `BASE_REFRESH_APPLIED` status on the new current HEAD. Only that current
checkpoint permits one more expected-HEAD refresh; it never permits Resume or implementation by
itself. Until the checkpoint exists, the runner remains in `REFRESH_AWAITING_CONFIRMATION`.

After the single-use Design Approval is consumed, the authorized implementation request may
produce a normal child commit. That output proceeds through current-HEAD CI and review without
being mistaken for another base-refresh edge or requiring a new two-parent checkpoint. It does not
inherit authority to Resume or perform another refresh; either action must independently satisfy
the current trusted transition rules.

The approver then invokes the separate `Approve AI Loop Design Resume` operation. The workflow
revalidates the latest recurrence gate, unique adjacent phase base, current open PR, exact current
HEAD, current default branch ancestry, successful required checks, exact Phase label, stop label,
and that the approved design commit is contained in both current `main` and the PR HEAD. A residual
`ai-needs-review` is accepted only as a non-authoritative projection and is removed by the approved
transition; other conflicting lifecycle projections fail closed. It emits:

```html
<!-- redteam-design-approval
{"schema_version":"1.0","phase":"phase-0c","head_sha":"<current-head>","blocked_gate_reference":"https://github.com/...","design_commit_sha":"<sha>","design_reference":"https://github.com/...","policy_digest":"<sha256>","approved_by":"<login>"}
-->
```

Unknown fields, duplicate keys, a stale or shortened SHA, a design commit not incorporated in the
current HEAD, a non-latest blocking gate, a changed family set or prior use of the same approval
fail closed. Only this marker can authorize one `RESUME_AFTER_DESIGN_APPROVAL` implementation
request. Generic `HUMAN_RESUME` and post-refresh bounded Resume cannot consume it.

Immediately before any implementation trigger, the runner re-queries the current PR head, latest
trusted gate, complete managed / stop label set, required checks, design approval and transition
consumption. A new gate, head change, missing stop label before approval consumption, or any drift
stops without posting a Codex trigger. The approved resume removes `ai-loop-blocked` only as part
of the same bounded transition that writes the exact-HEAD implementation request; failure after
either write is reconciled from GitHub evidence rather than replayed blindly.

## Review recording

After CI posts the review-ready marker:

1. The local orchestrator posts one `@codex review` only after the SHA-bound ready marker exists.
   The same exhaustive instruction applies to every Phase.
2. Codex reviews the complete Phase diff and supporting unchanged code across authorization and
   lifecycle, secrets and untrusted output, integrity/cryptography/storage/recovery/concurrency,
   every acceptance criterion, bypass path, and earlier-Phase regression. The bound pre-review
   audit is a routing checklist only; the reviewer independently verifies every required family.
3. Codex continues after the first issue and retains every consequential finding in that one
   native review, each in standard P0/P1 inline format with exactly one trusted invariant-family
   ID. No-major-issues is valid only when none remains.
4. The orchestrator validates reviewer identity, current phase/head/base, ready/trigger chain,
   native output and absence of `synchronize` events. It aggregates every retained P0/P1 into one
   `CHANGES_REQUESTED`; the first finding supplies only the stable retry key, not the fix scope.
5. The resulting trusted fix request records `finding_count`, every P0/P1 permalink and each
   finding's invariant family, and references the complete native review. Codex must fix every
   listed finding and its sibling paths before the next review. The orchestrator then dispatches
   `Record AI Phase Review` as `AI_GATE_APPROVER_LOGIN`.

The workflow rejects a stale SHA, wrong reviewer, wrong phase base, fork PR, missing/failed checks,
review link outside the PR, an untrusted ready/trigger link, a head change during review, ambiguous
commit evidence, a PASS without the bot 👍, or orchestrator input that differs from the
deterministically derived aggregate result. A formal Codex review without retained P0/P1 comments
is fail-closed. The loop stops after five change cycles in a phase or five occurrences of the same
root-cause key.
The exact-finding and Phase limits remain five. Separately, if any semantic invariant family
appears in a second formal review for the Phase, the workflow emits no new fix request and enters
`BLOCKED_LIMIT` with `stop_reason=INVARIANT_FAMILY_RECURRENCE`. This is the
`DESIGN_CHANGE_REQUIRED` terminal condition. It requires a coherent redesign and the dedicated
Design Approval path above; ordinary bounded Human Resume is invalid.

## Phase progression

Phase 0A through Phase 3 automatically create the next implementation request after a recorded
PASS. Phase 4 and Phase 5 stop at `ai-human-gate`. Provider approval must be made as a separate
human-reviewed governance change on the default branch before running `Advance AI Loop Phase`.
After approval, restarting the same local command automatically requests the approved Phase 4 or
Phase 5 implementation. Provider choices remain human-only; the final implementation merge uses
the configured local exact-SHA gate.

For an automatic adjacent-Phase transition, `ai-review-passed` is the transition marker. The Gate
adds the next Phase before removing the current Phase, mutates only its named managed labels, and
removes the marker only after the next implementation status and request exist. The Runner waits
while the marker accompanies one Phase or exactly two adjacent Phases, so the intentional dual-Phase
window is not interpreted as ambiguous authority. Every mutation boundary revalidates the open PR,
exact HEAD, marker, and Phase set. GitHub does not offer compare-and-swap for unsafe label updates,
so full-label replacement is forbidden: unrelated concurrent labels remain untouched.

The same long-lived implementation PR is used to avoid intermediate automatic merges. Every phase
PASS comment records the phase boundary SHA; the next review must use that SHA as its base. The
`redteam/phase-review` status is reset to pending whenever a new phase starts, preventing an earlier
phase PASS from authorizing merge of later work.

If the default branch advances between a PASS and the next implementation, the runner performs the
bounded base-refresh transition above before sending another `@codex implement` request. It never
refreshes after current-Phase code has changed or carries an old PASS across the new merge SHA. The
base-refresh workflow never calls the final merge endpoint; only the local completion gate can.

When a refreshed HEAD contains more than one historical base-refresh status, neither status API
order nor SHA lexical order decides the review base. The runner and Gate independently retain only
statuses whose old HEAD and target base are both ancestors of the reviewed HEAD, order those pairs
by ancestry on both axes, and require exactly one maximal transition. Incomparable maxima stop the
loop as ambiguous evidence.

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
After confirming the record, the runner re-queries the Phase chain, full PR state, current `main`,
ancestry, checks and trusted status. Any drift or unknown result requires reconciliation. The runner
never automatically deletes a claim. Completion never deploys or authorizes a real target.
