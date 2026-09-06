# AI Loop Runbook (Local Workers, No Codex Cloud)

## What is automated

Start `automation/run_phase_loop.py` once for the long-lived implementation pull request. It then
repeats this sequence:

1. Read a SHA-bound implementation request created by `github-actions[bot]`.
2. Claim that exact request and launch a fresh local implementation worker in a separate scoped
   workspace. Do not send an `@codex` comment or create a Cloud task.
3. Have the trusted launcher validate the complete phase gate and resulting diff, create and push
   a normal commit to the existing PR branch, then require all current-HEAD CI checks to pass.
4. Require Codex's phase-specific invariant-family audit, including sibling-path coverage and
   positive/negative/failure tests; stateful changes also require property/state-machine evidence.
   CI binds its canonical digest to the implementation request and output HEAD.
5. Publish a unique local review start and launch a fresh read-only local review session for the
   exact phase, head SHA and phase base SHA. The same exhaustive instruction applies to every Phase.
6. Require the reviewer to continue after the first issue and retain every consequential P0/P1 in
   one structured result. The launcher verifies session/source integrity and publishes the full
   `local-review-v1` start/result/finding chain with its own authenticated GitHub account.
7. Dispatch **Record AI Phase Review**, which independently revalidates that evidence, all
   findings, current SHA/base/ready/audit/policy and CI. No human approval is needed for each review.
8. Request a bounded semantic-family fix or continue with the next phase. A family recurring in a
   second formal review stops for coherent redesign instead of requesting another local patch.
9. If `main` advanced before the next Phase implementation began, roll back one Phase, incorporate
   `main` with an exact expected HEAD, and repeat that prior Phase gate on the new HEAD.
10. At Phase 5 completion, revalidate the full Phase 0A→5 SHA chain and current-head checks, then
   merge the `ai-loop` PR once with the exact current HEAD SHA.

The process stops on a failure limit, `BLOCKED`, a runtime limit, the Phase 4/5 Human Gates, or
successful project merge. It never deploys. Ctrl-C cancels the local run and stops its child process
group; an in-flight or uncertain outcome must be reconciled rather than replayed on restart.
Trusted GitHub evidence and the durable launcher journal preserve progress. Lifecycle
labels are a reconstructable operator projection; only the Phase label and conservative stop latch
participate in routing/safety checks.

## One-time repository setup

The qualified runtime is Linux with the desktop-bundled Codex CLI at
`/usr/lib/chatgpt/resources/codex`, its root-owned standalone
`/usr/lib/chatgpt/resources/codex-code-mode-host`, `bubblewrap` at `/usr/bin/bwrap`,
and Node at `/usr/lib/chatgpt/resources/cua_node/bin/node`. There is no unisolated,
Cloud, in-process Code Mode, or alternate-runtime fallback. Maintain the repository's
locked `.venv`; it is mounted read-only into each isolated workspace. The launcher
creates the empty `.venv` mount point before freezing a review snapshot.

Only the trusted host's top-level `model` and `model_reasoning_effort` preferences
are copied from Codex configuration. Other host settings, providers, plugins, MCP,
hooks and prior conversations are not inherited. Model inference still uses native
Codex account authentication and its service connection; worker tool networking is denied.

Each attempt keeps a private `redteam-local-implementation-*` or
`redteam-local-review-*` directory in the host temporary directory, containing the
isolated checkout, read-only input bundle and parent-only append-only journal. Preserve
it when reconciling an unknown result. Do not delete the GitHub claim or manually
relaunch the same input. Apply operator retention/cleanup only after reconciliation;
normal execution does not erase attempt evidence. No model transcript is copied into
GitHub: the journal stores the result and transcript digest, and GitHub receives bound
start/result/finding records.

1. Put the governance/bootstrap changes on a dedicated pull request created with only the
   `governance-change` label. Review and merge it manually before starting the loop. This first
   merge is not a Phase 0A PASS.
2. Reauthenticate GitHub CLI if necessary and confirm the active identity:

   ```bash
   gh auth login --hostname github.com
   gh auth status --hostname github.com
   gh api user --jq .login
   ```

3. Make the supported local Codex CLI and its ChatGPT account authentication available to the
   trusted launcher. Verify CLI sandbox / fresh-session support and isolation from the operator's
   GitHub credentials, user configuration, MCP/plugins and previous conversation history. Do not
   enable GitHub Code Review or connect GitHub to a Cloud task for this loop. Local execution still
   needs model-service network access; it is not offline inference or a local-model integration.
4. Set repository variables. The operator value is an exact, case-sensitive GitHub login:

   ```bash
   gh variable set AI_GATE_APPROVER_LOGIN --body '<operator-login>'
   gh variable set AI_LOOP_MAX_ITERATIONS --body '5'
   ```

   `AI_GATE_APPROVER_LOGIN` must equal the account returned by `gh api user --jq .login`.
   Local review provenance uses this same configured operator account, not the Cloud bot identity.
   Preserve an existing `AI_REVIEWER_LOGIN` for historical `codex-native-v1` gate verification;
   it is not the authenticator for new `local-review-v1` evidence and must not be rewritten to
   pretend the launcher is a Cloud reviewer.
   `AI_LOOP_MAX_ITERATIONS` is fail-closed at exactly `5`; smaller or larger values block the loop.

   For migration of an existing native gate chain only, the historical reviewer configuration is
   retained as `gh variable set AI_REVIEWER_LOGIN --body 'chatgpt-codex-connector[bot]'` when that
   exact login authored the existing verified reviews. This value neither starts Cloud work nor
   authenticates local results. Do not infer the author from a display name.

5. Do not create an `OPENAI_API_KEY` secret. Only the parent launcher accesses the existing `gh`
   credential store. Workers receive neither its token nor access to the store, parent journal,
   main checkout or GitHub write tools. The reviewer gets a separate read-only snapshot; the
   implementer gets only its scoped workspace. Missing isolation must block startup.
6. Create the labels through the approved workflow:

   ```bash
   gh workflow run bootstrap-ai-loop.yml \
     --ref main \
     --raw-field confirmation=BOOTSTRAP_AI_LOOP
   ```

7. Set the GitHub Actions spending limit to zero if use beyond the included private-repository
   quota must be prevented.

## Repository merge controls

This private repository's current GitHub plan does not expose branch protection or repository
rulesets. Do not create an empty ruleset. The controls in this section are therefore mandatory
operator procedure, not server-enforced protection. This is an explicitly accepted residual risk
and is weaker than GitHub-enforced branch protection.

Neither GitHub Actions nor Codex may merge, push directly to `main`, force-push, delete `main`, or
receive a merge bypass. `CODEOWNERS` identifies the human reviewer but cannot require that review
on the current plan. Repository collaborators must make every change through a pull request.

Governance PRs are never automatic. Immediately before every governance merge, the human operator
must:

1. Copy the pull request's current full 40-character head SHA and confirm it is still current.
2. Confirm an implementation PR has no governance-controlled paths. A PR that intentionally
   changes those paths must have only the `governance-change` control label, not `ai-loop`.
3. Confirm the following exact checks are successful for that head SHA:

- `tests (3.12)`
- `tests (3.14)`
- `quality`
- `governance-integrity`
- `redteam/phase-review`

4. Confirm `redteam/phase-review` reports `not applicable: human-reviewed governance change` for
   that SHA and perform the owner review yourself; a governance PR does not receive an AI phase
   verdict.
5. Resolve all review conversations and inspect the complete final diff.
6. Add a PR comment recording the reviewed head SHA, the five successful checks, the applicable
   Codex-review permalink or governance-review status, and whether governance-controlled paths
   changed.
7. Merge through the GitHub pull request UI as the human operator. Never use a direct push or
   force-push to update `main`.

The long-lived implementation PR is merged differently. `automation/final-merge-policy.json`
enables only the local orchestrator, Phase 5, `ai-loop` plus completion/PASS labels, absence of all
stop labels, one exact `base_sha`-linked PASS per Phase, the latest trusted Phase status, all four
current-head Check Runs, and current `main` ancestry. The orchestrator re-reads live state and calls
GitHub only after atomically creating
`refs/redteam-final-merge-attempts/pr-<PR>-<FULL_HEAD>`, and then persisting a
`redteam-final-merge-attempt` PR marker bound to PR, full HEAD, current `main`, Phase 5 gate, policy
digest, actor and claim ref. It then calls the merge endpoint with
`sha=<current-40-character-head>` and `merge_method=merge`. A 409, conflict, drift, malformed
response or unknown claim/merge outcome stops without an automatic retry. GitHub ref creation is
the atomic winner selection: only one overlapping runner can own it. The same PR/HEAD claim or
marker blocks every normal restart until explicit reconciliation; the runner never deletes the
claim. Immediately before dispatch, it re-queries the complete Phase chain, attempt marker, full PR
state, current `main`, ancestry, checks and trusted status; any post-claim drift enters
reconciliation. Fork and governance PRs cannot satisfy this policy.

If GitHub branch protection or rulesets later become available, configure the pull-request,
CODEOWNERS, stale-review, conversation-resolution, force-push/deletion, and five exact status-check
requirements before treating them as server-enforced. Keep this manual checklist until the active
rules are independently verified.

## Create the Phase 0A pull request

Use a normal branch in the same repository, push it, and open one long-lived PR to `main`. Apply
exactly one phase label plus `ai-loop`:

```bash
gh pr create --base main --head ai/redteam-agent-build \
  --title 'AI loop: implement SystemDesign by phase' \
  --body-file .github/pull_request_template.md \
  --label ai-loop \
  --label phase-0a
```

Do not use a fork PR. Keep governance changes out of this implementation PR.

## Start or resume the automatic loop

The runner is a control process, so launch it from a clean, current `main` checkout rather than the
implementation branch:

```bash
git switch main
git pull --ff-only
.venv/bin/python automation/run_phase_loop.py \
  --repo Pizza73/RedTeam_Agent \
  --pr <PR_NUMBER>
```

Optional bounded controls:

```bash
.venv/bin/python automation/run_phase_loop.py \
  --repo Pizza73/RedTeam_Agent \
  --pr <PR_NUMBER> \
  --poll-seconds 30 \
  --max-runtime-hours 24
```

Use `--dry-run` to validate local/GitHub prerequisites and report the next action without posting a
comment or dispatching a workflow. A normal restart is idempotent: the runner recognizes its own
SHA-bound local run claims and evidence and does not intentionally request the same work twice.
An existing claim with unknown process/publication/push outcome is a reconciliation stop, not
permission to relaunch. Do not manually invoke a worker to bypass this stop.

The runner selects work from current-HEAD trusted evidence, not from transient lifecycle labels. A
current implementation request wins over an older ready projection; otherwise a current ready
record selects review. Delayed `ai-needs-*` projection updates therefore do not create a false stop
or duplicate action.

The runner may use GitHub's **Update a pull request branch** operation. This merges the current
default branch into the long-lived PR branch only after the approver-restricted workflow records a
SHA-bound `redteam/base-refresh/...` commit status. The status is attached to the old full HEAD,
encodes the adjacent Phase rollback and exact target-base SHA in its context, and links to the prior
PASS. The workflow token has `statuses: write` and only `pull-requests: read`; it cannot write labels
or merge the PR. The local runner verifies that status, re-reads the full PR state, and performs the
exact label projection required by the transition. A normal refresh gets the adjacent-Phase
rollback set. A blocked current-Phase refresh restores `ai-loop-blocked` and removes stale
lifecycle labels before the branch update. The runner then verifies the full resulting state. It also
re-fetches the trusted transition snapshot immediately before and after both the label and branch
writes. The branch-update request includes the old full HEAD as `expected_head_sha`, so a concurrent
Codex or human commit is rejected. CI must then produce a new SHA-bound PASS. This operation does
not merge the PR into `main`; it is distinct from the local Phase 5 final merge gate above.

The local reviewer returns the closed `review-result.schema.json` result to the launcher, with
P0/P1 represented by `BLOCKER`/`HIGH`. The launcher publishes `redteam-local-review-start`, every
`redteam-local-review-finding` and one `redteam-local-review-result`; only the trusted workflow
publishes `redteam-phase-gate`. The workflow checks launcher identity, full head/base, canonical
ready/audit source and policy digests, unique run and fresh session, unchanged review timeline and
every finding reference. A missing/ambiguous/edited record blocks; model output alone cannot PASS.
The fix request records the exact `finding_count`, every finding permalink and each family ID.
`finding_key` is only the retry key; the local implementer must resolve all findings and sibling
paths. Routine recording is unattended. No bot reaction or Cloud review is required.

This trusts the operator host/sandbox/launcher and its GitHub account. It is context and process
separation, not a second independent GitHub identity. A host/account compromise can undermine this
boundary; the GitHub workflow cannot remotely attest the local model process. Historical native
Cloud gate evidence retains its original identity and timeline rules for ancestry only.

## Human Gates and blocked runs

- `CHANGES_REQUESTED`: the runner requests one same-phase fix covering all findings and every
  sibling path in their semantic invariant families. The fifth occurrence of one exact root-cause
  key or the fifth change cycle blocks the loop. A semantic family appearing in a second formal
  review blocks immediately as `DESIGN_CHANGE_REQUIRED` for a documented coherent redesign.
- CI failure: the runner consumes the bounded failure request and asks Codex for a same-phase fix;
  CI failure never counts as PASS. For a stopped PR, CI records failure but issues no fix request
  and does not clear the stop latch. Missing permission to read the trusted phase plan fails closed.
- `BLOCKED`: resolve the recorded cause. For Phase 0A through Phase 3, run **Resume AI Loop** with
  the current HEAD SHA and a repository permalink documenting the resolution, then restart the
  local command. Do not use this workflow when the latest trusted gate has
  `stop_reason=INVARIANT_FAMILY_RECURRENCE`; it is intentionally rejected.
- If an older control version incorrectly relabeled cumulative later-Phase code as the adjacent
  prior Phase, do not use Resume AI Loop first and do not change labels manually. Run **Recover
  Blocked AI Loop Current Phase** with the source Phase, exact reviewed HEAD, exact current HEAD,
  original Codex P0/P1 permalink, and `RECOVER_CURRENT_PHASE`. The approver-restricted workflow
  requires the reviewed HEAD to be an ancestor of the current HEAD with an identical Git tree,
  revalidates the current-Phase gate and its incorporated adjacent PASS, checks current CI, and runs
  the complete current-Phase gate. It then restores the source Phase with `ai-needs-review` for a
  fresh current-HEAD review. It does not synthesize a PASS or review later-Phase code as the prior
  Phase.
- If the subsequent Codex implementation reports that the PR branch still contains the old
  exact-HEAD prior-PASS rule, keep the current Phase label. Restart the local runner from clean,
  current `main`; it dispatches **Prepare AI Loop Base Refresh** using the trusted current-Phase
  `BLOCKED_LIMIT` gate as the authorization reference. The workflow validates that gate and its
  adjacent base PASS, and the runner performs one expected-HEAD update without a Phase rollback.
  The refresh authorizes only that branch update; it must keep `ai-loop-blocked` and cannot trigger
  Resume or any local worker. After current-HEAD CI succeeds, a recurrence stop still requires the dedicated
  **Approve AI Loop Design Resume** operation.
- If `main` advances again while the same `BLOCKED_LIMIT` remains active, restart the runner from
  the new clean `main`. It may reuse the same blocking Gate only when the exact current HEAD has one valid
  `BASE_REFRESH_APPLIED` checkpoint. After a branch update the runner dispatches the confirmation
  mode of **Prepare AI Loop Base Refresh**, which verifies the immediate two-parent merge and
  previous-HEAD authorization, then certifies the new HEAD. Do not manually merge, push, relabel, or skip the
  confirmation; `REFRESH_AWAITING_CONFIRMATION` cannot Resume, implement, or refresh again. The
  checkpoint authorization permalink selects the Gate directly; Resume does not compare every
  historical Gate pair. A bot-authored current-HEAD Gate always supersedes an older checkpoint.
  For a blocked-Phase refresh, the trusted workflow restores `ai-loop-blocked` and removes stale
  lifecycle projections before branch update. Confirmation may perform the same conservative
  repair for an already-applied exact refresh, but it never issues the implementation request.
- For `DESIGN_CHANGE_REQUIRED`, first review and merge the coherent design as a governance PR.
  Refresh the blocked PR to incorporate that exact design commit, wait for current-HEAD checks,
  then run **Approve AI Loop Design Resume** with the latest blocking gate permalink, full current
  HEAD, full design commit SHA and repository design permalink. Restart the runner only after the
  trusted `redteam-design-approval` marker exists. The marker is single-use; do not remove the stop
  label or post a generic Resume manually. CI suppresses Review Ready publication while the stop
  latch is present. If an older control run left only `ai-needs-review`, the approval workflow
  treats it as a stale UI projection and removes it in the authorized label transition; fix/pass/
  provider-gate projections remain conflicting and are rejected.
- Before Phase 4 or Phase 5: approve `automation/provider-gates.json` in a separate,
  human-reviewed `governance-change` PR, merge it to `main`, run **Advance AI Loop Phase**, then
  restart the local command. The approved phase is automated, but the gate itself is not.
- `ai-project-complete`: keep the runner active. It revalidates the configured final gate and
  reports `PROJECT_MERGED:<merge-sha>` only after GitHub confirms the exact-HEAD merge.

## Troubleshooting

- `required executable is not installed`: provision the supported local Codex CLI, `gh` and the
  repository `.venv` before starting. Do not substitute a Cloud task or disable sandbox checks.
- `gh login must exactly match ...`: reauthenticate as `AI_GATE_APPROVER_LOGIN`, or correct the
  repository variable through human governance.
- `local governance checkout must have a clean working tree`: commit/stash unrelated work and run
  from clean `main`. Do not discard user changes.
- `local governance checkout is not the current default-branch SHA`: run `git pull --ff-only`.
- Local worker unavailable: verify supported CLI/authentication and the launcher's isolation
  preflight. Do not print account credentials, enable arbitrary plugins/MCP, or fall back to Cloud.
- Local review remains pending: inspect the exact `redteam-local-review-start`, durable run state,
  reviewer process outcome and matching result. A missing result after crash/timeout is not PASS
  and is not permission to start another session for the same claim. Manually pasted model output
  and implementation-worker summaries are not review provenance.
- Implementation or push outcome unknown: reconcile the durable claimed request and exact output
  commit against the current PR before restarting. Do not delete claims, reset the branch or
  repeat a push/worker invocation merely because the previous acknowledgement was lost.
- Old Cloud request outstanding: stop cutover for that input and reconcile the previously sent
  task, its terminal outcome and any PR commit. Stopping a local runner does not cancel a Cloud
  task. Do not send another Cloud request or run local implementation against the same input while
  the old outcome is unknown.
- An audit-binding review finding must distinguish the implementation request's input HEAD from the
  ready marker's output HEAD and compare the marker against canonical JSON digest, not raw file
  bytes. CI already rejects a non-ancestor input, wrong request binding, wrong output HEAD, or wrong
  canonical digest; do not rewrite valid audit evidence to satisfy the opposite interpretation.
- `AI_LOOP=BLOCKED`: inspect the latest trusted bot marker and workflow run. Do not remove the stop
  latch, alter review evidence, or weaken CI to continue. A transient lifecycle projection mismatch
  should be reconciled by the trusted transition rather than treated as new authorization.
- `DESIGN_CHANGE_REQUIRED`: stop the runner. A base refresh may incorporate approved governance but
  cannot resume implementation. Confirm the latest recurrence gate, merged design commit, current
  PR HEAD/checks and single-use Design Approval marker before restarting.
- `waiting for trusted base-refresh transition`: inspect **Prepare AI Loop Base Refresh**. It must
  be dispatched by `AI_GATE_APPROVER_LOGIN` and bind the old PR HEAD, current `main`, prior PASS and
  current implementation request. Its token deliberately cannot change PR labels; the local runner
  restores a blocked stop latch only after consuming the trusted status.
- `waiting for refreshed PR head`: GitHub accepted or is processing the exact-HEAD branch update.
  A changed HEAD causes the request to fail closed; restart from current clean `main` and inspect
  the PR evidence rather than forcing an update.
- A stopped PR immediately reports `AI_LOOP=BLOCKED` after a later governance merge: verify the
  exact current-HEAD `redteam/base-refresh-applied/...` checkpoint, its immediate two-parent merge,
  and the matching `redteam/base-refresh/...` authorization on the previous HEAD. A missing
  checkpoint requires confirmation or governance repair, not a manual branch update.
- If a Design-Approved implementation output reports `base-refresh checkpoint requires one exact
  two-parent merge`, the runner is incorrectly applying refresh inheritance to a normal output
  commit. That commit should proceed to current-HEAD review, but it does not authorize Resume or a
  later refresh.
- Automatic final merge blocked: inspect the Phase 0A→5 PASS chain, latest
  `redteam/phase-review`, four Check Runs, stop labels, current `main` ancestry, the exact-HEAD
  attempt comment and `refs/redteam-final-merge-attempts/pr-<PR>-<HEAD>`. Do not retry an uncertain
  claim or merge response, and do not delete the claim, until the PR's live merged/open state and
  claim ownership have been explicitly reconciled.

## Adopt the implementation-strategy update (2026-09-06)

This update makes the development AI loop carry the approved reuse/replace/new strategy through
implementation requests, the existing invariant audit, CI and independent review. It does not
implement the product's AI runtime loop or authorize a stopped PR to resume.

1. Human-review the governance/design diff, including the protected normative AI companion and
   invariant-family review questions, and merge it through a `governance-change` PR. Do not place
   these protected-file edits directly on the implementation PR. Historical PR status in documents
   is not authority; re-query the exact Phase, full HEAD, latest blocking gate and current `main`.
2. For a Design Stop, use the existing authorized exact-HEAD base-refresh/checkpoint path to
   incorporate the approved governance/design revision. Keep the stop latch and Phase label;
   never use an ordinary branch update or generic Resume to bypass the stop.
3. Require current-HEAD checks and the dedicated single-use Design Approval bound to the blocking
   gate, incorporated design, current Phase/full HEAD and **current** invariant policy digest.
   This update changes that digest; do not copy a historical approval or manually edit a request.
4. The resulting trusted implementation request must contain
   `invariant_audit.implementation_strategy_version=1.0`. Only after those prerequisites are met,
   run the existing runner from a clean current-default-branch checkout as described above.
5. Inspect the output's `docs/review/<phase>-invariant-audit.json`: each strategy unit explains
   before → after, classification rationale, preserved tests and migration impact. Missing or
   stale records must fail CI, not be waived. Independent review must verify the actual diff.

For local governance validation, use the repository `.venv`, Git and Node.js on `PATH` (Node is
needed by existing and new JavaScript boundary tests; missing Node is an environment failure):

```bash
python -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers
python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py
python -m compileall -q automation scripts/ci
python scripts/ci/validate_automation.py
```

After an authorized implementation, run the complete Phase gate and the explicit
strategy requirement check with the current Phase substituted:

```bash
bash scripts/ci/run_phase_gate.sh <current-phase>
python scripts/ci/validate_invariant_audit.py --phase <current-phase> --require-implementation-strategy
```

The gate's `--if-present --historical-preflight` audit check can read an unchanged committed legacy
report during blocked governance refresh. It verifies the proper-ancestor report/input, unchanged
evidence/source and the original policy before applying that policy's stateful test requirement.
The result is `PREFLIGHT_ONLY`, never a PASS for new implementation or permission to resume.
The validator without this option remains current-policy strict. New-policy reports cannot omit
the strategy to use legacy validation; review-ready and review-gate checks require the new block.
Do not add unexecuted test modes to an old audit, waive checks, or issue Design Approval on failure.
No tests or skip rules are removed; the gate still runs every existing lint/type/test/coverage step.
See `docs/review/ai-loop-strategy-update.md` for this update's file-level changes and local results.

## Adopt local-only unattended execution

This governance change changes the development runner, not the application's AI runtime. Do not
resume product implementation as part of preparing or validating the control-plane change.

1. Stop old polling and identify every already-issued Cloud implementation/review request for the
   active Phase and full input HEAD. Reconcile its terminal state and any late output before a
   local worker can consume that same input. Preserve all records, retry consumption and findings;
   a label change, missing response or stopped polling process is not cancellation evidence.
2. Human-review and merge the protected launcher/workflow/schema/prompt/documentation changes
   through a `governance-change` PR. This is the initial trust-boundary approval, not a new human
   approval required at each ordinary implementation/review cycle.
3. Run deterministic governance tests, launcher isolation/failure/replay tests and the local
   environment preflight. Verify that workers cannot access GitHub credentials, write the parent
   journal or alter trusted governance; reviewer source and session/context remain separate.
   Never use live C2/MCP/target commands for this validation.
4. Incorporate the approved governance into the implementation PR only through its existing
   authorized refresh/checkpoint path. Re-query current Phase/full HEAD/request, adjacent base,
   current CI and any Design/Provider stop. A past approval for another input or policy does not
   authorize the refreshed input. Retain historical `codex-native-v1` gates as historical evidence.
5. Once cutover, isolation and authority are verified, start the same local runner command above
   from clean current `main`. Observe a claimed local implementation run, launcher-published normal
   output commit, CI, a distinct local review session and a trusted `local-review-v1` phase gate.
   No Cloud task, `@codex` comment or routine human review-approval step belongs in this sequence.

Cancel/timeout, sandbox/authentication failure, uncertain legacy task, duplicate run or unknown
publication/push requires reconciliation, not automatic retry or fallback. The existing five-cycle
and exact-finding limits, two-review family recurrence Design Stop, Provider Human Gates and exact-
SHA final-merge safeguards remain unchanged.

## CI/CD boundary

GitHub Actions invokes no AI model and uses no OpenAI API key. CI performs only deterministic
validation and trusted state transitions. It never connects to a real C2, MCP server or external
target and never deploys the application. Any later isolated-lab deployment needs a separately
reviewed design and explicit authorization.
