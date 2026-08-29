# AI Loop Runbook (No OpenAI API)

## What is automated

Start `automation/run_phase_loop.py` once for the long-lived implementation pull request. It then
repeats this sequence:

1. Read a SHA-bound implementation request created by `github-actions[bot]`.
2. Post an `@codex` implementation request as the ChatGPT-linked GitHub user.
3. Wait for Codex to push a normal PR commit and for all required CI checks to pass.
4. Post `@codex review` for that exact phase, head SHA and phase base SHA.
5. Validate the reviewer identity and the single machine-readable review marker.
6. Dispatch **Record AI Phase Review**, which independently revalidates the SHA, review and CI.
7. Request a bounded fix or continue with the next phase.

The process stops on a failure limit, `BLOCKED`, a runtime limit, the Phase 4/5 Human Gates, or
project completion. It never merges or deploys. Closing it with Ctrl-C only pauses local polling;
GitHub comments, labels and checks preserve the state for a later restart.

## One-time repository setup

1. Put the governance/bootstrap changes on a dedicated pull request created with only the
   `governance-change` label. Review and merge it manually before starting the loop. This first
   merge is not a Phase 0A PASS.
2. Reauthenticate GitHub CLI if necessary and confirm the active identity:

   ```bash
   gh auth login --hostname github.com
   gh auth status --hostname github.com
   gh api user --jq .login
   ```

3. In ChatGPT/Codex, connect that same GitHub account and authorize only this private repository.
   Enable Codex Code Review. The [official GitHub integration guide](https://learn.chatgpt.com/docs/third-party/github)
   documents `@codex review` and GitHub-comment task requests.
4. Set repository variables. Both actor values are exact, case-sensitive GitHub logins:

   ```bash
   gh variable set AI_GATE_APPROVER_LOGIN --body '<operator-login>'
   gh variable set AI_REVIEWER_LOGIN --body '<codex-review-login>'
   gh variable set AI_LOOP_MAX_ITERATIONS --body '5'
   ```

   `AI_GATE_APPROVER_LOGIN` must equal the account returned by `gh api user --jq .login`.
   `AI_REVIEWER_LOGIN` must equal the author shown on a real Codex PR review/comment; do not guess
   or use a display name.
5. Do not create an `OPENAI_API_KEY` secret. The local process uses the existing `gh` credential
   store and never passes its token to Codex.
6. Create the labels through the approved workflow:

   ```bash
   gh workflow run bootstrap-ai-loop.yml \
     --ref main \
     --raw-field confirmation=BOOTSTRAP_AI_LOOP
   ```

7. Set the GitHub Actions spending limit to zero if use beyond the included private-repository
   quota must be prevented.

## Repository control mode: manual merge

This private repository's current GitHub plan does not expose branch protection or repository
rulesets. Do not create an empty ruleset. The controls in this section are therefore mandatory
operator procedure, not server-enforced protection. This is an explicitly accepted residual risk
and is weaker than GitHub-enforced branch protection.

Neither GitHub Actions nor Codex may merge, push directly to `main`, force-push, delete `main`, or
receive a merge bypass. `CODEOWNERS` identifies the human reviewer but cannot require that review
on the current plan. Repository collaborators must make every change through a pull request.

Immediately before every governance or implementation merge, the human operator must:

1. Copy the pull request's current full 40-character head SHA and confirm it is still current.
2. Confirm an implementation PR has no governance-controlled paths. A PR that intentionally
   changes those paths must have only the `governance-change` control label, not `ai-loop`.
3. Confirm the following exact checks are successful for that head SHA:

- `tests (3.12)`
- `tests (3.14)`
- `quality`
- `governance-integrity`
- `redteam/phase-review`

4. For an implementation PR, confirm the Codex review and `redteam/phase-review` evidence refer to
   the same current head SHA. For a governance PR, confirm `redteam/phase-review` reports
   `not applicable: human-reviewed governance change` for that SHA and perform the owner review
   yourself; a governance PR does not receive an AI phase verdict.
5. Resolve all review conversations and inspect the complete final diff.
6. Add a PR comment recording the reviewed head SHA, the five successful checks, the applicable
   Codex-review permalink or governance-review status, and whether governance-controlled paths
   changed.
7. Merge through the GitHub pull request UI as the human operator. Never use a direct push,
   force-push, automated merge, or command-line bypass to update `main`.

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
SHA-bound trigger markers and does not intentionally request the same work twice.

## Human Gates and blocked runs

- `CHANGES_REQUESTED`: the runner automatically requests a same-phase fix. The third occurrence of
  one root-cause key or the fifth change cycle blocks the loop.
- CI failure: the runner consumes the bounded failure request and asks Codex for a same-phase fix;
  CI failure never counts as PASS.
- `BLOCKED`: resolve the recorded cause. For Phase 0A through Phase 3, run **Resume AI Loop** with
  the current HEAD SHA and a repository permalink documenting the resolution, then restart the
  local command.
- Before Phase 4 or Phase 5: approve `automation/provider-gates.json` in a separate,
  human-reviewed `governance-change` PR, merge it to `main`, run **Advance AI Loop Phase**, then
  restart the local command. The approved phase is automated, but the gate itself is not.
- `ai-project-complete`: inspect the complete diff and evidence, then merge manually if acceptable.

## Troubleshooting

- `required executable is not installed`: install `gh` or use the repository `.venv` command shown
  above.
- `gh login must exactly match ...`: reauthenticate as `AI_GATE_APPROVER_LOGIN`, or correct the
  repository variable through human governance.
- `local governance checkout must have a clean working tree`: commit/stash unrelated work and run
  from clean `main`. Do not discard user changes.
- `local governance checkout is not the current default-branch SHA`: run `git pull --ff-only`.
- No Codex response: verify the GitHub account is connected to ChatGPT/Codex, repository access is
  granted, and `AI_REVIEWER_LOGIN` matches the actual integration author.
- `AI_LOOP=BLOCKED`: inspect the latest trusted bot marker and workflow run. Do not bypass labels,
  alter review evidence, or weaken CI to continue.

## CI/CD boundary

GitHub Actions invokes no AI model and uses no OpenAI API key. CI performs only deterministic
validation and trusted state transitions. It never connects to a real C2, MCP server or external
target and never deploys the application. Any later isolated-lab deployment needs a separately
reviewed design and explicit authorization.
