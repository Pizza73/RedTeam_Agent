# Automatic Final Merge Governance Report

## Decision and scope

- Governance phase: approved automatic final merge control
- Trusted default-branch input SHA: `2f7c062153b27cd4b69a455d1ddc7c38cd99f555`
- User decision: include the final implementation PR merge in the automatic AI loop
- OpenAI API use: none
- Merge authority: local `gh` identity matching `AI_GATE_APPROVER_LOGIN`; never Codex or GitHub
  Actions
- Eligible PR: same-repository `ai-loop` PR at Phase 5 with `ai-project-complete` and
  `ai-review-passed`; a `governance-change` or stop-state label denies the operation

This is an explicit governance change to LOOP-012, the Project Complete acceptance criterion and
the Development Loop safety invariant. Phase 4/5 provider selection remains a Human Gate.
Governance PRs remain human-reviewed and are not eligible for automatic merge.

## Exact merge gate

The local orchestrator performs the following fail-closed checks before one merge request:

1. Reconstruct exactly one Phase 0A through Phase 5 PASS chain backward from the current PR HEAD,
   using each record's full `base_sha` as the previous record's required `reviewed_sha`.
2. Require every record to use the closed field set, `codex-native-v1`, the configured reviewer,
   the configured approver as recorder, all required checks as PASS, and permalinks on the same
   exact PR number.
3. Require the latest `redteam/phase-review` status on the current HEAD to be a workflow-bot
   success linked to the exact Phase 5 record.
4. Re-query the four current-HEAD Check Runs and require success.
5. Require current `main` to be an ancestor of the PR HEAD.
6. Re-read the live PR HEAD, labels and current default-branch SHA.
7. Re-query PR comments and persist one `redteam-final-merge-attempt` marker bound to PR, full HEAD,
   current `main`, the Phase 5 gate, final-merge policy digest and operator identity.
8. Call GitHub's merge endpoint once with `sha=<full-current-head>` and `merge_method=merge`.
9. Accept completion only when GitHub returns `merged: true` and a full merge commit SHA.

A conflict, drift, malformed/unknown/duplicate evidence, missing Phase, forged status, wrong PR
permalink, existing exact-HEAD attempt, unexpected response or unknown outcome stops without an
automatic retry. A normal restart cannot redispatch while the attempt marker exists; explicit live
GitHub outcome reconciliation is required.

## Independent review finding addressed

- Codex P1: `https://github.com/Pizza73/RedTeam_Agent/pull/9#discussion_r3889226470`
- Finding: a lost merge response could allow a restarted process to submit a second request
- Fix: persist the exact PR/HEAD attempt marker before dispatch and reject every recorded attempt
  until explicit reconciliation

## Modified files

- Governance sources: `AGENTS.md`, `docs/requirements.md`, `docs/acceptance-criteria.md`,
  `docs/safety-invariants.md`, `docs/implementation-status.md`, `docs/threat-model.md`
- Operator documentation: `docs/ai-development-loop.md`, `docs/ai-loop-runbook.md`
- Configuration: `automation/project-settings.yml`, `automation/final-merge-policy.json`,
  `automation/schemas/final-merge-policy.schema.json`
- Implementation: `automation/run_phase_loop.py`, `scripts/ci/validate_automation.py`
- Workflow text/labels: `.github/workflows/ai-loop-control.yml`,
  `.github/workflows/bootstrap-ai-loop.yml`, `.github/pull_request_template.md`
- Phase boundary: `prompts/phases/phase-5.md`
- Regression tests: `tests/unit/test_phase_loop.py`,
  `tests/unit/test_automation_validation.py`

## Regression coverage

Positive tests cover the exact eight-record Phase chain, trusted final status, durable attempt
record and one merge API call,
exact input HEAD and confirmed merge SHA. Negative and failure-path tests cover unknown fields,
broken chains, adjacent PR-number prefix confusion, untrusted status authors, stop labels,
`governance-change`, missing current-main ancestry, an unconfirmed merge result and restart after an
unknown outcome without a second dispatch.

## Validation results

- `.venv/bin/python -m pytest -q tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py --strict-markers`
  - PASS: 71 tests
- `REDTEAM_COVERAGE_FILE=/tmp/redteam-auto-merge-coverage .venv/bin/python -m coverage run --source=automation,src -m pytest -q tests --strict-markers`
  - PASS: 223 tests; total coverage 74%
- `.venv/bin/python -m ruff check automation/run_phase_loop.py scripts/ci/validate_automation.py tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py`
  - PASS
- `.venv/bin/python scripts/ci/validate_automation.py`
  - PASS: `AUTOMATION_VALIDATION=PASS`
- `.venv/bin/python -m compileall -q automation scripts/ci tests/unit/test_phase_loop.py tests/unit/test_automation_validation.py`
  - PASS
- `.venv/bin/python -m mypy automation/run_phase_loop.py scripts/ci/validate_automation.py`
  - BLOCKED by the existing environment dependency: `types-jsonschema` stubs are not installed;
    Mypy reports only the two `jsonschema` `import-untyped` errors
- Ruby YAML parse of all seven `.github/workflows/*.yml` files
  - PASS
- `git diff --check`
  - PASS
- `bash scripts/ci/run_phase_gate.sh phase-0a`
  - FAIL at repository-wide Ruff with the unchanged 88 Phase 0A implementation findings; the
    script does not reach its later steps

The application findings are outside this governance change. PR #3 contains the Phase 0A fixes
and must repeat the exact Phase 0A gate after incorporating this governance base.

## Remaining constraint

GitHub's merge endpoint binds the exact PR HEAD SHA but has no expected-base-SHA parameter. The
runner checks current `main` ancestry twice and stops when the local trusted default branch moves,
but the current private-repository plan provides neither server-enforced branch protection nor a
merge queue for the final base-branch race. This accepted residual is documented in the threat
model; direct and force pushes remain prohibited.
