# Blocked Phase Prior-Phase Revalidation Governance

> Superseded by `cumulative-phase-authority-governance.md`. Rolling an unchanged cumulative tree
> to its adjacent prior Phase was found to be semantically invalid once later-Phase code existed.
> This file is retained only as historical audit evidence.

## Problem

The active pull-request authority rule requires an adjacent prior-Phase PASS bound to the exact
input HEAD for Phase 0B and later. Existing base refresh is intentionally limited to the window
before current-Phase implementation and therefore rejects a blocked implementation HEAD whose
prior-Phase PASS belongs only to an ancestor. Manually changing Phase labels or updating the PR
branch would bypass the SHA-bound evidence chain.

## Approved change

`Revalidate Blocked AI Loop Prior Phase` adds a separate human-governed recovery path for automatic
Phases 0B through 3. It does not relax or modify the normal base-refresh checks.

The workflow requires and revalidates:

- the configured approver identity and literal `REVALIDATE_PRIOR_PHASE` confirmation;
- an open same-repository `ai-loop` PR with one exact blocked source-Phase label;
- the exact current 40-character HEAD and an unchanged default-branch SHA;
- an inline Codex P0/P1 finding whose original commit and formal review bind that HEAD;
- uniquely successful current-HEAD `tests (3.12)`, `tests (3.14)`, `quality`, and
  `governance-integrity` Check Runs;
- the trusted phase plan and exactly one adjacent prior Phase; and
- a complete repository phase gate for that adjacent prior Phase before any PR mutation.

The validation job has read-only GitHub permissions. The later publication job is the only job with
PR/status write permissions and never checks out or executes pull-request code.

After the gate passes, the workflow posts bot-authored implementation and review-ready markers for
the adjacent prior Phase at the same HEAD, marks `redteam/phase-review` pending, and atomically
replaces the control labels with the adjacent prior Phase and `ai-needs-review`. It re-reads the PR
immediately before and after the label write. The local orchestrator and existing independent review
path then produce the real prior-Phase PASS; no PASS is synthesized by this workflow.

## Boundaries

- No branch update, merge, force push, contents write, test weakening, or provider action is added.
- Phase 4 and Phase 5 remain excluded and continue to require their provider Human Gates.
- The normal base-refresh prior-PASS requirement remains unchanged.
- A failed gate or any identity, HEAD, label, finding, check, default-branch, or post-write drift
  stops without releasing the blocked Phase.

## Validation

Run the governance bootstrap checks used by CI:

```text
python -m compileall -q automation scripts/ci
python scripts/ci/validate_automation.py
python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py \
  tests/unit/test_governance_check.py tests/unit/test_phase_loop.py
python -m pytest -q tests/unit/test_automation_validation.py \
  tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers
```
