# Blocked Current-Phase Base Refresh Governance

> Supersession note: this record remains the authority for the exact-HEAD branch-update mechanism,
> but its post-refresh generic Resume rule does not apply to a later invariant-family recurrence
> stop. `docs/review/phase-0c-coherent-redesign.md` and LOOP-027 through LOOP-029 require the stop to
> remain in place until a current-HEAD, blocking-gate-bound Design Approval is issued.

## Finding

After the cumulative Phase recovery control was merged to `main`, the long-lived implementation PR
still carried the older `AGENTS.md` and implementation prompt. Codex correctly read the PR HEAD and
stopped because that older policy required the adjacent PASS on the exact current HEAD. A free-form
branch update would make the new rules visible but would bypass the repository's exact-SHA refresh
evidence.

## Correction

- Phase 0B through Phase 3 may request a current-Phase refresh only from an exact current-HEAD
  trusted `BLOCKED_LIMIT` gate.
- The preparation workflow validates the gate author, reviewer, recorder, check set, finding key,
  exact fields, and the one adjacent PASS referenced by its `base_sha`.
- The adjacent PASS must be incorporated in the blocked HEAD. The target must still be the current
  default-branch SHA and must contain at least one commit not in the PR HEAD.
- The status remains read-only evidence: the workflow has no contents write, label write, branch
  update, or merge permission.
- The local runner consumes the status, keeps the current Phase label, performs the existing
  expected-HEAD branch update, and verifies the old HEAD and target base are both ancestors of the
  resulting HEAD.
- An incorporated blocked refresh for a non-design stop can start only the existing
  approver-restricted bounded Resume, bound to the original gate permalink and only after
  current-HEAD deterministic checks pass. An invariant-family recurrence remains blocked and uses
  the dedicated Design Approval path.

## Non-goals

The change does not synthesize a PASS, reset iteration counters, authorize later-Phase code, weaken
the Phase gate, or add a GitHub Actions merge path. Any ambiguous gate, base PASS, status, ancestry,
label, check, HEAD, or default-branch state fails closed.
