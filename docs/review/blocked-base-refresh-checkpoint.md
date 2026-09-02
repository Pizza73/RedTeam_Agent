# Blocked Base Refresh Current-HEAD Checkpoint

## Problem

The Phase 0C Design Stop Gate reviewed `4e86a7e4f5a6578133cd3579fbb5a004ab5c80c3`.
One trusted refresh incorporated design PR #30 and produced
`91392eb375bd10d840cae542acf36d79a00a3f4f`. When governance PR #31 later advanced `main`, the
runner could not authorize another refresh because the Gate no longer directly reviewed the
current HEAD.

Walking every historical refresh edge would prove that ancestry, but it makes a current decision
depend on an ever-growing list of old records. The corrected model turns every completed refresh
into one certified current-state transition.

## Current-HEAD model

| Concern | Historical-chain model | Current-HEAD checkpoint model |
|---|---|---|
| Decision input | Gate-to-HEAD refresh history | One status on the exact current HEAD |
| Validation work | Proportional to refresh count | Constant: the immediate edge |
| Interrupted update | Discovered while walking history | Explicit `REFRESH_AWAITING_CONFIRMATION` |
| Later governance merge | Reconstruct every earlier edge | Inherit only from the current checkpoint |
| Resume authority | Not granted | Still not granted |

The preparation workflow still writes a one-use authorization on the old HEAD. The local
orchestrator performs the expected-HEAD branch update. It then invokes the confirmation mode of
**Prepare AI Loop Base Refresh**, which verifies:

1. the live PR HEAD equals the claimed new HEAD;
2. the new commit has exactly two parents;
3. its first parent is the claimed previous PR HEAD;
4. its second parent is the exact authorized default-branch SHA;
5. the previous HEAD has one matching `github-actions[bot]` authorization;
6. the blocking Gate, adjacent base PASS, Phase and stop latch remain valid; and
7. if this is not the first refresh from the Gate, the previous HEAD already has its own valid
   checkpoint.

On success it writes a `redteam/base-refresh-applied/<sha256>` commit status on the new current
HEAD. The digest binds `head_sha`, `previous_head_sha`, `target_base_sha`, the Phase pair and the
Gate permalink. GitHub Actions retains only `contents: read`, `pull-requests: read` and
`statuses: write`; it cannot update the branch or merge the PR.

## Fail-closed recovery

If the branch update succeeds but confirmation has not completed, the runner permits only the
workflow confirmation mode. It cannot issue Design Approval, Resume, implementation, review, or another
base refresh. Re-running confirmation is idempotent for the same exact transition.

A normal commit, wrong parent order, missing old-HEAD authorization, stale Gate, forged digest,
untrusted status author, or missing previous checkpoint rejects the transition. Historical statuses
remain available for audit, but ordinary action selection never walks them.

## PR #3 migration

PR #3's existing `91392eb375bd...` commit is the first transition from the recurrence Gate. The
workflow confirmation mode can seed its current-HEAD checkpoint by verifying the immediate parents and
the existing authorization on `4e86a7e4f5a6...`. Once certified, the runner can authorize one new
refresh to current `main`, certify its resulting HEAD, wait for deterministic checks, and stop for
the dedicated Design Approval.
