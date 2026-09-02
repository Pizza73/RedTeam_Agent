# Blocked Base Refresh Chain

## Problem

The Phase 0C Design Stop Gate reviewed `4e86a7e4f5a6578133cd3579fbb5a004ab5c80c3`.
One trusted refresh incorporated design PR #30 and produced
`91392eb375bd10d840cae542acf36d79a00a3f4f`. When governance PR #31 later advanced `main`, the
runner rejected another refresh because the Gate no longer directly reviewed the current HEAD.

## Previous and corrected behavior

| Concern | Previous behavior | Corrected behavior |
|---|---|---|
| First blocked refresh | Exact Gate HEAD and status authorize one update | Unchanged |
| Later governance merge | No trusted reauthorization path | Allowed only through the verified refresh chain |
| Current HEAD ancestry | Gate must equal current HEAD | Gate may precede current HEAD only through authorized merge edges |
| Edge evidence | Not evaluated after the first output | Two parents plus matching bot status are mandatory for every edge |
| Missing or ordinary commit | Falls through to generic blocked state | Fails closed as an invalid refresh chain |
| Resume authority | Not granted | Still not granted |

## Trusted edge

For each edge from the Gate HEAD to the current PR HEAD:

1. the output is a two-parent merge;
2. its first parent is the previous PR HEAD;
3. its second parent is the exact default-branch SHA named by the earlier authorization;
4. the first parent carries one matching `github-actions[bot]` status bound to the same Gate,
   Phase pair and second-parent SHA.

The walk follows only first parents and is bounded to 32 edges. A missing status, malformed trusted
status, non-merge commit, parent mismatch, ambiguous Design Stop Gate or depth overflow rejects the
chain. A valid chain permits the preparation workflow to create one new status on the exact current
HEAD for one expected-HEAD branch update. It never consumes the Design Approval or removes the stop
latch.

## Current migration

Read-only validation against PR #3 reconstructs the first edge from `91392eb375bd...` to the Gate
HEAD and selects the existing recurrence Gate as the next refresh authority. After this governance
change is merged, the normal runner can request the status for current `main`, perform the single
exact-HEAD update, wait for checks, and then stop for the dedicated Design Approval.
