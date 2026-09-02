# AI Loop Governance Simplification

## Decision

Keep deterministic CI, exact-SHA review binding, Phase ordering, stop latches, Human Gates and the
single-use Design Approval. Remove transient lifecycle labels from action authorization and resolve
each action from current-HEAD trusted evidence with deterministic precedence.

## Current and simplified control model

| Concern | Previous control | Simplified control |
|---|---|---|
| Action selection | Trusted records plus `ai-needs-*` label timing | Current-HEAD trusted record only |
| CI success | Always creates Review Ready and `ai-needs-review` | Creates Review Ready only when not blocked |
| Design stop refresh | CI and approval workflows can create conflicting label states | CI records checks; Design Approval owns the resume projection |
| Lifecycle labels | Treated as authorization prerequisites | Reconstructable operator UI projection |
| Phase label | Mixed with lifecycle state | Retained only as exact Phase routing evidence |
| `ai-loop-blocked` | Stop label and general state field | Conservative stop latch removed only by a trusted transition |
| Delayed event or label | Stops the loop | Idempotently reconciled if authority is unchanged |
| Head, Gate, approval or ancestry drift | Stops the loop | Still stops the loop |

## Authority precedence

For one current Phase and full PR HEAD, the runner uses this order:

1. an incorporated recurrence Gate remains `DESIGN_CHANGE_REQUIRED` until its single-use Design
   Approval is consumed;
2. a trusted current-HEAD Implementation Request selects implementation;
3. otherwise, a trusted current-HEAD Review Ready record selects review;
4. otherwise, the runner waits without inventing authority from a label.

The implementation request wins over an older ready projection on the same HEAD. Process memory and
transient labels never select an action.

## Blocked CI and Design Approval

When `ai-loop-blocked` is present, CI still runs governance, tests and quality checks but does not
publish Review Ready, set `ai-needs-review`, or reset the phase-review status. This keeps deterministic
validation separate from the human design-resume transition.

For compatibility with a HEAD produced before this rule, Design Approval may observe
`ai-needs-review` together with the stop latch. It treats that label as a stale projection only after
it independently verifies the current default branch, PR HEAD, Phase, blocking Gate, adjacent PASS,
recurring family set, required checks, design reference and design-commit ancestry. The approved
transition then replaces all managed lifecycle projections with `ai-needs-implementation`.

`ai-needs-fix`, `ai-review-passed`, `ai-human-gate` and `ai-project-complete` remain conflicting at
this boundary and fail closed. The stop latch itself is never ignored or manually removed.

## Failure policy

Stop on:

- missing, stale, malformed or ambiguous trusted authority;
- PR HEAD, Phase, base, gate, design approval or ancestry drift;
- failed or non-unique required checks;
- missing stop latch at a Design Approval boundary;
- conflicting fix, pass, provider-gate or completion state.

Reconcile without a product-design stop on:

- delayed or residual `ai-needs-*` projection labels;
- duplicate processing of the same trusted request;
- local orchestrator restart;
- GitHub event ordering that does not change HEAD or authority.

## Current PR migration

PR #3 remains blocked at `91392eb375bd10d840cae542acf36d79a00a3f4f`. The failed Design Approval
run created no current-HEAD approval or implementation request. PR #31 merged the projection
simplification, then exposed one additional constraint: the original exact-HEAD refresh path could
not authorize a second governance advance after its first merge output. The follow-up rule records
one bot-authored, digest-bound `BASE_REFRESH_APPLIED` checkpoint on each new current HEAD after
verifying its immediate merge edge. Future decisions read only that current checkpoint rather than
reconstructing the full refresh history. After that rule is merged, PR #3's existing refresh is
certified once, then it can incorporate current `main` while retaining Phase 0C and the stop latch.
Current-HEAD checks run without producing Review Ready, then the existing PR #30 design commit and
recurrence Gate can be bound to one Design Approval and one implementation request.
