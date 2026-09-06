# Phase 1: Agent Loop with Mocks

## Implement

- Implement `system-design-v1-r1` with normative `SystemDesign_AI_Control.md` AI-01 through AI-12 and AC-01 through AC-20; preserve earlier safety invariants and the formal Phase gate order
- LangGraph as the only workflow engine
- Graph state/routing/checkpoint using repository IDs, not duplicated source-of-truth objects
- Mock Planner and Analyzer with strict typed boundaries
- Knowledge Base, provenance reducer, Context Index/Selector/Authorization/Builder
- Session Manager and Session Context Authorization
- Tool Availability calculation/persistence before Planner and revalidation after Planner
- A strict `PlannerOutput` union of action proposal or bounded context request; a context request restarts the
  context pipeline without creating execution, policy or approval records
- Planner information environment with a current-bound `PlannerContextEnvelope`, deterministic bounded retrieval,
  typed non-authoritative hints, recent redacted execution summaries and versioned safe policy/failure feedback
- Application-owned `PlanThread` / `WorkingHypothesis` snapshots with OCC, provenance, limits and mission-revision /
  authorization-epoch invalidation; working state never becomes confirmed fact, goal evidence or authorization
- Canonical entity/alias resolution with strong-identifier-only automatic merge and explicit candidate/conflict plus append-only merge/split history
- Policy -> Executor -> secure ingestion -> Analyzer sequence
- Analyzer candidate evidence bound and revalidated against condition ID, evidence kind, canonical entity and current record revision
- Deterministic three-valued Goal Evaluator
- One common controller for goal evaluation, ready action candidates, source-read recovery, approval waits and finite reasoned pauses; goal unknown is not a global action denial
- Registered ActionContracts and bounded prerequisite search, with exact contract / execution-precondition digests revalidated by Policy and pre-dispatch; goal-evaluation references are audit-only, never a new authorization head
- Separate verified facts, published observations and hypotheses, each with current authorized reads; verification rules and source owners alone change confirmed facts, and predicted effects or LLM confidence never constitute proof
- Durable meaning-key information budgets, all-attempt LLM reservations, atomic hypothesis operations and once-per-logical-execution failure accounting; rewording, restart or pause/resume never replenishes consumption
- Coarse-grained graph nodes backed by composite application services, with separate retry boundaries for context,
  persistent commit, dispatch, collection, ingestion and reconciliation
- Supervised-autonomy intervention classes and safe notifications; acknowledgement, attention clearing and outcome review are not approval or resume authority
- FINALIZING workflow, FAILED state, pause/resume invalidation

## Required flow

```text
Current Mission / Security / Limits / Pending Execution -> Session Refresh -> Goal -> Common Controller
-> [Finalize / Recover Existing / Wait / Reasoned Pause | Registered Action Candidates]
-> Context Select/Auth/Build + Tool Snapshot + Candidate Projection -> Planner
-> [Context Request: bounded rebuild, no execution | Action: Snapshot + Prerequisites Revalidation -> Policy / Approval -> Pre-dispatch -> Executor/Mock Adapter]
-> Quarantine/Secure Ingestion -> Verified Source Updates + Analyzer Candidates -> Reducer
-> Current Mission / Session / Goal -> Common Controller
```

The compact flow is not a second priority table: follow the exact controller ordering in AI Control Section 6 / 9.
An analyzer failure cannot retract already verified source facts or cause an external action to be resubmitted.

## Test

- Scope and availability violations never reach adapter
- Grantless/unauthorized context cannot enter Planner/Analyzer
- Retrieval hints cannot express arbitrary SQL/path/full-text queries or expand scope/classification/TTL/tool
  availability; ranking/truncation is deterministic and system-owned count/token/request limits cannot be widened by Planner, caller or tool output
- Stale context envelopes are rejected before LLM invocation; envelope, feedback, phase and working state cannot authorize execution, approval or goal completion
- Recent summaries and feedback contain no raw error/output, secret, prohibited target or hidden tool identity, and denial feedback cannot override policy
- Plan-thread OCC conflicts, stale revision/epoch, invalid references and limits fail closed; hypotheses remain unconfirmed data
- Alias-only/fuzzy/conflicting entities do not auto-merge
- Wrong condition/evidence-kind/entity/revision bindings cannot satisfy a goal
- Operational phase and operator acknowledgement/outcome review do not alter policy, approval or resume authority
- Graph crash/retry tests keep context, transaction commit, dispatch, collection, ingestion and reconciliation budgets isolated and never replay external effects
- Candidate observations do not mutate runtime truth
- Persistence/restart/checkpoint consistency
- Goal achieved/not-achieved/indeterminate cases
- All AC-01 through AC-20 with independent fixture state / history oracles, positive, negative and failure paths; state-machine tests cover budget reservations, OCC, lifecycle and recovery
- Initial/resumed already-achieved goals dispatch nothing; unknown goals can use independently authorized preparation / observation; empty, cyclic or exhausted searches terminate with distinct reasons
- Verified versus unverified conflicts, confidence-only changes, authorized observation reads, stale prerequisites, obsolete mode/head schema replay, last-budget-slot races and analyzer failure after fact commit
- Bounded iteration, per-kind attempt budgets and meaning-key information limits without reset on pause/resume, new explanations or new proposal keys
- FINALIZING reconciliation/audit and unresolved outcome handling

Use mocks only; no real LLM/C2/MCP/local attack execution.
