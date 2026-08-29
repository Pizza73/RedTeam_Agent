# Phase 1: Agent Loop with Mocks

## Implement

- LangGraph as the only workflow engine
- Graph state/routing/checkpoint using repository IDs, not duplicated source-of-truth objects
- Mock Planner and Analyzer with strict typed boundaries
- Knowledge Base, provenance reducer, Context Index/Selector/Authorization/Builder
- Session Manager and Session Context Authorization
- Tool Availability calculation/persistence before Planner and revalidation after Planner
- Policy -> Executor -> secure ingestion -> Analyzer sequence
- Deterministic three-valued Goal Evaluator
- Indeterminate handler with bounded retry key
- FINALIZING workflow, FAILED state, pause/resume invalidation

## Required flow

```text
Session Refresh -> Context Select/Auth/Build -> Tool Snapshot -> Planner
-> Snapshot Revalidation -> Policy -> Executor/Mock Adapter
-> Quarantine/Secure Ingestion -> Analyzer -> Reducer
-> Session Refresh -> Goal -> Next/Indeterminate/FINALIZING
```

## Test

- Scope and availability violations never reach adapter
- Grantless/unauthorized context cannot enter Planner/Analyzer
- Candidate observations do not mutate runtime truth
- Persistence/restart/checkpoint consistency
- Goal achieved/not-achieved/indeterminate cases
- Bounded iteration and indeterminate retry
- FINALIZING reconciliation/audit and unresolved outcome handling

Use mocks only; no real LLM/C2/MCP/local attack execution.
