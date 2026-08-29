# Phase 0B: Execution Safety

## Preconditions

- Latest Phase 0A Gate verdict is PASS for the current branch ancestry.
- Phase 0A zero metrics remain zero.

## Implement

- Execution state machine including `AUTHORIZED -> BLOCKED`
- Independent Result Ingestion state machine
- Idempotency key and one-decision/one-execution constraint
- ExecutionRecord and Executor
- `ExecutionAdapter` Protocol and Mock Adapter only
- RawResultSink, chunk streaming, metadata-only AdapterRawResult
- Application-owned result normalization
- Quarantine interface, receipt and recovery metadata
- Reconciliation, `OUTCOME_UNKNOWN`, crash recovery
- Explicit retry policy; no automatic retry for external side effects
- Authorization epoch/TTL/current-state pre-dispatch checks
- run_id/thread_id lifecycle and FINALIZING skeleton
- Approval execution predicate and graph/mission state mapping

## Test

- Crash before/after provider task ID and no duplicate dispatch
- Unknown/unsupported/uncertain reconcile results
- Pre-dispatch stale epoch/sandbox/TTL -> BLOCKED, no provider call/result
- Commit-after-success retry idempotency
- Raw streaming without full-memory buffering
- Result ingestion resume without action resubmit
- Approval missing/expired/replayed/mismatched
- Goal cannot directly transition to COMPLETED

Use only Mock Adapter. Do not connect to a real provider.
