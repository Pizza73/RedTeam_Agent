# Phase 3: Human Approval and Durable Resume

## Implement

- LangGraph interrupt/resume around ApprovalRequest/ApprovalRecord
- Structured approval UI contract and authorization/presentation digest binding
- Approval expiration, rejection, replay prevention and one-execution constraint
- Authorization epoch invalidation on pause/resume/emergency stop
- Durable resume and reconciliation order: checkpoint -> application DB -> adapter
- State handling for unknown non-idempotent action outcome

## Test

- Plan/target/risk/side-effect/adapter/arguments changed after approval
- Wrong request/record/decision/execution binding
- Expired/rejected/replayed approval
- Resume with stale epoch/mission revision/checkpoint
- DB/checkpoint disagreement with DB as source of truth
- Unknown outcome never automatically redispatched

Use Mock Approval Service and Mock Adapter. Do not wait for or contact a real operator system in CI.
