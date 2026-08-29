# Phase 4: Approved C2 Adapter

## Human-gate preconditions

Stop with `BLOCKED` unless all are explicitly configured outside prompts and secrets:

- Approved C2 product and exact version
- Isolated lab endpoint and target scope
- Authentication method and Secret Reference mapping
- Egress/network allowlist
- Provider API capability matrix
- Authorization confirming no payload/implant generation is in scope

Read the approved non-secret metadata from `automation/provider-gates.json`. Never replace references there with credential values.

## Implement

- One provider-specific `ExecutionAdapter` behind the existing Protocol
- Session discovery/refresh and capability snapshot
- Submit, task status, result collection, cancel and reconcile
- Provider task identity and idempotency/deduplication mapping
- Chunked result collection into RawResultSink
- Timeout/crash/unknown-outcome mappings
- Contract tests and isolated integration harness

## Prohibited

- Payload or implant generation/distribution
- Persistence or destructive functionality
- Embedded credentials
- CI connection to real C2 or real targets
- Provider-specific branching in Planner, Analyzer, Policy or Executor core

All CI tests must use a test double or explicitly isolated disposable lab selected by human configuration outside default CI.
