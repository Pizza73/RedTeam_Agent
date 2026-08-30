# Phase 5: Approved MCP Adapter

## Human-gate preconditions

Stop with `BLOCKED` unless all are explicitly configured:

- Approved MCP server and exact protocol revision
- Logical server identity and stable internal ID
- Transport identity policy: TLS/SPKI/mTLS or executable/config digest
- Execution-location classification: local_process/managed_remote/untrusted_remote
- Required enforcement capabilities and egress policy
- Approved tool definitions/registry revision

Read the approved non-secret metadata from `automation/provider-gates.json`. Never store tokens, passwords, private keys or other secret values there.

## Implement

- Discovery with exact revision pinning and capability negotiation
- Logical/transport identity verification and persisted snapshots
- Tool-list revision handling; notifications create candidates only
- Unique ToolRef/server/adapter routing
- Optional task extension only when native or verified custom support exists
- Submit/status/result/cancel/reconcile capability checks
- Timeout/unknown-outcome handling
- Remote trust policy and sandbox/enforcement availability integration
- Contract tests against an approved test server

## Prohibited

- Automatic tool registration/update
- Unknown revision auto-upgrade or legacy fallback
- Task API calls without advertised/verified capability
- High-risk untrusted-remote tool availability
- CI connection to an unapproved MCP server or target

## Final project evidence

After Phase 5 implementation, update README/runbook/config documentation and produce a final traceability report covering Phase 0A–5, all test/check results, remaining limitations and fresh-environment reproduction. Do not merge or deploy. The trusted local orchestrator alone performs the separately configured exact-SHA final merge after independent review and every deterministic gate passes.
