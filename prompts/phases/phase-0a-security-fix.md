# Phase 0A Security Fix

## Scope

Fix Phase 0A only. Do not implement ExecutionAdapter dispatch, LangGraph, real LLM, C2 or MCP integration. The authorization gate must continue returning `dispatch_performed=False`.

## Required findings

### B-01: Concrete scope

- Carry endpoint `port` and normalized `protocol` through trusted extraction/normalization/evaluation.
- Enforce allowed and prohibited port/protocol rules; prohibited wins.
- Treat required-but-unextractable port/protocol as DENY.
- Authorize `session_id` against Mission SessionScope, current Session Security Context and eligible sessions.
- Missing SessionScope for a session-requiring action is DENY.

### B-02: PolicyDecision provenance and completeness

- Do not accept caller-created PolicyDecision objects at the execution gate.
- Load decisions from a trusted repository through a PolicyEngine-only issuance path.
- Reconstruct expected targets from Proposal using trusted extractor/normalizer and require exact set equality.
- Revalidate risk, side effect, approval, adapter, data access and target bindings.
- Preserve one Decision to one Execution.

### B-03: Mission lifecycle

- Make MissionManager the only production lifecycle entry point.
- Repository is a persistence primitive, not authorization authority.
- Only DRAFT can be initially created.
- Validate authorization reference, validity, scope, success conditions, limits, policies, profile/digest and goal identifiers before VALIDATED/RUNNING.
- Reject DRAFT -> RUNNING and unknown goal/privilege identifiers.

### B-04: Current context authorization

- Resolve Mission state/revision/epoch, policy version, session context and resource state from trusted repositories immediately before access.
- Reject non-RUNNING, expired, stale-policy, stale-epoch, stale-session, wrong-service, resource version/digest mismatch grants.

### B-05: Approval presentation

- Build structured ApprovalPresentation from trusted Decision/Plan/ToolDefinition.
- Bind tool, normalized targets, redacted arguments, risk, side effect and adapter.
- Bind ApprovalRecord to request ID, request digest and presentation digest.
- Rebuild and compare expected presentation at Gate.

### B-06/H-03: Repository integrity

- Recalculate expected digest and deterministic ID at write.
- Revalidate security-sensitive records at read.
- Reject corruption/mismatch with typed `DigestIntegrityError` or a more specific error.
- Cover Proposal, Plan, Context Grant, Tool/Session/Adapter/Sandbox/Remote snapshots, Decision, Approval Request/Record and profile/capability records.

## Required hardening

- H-01: `AuthorizationRuntimeContextResolver` obtains current trusted state.
- H-02: Common duplicate-aware strict JSON boundary parser; top-level and nested duplicate keys reject.
- H-04: Bind sandbox to sandbox_id/runtime_id/adapter_id/execution_location.
- H-05: Production revision lookup requires `mission_id + mission_revision`.
- H-06: Convert every prior negative probe into permanent regression tests.
- H-07: Preserve valid Git metadata; report commit and clean/dirty status.

## Required tests

- 443-only 443 ALLOW; port 22 DENY
- tcp-only tcp ALLOW; udp DENY; prohibited port DENY
- SessionScope present ALLOW; absent/prohibited/stale DENY
- Caller decision, changed REQUIRE_APPROVAL, omitted target, reduced risk reject
- Unregistered profile and DRAFT -> RUNNING reject
- Unknown AD privilege identifier reject
- Old policy, PAUSED, FINALIZING, old epoch/resource version/digest reject
- Approval target/risk/side-effect/presentation/request-record tamper reject
- Invalid first-insert and read-time corrupted security artifacts reject
- Top-level and nested duplicate JSON keys reject
- Unrelated sandbox cannot satisfy runtime
- Fresh DB and upgrade migration tests

## Output

Create/update `docs/review/phase-0a-fix-report.md` with B-01–B-06, H-01–H-07 mappings, changed files, migrations, regression tests, all commands/results, security metrics and remaining findings.

Stop with `Phase 0A Fixed`; do not start Phase 0B. The independent reviewer owns the Phase 0A Gate.
