# Phase 0A Implementation Report

- Status: **PHASE 0A SECURITY FIX COMPLETE — independent re-gate pending**
- Date: 2026-08-29
- Authoritative specification: `SystemDesign.md` plus the accepted Phase 0A Gate fix requirements
- Test runtime: Python 3.14.6 / SQLite 3.53.4
- Test result: **135 passed, 0 failed**
- Detailed fix evidence: `docs/review/phase-0a-fix-report.md`

## Phase 0A Scope

Implemented scope:

```text
ExecutionPlanProposal
  -> strict/duplicate-aware validation
  -> application-owned ExecutionPlan
  -> current Runtime State resolution
  -> Tool / Target / Scope / Context resolution
  -> Policy Engine issuance
  -> ALLOW / REQUIRE_APPROVAL / DENY
  -> repository-backed Executor Authorization Gate
```

No external Tool Dispatch, ExecutionAdapter, LangGraph, vLLM/Pydantic AI connection, C2/MCP/Local Tool execution, Raw Result processing, payload, implant, exploit, or attack command is implemented.

## Implemented Components

| Component | Implementation | Security responsibility |
|---|---|---|
| Strict boundary / Canonical JSON | `models/base.py`, `validation.py`, `canonical/` | extra forbid, strict types, duplicate-key rejection, deterministic digest |
| Mission lifecycle | `mission/manager.py`, `mission/goal_registry.py`, `mission/authorization_registry.py` | validation before VALIDATED/RUNNING; goal/profile/authorization reference registries |
| Mission persistence | `repositories/mission.py` | Root/Revision/State separation, composite revision key, OCC, authorization epoch |
| Runtime Source of Truth | `models/runtime.py`, `repositories/runtime.py`, `authorization_runtime.py` | explicit current Policy/Registry/Capability/Snapshot selection and consistency |
| Typed Scope | `models/scope.py`, `policy/scope.py` | IPv4/IPv6/CIDR/port/protocol/Host/Session, Prohibited wins |
| Context authorization | `context/authorization.py`, `repositories/context.py` | application-issued Grant; current Mission/Policy/Session/Resource/Data Policy revalidation |
| Tool Registry / Extractors | `tools/registry.py`, `tools/target_extractors.py` | trusted ToolRef/Extractor only; no dynamic import |
| Availability | `tools/availability.py` | planning candidate calculation; Session/Adapter/Sandbox/Remote Trust compatibility |
| Policy issuance | `policy/engine.py`, `policy/issuance.py`, `repositories/policy.py` | PolicyEngine-only persisted Decision provenance |
| Approval | `models/approval.py`, `policy/approval.py`, `repositories/approval.py` | structured human presentation and Request/Record digest binding |
| Authorization Gate | `executor/authorization_gate.py` | ID-only trusted lookup, deterministic Decision/presentation re-evaluation, no dispatch |
| Repository integrity | `repositories/` | store/read digest, deterministic ID, row/envelope/child binding validation |
| SQLite migration | `storage/migrations.py` | Phase 0A schema v1 plus current authorization/provenance migration v2 |

## Source of Truth

| Data | Source of Truth |
|---|---|
| Mission identity | `missions` |
| Authorization configuration | immutable `mission_revisions` |
| Lifecycle/OCC/authorization epoch | `mission_states` |
| Current Policy | `policy_states` |
| Current authorization snapshot selection | `authorization_runtime_bindings` |
| Context metadata | `context_resource_index` |
| Context authorization | `context_data_access_grants` envelope |
| Tool metadata | `tool_registry_revisions` |
| Available tools | verified immutable `available_tool_snapshots` |
| Session/Adapter/Sandbox/Remote Trust evidence | corresponding capability snapshot tables |
| Proposal/Plan | `execution_plan_proposals`, `execution_plans` |
| Execution authorization | PolicyEngine-issued `policy_decisions` |
| Human presentation/decision | `approval_requests`, `approvals` |
| Agent profile | `llm_profiles`, `llm_capability_results` |

## DB Schema

```text
schema_migrations
missions
mission_revisions
mission_states
policy_states
authorization_runtime_bindings
context_resource_index
context_data_access_grants
data_access_grants
tool_registry_revisions
available_tool_snapshots
session_security_context_snapshots
adapter_capability_snapshots
sandbox_capability_snapshots
remote_mcp_trust_snapshots
execution_plan_proposals
execution_plans
policy_decisions
approval_requests
approvals
llm_profiles
llm_capability_results
audit_logs
```

Raw Secret、Raw stdout/stderr、Artifact Body、Quarantine dataを保存するPhase 0A Table/Columnはない。

## Security Controls

- Planner/Caller cannot authorize or inject a PolicyDecision object into the Gate.
- PolicyDecision is persisted only through the issuance service and is deterministically re-evaluated at use.
- Caller cannot remove targets, reduce risk, change approval requirement, or replace adapter metadata.
- Port/protocol restrictions and execution session scope are enforced end-to-end.
- Human approval is bound to structured Tool/Target/Arguments/Risk/Side Effect/Adapter presentation.
- Mission cannot enter RUNNING before profile, authorization reference, goal identifiers, scope, limits, and policy validation.
- Context Grant cannot survive Policy change, Mission pause/finalization, Epoch change, Session security change, Resource version/digest change, or TTL expiry.
- Bad digest/ID/binding cannot be inserted or returned by security artifact repositories.
- Explicit Runtime Binding, not timestamp recency, selects current capability state.
- Sandbox capability must match execution runtime, adapter, and execution location.
- Boundary and persisted JSON reject duplicate keys.
- Authorization Gate always returns `dispatch_performed=False`.

## Tests

```text
python -m pytest tests/unit -q        # 24 passed
python -m pytest tests/integration -q # 4 passed
python -m pytest tests/security -q    # 107 passed
python -m pytest -q                   # 135 passed
python -m compileall -q src/redteam_agent tests # PASS
```

Critical regression acceptance counts are all zero: Scope false-allow, Approval bypass, Policy bypass, stale authorization, digest mismatch, mission validation bypass, misleading approval presentation, and external dispatch.

## Known Limitations

- Git metadata has no commits and all repository files are untracked; revision traceability remains open.
- Ruff, mypy/pyright, coverage, and Hypothesis are not installed in the execution environment and were not reported as PASS.
- System-wide `pip check` is not clean because of unrelated preinstalled Kali packages; a project-only isolated environment check remains pending.
- Context Builder is Phase 1; external execution and result safety are Phase 0B/0C.
- PostgreSQL repository protocol and DB-level FK for polymorphic DataAccess child ownership remain follow-up items.

## Open ADRs

`docs/adr/0001-phase-0b-deferred-execution-decisions.md` remains unchanged. No Phase 0B decision was implemented during this fix.

## Acceptance Criteria

| Criterion | Status |
|---|---|
| All Unit/Integration/Security tests | PASS |
| Scope False-Allow | 0 |
| Approval / Policy bypass | 0 |
| Unknown Field acceptance | 0 |
| Stale authorization acceptance | 0 |
| Digest mismatch acceptance | 0 |
| Mission validation bypass | 0 |
| External Tool Dispatch | 0 |
| Attack logic | 0 |

```text
READY FOR PHASE 0A RE-GATE: YES
PHASE 0B IMPLEMENTATION: NOT STARTED
```
