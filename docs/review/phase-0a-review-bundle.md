# Phase 0A Independent Review Bundle

## Review identity

| Item | Value |
| --- | --- |
| Git commit | `UNAVAILABLE` |
| Branch | `UNAVAILABLE` |
| Working tree | `UNAVAILABLE`; empty `.git` directory is not a repository |
| Filesystem snapshot | `sha256:3a7fae9806d473ca6e180fcf9e950df52f69d56f72e3fa5e46406a44132e2c9a` |
| Snapshot files | 77; `docs/review/**` and caches excluded |
| Review date | 2026-08-29 |
| Authoritative requirement | `SystemDesign.md` |

## Repository tree

```text
Red_Agent/
├── SystemDesign.md
├── README.md
├── pyproject.toml
├── requirements.lock
├── runtime.lock
├── docs/
│   ├── adr/0001-phase-0b-deferred-execution-decisions.md
│   ├── implementation-notes/phase-0a-open-issues.md
│   ├── phase-0a-implementation-report.md
│   └── review/{phase-0a-gate-review.md,phase-0a-traceability.json,phase-0a-review-bundle.md}
├── src/redteam_agent/
│   ├── canonical/{json.py,digest.py,models.py}
│   ├── context/{selector.py,authorization.py}
│   ├── executor/authorization_gate.py
│   ├── mission/validation.py
│   ├── models/{base.py,mission.py,goals.py,scope.py,context.py,tools.py,plans.py,policy.py,approval.py,capabilities.py,llm.py}
│   ├── policy/{scope.py,data_access.py,digests.py,plans.py,engine.py,approval.py}
│   ├── repositories/{base.py,mission.py,context.py,tools.py,capabilities.py,plans.py,policy.py,approval.py,llm.py}
│   ├── storage/{database.py,migrations.py}
│   ├── tools/{registry.py,target_extractors.py,capability_snapshots.py,availability.py}
│   ├── errors.py
│   ├── seeds.py
│   └── validation.py
└── tests/
    ├── unit/{test_canonical.py,test_mission_validation.py,test_scope.py}
    ├── integration/test_phase0a_flow.py
    └── security/{test_strict_boundaries.py,test_mission.py,test_context_authorization.py,
                  test_tool_registry_availability.py,test_snapshot_bindings.py,
                  test_policy_and_gate.py,test_remote_mcp_trust.py,test_ttl.py,
                  test_phase_boundary.py}
```

No `config/` or root `migrations/` directory exists. Migrations are Python constants in `storage/migrations.py`.

## Architecture summary

```text
ExecutionPlanProposal
  -> create_execution_plan
  -> PolicyEngine.authorize
       -> Snapshot revalidation
       -> trusted Tool resolve
       -> Target Extractor
       -> Target Normalizer
       -> Scope/Data/Risk/Approval
  -> PolicyDecision
  -> authorize_execution
       -> optional Approval predicate
  -> AuthorizationGateResult(dispatch_performed=False)

Context Index Metadata
  -> ContextSelector
  -> ContextAuthorizationService
  -> ContextDataAccessGrant
  -> ContextAccessGate
  -> ResourceBinding
```

The package contains no external dispatch. The architecture is recognizable, but the final Gate does not establish PolicyDecision provenance or re-derive target/risk/approval completeness.

## Phase 0A component list

Implemented:

- Strict Pydantic boundary base and immutable collections
- Canonical JSON/digest helpers
- Mission Root/Revision/State models and repositories
- Typed Scope and Data Access Policy
- Context metadata index, selector, authorization grant, access gate
- ToolRef, trusted registry, closed target extractor registry
- Capability snapshots and Tool Availability Resolver
- Proposal/Plan, proposal digest and authorization digest
- Policy Engine and immutable PolicyDecision
- ApprovalRequest/ApprovalRecord factories and repositories
- Authorization Gate with no dispatch
- SQLite migration/repository layer
- Mock/seed snapshots and tools

Intentionally not implemented in Phase 0A:

- LangGraph, real LLM/Pydantic AI/vLLM
- C2/MCP/Local execution adapters
- External execution state, streaming/quarantine/secure ingestion
- Secret value storage, real sandbox, approval UI
- Goal evaluator/agent loop/finalization

## DB schema summary

Verified application tables:

```text
missions, mission_revisions, mission_states,
context_resource_index, context_data_access_grants, data_access_grants,
tool_registry_revisions, available_tool_snapshots,
session_security_context_snapshots, adapter_capability_snapshots,
sandbox_capability_snapshots, remote_mcp_trust_snapshots,
execution_plan_proposals, execution_plans, policy_decisions,
approval_requests, approvals, llm_profiles, llm_capability_results,
audit_logs, schema_migrations
```

- `PRAGMA foreign_keys=ON`
- file-backed SQLite uses WAL
- Mission revision has `(mission_id, mission_revision)` primary key
- Context resource has `(mission_id, resource_id, resource_version)` unique key
- Audit log has `(mission_id, sequence_number)` unique key
- `data_access_grants.owner_id` has no parent Foreign Key
- Security artifact repositories generally do not recompute stored digest on first insert

## Important model summary

| Model | Purpose | Review note |
| --- | --- | --- |
| `StrictBoundaryModel` | unknown/coercion rejection | Correct config |
| `CanonicalJsonObject` | immutable JSON payload | Deep immutable; raw duplicate parser not wired |
| `MissionRevision` | immutable authorization config | Structural validation present |
| `MissionState` | lifecycle/OCC/epoch | Transition repository bypasses Mission validation |
| `ResourceBinding` | Resource ID/version/digest | Correct TOCTOU shape |
| `ContextDataAccessGrant` | Context authorization envelope | current policy/state not checked at use |
| `ToolDefinition` | trusted routing/risk/schema/capability metadata | Broad invariant set |
| `AvailableToolSnapshot` | planner-facing immutable candidates | Full digest bindings, store-time digest gap |
| `ExecutionPlanProposal` | LLM Proposal only | Injection schema correct |
| `ExecutionPlan` | application IDs/bindings | Proposal/snapshot bindings |
| `PolicyDecision` | immutable authorized intent | Public self-consistent object can bypass issuer |
| `ApprovalRequest` | Human presentation | Display fields not compared to Decision by Gate |
| `ApprovalRecord` | Human decision | Honest binding path works |

## Requirement status summary

| Status | Count |
| --- | ---: |
| PASS | 24 |
| PARTIAL | 19 |
| FAIL | 17 |
| NOT_TESTED | 3 |
| NOT_IMPLEMENTED | 2 |

Machine-readable detail: `docs/review/phase-0a-traceability.json`.

## Security invariant summary

| Invariant | Result |
| --- | --- |
| Unknown Proposal fields rejected | PASS |
| Python-side type coercion rejected | PASS |
| Tool Registry/Snapshot unknown Tool rejected | PASS |
| Standard IP/CIDR prohibited precedence | PASS |
| Port/protocol Scope enforced | **FAIL** |
| Execution Session ID is in Mission Session Scope | **FAIL** |
| Only Policy Engine can create executable ALLOW | **FAIL** |
| REQUIRE_APPROVAL cannot be reclassified | **FAIL** |
| Human sees exact authorized targets/risk/effect | **FAIL** |
| Invalid Mission cannot reach RUNNING | **FAIL** |
| Context Policy Version stale rejected | **FAIL** |
| Context Grant unusable outside RUNNING | **FAIL** |
| Stored Security Digest verified on insert | **FAIL** |
| Epoch mismatch at Execution Gate rejected | PASS |
| External dispatch absent | PASS |

Observed critical metrics:

```text
Scope False-Allow: 3
Approval Bypass/Integrity Bypass: 2
Unknown Field Acceptance: 0
Unauthorized Tool Acceptance: 0
Stale Authorization Acceptance: 2
Digest Mismatch Acceptance: 1
Policy Engine Bypass: 2
External Tool Dispatch: 0
```

Counts are distinct reproduced paths, not an exhaustive upper bound.

## Test commands and results

```text
python -m pytest tests/unit -q
23 passed

python -m pytest tests/integration -q
4 passed

python -m pytest tests/security -q
65 passed

python -m pytest -q
92 passed

python -m compileall -q src/redteam_agent
PASS

python -m ruff check .
NOT_TESTED: No module named ruff

python -m mypy src/redteam_agent
NOT_TESTED: No module named mypy

python -m coverage run --data-file=/tmp/phase0a.coverage -m pytest -q
NOT_TESTED: No module named coverage
```

Hypothesis is absent; no property-based tests were collected.

## Coverage summary

No coverage percentage is available because the `coverage` package is not installed. Test presence/count is not used as a substitute for coverage.

## Static analysis summary

- Python compile: PASS
- Ruff: NOT_TESTED
- mypy/pyright: NOT_TESTED
- Phase boundary AST test: PASS; no subprocess/socket/http client roots in production package
- SQL confinement test: PASS
- Project dependency pins: Pydantic 2.13.4, jsonschema 4.26.0, pytest 9.1.1
- Runtime: Python 3.14.6, SQLite 3.53.4
- Hypothesis/ruff/mypy/coverage are not pinned or installed

## Findings

### BLOCKER (6)

1. Scope port/protocol and execution-session False-Allow.
2. Self-consistent PolicyDecision bypasses Policy Engine, Scope target completeness, and Approval.
3. Mission Validation is not enforced by State Repository or Policy entry.
4. Context Gate accepts stale policy-version and non-RUNNING grants.
5. ApprovalRequest display is not fully bound to actual Decision intent.
6. Invalid Security Digest can be persisted on first insert.

### HIGH (7)

1. Current capability Source-of-Truth acquisition is caller-controlled/undefined.
2. Duplicate-key rejection is not connected to raw Pydantic ingress.
3. Repository full binding validation is incomplete.
4. Sandbox capability is not tied to Tool/Adapter runtime identity.
5. Mission Revision inherited lookup is ambiguous for composite keys.
6. Critical negative tests are missing and Implementation Report claims are contradicted.
7. No Git revision can be recorded.

### MEDIUM (5)

1. No Context Builder/mandatory context workflow integration yet.
2. Context Selector ignores candidate sessions and operational phase for relevance.
3. DataAccess child has no parent FK.
4. Property/lint/type/coverage evidence is unavailable.
5. Commit-after-exception/concurrency persistence tests are absent.

### LOW (1)

1. Repository layer is concretely coupled to SQLite and lacks portability protocols.

## Phase 0B recommendation

```text
PHASE 0B READINESS: NO-GO
```

Do not connect external execution while the Authorization Gate accepts forged Decisions and Policy Engine has concrete Scope False-Allow paths. Fix all BLOCKERs, add formal negative tests matching the review probes, restore Git revision traceability, then repeat this Gate Review.

## Files recommended for independent review

1. `src/redteam_agent/models/base.py` — strict boundary configuration.
2. `src/redteam_agent/canonical/json.py` — canonical rules and raw duplicate-key parsing.
3. `src/redteam_agent/canonical/digest.py` — digest conversion/verification and authenticity limitation.
4. `src/redteam_agent/models/mission.py` — Mission structural/version validation.
5. `src/redteam_agent/repositories/mission.py` — transition validation, OCC/epoch, composite lookup.
6. `src/redteam_agent/context/selector.py` — metadata-only selection and relevance.
7. `src/redteam_agent/context/authorization.py` — stale policy/state/resource/session checks.
8. `src/redteam_agent/models/context.py` — ResourceBinding and Grant envelope.
9. `src/redteam_agent/models/tools.py` — trusted Tool/Snapshot models.
10. `src/redteam_agent/tools/target_extractors.py` — closed extractors and target completeness.
11. `src/redteam_agent/policy/scope.py` — IP/CIDR/port/protocol/session evaluation.
12. `src/redteam_agent/tools/availability.py` — capability/session/sandbox/trust candidate resolution.
13. `src/redteam_agent/repositories/tools.py` — snapshot persistence integrity.
14. `src/redteam_agent/models/plans.py` — Proposal/Plan boundary.
15. `src/redteam_agent/policy/digests.py` — proposal vs authorization payload.
16. `src/redteam_agent/policy/engine.py` — complete authorization flow.
17. `src/redteam_agent/policy/approval.py` — Human presentation/decision factories.
18. `src/redteam_agent/executor/authorization_gate.py` — final provenance/scope/approval enforcement.
19. `tests/security/test_policy_and_gate.py` — critical negative-test gaps.
20. `tests/integration/test_phase0a_flow.py` — repository/order/source-of-truth integration.
