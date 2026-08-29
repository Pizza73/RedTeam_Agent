# Phase 0A Implementation Gate Review

## 1. Executive Summary

**判定: NO-GO**

既存Test SuiteはUnit 23、Integration 4、Security 65、合計92件すべてPASSした。しかし、要件と実コードを突き合わせたReview用negative probeにより、既存Testが検出していない重大な受理経路を確認した。

- `NetworkScopeRule.ports/protocols`がPolicy評価に使われず、許可Port 443のMissionでPort 22が`ALLOW`となる。
- ToolがExecution Sessionを要求する場合、そのSessionがMissionのSession Scopeに存在しなくても`ALLOW`となる。
- GateはPolicy Engine発行証明を持たない自己整合`PolicyDecision`を受理する。`REQUIRE_APPROVAL -> ALLOW`およびScope外ProposalのTarget除去により`AUTHORIZED`となる。
- Mission Validation helperがState Repositoryへ統合されず、Profile未登録でも`DRAFT -> VALIDATED -> RUNNING`へ遷移できる。
- Context Access時にcurrent Policy VersionとMission Stateを検査せず、Stale Grantを受理する。
- Humanへ提示するApprovalRequestのTarget表示を改変して再Digestしても、元の実行Intentが`AUTHORIZED`となる。
- Snapshot Repositoryは新規IDの不正Digestを検証せず永続化する。

これらは、明示されたGO禁止条件であるScope False-Allow、Approval Bypass、Policy Engine Bypass、Stale Authorization Acceptance、Digest Mismatch Acceptanceに該当する。Phase 0Bへ進む前にAuthorization Kernelを修正し、negative regression testを追加して再Gate Reviewする必要がある。

## 2. Reviewed Git Revision

| 項目 | 値 |
| --- | --- |
| Git commit | `UNAVAILABLE` |
| Branch | `UNAVAILABLE` |
| Git status | `UNAVAILABLE` |
| 理由 | `.git`は存在するが空Directoryであり、`git rev-parse`と`git status`は`fatal: not a git repository` |
| 代替Review identity | `snapshot_sha256=3a7fae9806d473ca6e180fcf9e950df52f69d56f72e3fa5e46406a44132e2c9a` |
| Snapshot file count | 77 |
| Snapshot範囲 | `src/`, `tests/`, `docs/`、`SystemDesign.md`、`README.md`、`pyproject.toml`、lock files。`docs/review/**`とcacheを除外 |

Git revisionへ結び付けられないため、今回の結果は上記Filesystem Snapshotだけに適用される。

## 3. Working Tree Status

Git repository metadataがないため、tracked/modified/untrackedおよびWorking Tree clean/dirtyを判定できない。Review開始時のFilesystemには以下が存在した。

- Root: `README.md`, `SystemDesign.md`, `pyproject.toml`, `requirements.lock`, `runtime.lock`
- `src/redteam_agent`: 53 Python files
- `tests`: 15 Python files
- 既存docs: Implementation Report 1、Open Issues 1、ADR 1
- `config/`: なし
- Root-level `migrations/`: なし。Migration実体は`src/redteam_agent/storage/migrations.py`
- `.git`: 空Directory

本Reviewで意図的に生成した永続Fileは`docs/review/`配下の3文書だけである。Test実行により通常のpytest/Python cacheは更新され得る。

## 4. Review Scope

確認対象:

- `SystemDesign.md`のPhase 0A、Mission、Context、Tool、Scope、Policy、Approval、Storage、Testability要件
- `src/redteam_agent/**`全53 files
- `tests/unit`, `tests/integration`, `tests/security`全15 files
- SQLite migrationと全Repository
- `pyproject.toml`, `requirements.lock`, `runtime.lock`
- README、Phase 0A Implementation Report、Open Issues、ADR
- Alternate/bypass path search、import/static search、DB PRAGMA、Review専用negative probe

対象外:

- Phase 0B以降のExecutionAdapter、dispatch、quarantine、LangGraph、実LLM/C2/MCP
- Source/Test/Configuration/Migration/Requirementの修正

## 5. Requirement Traceability Matrix

完全なmachine-readable evidenceは[phase-0a-traceability.json](phase-0a-traceability.json)にある。以下のPASSは、Implementation Evidenceと今回実行済みTest Evidenceの双方が存在する項目だけである。

| ID | Requirement | Status | Implementation Evidence | Test Evidence | Notes |
| --- | --- | --- | --- | --- | --- |
| P0A-001 | Strict Boundary config | PASS | `models/base.py:6-15` | `test_strict_boundaries.py::test_execution_proposal_rejects_unknown_fields`, `::test_python_boundary_rejects_type_coercion` | extra forbid/strict |
| P0A-002 | Proposal injection拒否 | PASS | `models/plans.py::ExecutionPlanProposal` | 7-field parameterized test | Adapter/Risk/System IDを拒否 |
| P0A-003 | Nested boundary strictness | PARTIAL | Scope/Context/Tool/Policy/Approval models | Nested ToolRef testのみ | 全Nested Modelのnegative testなし |
| P0A-004 | Raw JSON duplicate key拒否 | FAIL | `canonical/json.py::canonical_loads`; boundary未接続 | Canonical unit testのみ | ProbeでPydantic JSON ingressが後勝ち受理 |
| P0A-005 | Deep immutable collection | PASS | `canonical/models.py::CanonicalJsonObject`、tuple/frozenset fields | `test_canonical_json_object_is_deeply_immutable` | 直接Nested mutationを防止 |
| P0A-006 | Mission Root/Revision/State分離 | PASS | `models/mission.py`, `repositories/mission.py`, migrations | DB schema + pause test | 3 tables/repositories |
| P0A-007 | RUNNING->PAUSED version semantics | PASS | `MissionStateRepository.transition` | `test_pause_changes_occ_and_epoch_but_not_revision` | 仕様どおり |
| P0A-008 | PAUSED->RUNNING epoch invalidation | PARTIAL | `repositories/mission.py:143-151` | Decision epoch replay testのみ | Resume遷移/全Artifact testなし |
| P0A-009 | 設定変更で新Mission Revision | PARTIAL | `MissionRevisionRepository.add` | `test_scope_change_creates_new_revision_without_mutating_old` | Managerによる強制なし |
| P0A-010 | Mission構造Validation | PARTIAL | `MissionRevision`, `Mission` validators | mission boundary tests | Epoch/TTL/Auth Ref等にtest gap |
| P0A-011 | Invalid MissionのVALIDATED/RUNNING拒否 | FAIL | validation helperとState repoが分離 | helper unit test | ProbeでProfile 0件のままRUNNING |
| P0A-012 | Unsupported Goal Identifier拒否 | FAIL | Goal identifier fieldsは自由文字列 | なし | Probeで未知Privilegeを受理 |
| P0A-013 | Agent Profile binding | PARTIAL | `validate_mission_for_state` | profile unit test | State/Policyの必須Gateではない |
| P0A-014 | Context Index metadata only | PASS | `ContextResourceIndexRecord.no_content_in_metadata` | body/secret rejection tests | 本文Fieldなし |
| P0A-015 | Deterministic Context Selector | PASS | `ContextSelector.select` | selector/integration tests | Index Repositoryのみ依存 |
| P0A-016 | Selector->Auth->Grant->Builder順序 | PARTIAL | Selector/Auth/AccessGate | integration + no-grant test | Context Builder/単一Workflowなし |
| P0A-017 | Resource ID/version/digest TOCTOU | PASS | `ResourceBinding`, `ContextAccessGate` | stale version test | latest暗黙readをGateで拒否 |
| P0A-018 | Context Grant binding completeness | PARTIAL | `ContextDataAccessGrant` fields | session/resource tests | Current policy version未検査 |
| P0A-019 | Planner/Analyzer identity分離 | PARTIAL | service identity Literal + compare | なし | Analyzer replay testなし |
| P0A-020 | SessionContextGrant enforcement | PASS | session digest and allowed IDs | session exclusion/stale tests | Security changeを拒否 |
| P0A-021 | Policy Version changeでGrant stale | FAIL | Gateにcurrent policy入力なし | なし | Probeで旧Grant access成功 |
| P0A-022 | 非RUNNING MissionでContext拒否 | FAIL | issuanceだけstate check | なし | FINALIZINGで旧Grant利用成功 |
| P0A-023 | DataAccessGrant非Bearer | PARTIAL | child persistence + Gate signature | bearer parameter absence test | Parent FKなし |
| P0A-024 | Trusted ToolRef/Registry | PASS | Tool models + registry builder | unknown tool/extractor tests | Global ID構造あり |
| P0A-025 | ToolDefinition invariants | PARTIAL | `definition_invariants` | timeout/remote trust一部 | Negative matrix不足 |
| P0A-026 | Trusted Target Extractor Registry | PASS | closed registry | unknown ID/no import API test | dynamic importなし |
| P0A-027 | Basic Scope normalization | PASS | TargetNormalizer/ScopeEvaluator | IPv4/v6/CIDR/Host/Session tests | 未実装Scopeを拒否 |
| P0A-028 | Prohibited wins | PASS | evaluator order | precedence/CIDR overlap tests | 実行済み |
| P0A-029 | Network port/protocol enforcement | FAIL | ModelにはField、Evaluatorは未使用 | なし | Port 22が443-only ScopeでALLOW |
| P0A-030 | Execution Session Scope enforcement | FAIL | eligible/gateがMission SessionScope未確認 | なし | SessionScopeなしでsession-1 ALLOW |
| P0A-031 | Availability != concrete auth | PASS | calculate API/compatibility | signature + target-independent snapshot tests | 具体IP入力なし |
| P0A-032 | Availability capability intersection | PARTIAL | adapter/sandbox/remote/session checks | adapter/remote tests | Session/Sandbox binding gap |
| P0A-033 | Sandbox-to-runtime binding | FAIL | any matching sandboxを採用 | なし | Tool/Adapterとの対応IDなし |
| P0A-034 | Snapshot full bindings | PASS | Snapshot model/revalidate | 4 digest change + telemetry tests | Required digest fieldsあり |
| P0A-035 | Canonical not_applicable Snapshot | PARTIAL | seed remote trust snapshot | remote digest test | 全call siteの専用invariantなし |
| P0A-036 | Calculate/Persist idempotency | PASS | resolver + snapshot repo | same input/same ID、same ID/diff payload | Commit-exception testなし |
| P0A-037 | Snapshot store-time digest verify | FAIL | Snapshot repoはpayload conflictのみ | conflict testのみ | Bad digest新IDを保存可能 |
| P0A-038 | Canonical JSON profile | PASS | canonical JSON/digest modules | key/finite/type/datetime tests | Boundary duplicate issueはP0A-004 |
| P0A-039 | Proposal Digest separation | PASS | `proposal_payload` | target order/argument order tests | Proposalだけをhash |
| P0A-040 | Authorization Digest completeness | PARTIAL | `authorization_intent_payload` | tamper test | Field単位inclusion testなし |
| P0A-041 | Policy Engine-only authorization | FAIL | Policy Engine + public Gate | missing-decision testのみ | Self-authored DecisionをGateが受理 |
| P0A-042 | Policy evaluation flow | PARTIAL | `PolicyEngine.authorize` call chain | normal/prohibited/unknown target tests | port/session False-Allow |
| P0A-043 | Registry/Snapshot外Tool拒否 | PASS | `_resolve_tool`, Gate | unknown tool test | Fail Closed |
| P0A-044 | Immutable PolicyDecision | PASS | frozen Decision + separate approvals | approval/integration tests | Decision自体は不変 |
| P0A-045 | ApprovalRequest display binding | FAIL | request factory + approval predicate | stale-digest testのみ | Misleading displayを再Digestすると通過 |
| P0A-046 | Approval executable predicate | FAIL | Gate branches | honest ALLOW/approval/reject/deny tests | Self-consistent ALLOWで承認回避 |
| P0A-047 | TTL invariants | PARTIAL | factories/repos/Gate | Decision/request/equality一部 | 全Artifact/Record境界不足 |
| P0A-048 | Gate complete revalidation | FAIL | `authorize_execution` | digest/epoch/snapshot tests | Target/risk/approval/provenance未再計算 |
| P0A-049 | External dispatchなし | PASS | Gate result false literal | phase boundary + gate tests | Network/process dependencyなし |
| P0A-050 | SQLite tables/FK/WAL | PASS | Database/migrations | schema/FK test + Review WAL probe | 21 app tables |
| P0A-051 | Repository/SQL confinement | PASS | repository layer | SQL confinement + integration | ServiceにSQL literalなし |
| P0A-052 | Store-time digest integrity | FAIL | multiple add methods lack verify | same-ID conflict testだけ | Invalid Snapshot digestを永続化 |
| P0A-053 | Child DataAccess atomicity | PARTIAL | Context/Policy transactions | grant idempotency/integration | polymorphic parent FKなし |
| P0A-054 | Current Source-of-Truth revalidation | FAIL | Plan/caller digestを使用 | changed input digest test | current snapshot取得経路なし |
| P0A-055 | Composite Mission Revision lookup | PARTIAL | `get_for_mission`あり | なし | inherited `get(revision)`が曖昧 |
| P0A-056 | Mock without production bypass | PARTIAL | production seed module | integration | RUNNING mockを直接生成可能 |
| P0A-057 | Negative security test completeness | FAIL | 92 tests | 92 PASS | Review probesが複数bypassを発見 |
| P0A-058 | Property-based tests | NOT_IMPLEMENTED | Hypothesis依存なし | なし | Scope/digest境界を未実施 |
| P0A-059 | Lint | NOT_TESTED | Ruff configあり | Ruff moduleなし | 実行不能 |
| P0A-060 | Type check | NOT_TESTED | mypy configあり | mypy/pyrightなし | 実行不能 |
| P0A-061 | Coverage | NOT_TESTED | testsあり | coverage moduleなし | 数値なし |
| P0A-062 | Dependency pinning | PARTIAL | exact main pins/lock | import version probe | Hypothesis/toolingなし |
| P0A-063 | Git revision traceability | NOT_IMPLEMENTED | empty `.git` | git commands failed | Snapshot digestで代替 |
| P0A-064 | No attack/dispatch code | PASS | executor/package search | phase boundary test | Phase 0A内 |
| P0A-065 | Implementation Report accuracy | FAIL | existing report | test rerun + Review probes | COMPLETE/zero-metric claimsを反証 |

Status集計:

| Status | 件数 |
| --- | ---: |
| PASS | 24 |
| PARTIAL | 19 |
| FAIL | 17 |
| NOT_TESTED | 3 |
| NOT_IMPLEMENTED | 2 |

## 6. Architecture Verification

実装されている主経路:

```text
ContextResourceIndexRepository
        -> ContextSelector
        -> ContextAuthorizationService.calculate
        -> ContextAuthorizationRepository.add
        -> ContextAccessGate

ExecutionPlanProposal
        -> create_execution_plan
        -> PolicyEngine.authorize
             -> Snapshot revalidation
             -> Tool resolve
             -> Target extraction
             -> Target normalization
             -> Scope/Data/Risk/Approval
        -> PolicyDecision
        -> authorize_execution
             -> Approval predicate
             -> AuthorizationGateResult(dispatch_performed=False)
```

基本責務分離はコード配置上は明確であり、Planner schemaにAdapter/Risk/Approvalは存在しない。一方、これらを必ず通るApplication Serviceがなく、GateがDecisionのPolicy Engine provenanceを検証しないため、責務分離がSecurity invariantとして完結していない。

## 7. Trust Boundary Review

### 確認できたControl

- `StrictBoundaryModel`: `ConfigDict(extra="forbid", strict=True)`。
- Listed boundary/nested modelsは原則`StrictImmutableBoundaryModel`を継承。
- Proposal injection 7種、Nested ToolRef、Python-side coercion、wire string integerのnegative testsはPASS。
- `CanonicalJsonObject`はdeep copyし、dict/listをimmutable internal representationへ変換。

### 残存問題

`canonical_loads()`はDuplicate Keyを拒否するが、`validate_boundary()`およびRepositoryの`model_validate_json()`はこれを使用しない。Review probe:

```text
raw JSON: objective="first", objective="second"
ExecutionPlanProposal.model_validate_json(...)
result: accepted, objective="second"
```

したがってCanonical parser単体testを、実際のTrust BoundaryがDuplicate Keyを拒否するEvidenceとして扱えない。

## 8. Mission Version Review

`mission_revision`、`mission_state_version`、`authorization_epoch`はModel/Table上分離され、RUNNING->PAUSED testはPASSした。PAUSED->RUNNINGもコード上epoch boundaryである。

ただしMission validationはstate transition前提として強制されない。

```text
Review probe:
DRAFT(v0, epoch0)
  -> MissionStateRepository.transition(... VALIDATED)
  -> MissionStateRepository.transition(... RUNNING)
registered llm_profiles: 0
result: both transitions succeeded
```

`MissionStateRepository.add()`は任意Lifecycle stateを初期投入できる。`PolicyEngine.authorize()`はcaller提供のflat `Mission(state="RUNNING")`を信頼し、Mission Repository/Profile Repositoryを参照しない。Integration testも`build_environment()`内でDecisionを先に作成してから、後でProfileを登録・validateしている。

さらにGoal固有identifier registry/validatorがなく、未知`ADPrincipalPrivilegeCondition.privilege_identifier`がMission validationを通過した。

## 9. Context Authorization Review

### 実装済み

- SelectorはIndex Metadata Repositoryだけを参照し、CandidateにはResourceBinding/分類等だけを返す。
- ResourceBindingはID/version/digestを持つ。
- Grantなし、未許可Resource、Resource update、Session security changeを拒否するTestsはPASS。
- Session IDはMission SessionScopeとexisting snapshotの積集合から発行。

### BLOCKER

`ContextDataAccessGrant.policy_version`は保存されるが、`ContextAccessGate.authorize_resource()`にcurrent policy version引数がなく比較されない。同じくGateはMission stateを確認しない。

Review probes:

```text
grant policy_version=policy-v1
current policy versionを渡すAPIなし
resource access: accepted

mission state=FINALIZING, epoch unchanged
old RUNNING grant resource access: accepted
```

Context Builder本体はPhase 1対象であるため未実装はPhase逸脱ではないが、現状のAccess Gateだけではstale policy/stateをFail Closedできない。

## 10. Tool Registry / Availability Review

### PASS部分

- Application stable `ToolRef(tool_id, registry_revision)`。
- Trusted Adapter type/id/provider metadata、schema、risk、approval、side effect、timeout/output、capability/sandbox fields。
- Registry builderはJSON SchemaとExtractor IDを確認。
- Extractor Registryは固定4 IDだけで、register/import/eval pathなし。
- Resolver APIは具体Targetを受け取らず、Adapter/Session/Sandbox/Remote Trust/Scope typeで候補化。
- Snapshotは全要求Digest/EpochへBindingし、Telemetry timestampをSession digestから除外。

### 問題

1. `eligible_session_ids`はSession status/OS/arch/capabilityを見るが、Missionの`SessionScopeRule`を見ない。Network toolがsessionを要求するケースで、Session Scopeなしでもsession-1が候補・Policy ALLOWとなった。
2. Sandboxは`any(meets(item) for item in sandboxes)`で評価され、Sandbox IDとTool/Adapter実行環境を結ぶFieldがない。別Runtime用Sandbox capabilityでToolをavailableにできる。
3. Policy EngineのSnapshot revalidationはcurrent capability repositoryではなく、Planへ複写済みのdigestを使用する。最終Gateも`current_*_digest: str`をcallerから受け、Source-of-Truth acquisitionを強制しない。

## 11. Scope / Policy Review

Standard IPv4/IPv6/CIDR/Host/SessionのNormalizer/EvaluatorとProhibited precedenceはTest済みである。一方、3つのFalse-Allowを再現した。

### Scope False-Allow A: Port/Protocol

`NetworkScopeRule`は`ports`と`protocols`を持つが、Target Extractor/Normalizer/EvaluatorはそれをNormalizedTargetへ反映・比較しない。

```text
Allowed Scope: 10.0.0.0/24, tcp/443
Proposal: target=10.0.0.10, port=22
PolicyDecision: ALLOW
NormalizedTarget.port: None
```

### Scope False-Allow B: Execution Session

```text
Mission allowed scope: Network only; SessionScopeRuleなし
Tool: requires_session=True
Proposal session_id: session-1
AvailableToolSnapshot eligible_session_ids: (session-1,)
PolicyDecision: ALLOW
```

### Scope False-Allow C / Policy Engine Bypass

GateはDecisionのTargetがProposalから抽出された完全な集合であることを再確認しない。

```text
Proposal target: 10.0.0.200 (prohibited)
Original PolicyDecision: DENY
Self-consistent replacement: decision=ALLOW, normalized_targets=()
authorization_digest/decision_digestを公開algorithmで再計算
Gate: AUTHORIZED
```

これはPolicy Engine以外がDecisionを発行できないという中核Trust Boundaryを破る。

## 12. Digest Review

### PASS部分

- Canonical APIはUTF-8、sorted keys、minimal separator、finite JSON only、UTC datetime、arbitrary object/bytes拒否。
- Enum/BaseModel/frozensetはdigest helperで明示変換。
- Proposal targets、normalized targets、data access entriesは呼出側でsort。
- Proposal digestとAuthorization digestは分離されている。
- GateはSnapshot/Decision/Approvalの保存Digest、Proposal/Authorization digestを使用前に再検証する。

### 問題

- Digestはunkeyed SHA-256であり、Integrityにはなるがissuer authenticityにはならない。GateはPolicyEngine-issuedかを証明できない。
- Repositoryは多くの初回insertでstored digestを再計算しない。Review probeでは`AvailableToolSnapshot(snapshot_digest="sha256:not-the-content-digest")`を新IDで保存・取得できた。
- Raw JSON duplicate key rejection pathがPydantic ingressとRepository readへ接続されない。
- Authorization digestの全Field inclusion/exclusionを固定する専用Testがない。

## 13. Approval Review

通常factory経路のALLOW、WAITING_APPROVAL、APPROVED、REJECTED、DENYおよびDecision immutable testはPASSした。

しかし次の2経路がある。

1. `REQUIRE_APPROVAL` Decisionを同じAuthorization Intentの`ALLOW`へ変更し、decision digestを再計算すると、Gateが承認なしで`AUTHORIZED`を返す。
2. ApprovalRequestの`normalized_targets=()`、summaryを`harmless.example`へ変更してrequest digestを再計算し、そのRequestへHuman APPROVED Recordを作ると、実際のDecision target 1件をGateが`AUTHORIZED`する。

`_approval_predicate()`はRequestのMission/Decision/Auth digest/ToolRef等を比較するが、Humanへ表示したnormalized targets、risk、side effect、display name/summaryがDecisionと一致することを検証しない。

## 14. Repository / DB Review

### Schema

次のapplication tablesを確認した。

```text
missions
mission_revisions
mission_states
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
schema_migrations
```

`PRAGMA foreign_keys=1`、file DB `journal_mode=wal`、Mission/Context/Audit等のunique constraintsを確認した。

### Repository findings

- SQL literalはRepository/Storage層に限定される。
- Context GrantとPolicy DecisionのDataAccess child insertはTransaction内。
- `data_access_grants`はpolymorphic ownerを持つがparent Foreign Keyがない。
- Available Tool/Capability/Context/Policy/Approval Repositoryの多くはstore-time digest verificationをしない。
- Approval RepositoryはID存在とTTLを検査するが、Request/Recordの全bindingを保存時に検証しない。
- `PlanProposalRepository.add()`はcaller提供proposal digestを再計算しない。
- `MissionRevisionRepository`には正しい`get_for_mission()`と、基底から継承した曖昧な`get(mission_revision)`が共存する。
- PostgreSQL用Repository Protocol/Unit of Work抽象はなく、SQLite connectionへ直接結合している。

## 15. Source Code Trace

### Context Flow

| Step | Source / Symbol | Input | Output / Check |
| --- | --- | --- | --- |
| 1. Metadata query | `repositories/context.py::ContextResourceIndexRepository.list_for_mission` | mission_id | Index records only |
| 2. Select | `context/selector.py::ContextSelector.select` | `ContextSelectionRequest` | sorted `CandidateContextResource` refs |
| 3. Authorize | `context/authorization.py::ContextAuthorizationService.calculate` | Mission, candidates, sessions, snapshot, policy/TTL | digested `ContextDataAccessGrant` |
| 4. Persist | `repositories/context.py::ContextAuthorizationRepository.add` | Grant | Envelope + child grants atomically |
| 5. Access check | `context/authorization.py::ContextAccessGate.authorize_resource` | Grant, Mission, service, Resource ID, Session snapshot, now | current `ResourceBinding` or exception |
| 6. Builder | **未実装（Phase 1）** | Authorized binding | — |

Security gap: Step 5にcurrent policy versionとMission RUNNING checkがない。単一Flow orchestratorもない。

### Execution Authorization Flow

| Step | Source / Symbol | Input | Output / Check |
| --- | --- | --- | --- |
| 1. Proposal | `models/plans.py::ExecutionPlanProposal` | LLM/external structured content | strict immutable proposal |
| 2. Plan creation | `policy/plans.py::create_execution_plan` | Mission, Proposal, Snapshot | Application-owned ID/bindings |
| 3. Snapshot revalidation | `policy/engine.py::PolicyEngine.authorize` lines 78-95 | Snapshot + plan-copied/current parameters | stale exception |
| 4. Tool resolve | `PolicyEngine._resolve_tool` | ToolRef, Registry, Snapshot | trusted ToolDefinition |
| 5. Extract | `tools/target_extractors.py::TrustedTargetExtractorRegistry.extract` | Proposal + trusted schema | TargetReference tuple |
| 6. Normalize | `policy/scope.py::TargetNormalizer.normalize` | TargetReference | NormalizedTarget |
| 7. Scope | `policy/scope.py::ScopeEvaluator.evaluate` | target + allowed/prohibited | allow/reason |
| 8. Data/Risk/Approval | `PolicyEngine._authorize_data_access/_effective_risk/_requires_approval` | trusted metadata | decision inputs |
| 9. Decision | `PolicyEngine.authorize` lines 123-174 | resolved intent | immutable digested PolicyDecision |
| 10. Gate | `executor/authorization_gate.py::authorize_execution` | Plan, Decision, Mission, Registry, Snapshot, approvals/current digests | typed Gate result; no dispatch |
| 11. Approval | `_approval_predicate` | Request/Record/Decision/Mission | authorized/denied/stale/invalid |

Security gap: Step 10 can be called with a PolicyDecision not issued/persisted by Step 9 and does not repeat extraction/completeness/risk/approval derivation.

## 16. Test Execution Results

実行Commandと結果:

```text
python -m pytest tests/unit -q
23 passed in 0.33s

python -m pytest tests/integration -q
4 passed in 0.37s

python -m pytest tests/security -q
65 passed in 0.59s

python -m pytest -q
92 passed in 0.61s

python -m pytest --collect-only -q
92 tests collected
```

既存Test PASSは事実だが、Review probeの失敗ケースがrepository testsに存在しないため、Phase 0A AcceptanceのSecurity metricsを証明しない。

### Review-only negative probes

Source/Test Fileは作成せず、インメモリDBとProduction APIを呼び出した。

| Probe | Result |
| --- | --- |
| ProfileなしMission state transition | VALIDATEDおよびRUNNINGに成功 |
| Unsupported AD privilege identifier | Mission validation accepted |
| REQUIRE_APPROVALを自己整合ALLOWへ置換 | Gate AUTHORIZED |
| Prohibited targetをDecision target listから除去 | Gate AUTHORIZED |
| Approval表示Targetを空へ変更 | APPROVED Recordとの組合せでGate AUTHORIZED |
| Context Grant policy version stale | Access accepted |
| FINALIZING Missionで旧Context Grant | Access accepted |
| Duplicate-key raw Proposal JSON | Accepted; last key won |
| 443-only Network Scopeでport 22 | Policy ALLOW |
| SessionScopeなしでexecution session-1 | Policy ALLOW |
| Invalid Snapshot digest first insert | Repository accepted |

## 17. Static Analysis / Coverage

| Check | Command | Result |
| --- | --- | --- |
| Python syntax/import compile | `python -m compileall -q src/redteam_agent` | PASS |
| Lint | `python -m ruff check .` | NOT_TESTED: `No module named ruff` |
| Type check | `python -m mypy src/redteam_agent` | NOT_TESTED: `No module named mypy`; pyrightもなし |
| Coverage | `python -m coverage run --data-file=/tmp/phase0a.coverage -m pytest -q` | NOT_TESTED: `No module named coverage` |
| Property tests | Hypothesis import/config/search | NOT_IMPLEMENTED |
| Dependency health | `python -m pip check` | FAIL for unrelated system-wide Kali packages; project-isolated environmentでないためGate evidenceには不採用 |

Runtime evidence:

```text
Python 3.14.6
SQLite 3.53.4
Pydantic 2.13.4
pytest 9.1.1
jsonschema 4.26.0
```

`pyproject.toml`はPython `>=3.12,<3.15`、Pydantic/jsonschema/pytestをexact pinする。LangGraph/vLLM/Pydantic AI/C2/MCP SDKはPhase 0A Runtimeへ導入されていない。一方、Hypothesis、ruff、mypy/pyright、coverageはdev dependency/lockにない。

## 18. Findings

### BLOCKER

#### B-01: Concrete Scope False-Allow（Port/ProtocolおよびExecution Session）

- Evidence: `policy/scope.py:79-102`はCIDRだけを比較しport/protocolを使用しない。`tools/availability.py:233-245`はMission SessionScopeを見ない。
- Reproduction: 443-only Scopeで22がALLOW。SessionScopeなしでsession-1がALLOW。
- Impact: Scope外ActionをPolicy Engine自身がALLOWする。
- Required before Phase 0B: Target extraction/normalizationにendpoint metadataを含め、PolicyとGateで完全性を検証する。Execution Sessionも具体Scope targetとして認可する。

#### B-02: Policy Engine / Approval / Scope Gate bypass

- Evidence: `authorize_execution()`は受け取ったDecisionのdigestと内部整合性を検査するだけでIssuer provenance、Target completeness、risk/approval derivationを再構築しない。
- Reproduction: `REQUIRE_APPROVAL -> ALLOW`で承認なしAUTHORIZED。Prohibited ProposalのDecision targetsを空にしてAUTHORIZED。
- Impact: Policy Engine-only Authorization、Default Deny、Approval predicateを同時に破る。
- Required: Gateがtrusted repositoryのPolicyEngine-issued Decisionを参照し、Decision identity/contentを再導出可能なbindingへ固定する。少なくともTarget completenessとapproval requirementをGateで再検証する。

#### B-03: Mission Validation bypass

- Evidence: `MissionStateRepository.transition()`は`validate_mission_for_state()`を呼ばない。`add()`はRUNNINGを直接保存できる。
- Reproduction: Profile 0件でDRAFT->VALIDATED->RUNNING。
- Impact: Authorization Reference/Profile/Goal/Scope validation前のMissionがPolicyへ到達する。
- Required: Mission Manager/validated transition transactionを唯一のstate entry pathとし、不正初期Stateとdirect transitionを拒否する。

#### B-04: Stale Context Authorization acceptance

- Evidence: `ContextAccessGate.authorize_resource()`にcurrent policy versionおよびRUNNING state checkがない。
- Reproduction: policy-v1 Grantをcurrent-policy不明のまま受理。FINALIZINGで利用成功。
- Impact: Policy invalidationやLifecycle終了後のKnowledge/Artifact access。
- Required: Current policy/version/state/revision/epochをSource of Truthからrevalidateし、negative testsを追加。

#### B-05: ApprovalRequest presentation binding failure

- Evidence: `_approval_predicate()`はrequest display targets/risk/side effect/summaryをDecisionと照合しない。
- Reproduction: target表示を空・harmlessへ変更したRequestに対するAPPROVEDで実TargetをAUTHORIZED。
- Impact: Humanは許可対象と異なる内容を承認し得る。
- Required: Application-generated immutable presentation payloadをDecision/authorization digestへ完全Bindingし、Gate/Repositoryで比較。

#### B-06: Digest mismatch persistence

- Evidence: `AvailableToolSnapshotRepository.add()`はstored digestを再計算しない。同様のpatternがcapability/context/policy/approval repositoriesにある。
- Reproduction: 新IDかつ不正Snapshot Digestを保存・取得。
- Impact: Source of Truthに不正Security Artifactが存在し得る。GO条件`Digest Mismatch Acceptance=0`を満たさない。
- Required: Store/read時のcanonical digest/ID/binding verificationとnegative tests。

### HIGH

#### H-01: Current capability/source-of-truth acquisitionが未定義

Policy EngineはPlan-copied digestsでSnapshotを再検証し、Gateはcaller-provided `current_*_digest`を信頼する。Capability repositoriesにcurrent/latest selection contractがなく、古いsnapshot一式を揃えたcaller replayを構造的に排除できない。

#### H-02: Duplicate-key rejectionが実Trust Boundaryへ未接続

Canonical unit APIだけが拒否し、Pydantic raw JSON ingressは後勝ち受理する。LLM/external wire parserをCanonical duplicate-aware parserへ固定する要件を満たさない。

#### H-03: Repository binding validationが不完全

Plan Proposal digestはcaller入力、Approval repositoriesはfull bindingを未検査、Policy/Capability/Context storesはfirst insert digestを未検査。Use-time Gateが一部を検査しても、DBのSource-of-Truth品質を保証しない。

#### H-04: Sandbox capabilityがTool/Adapter execution runtimeへ結合されない

複数Sandboxがある場合、無関係なSandbox capabilityでHigh-risk Toolがavailableになり得る。

#### H-05: Mission Revision public lookupの複合Key不整合

`MissionRevisionRepository.get_for_mission()`は正しいが、基底`get(revision)`も公開され、複数Missionの同revisionで曖昧。

#### H-06: Security Test Gateが既知のcritical negative casesを欠く

Port/protocol、Execution SessionScope、self-consistent Decision、Approval display、policy-version stale、store-time bad digest、Validation-before-transitionが未Test。既存Implementation Reportの`COMPLETE`とzero metric claimsは根拠不十分。

#### H-07: Git revisionを固定できない

空`.git`のためcommit/branch/statusが取得不能。Reproducibilityと独立再Reviewの同一性保証がFilesystem hashだけに限定される。

### MEDIUM

#### M-01: Context Builder/強制Workflow ServiceがPhase 0Aに存在しない

Phase 1対象のため実装欠如自体は範囲逸脱ではないが、Phase 0AでAccess Gateが実際のcontent repositoryの唯一入口であることをintegrationで証明できない。

#### M-02: Context Selector relevance入力の一部が未使用

`candidate_session_ids`と`operational_phase`をselectionへ使用せず、targetなしの場合にMissionの全confirmed/candidate metadataを候補化する。Authorizationは守られるがleast-context selectionが弱い。

#### M-03: DataAccess polymorphic childにDB parent FKがない

Repository経路はatomicだが、DB levelでorphan ownerを防止しない。

#### M-04: Tooling/Property/Coverage evidence不足

Hypothesis、ruff、mypy/pyright、coverage未導入。境界の探索的Testと静的品質Gateがない。

#### M-05: Persistence/concurrency negative tests不足

Commit成功後response exception、concurrent retry、Mission Revision check/insert race、Approval repository misbindingを検査していない。

### LOW

#### L-01: Repository portability/maintenance debt

Repositoriesはconcrete `sqlite3.Connection`へ直接依存し、PostgreSQL交換用Protocol/Unit of Workがない。Phase 0Aで直ちにSecurity bypassではないが移行コストが高い。

## 19. Severity Classification

| Severity | Count |
| --- | ---: |
| BLOCKER | 6 |
| HIGH | 7 |
| MEDIUM | 5 |
| LOW | 1 |

Critical Security Metrics（Reviewで再現したdistinct acceptance path数。網羅上限ではない）:

| Metric | Count | Evidence |
| --- | ---: | --- |
| Scope False-Allow | 3 | port restriction、execution session scope、forged Decision target omission |
| Approval Bypass/Integrity Bypass | 2 | forged ALLOW、misleading ApprovalRequest |
| Unknown Field Acceptance | 0 | 7 injection tests PASS |
| Unauthorized Tool Acceptance | 0 | unknown registry/snapshot Tool test PASS |
| Stale Authorization Acceptance | 2 | stale policy-version Grant、FINALIZING Grant |
| Digest Mismatch Acceptance | 1 | invalid Snapshot digest persistence |
| Policy Engine Bypass | 2 | forged ALLOW approval case、forged ALLOW scope case |
| External Tool Dispatch | 0 | AST/import search + tests |

## 20. Open ADRs

Existing ADR:

- `docs/adr/0001-phase-0b-deferred-execution-decisions.md`: ExecutionRequest digest、timeout/output limit、lifecycle、cancel、sync provider、RawResultSink、Quarantine、C2/MCP/vLLM versionsをPhase 0B以降へ保留。

Phase 0B着手前に追加/確定が必要なADR候補:

1. PolicyDecision issuer provenanceとGate verification model。
2. Network target endpoint（IP/CIDR/port/protocol）およびExecution Session scopeのcanonical target completeness。
3. Mission Managerを唯一のvalidation/state transition authorityにするtransaction boundary。
4. Current capability snapshot selectionとGate DI trust contract。
5. Store-time digest/ID verification policy。
6. Sandbox-to-Adapter/Tool runtime identity binding。
7. Wire JSON duplicate-key rejection entrypoint。

## 21. Phase 0B Readiness

```text
PHASE 0B READINESS:
NO-GO
```

GO禁止条件に該当するBLOCKERが6件ある。特に、Policy Engine自身のScope False-Allowと、Policy Engineを通さず自己整合DecisionをGateへ渡す経路は、Phase 0Bで外部Dispatchを接続すると直接の副作用リスクになる。

## 22. Final Recommendation

Phase 0Bを開始しないこと。次の順でPhase 0Aを修正し、全negative regression testsを追加して再Gate Reviewする。

1. Scope endpoint/session completenessをPolicy EngineとGateでEnforceする。
2. PolicyDecision issuer provenanceを確立し、GateのTarget/Risk/Approval derivation bypassを閉じる。
3. Mission validationとstate transitionを単一Mission Manager transactionへ統合する。
4. Context Gateへcurrent Policy/State Source-of-Truth revalidationを追加する。
5. Approval presentationの全FieldをDecision/Authorization IntentへBindingする。
6. 全Security Artifact Repositoryでstore/read digestとdeterministic IDを検証する。
7. current capability/sandbox runtime bindingを明確化する。
8. 今回のReview probesを正式なSecurity/Integration testsへ移し、lint/type/coverage/property gateを実行可能にする。
9. Git repositoryを初期化または正しいmetadataを復元し、修正版をcommitへ固定して再Reviewする。

## Files recommended for independent review

| Priority | Path | Important symbols | Reviewer focus |
| ---: | --- | --- | --- |
| 1 | `src/redteam_agent/models/base.py` | `StrictBoundaryModel`, `StrictImmutableBoundaryModel` | extra/strict/frozenの適用範囲 |
| 2 | `src/redteam_agent/canonical/json.py` | `canonicalize`, `canonical_loads` | Duplicate keys、number/datetime profile、ingress接続 |
| 3 | `src/redteam_agent/canonical/digest.py` | `sha256_digest`, `digest_model`, `verify_model_digest` | 自己Field除外、issuer authenticityとの違い |
| 4 | `src/redteam_agent/models/mission.py` | `MissionRevision`, `MissionState`, `Mission` | ValidationとVersion semantics |
| 5 | `src/redteam_agent/repositories/mission.py` | `MissionStateRepository.transition`, `MissionRevisionRepository` | Validation-before-transition、composite key、OCC/Epoch |
| 6 | `src/redteam_agent/context/selector.py` | `ContextSelector` | Metadata-only、relevance/least-context |
| 7 | `src/redteam_agent/context/authorization.py` | `ContextAuthorizationService`, `ContextAccessGate` | Policy/state/epoch/session/resource stale checks |
| 8 | `src/redteam_agent/models/context.py` | `ResourceBinding`, `DataAccessGrant`, `ContextDataAccessGrant` | TOCTOU、service/session binding |
| 9 | `src/redteam_agent/models/tools.py` | `ToolDefinition`, `AvailableToolSnapshot` | Registry invariants、sandbox/runtime identity |
| 10 | `src/redteam_agent/tools/target_extractors.py` | `TrustedTargetExtractorRegistry` | closed registry、target completeness |
| 11 | `src/redteam_agent/policy/scope.py` | `TargetNormalizer`, `ScopeEvaluator` | port/protocol/session、CIDR precedence |
| 12 | `src/redteam_agent/tools/availability.py` | `ToolAvailabilityResolver` | SessionScope、Sandbox binding、Snapshot inputs |
| 13 | `src/redteam_agent/repositories/tools.py` | `AvailableToolSnapshotRepository` | deterministic ID、store-time digest verification |
| 14 | `src/redteam_agent/models/plans.py` | `ExecutionPlanProposal`, `ExecutionPlan` | LLM vs application-owned fields |
| 15 | `src/redteam_agent/policy/digests.py` | proposal/authorization payloads | inclusion/exclusionとcanonical sorting |
| 16 | `src/redteam_agent/policy/engine.py` | `PolicyEngine.authorize` | End-to-end scope/data/risk/approval、current snapshot |
| 17 | `src/redteam_agent/policy/approval.py` | approval factories | presentation binding、TTL |
| 18 | `src/redteam_agent/executor/authorization_gate.py` | `authorize_execution`, `_approval_predicate` | issuer provenance、target completeness、approval bypass |
| 19 | `tests/security/test_policy_and_gate.py` | Gate/approval negative tests | Self-consistent forgeryとdisplay binding不足 |
| 20 | `tests/integration/test_phase0a_flow.py` | complete repository flow | Validation order、Source-of-Truth acquisition、no dispatch |
