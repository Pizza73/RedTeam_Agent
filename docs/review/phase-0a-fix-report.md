# Phase 0A Authorization Kernel Security Fix Report

## 1. Executive Summary

直前のPhase 0A Gate Reviewで検出されたBLOCKER B-01〜B-06およびHIGH H-01〜H-06を、Phase 0AのAuthorization Kernel内で修正した。外部Tool Dispatch、ExecutionAdapter、C2/MCP/Local Tool実行、LangGraph、LLM接続、Raw Result処理には進んでいない。

修正後は、Planner/CallerがPolicyDecisionをGateへObjectとして注入できず、Gateは永続化済みPlan ID / PolicyDecision IDからTrusted Repositoryを参照する。Mission、Policy、Registry、Session、Adapter、Sandbox、Remote Trust、Available Toolのcurrent値は、timestamp推測ではなく明示的な`AuthorizationRuntimeBinding`から取得する。GateはPolicy Engineの評価を同じTrusted Inputから再実行し、Target Set、Risk、Side Effect、Approval Requirement、Adapter、Data Accessを含むDecision完全性を比較する。

既存Testを削除せず、Gate ReviewのNegative Probeを正式なRegression Testへ追加した。2026-08-30の正式Phase GateではUnit 61、Integration 4、Security 109、合計174件がすべてPASSし、Ruff、Mypy、Coverage、Automation Validation、dependency checkもPASSした。

## 2. Fixed Findings

| Finding | Status | Fix | Source Evidence | Regression Test |
|---|---|---|---|---|
| B-01 | FIXED | IP/CIDR Targetへport/protocolを伝播し、Allowed/Prohibitedの両方でendpointを評価。Execution SessionをMission Session Scope、eligible session、current sessionへBinding | `models/scope.py::IpTargetReference/CidrTargetReference/NormalizedTarget`、`tools/target_extractors.py::_network`、`policy/scope.py::ScopeEvaluator`、`policy/engine.py::_validate_session`、`tools/availability.py::_session_in_scope` | `test_gate_review_regressions.py::test_network_endpoint_scope_is_enforced`、`test_prohibited_port_wins`、`test_execution_session_scope_present_allows_and_absent_removes_tool` |
| B-02 | FIXED | Gate APIをPlan ID / Decision ID参照へ変更。PolicyEngine issuance serviceとprovenance付きRepositoryを導入。Gateがcurrent trusted stateでDecisionを完全再評価 | `policy/issuance.py::PolicyDecisionIssuanceService`、`repositories/policy.py::PolicyDecisionRepository._store_issued/get`、`executor/authorization_gate.py::authorize_execution` | `test_policy_and_gate.py::test_gate_public_api_cannot_accept_policy_decision_object`、`test_gate_review_regressions.py::test_require_approval_cannot_be_rewritten_to_allow`、`test_decision_target_omission_is_rejected`、`test_out_of_scope_target_cannot_be_deleted_to_create_allow` |
| B-03 | FIXED | `MissionManager`をLifecycleの正規入口とし、DRAFT初期化、VALIDATED前/START前Validation、Profile/Authorization Reference/Goal Identifier RegistryをEnforce | `mission/manager.py::MissionManager`、`mission/goal_registry.py`、`mission/authorization_registry.py`、`repositories/mission.py::MissionStateRepository` | `test_mission.py::test_draft_cannot_start_and_unregistered_profile_cannot_validate`、`test_unknown_ad_privilege_identifier_is_rejected`、`test_unregistered_authorization_reference_cannot_validate` |
| B-04 | FIXED | Context Access時にGrant IDからRepository読出しし、Runtime Resolverからcurrent Mission/Revision/Epoch/Policy/Session/Resourceを再取得。RUNNING以外はFail Closed | `context/authorization.py::ContextAccessGate`、`ContextAuthorizationApplicationService`、`authorization_runtime.py` | `test_approval_and_context_regressions.py::test_old_policy_version_context_grant_is_rejected`、`test_changed_current_session_security_context_rejects_old_grant`、`test_context_authorization.py::test_context_grant_rejected_when_mission_not_running`、`test_old_epoch_context_grant_rejected_after_pause_resume` |
| B-05 | FIXED | Human表示をStructured `ApprovalPresentation`にし、canonical presentation digestをRequest/RecordへBinding。GateがPlan/Decision/ToolからExpected Presentationを再構築 | `models/approval.py::ApprovalPresentation`、`policy/approval.py::build_approval_presentation/ApprovalService`、`executor/authorization_gate.py` | `test_approval_and_context_regressions.py::test_misleading_approval_presentation_is_rejected`（target/arguments/risk/side_effect）、`test_wrong_approval_request_record_pair_is_rejected` |
| B-06 | FIXED | Security Artifactのstore/readでcanonical digest、deterministic ID、SQL row binding、parent/child bindingを再検証 | `repositories/base.py::parse_model_json/ImmutableJsonRepository`、`repositories/{capabilities,context,tools,plans,policy,approval,llm,runtime}.py` | `test_gate_review_regressions.py::test_security_repositories_reject_invalid_digest_on_first_insert_and_read`、`test_available_snapshot_read_revalidates_parent_capability_bindings`、`test_execution_plan_read_revalidates_persisted_proposal_binding`、`test_approval_and_context_regressions.py::test_context_grant_child_row_binding_is_verified_on_read`、`test_policy_decision_child_row_binding_is_verified_on_read` |
| H-01 | FIXED | current Snapshot選択を明示的なBinding Rowへ固定し、全SnapshotをRepositoryから解決。Available Toolはcurrent Capabilityから再計算し、Mission RevisionはRepositoryの最新Authorization Revisionとも一致確認 | `models/runtime.py`、`repositories/runtime.py`、`authorization_runtime.py::AuthorizationRuntimeContextResolver` | `test_snapshot_bindings.py::test_newer_snapshot_is_not_current_until_explicitly_bound`、`test_capability_binding_change_invalidates_snapshot`、`test_gate_review_regressions.py::test_old_runtime_binding_is_stale_after_new_mission_revision` |
| H-02 | FIXED | Raw JSONをduplicate-aware parserへ通してからPydantic JSON modeでstrict validation。Persisted JSONにも同じparserを適用 | `canonical/json.py::canonical_loads`、`validation.py::parse_boundary_json`、`repositories/base.py::parse_model_json` | `test_gate_review_regressions.py::test_duplicate_keys_rejected_at_boundary_top_level_and_nested` |
| H-03 | FIXED | Proposal digestをRepository側で計算。Plan/Snapshot/Decision/Grant/Approval/Capability/Profile/LLM Capability Resultのstore/read binding validationを追加 | `repositories/plans.py`、`repositories/tools.py`、`repositories/policy.py`、`repositories/context.py`、`repositories/approval.py`、`repositories/llm.py` | B-06のRepository Integrity tests、`test_llm_capability_result_enforces_profile_binding_on_store_and_read`、Integration flow |
| H-04 | FIXED | Tool/Adapter/Sandboxへexecution runtime IDを追加し、Sandboxをruntime ID、adapter ID、execution locationの完全一致で選択 | `models/tools.py::ToolDefinition.execution_runtime_id`、`models/capabilities.py::AdapterCapabilities/SandboxCapabilities`、`tools/availability.py::_sandbox_satisfies` | `test_gate_review_regressions.py::test_unrelated_sandbox_runtime_cannot_satisfy_tool` |
| H-05 | FIXED | Mission Revision public lookupを`get(mission_id, mission_revision)`の複合Keyへ統一 | `repositories/mission.py::MissionRevisionRepository.get` | `test_gate_review_regressions.py::test_mission_revision_repository_requires_composite_key` |
| H-06 | FIXED | Review-only probesを正式Security Regressionへ移し、既存Testを維持 | `tests/security/test_gate_review_regressions.py`、`test_approval_and_context_regressions.py`、更新済みMission/Context/Policy tests | Security 107 PASS |

H-07（Git Revision Traceability）は再修正済みである。独立レビュー入力はPR #3のcommit `fb3e2e8947e0402fa55ca1520ee71f9ad24367e3`、Phase baseは`2e50db4dbcc127d87237c212b909edb499c1bd34`、branchは`ai/redteam-agent-phase-loop`である。Codex reviewとP1 inline findingはいずれも同じinput review SHAへ固定された。P1修正後の新しいPR HEADは、このレポート内に自己参照SHAとして埋め込まず、GitHubのreview `commit_id`、PR head SHA、phase-review checkへ外部証跡として固定する。

## 3. Modified Files

### New implementation files

- `src/redteam_agent/authorization_runtime.py`
- `src/redteam_agent/json_schema.py`
- `src/redteam_agent/models/runtime.py`
- `src/redteam_agent/mission/manager.py`
- `src/redteam_agent/mission/goal_registry.py`
- `src/redteam_agent/mission/authorization_registry.py`
- `src/redteam_agent/policy/issuance.py`
- `src/redteam_agent/repositories/runtime.py`

### Updated implementation files

- Boundary/canonical/error: `validation.py`, `errors.py`, `repositories/base.py`
- Mission: `models/mission.py`, `mission/validation.py`, `mission/__init__.py`, `repositories/mission.py`
- Scope/tool/capability: `models/scope.py`, `models/tools.py`, `models/capabilities.py`, `tools/target_extractors.py`, `tools/availability.py`, `tools/capability_snapshots.py`
- Context: `context/authorization.py`, `context/__init__.py`, `repositories/context.py`
- Policy/Gate/Approval: `policy/engine.py`, `policy/approval.py`, `executor/authorization_gate.py`, `models/approval.py`, `repositories/policy.py`, `repositories/approval.py`
- Persistence: `repositories/plans.py`, `repositories/tools.py`, `repositories/capabilities.py`, `repositories/llm.py`, `repositories/__init__.py`, `storage/migrations.py`
- Seed: `seeds.py`

### New/updated tests

- New: `tests/security/test_gate_review_regressions.py`
- New: `tests/security/test_approval_and_context_regressions.py`
- New: `tests/security/test_review_evidence.py`
- Updated: integration flow、Mission、Context、Policy/Gate、Snapshot、Tool Availability、Remote MCP Trust、TTL、shared helpers

### Independent review remediation

- Updated: `docs/review/phase-0a-fix-report.md`
- Added: `tests/security/test_review_evidence.py`

## 4. Architecture Changes

### Mission lifecycle

```text
MissionManager
  -> registered Authorization Reference / Agent Profile / Goal Identifier validation
  -> MissionStateRepository._initialize_draft / _transition
```

RepositoryはPersistence Primitiveであり、`add(RUNNING)`またはpublic `transition()`を公開しない。RUNNING→PAUSEDとPAUSED→RUNNINGはそれぞれ`authorization_epoch`を増加させる。

### Current authorization state

```text
AuthorizationRuntimeBinding (explicit current IDs)
  -> Mission Revision / Mission State / Policy State
  -> Tool Registry / AvailableToolSnapshot
  -> Session / Adapter / Sandbox / Remote Trust snapshots
  -> Tool Availability recalculation
```

timestamp最大値はcurrent選択に使用しない。明示的Bindingとcurrent Capabilityからの再計算が一致しない場合はFail Closedする。

### Execution authorization

```text
Plan ID + PolicyDecision ID
  -> trusted repositories
  -> current runtime resolver
  -> PolicyEngine deterministic re-evaluation
  -> exact PolicyDecision comparison
  -> structured ApprovalPresentation comparison (if required)
  -> AUTHORIZED / DENIED / WAITING_APPROVAL / STALE / INVALID
```

Gateの引数に`ExecutionPlan`または`PolicyDecision` Objectを渡すpublic経路はない。GateにはProcess、Network、Adapter、Tool Dispatch機能が存在しない。

### Context authorization

```text
ContextAuthorizationApplicationService
  -> deterministic calculation
  -> provenance-controlled persistence

ContextAccessGate(grant_id)
  -> current runtime resolution
  -> RUNNING / Revision / Epoch / Policy / TTL / Service check
  -> current Session digest / Resource version+digest / current DataAccess Policy
```

## 5. DB Migration

Migration version 2を追加した。

- `policy_states`: Missionごとのcurrent Policy VersionとDigest
- `authorization_runtime_bindings`: Authorizationに使用するcurrent Snapshot ID群の明示的Binding
- `policy_decisions.issuer`: `policy_engine_v1` provenance。既存rowは`legacy_unverified`となりGate用Repositoryでは拒否
- `policy_decisions_one_per_plan`: 1 Planに対するDecisionの一意制約

Fresh databaseはMigration 1→2を適用する。既存Phase 0A v1 schemaからv2へのUpgradeは`test_existing_v1_database_is_upgraded_to_v2`でPASSした。Migration Historyは削除・書換えしていない。

## 6. Regression Tests Added

- Network: 443 allow / 22 deny、TCP allow / UDP deny、Prohibited Port wins
- Execution Session: SessionScopeありで候補/Policy対象、ScopeなしでPlanner候補から除外
- Policy provenance/completeness: caller Object APIなし、unissued ID拒否、REQUIRE_APPROVAL→ALLOW改変拒否、Target omission/Scope外Target削除拒否
- Mission: DRAFT→RUNNING拒否、Profile未登録/VALIDATED後Profile削除時のRUNNING拒否、Unknown AD privilege拒否、Authorization Reference未登録拒否、Pause/Resume epoch更新
- Context: stale Policy、non-RUNNING、Pause/Resume後のold Epoch、Session security change、Resource version/digest mismatch拒否
- Approval: Human表示Target/Redacted Arguments/Risk/Side Effect改変拒否、wrong Request/Record、old Epoch、Digest binding
- Repository: bad digest first insert、read-time corruption、Plan parent/Snapshot parent/DataAccess child/Capability/Profile/LLM Capability Result/Context/Decision/Approval integrity
- JSON: top-level/nested duplicate key拒否、UTF-8以外のbyte ingress拒否
- Sandbox: 別Runtime capability拒否
- Runtime current selection: newer timestamp snapshotを暗黙選択しない
- Migration: v1→v2 upgrade
- Revision evidence: Phase 0A reportのinput review SHA、phase base、reviewed branchを固定し、旧dirty-tree証跡の再混入を拒否

## 7. Existing Tests

旧TestのSecurity Controlを削除していない。APIがtrusted repository参照型へ変わった箇所は、同じ要件を新しい正規経路で検証するよう更新した。

## 8. New Test Results

実行日時: 2026-08-30 (Asia/Tokyo)

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/unit/test_canonical.py tests/unit/test_scope.py \
  tests/security/test_tool_registry_availability.py \
  tests/security/test_policy_and_gate.py \
  tests/security/test_approval_and_context_regressions.py \
  tests/security/test_strict_boundaries.py \
  tests/security/test_snapshot_bindings.py
75 passed in 1.55s

PATH=/home/kali/Red_Agent/.venv/bin:$PATH \
  bash scripts/ci/run_phase_gate.sh phase-0a
AUTOMATION_VALIDATION=PASS
Ruff: PASS
Mypy: Success: no issues found in 61 source files
Unit: 61 passed
Integration: 4 passed
Security: 109 passed
Full coverage run: 174 passed
Dependency check: No broken requirements found
PHASE_GATE=phase-0a PASS
```

最初のtargeted testは`pytest` console entry pointで起動したため、環境のpackage path差により3件のcollection errorとなった。Repository-local Pythonを明示する`python -m pytest`で同一対象を再実行し、75件PASSを確認した。Test failure、skip、expected failureへの変更はない。

Validated runtime:

```text
Python 3.14.6
SQLite 3.53.4
Pydantic 2.13.4
pytest 9.1.1
jsonschema 4.26.0
```

P1 remediation後の最初の同一Gate実行は、追加test fileのimport blockに対するRuff `I001`でFAILした。空行のみを修正後、同じ`bash scripts/ci/run_phase_gate.sh phase-0a`を再実行してPASSし、最終report更新後にも同じcommandを再実行して上記174件PASSを確認した。Security test、requirement、acceptance criterionの削除・緩和・skipはない。

## 9. Lint / Type / Coverage

| Check | Status | Notes |
|---|---|---|
| Syntax/import compile | PASS | `python -m compileall -q src/redteam_agent tests` |
| Ruff | PASS | `python -m ruff check .` |
| Mypy | PASS | strict設定で61 source files、0 issues |
| Coverage | PASS | branch coverage 84%（閾値80%） |
| Hypothesis | PASS | Phase Gateの必須dependency importとproperty testsを含むUnit SuiteがPASS |
| Dependency integrity | PASS | Repository-local `.venv`で`python -m pip check`: `No broken requirements found` |

## 10. Remaining Findings

- Gate Review M-01 Context BuilderはPhase 1対象のため未実装。
- M-02 Context Selectorのleast-context relevance強化は未実装。Authorization/Resource body isolationは維持。
- M-03 polymorphic `data_access_grants` parentのDB FKはSQLite schema上未追加。Repository envelope/child exact-matchとprovenance-controlled serviceでFail Closedする。
- M-05 concurrent commit-after-response retryの完全なfault injectionは未追加。Deterministic ID、unique constraint、idempotent immutable insertは維持。
- L-01 PostgreSQL用Protocol/Unit of Workは未実装。
- 独立reviewはinput SHA `fb3e2e8947e0402fa55ca1520ee71f9ad24367e3`へP1を1件記録した。このP1修正を含む新しいPR HEADに対する再reviewがPASSするまでは、SHA固定の独立Phase 0A PASSとして扱ってはならない。
- GitHub AI loopの標準Codex reviewは起動済みだが、reviewer loginとmachine-readable verdict形式を現在のfail-closed parserが受理できるかは未解決である。

上記にBLOCKER B-01〜B-06またはHIGH H-01〜H-06の未修正はない。

## 11. Security Metrics

正式Regression Suiteで確認した既知のacceptance path数:

| Metric | Count |
|---|---:|
| Scope False-Allow | 0 |
| Approval Bypass | 0 |
| Policy Engine Bypass | 0 |
| Unknown Field Acceptance | 0 |
| Unauthorized Tool Acceptance | 0 |
| Stale Grant Acceptance | 0 |
| Stale Snapshot Acceptance | 0 |
| Old Authorization Epoch Acceptance | 0 |
| Digest Mismatch Acceptance | 0 |
| Misleading Approval Presentation Acceptance | 0 |
| Mission Validation Bypass | 0 |
| External Tool Dispatch | 0 |

## 12. Open ADR

既存`docs/adr/0001-phase-0b-deferred-execution-decisions.md`を維持する。ExecutionRequest digest、timeout/output limit、Execution lifecycle、RawResultSink、Quarantine、実C2/MCP/LLM versionは本修正で確定または実装していない。

再Gate時には以下を重点確認する。

1. Python module privacy tokenは暗号署名ではないため、最終Security BoundaryはRepository provenanceだけでなくGateのdeterministic complete re-evaluationで成立していること。
2. Explicit Runtime Bindingの更新権限をApplication Service境界以外へ公開しないこと。
3. Phase 0BでExternal Dispatchを追加するときも、Gateが返す型付きResult以外をDispatch条件にしないこと。

## 13. Recommendation for Re-Gate

```text
PHASE 0A IMPLEMENTATION GATE: PASS
READY FOR SHA-BOUND INDEPENDENT PHASE 0A REVIEW: YES
```

B-01〜B-06とH-01〜H-07はSource Evidenceと実行済みRegression Testの両方を持つ。全既存/追加TestがPASSし、critical security metricの既知acceptanceは0、External Tool Dispatchは0である。Phase 0Bへは進まず、commit/push後の正確なPR HEAD SHAに対する独立Phase 0A Reviewを次に実施する。

## 14. Current Revision and Working-Tree Evidence

| Item | Value |
|---|---|
| Prior independent review identity | `snapshot_sha256=3a7fae9806d473ca6e180fcf9e950df52f69d56f72e3fa5e46406a44132e2c9a` |
| Input independent review SHA | `fb3e2e8947e0402fa55ca1520ee71f9ad24367e3` |
| Phase base SHA | `2e50db4dbcc127d87237c212b909edb499c1bd34` |
| Reviewed branch | `ai/redteam-agent-phase-loop` |
| Input review working tree | CLEAN (`git status --short --branch` showed only branch tracking state) |
| Input review diff from phase base | 63 files, 494 insertions, 310 deletions |
| Independent review evidence | GitHub review `id=5059475416`, `commit_id=fb3e2e8947e0402fa55ca1520ee71f9ad24367e3`, P1 inline finding `id=3887981472` |
| P1 remediation diff | This report plus `tests/security/test_review_evidence.py`; exact post-commit SHA is bound by PR/review metadata |
| Diff whitespace check | `git diff --check`: PASS |

今回のMypy closureで直接変更した実装は以下である。

- Canonical/typing: `canonical/models.py`, `canonical/digest.py`, `models/common.py`
- Scope/target/capability: `policy/scope.py`, `tools/target_extractors.py`, `tools/capability_snapshots.py`, `tools/availability.py`
- Trusted boundaries: `json_schema.py`, `tools/registry.py`, `policy/engine.py`, `policy/digests.py`
- Repository/provenance: `repositories/base.py`, `repositories/llm.py`, `repositories/context.py`
- Typed security states/seeds: `models/context.py`, `context/authorization.py`, `executor/authorization_gate.py`, `seeds.py`

No test was removed, weakened, skipped, or marked as an expected failure. No external dispatch, C2, MCP side effect, local attack command, or Phase 0B behavior was added. The P1 remediation must receive a new independent review on the resulting PR HEAD before Phase 0B starts.
