# Phase 0A 開発記録 — Core Models / Authorization Kernel

本記録は正本 `SystemDesign.md` §40.1 が要求するPhaseごとの一つの開発記録である。
実装担当はClaude Code、独立レビューは実装セッションと分離したCodexが行う。
本記録の更新自体は実装着手・Phase受入完了・独立レビュー完了の証拠ではない。

## 1. 対象

| 項目 | 内容 |
| --- | --- |
| 設計Revision | `system-design-v1-r3` / `ai-control-v1-r3` |
| Phase | 0A: Core Models / Authorization Kernel |
| 入力コミット（完全ID） | `d78d089705104d5c10c5d364b3e0048c211d15b9`（`codex/phase-0a`、設計のみのbaseline） |
| 実装先 | Codexが用意した専用worktree `/tmp/redteam-phase0a`（ブランチ `codex/phase-0a`） |
| 実装対象コミット | **未確定（UNDETERMINED）**。本実装はまだコミットしていない。commit/push/mergeはCodex側が行う。 |
| 独立レビュー | **未実施（NOT PERFORMED）**。実装担当の自己確認を独立レビューとして扱わない。 |

ユーザー/Codex指示によりcommit/push/merge/branch切替/Git認証設定変更・isolation無効化は行わない。
成果物はworktreeの作業ツリーへ保存する。

### 実装範囲（§36 Phase 0A）

Strict Pydantic境界（`extra=forbid` / `strict=True` / frozen、nested duplicate JSON key / unknown field /
暗黙coercion拒否）、Mission と mission_revision / mission_state_version / authorization_epoch の分離、
Mission Managerだけによるlifecycle更新、Basic Typed Execution Scope（IP/CIDR・Host ID・Session ID を優先、
Port/Protocol・実行Session を含む具体Scope、その他はDefault Deny）、Data Access Policy（resource-pattern-v1）、
Secret Argument Path（RFC 6901 JSON Pointer）、ToolRef / ExecutionPlanProposal / ExecutionPlan、
ContextDataAccessGrant / SessionContextGrant / DataAccessGrant Model、Context Selector / Context Resource Index、
Tool Registry（Registry Revision / Digest / Validation）、Trusted Target Extractor Registry、
Tool Availability Resolver + AvailableToolSnapshot（Binding / Digest / Revalidation）、
session_security_context_digest / adapter_capabilities_digest / sandbox_capabilities_digest、
Policy Engine（Versioned Effective Risk / Global Approval Policy、Target Binding / TargetDispatchBinding、
PolicyDecision、Proposal Digest / Authorization Digest、Authorization TTL Invariants）、
ApprovalRequest / ApprovalRecord / ApprovalPresentation（完全一致Binding、Executable Predicate）、
Tool Availability と 具体Target Authorization の責務分離、Executor Authorization Gate（Adapter dispatchなし）、
Current Authorization Runtime Context、Source of Truth定義、SQLite Repository（write/read双方のIntegrity）、
Composition Root（Phase 0A Test Composition）。

### 範囲外（前倒ししない）

Phase 0Bの実行状態機械・Dispatch Claim・Secret Injection・実Adapter Dispatch、Phase 0CのProduction暗号 /
TPM / 消去、後続PhaseのAI旧Mode / GoalRouting、Payload/Implant生成・配布、実C2/MCP/Target接続。
Phase 0Aは**実外部Dispatchゼロ**。後続Phaseの依存境界は明示Test Double / Protocolで安全に分離し、
Production能力を偽らない。

## 2. 対応要件

### Common Gate（docs/acceptance-criteria.md）

Unit/Integration/Security PASS、ruff/mypy/compileall PASS、Branch Coverage取得、既存Test非削除、
未承認の設計・安全条件・受入条件変更なし、新規Security FindingにRegression Test、BLOCKER/HIGH 0件、
実C2/MCP/外部Target Side Effect 0件、Secret Leakage 0件、未解決仕様矛盾・仮実装・Security-critical TODOなし。
「対象実装コミット固定 + 独立レビュー完了」は Codex が別セッションで行うため本記録では **未確定 / 未実施** と明記する。

### Phase 0A Blockers / High / Zero metrics

| ID | 要件 | 実装Owner / 入口 |
| --- | --- | --- |
| B-01 | Port/Protocol と Execution Session を含む Concrete Scope False-Allow が0件 | `policy.scope_engine`、`policy.engine` |
| B-02 | Caller生成・改変PolicyDecision、Target omission、Approval bypass を拒否 | `executor.authorization_gate`、`approval.service` |
| B-03 | MissionManager以外から不正にVALIDATED/RUNNINGへ遷移できない | `mission.manager` |
| B-04 | Stale Policy/Mission State/Authorization Epoch/Session Context Grant を拒否 | `executor.authorization_gate`、`tools.availability` |
| B-05 | Approval Presentation と Executable Intent が完全一致 | `approval.presentation`、`approval.service` |
| B-06 | Security Artifact の Digest/ID/Binding を保存時・読出時に検証 | `storage.repositories`、`canonical.digest_service` |
| H-01 | Trusted Repository から Current Authorization Runtime Context を解決 | `runtime.authorization_context` |
| H-02 | Top-level/Nested duplicate JSON key を実Trust Boundaryで拒否 | `canonical.json_boundary` |
| H-03 | 全Security Artifact RepositoryでIntegrity検証 | `storage.repositories` |
| H-04 | Sandbox を実Runtime/Adapter/Execution LocationへBinding | `tools.availability`（Snapshot digest binding、実Adapter前倒しなし） |
| H-05 | Mission Revision lookup を `mission_id + mission_revision` へ固定 | `storage.repositories`、`mission.manager` |
| H-06 | Review Negative Probe を正式Regression Test へ追加 | `tests/security` |
| H-07 | Git commit/branch/status を取得可能にする | `devtools.git_state` |

Zero metrics: Scope False-Allow / Approval Bypass / Policy Engine Bypass / Unknown Field Acceptance /
Unauthorized Tool Acceptance / Stale Grant or Snapshot Acceptance / Old Authorization Epoch Acceptance /
Digest Mismatch Acceptance / Misleading Approval Presentation Acceptance / Mission Validation Bypass /
External Tool Dispatch = すべて0。各項目に対応するNegative/Failure試験を `tests/security` へ置く。

### 影響する安全不変条件（docs/safety-invariants.md）

Authorization（Planner非決定・Policy Engineのみ認可・Caller非発行・Default Deny・完全一致Gate・1 Decision→1 Execution・
`AUTHORIZED`は候補状態）、Mission and context（Mission Managerが唯一の入口・revision/state_version/epoch非代用・
PAUSE境界の一括失効・非RUNNINGのGrant拒否・Selectorはindexのみ）、Approval（提示とIntentの完全Binding・
free-textは根拠でない）、Integrity（write/read双方Digest・Duplicate key/unknown field/coercion拒否）。

## 3. 実施済み環境確認

| コマンド / 事項 | 結果 |
| --- | --- |
| `python3 --version` | Python 3.14.6（system） |
| `.venv` 作成 | worktree内にプロジェクト仮想環境を作成（system Python・global設定は変更しない） |
| 依存導入 | `.venv` へ pydantic 2.12.4 / pytest 8.4.2 / hypothesis 6.140.3 / coverage 7.11.0 / ruff 0.14.5 / mypy 1.18.2 を固定導入 |
| 依存Lock | `requirements.lock`（`.venv/bin/python -m pip freeze`、18 entries）を生成 |
| ライブラリ契約確認 | `scripts/verify_pydantic_contract.py` を仮想環境Pythonで実行し exit 0 |

確認結果: Pydantic strict は `"3"->3` / `True->1` / `3.0->3`（int）を拒否、`extra="forbid"` は未知Fieldを拒否、
frozen は変更で `ValidationError`。標準 `json.loads` は重複キーを最後値で吸収するため、Trust Boundaryでは
`object_pairs_hook` による重複キー拒否が必須であることを確認（H-02の根拠）。

## 4. 試験結果

対象コミット: **未確定**（未コミットの作業ツリー。Codexが後で実装コミットを固定する）。
実行環境: worktree `/tmp/redteam-phase0a`、`.venv`（Python 3.14.6）。全て仮想環境Pythonで実行。

| コマンド | 結果 |
| --- | --- |
| `.venv/bin/ruff check src tests scripts` | All checks passed |
| `.venv/bin/mypy`（package=redteam_agent, strict） | Success: no issues found in 75 source files |
| `.venv/bin/python -m compileall -q src` | 成功（exit 0） |
| `.venv/bin/python -m pytest`（Unit/Integration/Security/Property-StateMachine） | 177 passed, 1 warning |
| `.venv/bin/python -m coverage run --branch -m pytest` + `coverage report` | Branch coverage TOTAL 85%（取得済み） |
| `scripts/verify_pydantic_contract.py` / `scripts/verify_wire_and_immutable.py` | いずれも exit 0（strict/coercion/frozen/重複キー/wire/deep-immutable 契約を確認） |

試験の構成:
- Unit: canonical/digest（field-set固定含む）、json boundary（H-02重複キー・G例外非漏洩）、scope engine（B-01, IPv4-mapped対称正規化, property-based no-false-allow）、data access、secret path、risk policy、tool registry（+action contract binding）、target extractors（B-02隠しdestination）、immutable（deep）、success conditions、sandbox binding（H-04）、availability、mission validation、ttl/normalizer、git state（H-07）。
- Integration: 認可フロー（ALLOW/REQUIRE_APPROVAL）、mission manager（B-03 lifecycle/OCC/epoch/atomic audit）、repository integrity（B-06/H-03/row-key/model_construct/dup-key）、authorization context（H-01）、context authorization grant（B-04 stale）、mission state machine（Property/State-machine）。
- Security: forged writes（owner guard: 偽造decision/record/state/requestのraw save拒否, 未認証/未assign approver拒否）、gate negative（stale epoch/mission非RUNNING/window/decision expired/plan改変多数/approval bypass/RBAC revoked）、zero metrics（scope false-allow, prohibited full-path, unauthorized tool, secret未確認/確定SoT binding, misleading presentation）。

既知の警告: `test_model_construct_bypass_rejected_on_write` は不正型のserialize時にpydanticのUserWarningを1件出す（意図的な`model_construct`迂回を保存前に拒否することの確認）。テスト失敗ではない。

未実行/未達: 実LLM品質Gate（Phase 2）、TPM/`swtpm`統合（Phase 0C）、実Adapter Contract/Integration（Phase 4/5）、D4実機Qualification（`NOT_EVALUATED`）は本Phase対象外で未実施。

## 5. 独立レビュー

**未実施。** Codexが実装会話を引き継がない別セッションで、固定した実装コミットのRead-only Snapshot・
実コード・試験Evidenceを独立に照合する。実装担当の要約・モデルのPASS文字列・終了コード0を受入根拠にしない。
本依頼中にCodexから受けた開始前確認（A–G および追加の所有書込/契約/条件validation）への対応は
実装改善であり、正式な独立レビューPASSではない。

## 6. 受入と残課題

- Phase受入は**未成立**。本記録に受入完了・Phase PASSを記載しない。実装コミット固定と独立レビューは未完了。
- 実施した主な安全強化（レビュー指摘対応）:
  - Executor Gateは公開入口で `decision_id + plan` だけを受け、Trusted Clock と `AuthorizationContextResolver` から
    Current情報・現在時刻を自ら取得する（caller-supplied runtime/now を受けない）。
  - Gateは保存済みDecisionのみを信頼し（digest検証付き読出し）、Policy Engineの解決ロジックを再利用して
    authorization_digest と normalized_targets/bindings/grants/effective_risk を Current入力から再導出・完全一致照合し、
    Plan の identity/revision/observed epoch/state/tool_ref/action_contract/snapshot/capability digest も照合する。
  - 認可Artifact（mission state, lifecycle event, decision, snapshot, approval request/record, context grant）は
    Composition固定の Write Guard を持つ所有Serviceだけが永続化でき、公開repoの raw save では偽造保存できない。
    Mission状態遷移は UnitOfWork 内で expected version/epoch/state・legal edge を原子検証し、lifecycle event を同一Transactionで確定する。
  - Approvalは認証済みactor（Root固定 Principal Resolver）と Mission RBAC 経由でのみ生成・保存し、使用時に RBAC を再確認する。
  - Data Access（Secret）は Caller参照のHashではなく Secret Metadata Source-of-Truth から exact version/metadata digest/lifecycle head を解決し、未確認/失効/欠落/version不一致を拒否する。
  - Repositoryは write時に strict schema 再検証（model_construct迂回拒否）、read時に digest/ID/row-key binding を検証し、
    一括読出しも重複キー拒否入口を通す。未知の security family は無条件成功にせず fail closed。
  - Sandbox Capability は adapter/runtime/execution location へ binding し、他Runtimeの能力流用を拒否（H-04）。
  - TTL は暗黙 min-clamp をやめ範囲外を明示拒否（発行側 + 使用時再確認）。
  - Digest Catalog は explicit digest に included_field_paths を固定し、Field欠落/未知Fieldを検知（§32.2整合）。
  - SuccessCondition は Discriminated Union + 登録済みSemantic Catalog照合とし、未登録/未対応ConditionのMissionを開始させない。
  - ActionContract は exact ToolRef へ固定契約として登録され、parameter schema digest/extractor/evidence/publication/risk/side-effect の整合をTool登録時に検証する。
- 設計との整合メモ（矛盾ではない、適用限界の明示）:
  - `authorization_state_digest` は複数用途で可変shapeを取るため Digest Catalog の field-set 固定対象外（generic digest）。
    用途別の厳密固定は後続Phaseの Secret Lifecycle / Knowledge 実装時に細分化する。
  - Write Guard はPhase 0Aの配線的アクセス制御であり暗号署名ではない。§34.2のTPM witness/署名は後続Phase。
  - Owner Service経由でない低レベルSQLへの直接書込みをOSレベルで防ぐことは0A範囲外（正本§35.2 Production Composition/§34.2は後続）。
- 未解決の仕様矛盾・BLOCKER/HIGH・Security-critical TODO: 現時点で認識なし。発見時は本節へ追記する。
- 次Phase範囲: Phase 0B（Execution State Machine / Dispatch Claim / Secret Injection / 実行安全）。本実装では未着手。
