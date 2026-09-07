# Phase 0A 開発記録 — Core Models / Authorization Kernel

本記録は正本 `SystemDesign.md` §40.1 が要求するPhaseごとの一つの開発記録である。
実装担当はCodex、独立レビューは実装作業から分離したCodexレビュー担当が行う。
本記録の更新自体は実装着手・Phase受入完了・独立レビュー完了の証拠ではない。

## 1. 対象

| 項目 | 内容 |
| --- | --- |
| 設計Revision | `system-design-v1-r3` / `ai-control-v1-r3` |
| Phase | 0A: Core Models / Authorization Kernel |
| 入力コミット（完全ID） | `d78d089705104d5c10c5d364b3e0048c211d15b9`（`codex/phase-0a`、設計のみのbaseline） |
| 実装先 | Codexが用意した専用worktree `/tmp/redteam-phase0a`（ブランチ `codex/phase-0a`） |
| 実装対象コミット | **未確定（UNDETERMINED）**。第2回レビュー指摘への修正を固定後、この欄を更新する。 |
| 独立レビュー | 第1回 `dce65046f76526685b6ce97c651cf031b859ccd5`、第2回 `2161cc61d4e679ce10069c306d25d90b32facf8b`、第3回 `bfeede8415985049e0b33e5c2e58ebec5ecffd96` を実施。いずれも受入非支持。修正版の最終レビューは未実施。 |

成果物はブランチ `codex/phase-0a` に固定する。リモートへのpushとmainへのmergeは別途指示があるまで行わない。

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
「対象実装コミット固定 + 独立レビュー完了」は、修正版コミットの固定と最終レビュー後に判定する。

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

対象コミット: **未確定**（第2回レビュー指摘への修正を含む作業ツリー。固定後に完全IDを記録する）。
入力コミット `d78d089`。レビュー候補は第1回 `dce6504`、第2回 `2161cc6`、第3回 `bfeede8`。以下は第3回指摘F01–F04対応後の結果である。
実行環境: worktree `/tmp/redteam-phase0a`、`.venv`（Python 3.14.6）。全て仮想環境Pythonで実行。

| コマンド | 結果 |
| --- | --- |
| `.venv/bin/ruff check src tests` | All checks passed（0 warning） |
| `.venv/bin/mypy`（package=redteam_agent, strict） | Success: no issues found in 77 source files |
| `.venv/bin/python -m compileall -q src tests` | 成功（exit 0） |
| `.venv/bin/python -m pytest`（Unit/Integration/Security/Regression/Property-StateMachine） | 256 passed（warningなし） |
| `.venv/bin/python -m coverage run --branch -m pytest` + `coverage report/json` | line 3512/3831、branch 859/1136、coverage.py combined 88.00080531507953%（display 88%） |
| `.venv/bin/pip check` | No broken requirements found |
| `git diff --check` | 空（whitespace/conflict marker なし） |
| `sha256sum -c SHA256SUMS` | manifest記載の7ファイル全て OK（承認済みr3正本のHash整合を確認） |
| `scripts/verify_pydantic_contract.py` / `scripts/verify_wire_and_immutable.py` | いずれも exit 0（strict/coercion/frozen/重複キー/wire/deep-immutable 契約を確認） |
| 再現手順（README） | `pip install -r requirements.lock` + `pip install -e . --no-build-isolation`（lock済み `setuptools==80.9.0`/`wheel==0.45.1`）で構築・全チェック実行を確認 |

試験の構成:
- Unit: canonical/digest（field-set固定含む）、json boundary（H-02重複キー・G例外非漏洩）、scope engine（B-01, IPv4-mapped対称正規化, property-based no-false-allow）、data access、secret path、risk policy、tool registry（+action contract binding）、target extractors（B-02隠しdestination）、immutable（deep）、success conditions、sandbox binding（H-04）、availability、mission validation、ttl/normalizer、git state（H-07）。
- Integration: 認可フロー（ALLOW/REQUIRE_APPROVAL）、mission manager（B-03 lifecycle/OCC/epoch/atomic audit）、repository integrity（B-06/H-03/row-key/model_construct/dup-key）、authorization context（H-01）、context authorization grant（B-04 stale）、mission state machine（Property/State-machine）。
- Security: forged writes（owner guard: 偽造decision/record/state/requestのraw save拒否, 未認証/未assign approver拒否）、gate negative（stale epoch/mission非RUNNING/window/decision expired/plan改変多数/approval bypass/RBAC revoked）、zero metrics（scope false-allow, prohibited full-path, unauthorized tool, secret未確認/確定SoT binding, misleading presentation）。
- Regression（`tests/regression/test_review_probes.py`）: 第1回レビュー25 Probe（P01–P25）を現行公開APIへ移植し、修正後の fail-closed 挙動をアサート。正当系も対にして、拒否一辺倒になっていないことを確認。
- Unit（追加）: parameter schema subset validator（R01: closed object/型非強制/bool≠int/enum/const/bounds/minItems/未対応keyword fail-closed）、context selector（§18: target優先ランク/新しい順/per-type cap非拡張/cross-mission fail-closed）。

未実行/未達: 実LLM品質Gate（Phase 2）、TPM/`swtpm`統合（Phase 0C）、実Adapter Contract/Integration（Phase 4/5）、D4実機Qualification（`NOT_EVALUATED`）は本Phase対象外で未実施。

### 受入前検査で再現し修正した事項

いずれも修正前に公開入口から再現し、修正後にRegressionを追加した。

- A（Context Authorization 未完成）: `issue_grant` が要求TTLを無視し Mission `valid_until`（172800秒）へ暗黙延長、
  停止/未来時刻/失効/他Mission/未保存/改変Grant/Session範囲外/Source差替えを検証していなかった。
  修正: `issue_grant` は Current Mission RUNNING/valid window、Current Policy Version、Service Identity、
  Session存在+Freshness、Mission typed scope、Session security status、Index候補と Resource Metadata Source-of-Truth の version/digest/classification一致を検証し、
  実TTLを `now+ttl_seconds` として Mission validity/固定最大/Session freshness の各上限へ**明示拒否**（ttl<=0/過大/期限）。
  `verify_grant(grant_id, mission_id)` は Repository から保存済みGrantを読み Root Clock で全Current制約を再検証し、
  caller-supplied Grantモデルや caller now を権威にしない。Regression: `tests/integration/test_context_authorization.py`（17件）。
- B（Repository不正Model拒否時のSecret漏洩）: `_dump` が未検証Modelを先に `model_dump_json()` していたため、
  不正値がpydantic警告・例外へ露出した。修正: 保存前に全nested modelを生のfield値へ展開して厳格再検証し、失敗時は
  内容非公開の `RepositoryIntegrityError`（例外chainなし `from None`）へ変換してから直列化。Digest field-set不一致・
  boundary検証エラーはキー名/入力値をechoせずtype件数のみ。Regression: `tests/integration/test_repository_integrity.py::test_invalid_model_rejected_without_leaking_input`（warning/例外/chainに合成Secret非出力を確認）。
- C（再現設定）: `setuptools==80.9.0` / `wheel==0.45.1` を venv へ導入し `requirements.lock` と `pyproject.toml` の
  `build-system.requires` へ固定。`.python-version=3.14.6` を追加。READMEの `--no-build-isolation` 手順で lock済み backend による構築を確認。

## 5. 独立レビュー

候補コミット `dce6504` に対して第1回独立レビューが実施された（記録: `/tmp/phase0a-independent-review-1/review.md`、
再現Probe: `/tmp/phase0a-independent-review-1/probes.py`、結果: `probe-results.json`）。**受入は成立していない。**
指摘は HIGH 17 / MEDIUM 5 / LOW 1。全指摘（R01–R23）への対応を候補コミット `2161cc6` に固定し、25 Probe を正式Regressionへ移植した。

各指摘への対応（R番号はレビュー内番号）:

- R01（HIGH, P01/P16）: 登録 `parameter_schema` を認可入口（Policy Engine `resolve` 冒頭）で実引数へ厳格適用。安全なJSON Schema subset validator（closed object・型非強制・bool≠int・未対応keyword/type fail-closed）を追加。Tool登録時に schema supported を検証。
- R02（HIGH, P02）: `required_data_access_types` の宣言リソースについて Resource Metadata Source-of-Truth から read grant を導出し、未認可は DENY。
- R03（HIGH, P13）: `requires_session` Tool の実行ホストを normalized target に加え、prohibited host scope を評価。
- R04（HIGH, P04）: `AvailableToolSnapshot`/`CurrentSnapshotBindings` に `mission_id` を追加し、snapshot revalidation で mission 一致を検証。
- R05–R08（HIGH, P06–P09）: Context Authorization を維持強化。`verify_grant(grant_id, mission_id)` は保存済みGrantをRoot Clockで再検証し caller Grant/now を信頼しない（R06）。停止Missionでの発行/検証を拒否（R07）。Index候補は権威たる **origin record** をSoTキー・ポリシー評価・binding のcanonicalとし、許可IDへ禁止originをaliasする経路を封鎖（R08）。期限切れ/範囲外Sessionを拒否。
- R09（HIGH, P11）: Approval Request TTL を Mission `approval_ttl_seconds`・Global最大・Decision `expires_at`・Mission `valid_until` の最小へ発行時に束縛し、Record は Request を超えない。使用時（Gate `evaluate_executable`）に再検証。Mission TTL=1 → 2秒後は `not authorized`。
- R10/R12（HIGH, P05/P12/P25）: kv_store 行整合Digest（namespace+key+bytes）で raw-SQL 改変を読出し時に fail-closed。`execution_precondition_digest` はApplicationが登録契約から算出した値と一致必須（空/任意値は拒否）。
- R11（HIGH, P10）: SuccessCondition の selector_value を具体値必須（`""`/`any` 拒否）、`execution_outcome` fact type と未登録entityを finding goal から排除。
- R13（HIGH, P19/P20）: `ToolRegistryRepository` save/get で `validate_tool_registry` を再実行し raw保存の自己整合な不正Registryを拒否。Rule Catalog（publication/evidence/outcome）はRoot供給、Tool宣言のRule IDが未登録なら拒否。
- R14（MEDIUM）: `ExecutionAuthorizationService` が Decision発行前に snapshot を revalidate。
- R15（MEDIUM, P15）: 期限切れSessionは `_eligible_sessions` から除外され、session-required Toolはpublish時に snapshotから除外。snapshotに非正のTTLを許さない。
- R16（HIGH, P18）: Sandbox/Adapter の `execution_location` 一致と supported location を availability で検証（untrusted_remote は不可, H-04）。
- R17（HIGH, P21）: Phase 0Aは mock profile のみ受理し、local_llm の自己申告 capability を拒否。
- R18（HIGH, P22）: Mission Lifecycle 全公開操作に認証済みActor（Root固定 Principal Resolver + Mission RBAC: `mission_admin`/`mission_operator`）を要求し、認証済み `principal_id` を監査actorに記録（bare caller文字列は権威にしない）。
- R19（MEDIUM）: state-machine testはproductの `LEGAL_*` を輸入しない独立oracleへ書換え。
- R20（LOW）: coverage.pyのcombined TOTALとbranch coverageを区別し、line/branchの分子・分母を記録。
- R21（MEDIUM, P23）: RFC6901 array index を ASCII 限定し、`str.isdigit` のUnicode digit alias を封鎖。
- R22（MEDIUM, P24）: array index の secret pointer/presentation を list index対応。
- R23（HIGH, P25）: Gate は Decision の resolved adapter が登録Tool固定adapterと一致することを再照合。
- 対応の正当系: schema一致引数のALLOW、Context TTLの非延長発行、認証済みActorの監査記録、ASCII array index pointer、array index secret pointerでのApproval Request生成をRegressionで確認。

候補コミット `2161cc6` に対する第2回独立レビュー（記録: `/tmp/phase0a-independent-review-2/review.md`）は
HIGH 9 / MEDIUM 1 / LOW 1で受入を支持しなかった。N01–N11への修正は次のとおりで、最終判定は固定コミットへの再レビューで行う。

- N01/N02: Target extractorとparameter schemaのclosed contractを登録時に検証する。extractorなしは`timeout_seconds`だけ、target/resource/secret fieldは宣言した型・必須性・固定shapeと一致しなければ登録を拒否する。
- N03/N04: Context grantの発行・使用時にSession/HostのMission typed scope、Session security status、Resource/Index classificationを再検証する。
- N05: Success conditionは正本§24の型付きcondition/selectorを使う。Phase 0Aは具体Rule実装、closed Proof model、Session Source Protocolが揃う`SessionExistsCondition`だけを受理し、他conditionは開始前に拒否する。
- N06: Phase 0AはAction Contractの自由形式`preconditions`/`observes`/`may_change`を受理せず、PolicyDecision発行時にも登録契約のref/digestを照合する。
- N07: parameter schemaの全nodeに明示`type`を要求し、keyword適用先とJSON上の型を検証する。`bool`を`integer`と同一視しない。
- N08: Secret Referenceは4つのstring fieldだけを持つclosed objectとして登録時と引数検証時に強制する。
- N09: Repository保存前のstrict revalidationをnested modelまで行い、警告・入力値・例外chainを外へ出さずに拒否する。
- N10: P02/P03の元Probeと正当系を正式Regressionへ追加し、resource/report不一致、target omission、正当なartifact grantを確認する。
- N11: 本記録のテスト数・coverage・修正範囲・レビュー表現を検証結果に合わせて更新する。

候補コミット `bfeede8` に対する第3回独立レビュー（記録: `/tmp/phase0a-independent-review-3/review.md`）は
HIGH 3 / LOW 1で受入を支持しなかった。53種類の独立Probeで、第2回の主要修正と正当なartifact/secret経路は確認された一方、
兄弟経路F01–F03と記録誤差F04が見つかった。修正は次のとおりで、最終判定は次の固定コミットへの再レビューで行う。

- F01: 登録時にparameter schema内のclosed Secret Reference有無、`secret_argument_paths`、`required_data_access_types`の三者一致を要求する。認可時は実引数を再帰走査し、全Secret Reference leafの具体JSON Pointer集合と宣言集合の完全一致を要求する。可変長配列の未列挙要素をGrantから脱落させない。
- F02: trusted Session Repositoryの全Current snapshotをPolicy Engineへ渡し、抽出された全Session targetについてfreshness、security status、OS/architecture/capabilityを確認し、そのHostをScope対象へ追加する。
- F03: 旧簡略`HostPrivilegeCondition`/`FindingConfirmedCondition`を受理対象から除外した。Phase 0AのSuccessConditionはtyped `SessionSelector`を持つ`SessionExistsCondition`に限定し、実行可能な静的Rule object、closed `SessionStateProof` model、`SessionGoalSource` ProtocolとRepository adapterのbindingをValidationする。
- F04: Context Authorizationの局所試験件数を17件へ訂正し、全体試験数とcoverageを再計測した。

## 6. 受入と残課題

- Phase受入は**未成立**。第3回指摘の修正版コミット固定と最終独立レビューが未完了である。
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
  - Repositoryは write時にnested modelまで strict schema再検証（model_construct/model_copy迂回拒否）、read時に digest/ID/row-key binding を検証し、
    一括読出しも重複キー拒否入口を通す。未知の security family は無条件成功にせず fail closed。
  - Sandbox Capability は adapter/runtime/execution location へ binding し、他Runtimeの能力流用を拒否（H-04）。
  - CallerがTTLを指定する発行APIは範囲外を暗黙補正せず明示拒否し、使用時にも再確認する。Approval Request/Recordの期限はCaller入力ではなく Mission approval_ttl・Global最大・Decision・Mission validity から導出し、その最小へ束縛してGateで再確認する（R09）。
  - 登録 parameter schema を認可入口で実引数へ厳格適用する安全な JSON Schema subset validatorを導入し、全nodeの明示型、closed object、keyword適用先、JSON型をfail-closedで検証する（R01/N07）。
  - Context Index は権威 origin record を canonical resource とし、許可IDへ禁止originをaliasする経路を封鎖（R08）。
  - Mission Lifecycle 全操作は認証済みActor（Principal Resolver + Mission RBAC）を要求し、監査actorに認証済み principal_id を記録（R18）。
  - Digest Catalog は explicit digest に included_field_paths を固定し、Field欠落/未知Fieldを検知（§32.2整合）。
  - SuccessConditionはPhase 0Aで実装済みの`SessionExistsCondition`に限定する。typed selector、具体Rule object、closed Proof model、Session Source Protocol/Repository adapterを一体で登録し、文字列だけの実装済み判定を行わない。
  - ActionContract は exact ToolRefへ固定し、parameter schema digest/extractor/resource/secret/evidence/publication/risk/side-effectの整合をTool登録時に検証する。自由形式predicateはPhase 0Aで拒否する。
- 設計との整合メモ（矛盾ではない、適用限界の明示）:
  - `authorization_state_digest` は複数用途で可変shapeを取るため Digest Catalog の field-set 固定対象外（generic digest）。
    用途別の厳密固定は後続Phaseの Secret Lifecycle / Knowledge 実装時に細分化する。
  - Write Guard はPhase 0Aの配線的アクセス制御であり暗号署名ではない。§34.2のTPM witness/署名は後続Phase。
  - Owner Service経由でない低レベルSQLへの直接書込みをOSレベルで防ぐことは0A範囲外（正本§35.2 Production Composition/§34.2は後続）。
- 未解決の仕様矛盾・BLOCKER/HIGH・Security-critical TODO: 最終独立レビュー前のため未確定。既知の第2回N01–N11と第3回F01–F04は実装、Regression、記録へ反映済み。
- 次Phase範囲: Phase 0B（Execution State Machine / Dispatch Claim / Secret Injection / 実行安全）。本実装では未着手。
