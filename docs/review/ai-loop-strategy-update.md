# 開発AIループへの実装方針引継ぎ — 変更報告

日付: 2026-09-06

## 結論・作業範囲

承認済みの「適合する基盤を再利用し、変更の大きい責務を関連経路ごと置換し、未実装AI制御を新規実装する」
方針を、開発AIループの実装依頼・監査JSON・CI・独立レビューへ接続した。
記録形式を増やし過ぎないよう、既存のInvariant AuditとそのDigest Bindingを拡張し、新しい承認フローは作っていない。

- 作業種別: ユーザー承認によるローカルGovernance変更。製品Phase 0Cの実装依頼ではない。
- 入力ローカルHEAD: `e51d9bd81a216d81ea8c14f7d6bd0c2f4f648caa`
- 作業ブランチ: `codex/phase-0c-coherent-redesign-v3`
- 入力Review SHA: 今回のGovernance修正には該当なし。既存PRの最新SnapshotはPhase 0C、
  `ae09f40f6b593060d060cfb9a5090e0de4e2875d`のDesign Stopであり、この報告で再開を認可しない。
- 出力: Working-tree差分のみ。Commit / Push / Merge / GitHub Label変更 / Runner実起動は行っていない。
- 今回の差分: 既存23ファイルを更新し、本報告を新規追加。作業前から存在するSystemDesign等の大きな差分は
  保持しており、今回のAIループ実装変更と混同しない。製品`src/`、Integration / Security Test、DB、鍵は未変更。

製品自身のPlanner / Executor / Analyzerループを完成させた、あるいは全Phase GateがPASSしたという意味ではない。

## 何を変更したか

| 対象 | 変更前 | 変更後・理由 |
| --- | --- | --- |
| 実装依頼 | Family監査は必須だが、再利用・置換・新規の方針は機械的に引き継がれない | Trusted Phase Planの`invariant_audit`へ`implementation_strategy_version=1.0`を追加。全依頼生成経路が既存のPolicyコピー処理で引き継ぎ、Runnerは旧Policyや不足Requestを実行しない |
| 実装Prompt | Family単位の修正・監査が中心 | 現行AI制御別冊とSystemDesign §38を必須参照。Owner、全入口・兄弟経路、保存・復旧、保持する試験、移行影響、変更前後を記録させる |
| 監査JSON | Family一覧と試験証拠のみ | 同じAuditへVersion付き`implementation_strategy.units`を追加。各単位を`reuse` / `replace` / `new`に分類する |
| CI検証 | Family・Path・Request・Digestを検証 | 閉じたSchema、重複ID、現行規範参照、Input HEADでのFile存在、追加・変更・削除されたSource / Test Pathの網羅、Affected Family網羅、必要試験種別も検証する |
| Review Ready / Gate | 分類記録の必須性を確認しない | 新Policy RequestのOutputでStrategy Blockが欠落・Version不一致なら拒否。既存のRequest / Output HEAD / Audit Digestへ変更要約も含めてBindingする |
| 独立Review | 旧来の消去・互換性の表現が残存 | 用途別消去、単回配送とSecret Version Lifecycle、TPM Witness、旧権限を残さない移行を確認。分類や試験ラベルを適合の証明とせず実コードを検証する |
| 仕様保護 | AI制御別冊が明示保護対象にない | `AGENTS.md`、Governance Checker、CODEOWNERSへ追加し、実装PRからの自己都合の仕様変更を防ぐ |
| 操作説明 | 新方針の記録方法・採用手順がない | 要件LOOP-031/032、受入条件、開発ループ設計、Runbook、Statusを更新し、本報告へ変更・検証・残課題を分離して記録する |

### 変更ファイルの対応表

| ファイル | 今回の変更 |
| --- | --- |
| `automation/phase-plan.json` | 新規Requestが要求するStrategy Version |
| `automation/schemas/phase-plan.schema.json` | Current PlanではVersionを必須化 |
| `automation/schemas/implementation-request.schema.json` | 新フィールドを許可。旧履歴の読込み互換性は維持 |
| `automation/schemas/invariant-audit.schema.json` | 閉じたStrategy / Unit構造、必須項目、分類別Input制約 |
| `automation/run_phase_loop.py` | Current Policy照合、実装・レビュー依頼への方針引継ぎ |
| `.github/prompts/implement.md` | 分類・関連経路一体修正・変更要約・追加検証の実装手順 |
| `scripts/ci/validate_invariant_audit.py` | Input Git Object、Output / Evidence Path、変更網羅・試験種別検証。`--require-implementation-strategy`を追加 |
| `automation/loop_control_state.js` | Trusted RequestのStrategy必須性を確認する共有関数 |
| `.github/workflows/ci.yml` | Review Ready発行前に新PolicyのStrategy Blockを要求 |
| `.github/workflows/ai-loop-control.yml` | Gate記録時にも同じ必須性を再検証 |
| `automation/chatgpt-event-task-prompt.md` | 現行別冊・分類・移行と用途別消去の独立検証 |
| `automation/invariant-families.json` | 現行契約に沿うReview質問。Secret LifecycleをStatefulとして明示 |
| `AGENTS.md` | 今回はAI制御別冊の保護対象追加のみ。先行の設計変更分は保持 |
| `scripts/ci/check_governance.py` | 別冊の実装PR / 無Label変更を拒否 |
| `.github/CODEOWNERS` | 別冊のOwner指定。現行Repository PlanでのServer強制を新たに主張しない |
| `tests/unit/test_automation_validation.py` | Strategyの正常・拒否・障害境界、変更網羅、Digest、JS共有検証の回帰試験 |
| `tests/unit/test_governance_check.py` | 別冊の保護・Human Governance経路の回帰試験 |
| `tests/unit/test_phase_loop.py` | 全8 PhaseのPrompt引継ぎ、重複依頼防止、旧Policy拒否、dry-run無書込み |
| `docs/requirements.md` | LOOP-031/032追加 |
| `docs/acceptance-criteria.md` | 上記の正・負・障害試験と独立検証の受入条件 |
| `docs/ai-development-loop.md` | 引継ぎ契約と旧履歴の扱い。Governance CIの説明を既存実行範囲に訂正 |
| `docs/ai-loop-runbook.md` | 採用・Design Approval後の再開・検証手順 |
| `docs/implementation-status.md` | ローカルGovernance実装と、未実施の製品実装・外部再開を分離 |

本報告自身は`docs/review/ai-loop-strategy-update.md`として新規作成した。

## 安全性と互換性

- 旧Request / Auditは停止・祖先・Base Refreshの履歴として読める。新Policyへ暗黙に昇格させず、
  Runnerからの新規実装や新Policy Review Readyで必須分類を省く根拠にはしない。
- `--if-present`は停止中Governance取込みで旧Auditを読めるよう維持した。新規実装の受入は
  Ready / Gate側でもStrategy必須性を確認するため、ファイル省略で通過できない。
- UnitのInputは完全Request HEAD上のFile、現存する変更FileはOutput、削除FileはInputで網羅する。
  Git Rename検出に依存せず、旧File削除と新File追加の両方を確認する。
- Path / Version / Test Modeを機械検査しても、Owner境界や試験内容の正しさまでは証明しない。
  Selectorの意味、全Caller、保存・復旧・移行の完全性は独立Reviewが検証する。
- Phase順序、再試行上限、Family再発によるDesign Stop、単回Design Approval、Provider Human Gate、
  最終Mergeの認可境界は変更していない。既存テストを削除・skip・xfail化していない。
- Invariant Policyの質問・Stateful指定変更によりPolicy Digestも変わる。再開時には現行DigestへBindingした
  新しい専用Design Approvalが必要であり、過去Approvalを流用しない。

## 検証結果

環境: Repository `.venv`のPython 3.13.14。既存JS境界試験用のNode.jsはBundled Runtimeの24.19.0を使用。
下記`python`は`/home/kali/RedTeam_Agent/.venv/bin/python`。
Nodeが初期PATHにないため最初のJS試験は失敗したが、テストを緩和せず既存NodeをPATHへ追加して再実行した。

```bash
export PATH="/home/kali/RedTeam_Agent/.venv/bin:/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH"
python -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers
python -m ruff check automation scripts/ci tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py
python -m compileall -q automation scripts/ci src/redteam_agent
python scripts/ci/validate_automation.py
python docs/review/validate_ai_control_design.py
python automation/run_phase_loop.py --help
python -m pip check
git diff --check
```

| 検証 | 結果 |
| --- | --- |
| Governance回帰試験 | **265 passed**。実GitHub書込みやTarget操作なし |
| 変更対象のRuff | PASS |
| Compile / Automation Schema | PASS |
| 設計文書検証 | PASS。16文書、Goal参照240組合せ、Controller参照384組合せなど。製品適合を示すものではない |
| CLI読込み / pip check / 差分Whitespace | PASS |
| 変更Workflow構文 | System Pythonの既存PyYAMLとNodeを使って2 YAMLと内包JS 5 BlockをParse / Compile。PASS。GitHub上のWorkflow実行試験ではない |
| Governance限定Branch Coverage | 取得成功。Audit Validator 82%、Runner 63%、Governance Checker 54%。全体網羅やPhase PASSは主張しない |

Coverage取得コマンド:

```bash
COVERAGE_FILE=/tmp/redteam-loop-strategy-HWe7kE/governance-coverage python -m coverage run --branch --source=automation,scripts.ci -m pytest -q tests/unit/test_automation_validation.py tests/unit/test_governance_check.py tests/unit/test_phase_loop.py --strict-markers
COVERAGE_FILE=/tmp/redteam-loop-strategy-HWe7kE/governance-coverage python -m coverage report --include='scripts/ci/validate_invariant_audit.py,scripts/ci/check_governance.py,automation/run_phase_loop.py'
```

### 完全Phase Gateの診断結果 — FAIL、今回のループ修正とは分離

`scripts/ci/run_phase_gate.sh`は変更せず、次を実行した。これはローカル旧製品Treeの診断であり、
PRのCurrent-HEAD CI結果やPhase認可を代替しない。

```bash
bash scripts/ci/run_phase_gate.sh phase-0c
python -m mypy src/redteam_agent
python -m pytest -q tests/unit --strict-markers
python -m pytest -q tests/integration tests/security --strict-markers
COVERAGE_FILE=/tmp/redteam-loop-strategy-HWe7kE/full-coverage python -m coverage run --branch -m pytest -q tests --strict-markers --junitxml=/tmp/redteam-loop-strategy-HWe7kE/tests.xml
COVERAGE_FILE=/tmp/redteam-loop-strategy-HWe7kE/full-coverage python -m coverage report
COVERAGE_FILE=/tmp/redteam-loop-strategy-HWe7kE/full-coverage python -m coverage xml -o /tmp/redteam-loop-strategy-HWe7kE/coverage.xml
```

- Gateは既存のRepository全体Ruff **88件**で停止。作業前の件数と同じで、変更対象のGovernance RuffはPASS。
- 続くコマンドも診断として個別実行。Mypyは作業前と同じ**40 errors / 16 files**。
- Unit全体は収集時3 errors、Integration / Securityは合計11 errors。
  共通原因は未変更の`src/redteam_agent/canonical/models.py:13`にあるUnionと文字列Forward Referenceの型定義。
  製品コードの差分はない。今回の変更で修復済みとは扱わない。
- 全体Coverage Runも同じ収集時14 errorsで終了。XMLのskipped=0、errors=14、failures=0を確認した。
  Coverage File / XMLは生成されたが、収集段階の部分値であり有効な製品Coverage・合格証跡には使わない。
- ローカルに`tests/phases/phase_0c`とPhase 0C Auditはない。`INVARIANT_AUDIT=NOT_REQUIRED`は
  Governance作業TreeにAuditがないという結果であり、新規実装依頼のAuditが不要という意味ではない。
- Python 3.12 / 3.14のGitHub CI、Native Codex Review、ライブRunnerは未実施。

## 次に必要な作業

1. 今回のGovernance修正と先行する現行設計差分をHuman Reviewし、Governance PR経由で`main`へ取り込む。
2. 実装PRのPhase / 完全HEAD / 最新Gateを再取得し、既存の認可付きBase Refresh / Checkpointで取り込む。
3. 取込み後のCurrent-HEAD Checkを満たし、現行Design CommitとPolicy DigestへBindingした専用Design Approvalを発行する。
4. 新Strategy Version付きのTrusted Requestを確認してから、CleanなCurrent Default Branchで既存Runnerを起動する。
5. 実装AIが正式Input HEADを棚卸しし、Phase 0Cの置換を関連経路ごと実装・検証して新規Auditへ変更内容を残す。
   後続の共通AI制御はPhase 1 / 2のGate順序に従う。

Governance変更はレビュー可能だが、現時点で「ライブAIループが稼働中」「製品実装完了」「Phase PASS」とは報告しない。
