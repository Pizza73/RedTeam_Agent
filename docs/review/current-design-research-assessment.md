# 現行SystemDesignの研究評価・整合確認

確認日: 2026-09-06

対象は[SystemDesign.md](../../SystemDesign.md) `system-design-v1-r1` と必須別冊
[SystemDesign_AI_Control.md](../../SystemDesign_AI_Control.md) `ai-control-v1-r1`。
ユーザーの指定に従い、AI制御の競合は別冊§12の範囲で別冊を優先する。
SystemDesign_update.mdは比較用スナップショットであり、今回は更新しない。
本書は研究評価・ローカル文書検査の記録であり、規範の追加、正式PR Review、Phase PASS、実装再開許可ではない。

## 1. 結論

**限定された登録Tool環境では方向性は妥当。設計全体の作り直しは不要だが、実装可能性・安全性・達成能力の証明は未完了。**

LLMを候補提案に限定し、事実判定・実行前提・認可をモデル外で検査する構成は研究と整合する。
今回確認した改善点は、制御方式を増やすことではなく、既存の詳細仕様を構成図へ反映することと、
具体的な契約・独立Oracle・障害Traceを実装へ渡すことである。

設計のRoot of TrustはLLMではない。固定されたComposition Root、Host OS / Kernel、信頼済みRegistry / Rule、
Policy / Executor / Source Ownerとその認証済みCurrent状態をTCBとして扱う。
TPMは内容にBindingされたWitnessと鍵保護を支えるが、観測内容の真偽・人の許諾・侵害済みOSの正当性は証明しない。
この信頼前提はSystemDesign §2.5 / §2.6 / §34と整合する。

## 2. 公開研究・規格との比較

一次資料の本文・該当節または著者の公開説明を確認した。網羅的Systematic Reviewではなく、
古いモデルの実験結果を現在のLocal LLMの性能へ外挿しない。「対応」は本プロジェクトへの設計上の推論である。

| 資料・確認範囲 | 設計との対応・評価 | 保証されない点 / 必要な検証 |
| --- | --- | --- |
| [ReAct, ICLR 2023、Abstract](https://arxiv.org/abs/2210.03629) | 推論・行動・観測の反復と、一Action実行後に再評価する§26の構造は整合 | この形式だけでは認可・有限停止・単回副作用を保証しない。Mission Budgetと独立した実行履歴の検査が必要 |
| [LLM-Modulo, ICML 2024、§3 / §3.1](https://arxiv.org/html/2402.01817v2) | 候補生成とモデル外のHard Criticを分離。別冊§4〜§8のRule / Contract / Policy分離を支持 | 正しさは検証器の健全性に依存。本設計の局所前提探索は、全計画の因果・資源整合性や探索完全性の証明ではない |
| [SayCan, 2022、著者公開Approach / Limitations](https://say-can.github.io/) | 有用性と現在状態での実行可能性を分ける考え方が、候補順位と前提検査の分離に対応 | ロボットの学習Affordanceは権限ではない。本設計では確率・有用性でScopeや必要前提を相殺しない |
| [CaMeL, 2025 v2、§5 / §6.4 / §9](https://arxiv.org/html/2503.18813v2) | 出所・Capabilityに基づくモデル外の制御は、区分別ContextとPolicy境界に対応 | 本設計には同じInterpreterによる制御フロー分離はない。非信頼ObservationからPlanner候補が誘導され得るため、CaMeLと同等の保証やInjection完全防止とは評価しない |
| [AgentDojo, NeurIPS 2024、§3.1 / §3.4](https://arxiv.org/html/2406.13352v3) | 環境StateをOracleとし、正常時Utility・攻撃下Utility・攻撃成功を分ける。別冊§11 / D11と整合 | 全停止で攻撃成功だけを0にする実装を合格させない。固定Corpus外の未知・適応的攻撃への保証は残らない |
| [τ-bench, 2024、§4](https://arxiv.org/html/2406.12045v1) | 最終状態の比較と反復信頼性pass^kが、独立Oracle / pass^3診断に対応 | 最終状態だけでは途中の無承認操作を見落とす。全履歴を検査し、pass@3と区別する。3回の診断は高信頼性の統計的証明ではない |
| [Intrinsic self-correction, ICLR 2024、Abstract](https://arxiv.org/abs/2310.01798) | 対象モデル・推論課題で外部Feedbackなしの自己修正に限界を報告。LLM自己採点を完了根拠にしない方針を支持 | 全現行モデル・全修正課題が不可能という意味ではない。LLMレビューは反例候補を探す手段として利用できる |
| [Chubby, OSDI 2006、§2.4](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/burrows/burrows_html/index.html) | Lock世代を含むSequencerを受信側で検査し、遅延した旧保有者を拒否する考え方は、Storage側Fencingと整合 | Lease延長だけで旧Workerを無害化できない。単一HostのClock / TPM Epoch設計をこの論文が証明するわけではなく、新しい分散Lock Serviceの導入も必要ない |
| [TCG TPM 2.0 Architecture v185 Published、2026-03-12、§34.2.6.5](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Architecture_Version-185_pub.pdf) | NV Extendは旧Digestと入力をHashし、初回はZero Digestを用いる。ORDERLYが無効ならNVを書き換える。SystemDesign §34.2のSHA-256 / 32-byte / ORDERLY=0 / Genesisと整合 | Counterだけでは内容を選択できない。認証済みRecordとのPair、Index Identity、read-back、Crash試験はApplication側の責務。NV削除成功だけでは内部残留Dataの消去保証にならない |
| [NIST SP 800-88 Rev.2、2025、§3.2〜§3.2.3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf) | Cryptographic Eraseは鍵の回復経路・Backup / Escrowを含む前提と検証が必要。SystemDesign §34.1 / D4のCopy InventoryとRestore試験は妥当 | NISTが個別TPMのNV REK方式を認証したわけではない。File削除やTombstoneを消去証明としない。実機適格性は引き続きNOT_EVALUATED |

TCGとNISTは研究論文ではなく公開規格・指針として区別した。TCGについては現行正本が引用するv185の
Published版を確認し、旧版やRelease Candidateへの置換は行っていない。

### 研究に基づく維持方針と残る限界

- 一つのControllerと登録契約を維持し、認可用の第二LLM、多数決、新しい実行Modeを追加しない。
- verified_fact / observation / hypothesisを分離し、信頼できる検証RuleだけがFactを確定する。
- 深さ8 / 訪問64 / 候補32、情報取得3回、D11の90% / 80%等は製品の固定方針であり、論文から導かれた最適値ではない。
- 観測不能なunknown、登録モデル不足、探索上限では安全に停止する。任意Missionの達成保証はしない。
- 許可内の無駄な行動や誤った順位付けは残る。有限Budgetだけでなく攻撃下の達成能力も実測する。
- Secretの生涯使用回数を数えず、別認可ExecutionでのVersion再利用を維持する。単回性はDispatch試行へ置く。
- 外部結果が不明なら自動再送せずReconcileする。「副作用が必ず一度成功する」というExactly-once保証とは区別する。

## 3. 現行SystemDesignとの照合・修正

別冊§1〜§12に対し、正本の構成図・接続Schema・Fact / Context・認可・Controller・Budget・Aggregate / Witness・
受入・移行を確認した。安全基盤はSecret / Lease / Collection / Erasure / TPMの接続条件を照合した。
これは約8,700行全体の形式検証や、製品コードの網羅的Security Reviewではない。

| ID | 更新前の読み違いを起こす最小例 | 修正した箇所・内容 | 根拠 / 文書Regression |
| --- | --- | --- | --- |
| CUR-01 | §3 / §4.2の図ではPlannerの全出力がExecutionPlanに見える。context_requestでもExecutionを作り得る | PlannerOutputのaction / context_request分岐と、後者の共通Controller・有限Context再構築への戻りを明示 | 別冊§6.2 / §7.1、AC-12。両図の分岐とExecutionなし表記を検査 |
| CUR-02 | 図にはAnalyzer経由のKnowledge更新しかなく、Analyzer失敗時に検証済みFact保存まで止め得る | §3 / §4.2へSource Normalizer / Knowledge ServiceからCurrent Knowledge / Critical Witnessへの独立経路を追加 | 別冊§6.2 / §7.2、AC-15。Source Rule / Proof / Current認可とAnalyzer前の独立確定を明示 |
| CUR-03 | 簡略図でGoal達成を先に見ると、進行中Executionの回収やCurrent状態検査を省略し得る | §3 / §4.2 / §26でRead前の共通Guard、Pending Execution優先、Goal結果の同じControllerへの復帰を明示 | 別冊§6.1、AC-01 / 14。§4.2 / §26の優先表記と、§3の直接COMPLETED短絡がないことを検査 |

CUR-02は旧研究レビューC-07の詳細本文修正が構成図へ十分に反映されていなかった箇所である。
今回の変更は新規の状態・権限・Ruleではなく、既存の規範を図にも適用したもの。
図は第二の判断表ではなく、Current状態が変われば同じControllerで上位条件を再検査する。

Goal三値集約、廃止mode / Routing Head / Confidence閾値、Observation区分、契約Digest、Budgetの非Reset、
旧Schema拒否は、今回照合した現行本文と別冊の間で追加の衝突を確認しなかった。
§41、旧レビュー、SystemDesign_update.mdの旧記述は履歴であり、現行Runtime義務として読み戻さない。
既に解消済みのAGENTS.mdの消去規則不一致も、現状では再発を確認していない。

## 4. 次工程と今回進めた範囲

既存の[作業分解T1〜T8](ai-control-research-review.md)を継続し、別系統の実装計画は作らない。

| 順序 | 作業 | 状態 / 終了条件 |
| --- | --- | --- |
| N1 | 現行正本の一次研究評価 | 完了。本書§1〜§2。設計の方向性と保証の限界を区別 |
| N2 | 正本の矛盾・図の整合 | 完了。CUR-01〜03を修正。別冊と既存安全契約は維持 |
| N3 | 最初の実装Slice・独立Oracle・障害条件の具体化 | 文書準備完了。[実装準備書](ai-control-implementation-ready.md)へMock契約、8 Trace、T1〜T8、D4確認項目を記録。実Schema / Corpus / 製品テストは未実装 |
| N4 | 再実行可能な文書検査 | 完了。既存検査へ図のRegressionと準備書のAC対応検査を追加。結果は§6 |
| N5 | 正本変更の人間レビュー・mainへの採用 | 未実施。未コミットの文書を採用済みcommitとみなさない。Codexによるmergeは行わない |
| N6 | PRへの正式な取込み・実装再開権限 | BLOCKED。exact-HEAD refresh / checkpoint / 単回Design Approvalと正式Requestが必要 |
| N7 | Phase 0C安全基盤・D4採否検証 | 未着手。権限確認後に現Phase全不変条件Familyを実装・回帰試験し、要求される実機EvidenceとPhase Gateを満たす |
| N8 | Phase 1のMock Agent Loop | 未着手。Phase 0C PASSとPhase 1権限の後、T1＋T2を最初のSliceとしてT3〜T7へ進む |
| N9 | Phase 2の実Local LLM評価 | 未着手。Phase 1 PASSとPhase 2権限の後、T8 / D11の300 Runと履歴Oracleを評価 |

## 5. GitHubの読取確認と実装境界

2026-09-06に[PR #3](https://github.com/Pizza73/RedTeam_Agent/pull/3)の情報と全340件のコメントを読取取得した。
取得時点でopen / 未merge、HEADは`ae09f40f6b593060d060cfb9a5090e0de4e2875d`。
base branchはmain、取得したbase SHAは`43d0506fcc24ee7ee414b6c872f3a522d5c49059`。

同じHEADにBindingされたgithub-actions[bot]の[Gate](https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692085)は
phase-0c / CHANGES_REQUESTED / BLOCKED_LIMIT / INVARIANT_FAMILY_RECURRENCEを記録している。
同botの[停止通知](https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692776)も、局所PatchやGeneric Resumeではなく
coherent redesignと専用再開承認を要求している。

これは停止を尊重するための読取証拠であり、全Phase Label / prior PASS祖先関係 / Current checks / Requestを
再検証して実装権限を確定したものではない。Gate内の旧check結果も現在のlive CI PASSとして転用しない。
実際の再開時には、その時点のHEADと全権限Chainを再取得する。
ローカル作業branchは`codex/phase-0c-coherent-redesign-v3`、HEADは`e51d9bd81a216d81ea8c14f7d6bd0c2f4f648caa`。
今回の文書差分は未コミットであり、そのHEADにもGitHubの実装HEADにも含まれると主張しない。

PRへの投稿・Label変更・Workflow起動・Runner起動・commit・push・merge・製品実装は行っていない。

## 6. 検証記録

検査対象は文書と固定された純粋参照モデルのみ。製品の認可、状態永続化、実Adapter、LLM、TPMを通していない。

| 実行したコマンド | 結果 |
| --- | --- |
| `.venv/bin/python docs/review/validate_ai_control_design.py` | exit 0。16文書のリンク / Fence、AI-01〜12とAC-01〜20の対応、Goal 240組合せ、Controller 384組合せ・9分岐、unknown共通経路128組合せ、不正入力34件拒否、廃止Runtime 12パターン、接続Model 5種、Python例51 BlockのASTを検査 |
| 同Scriptの追加Regression | 3構成図の必要経路・順序を確認し、逆転・欠落等の文書Mutation 13件を拒否。準備書T1〜T8の明示AC対応20/20、Trace見出し8本を検査。実Traceの実行ではない |
| 同Scriptの既存消去規則Drift検査 | レビュー済みAGENTS記述と空白違い3件一致、不正Mutation 18件拒否。実消去や認可権限の検証ではない |
| `.venv/bin/python -m ruff check docs/review/validate_ai_control_design.py` | exit 0、All checks passed。今回更新した検査Scriptだけを対象 |
| `.venv/bin/python scripts/ci/validate_automation.py` | exit 0、AUTOMATION_VALIDATION=PASS。自動化定義の静的検査でありRunner起動ではない |
| `git diff --check` | exit 0、診断なし |

未追跡ファイルも含む本ターン差分は、次の各コマンドで診断出力なしを確認した。
各exit 1はno-index比較で差分があるためであり、Whitespace診断や製品テスト失敗を意味しない。

```text
git diff --no-index --check /tmp/redteam-current-review-yWf48I/SystemDesign.before.md SystemDesign.md
git diff --no-index --check /tmp/redteam-current-review-yWf48I/validate_ai_control_design.before.py docs/review/validate_ai_control_design.py
git diff --no-index --check /dev/null docs/review/current-design-research-assessment.md
git diff --no-index --check /dev/null docs/review/ai-control-implementation-ready.md
```

作業前Backup: `/tmp/redteam-current-review-yWf48I`。
本ターンの編集対象はSystemDesign.md、既存の文書検査Script、本書、実装準備書の4ファイル。
SystemDesign.mdは本ターン開始時から81行追加 / 31行削除、検査Scriptは90行追加。
既存の別冊・比較用スナップショット・AGENTS・関連要件・Phase Prompt等15ファイルは作業前後の`sha256sum`で一致を確認した。
対象はAGENTS.md、SystemDesign_AI_Control.md、SystemDesign_update.md、docs/requirements.md、
docs/safety-invariants.md、docs/acceptance-criteria.md、docs/implementation-status.md、docs/threat-model.md、
docs/review/phase-0c-coherent-redesign.md、docs/review/systemdesign-canonical-adoption.md、
docs/review/ai-control-research-review.md、docs/review/systemdesign-ai-agent-design-review.md、
prompts/phases/phase-0c.md、phase-1.md、phase-2.md。既存の未コミット作業を含むGit全差分とは区別する。

未実行: 製品Regression / Stateful Test、型検査、Coverage、正式Phase Gate、実LLM 300 Run、swtpm / 実TPM、D4実機消去試験。
次の仕様追加は別冊§11.2の反例形式に従う。抽象的な「もっと賢いLLMが必要」だけでは契約を増やさない。
