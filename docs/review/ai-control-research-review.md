# AI制御設計の研究比較・整合レビューと次工程

調査・更新日: 2026-09-06

> このReport本文はDraft統合時点の調査・検査履歴である。同日後続の承認によりW5の文書反映を実施した。
> 現行正本、実際の変更範囲、検査結果、後続承認で解消したAGENTS.mdとの規範不一致は[正本反映レポート](systemdesign-canonical-adoption.md)を参照する。
> 下記の「正本未変更」「11ファイル一致」は当時の作業境界であり、後続変更まで未変更と主張しない。

対象: [AI制御仕様](../../SystemDesign_AI_Control.md) `ai-control-v1-draft-r2` と
[統合Draft](../../SystemDesign_update.md)。ユーザー指定により前者を優先する。
これは設計レビュー・文書検査の記録であり、正式PR Review、Phase PASS、実装再開の認可ではない。
ローカル参照HEADは `e51d9bd81a216d81ea8c14f7d6bd0c2f4f648caa`。Draftは未コミットのため、このSHAに含まれると主張しない。

## 1. 評価結論

**限定された登録Tool環境における設計方針は妥当。製品としての安全性・達成能力は未検証。**

LLMの候補生成、Current Evidenceによる事実判定、モデル外の実行認可を分離する構造は、
外部検証器で計画候補を検査する研究の考え方と整合する。ただし研究と同じ検証器・モデルを実装したわけではなく、
その形式保証を継承したとはいえない。[LLM-Modulo §3](https://arxiv.org/html/2402.01817v2)

旧版の例外Modeを増やすより、共通Controller、登録済みActionContract、区分別の情報取扱いへ整理する方針を維持する。
これは本プロジェクトへの設計上の推論であり、「この構成なら指摘が出ない」と研究で証明されているわけではない。
残る主な作業は、新しい制御方式の追加ではなく、契約の具体化、Source Ruleの適格性、独立Oracleと境界試験である。

## 2. 一次研究との比較

論文本文または著者公開ページを確認した。網羅的なSystematic Reviewや2026年モデルの性能比較ではない。
古いモデルの実験値を現在のLocal LLMの性能予測へ転用しない。

| 研究・確認箇所 | 研究で述べられること | 本設計との対応・評価 | 適用限界 |
| --- | --- | --- | --- |
| [ReAct, ICLR 2023, 実験・誤り分析](https://arxiv.org/pdf/2210.03629) | 推論・行動・観測を反復する。過去の推論・Actionを繰り返す失敗も報告 | §2 / §6 / §9の一つずつ実行して再計画する構成と有限Budgetは整合 | 認可、停止、Exactly Onceの証明ではない。形式だけでループを解消できるとはいえない |
| [LLM-Modulo, ICML 2024, §3](https://arxiv.org/html/2402.01817v2) | LLM候補に外部Criticを適用し、Hard Constraintの正しさは検証器に依存する | §2 / §5 / §8で提案とRule / Contract / Policyの検証を分離する方向を支持 | Position / Framework論文。局所前提検査は全計画の因果・資源整合性や完全性の証明ではない |
| [SayCan, 2022, Approach / Limitations](https://say-can.github.io/) | Goalへの有用性と現在状態でのSkill成功見込みを分けて選択する | §5で有用性と実行前提を分ける考え方は整合 | ロボットの学習Affordanceは認可判定ではない。確率でScopeや必要前提を相殺しない |
| [CaMeL, 2025 v2, §5 / §6.4 / §9](https://arxiv.org/html/2503.18813v2) | 独自Interpreterと出所・許可ReaderのCapabilityでデータ流とTool呼出しを制御する。Policy管理負荷と残る攻撃も説明 | §3 / §7 / §8の出所検証とモデル外Policyは方向として整合 | 本設計のPlannerは非信頼Observationを見るため同じ制御フロー分離ではない。候補の誘導・許可内の無駄操作は残り、完全なInjection防止とは評価しない |
| [AgentDojo, NeurIPS 2024, §3.1 / §3.4](https://arxiv.org/html/2406.13352v3) | 明示的な環境状態で評価し、正常時Utility・攻撃下Utility・攻撃成功を分ける | §10 / §11の独立Oracle、正常達成と攻撃下達成の分離は整合 | 固定Corpusは未知・適応的攻撃への保証ではない。全停止で安全性だけを満たす実装は不合格にする |
| [τ-bench, 2024, §4](https://arxiv.org/html/2406.12045v1) | 最終DB状態を比較し、反復すべての成功をpass^kで測る。最終状態だけでは承認違反を見落とし得る | §11でpass^3を診断報告し、最終状態に加え操作履歴を検査 | pass@3と区別する。3回の診断値や300 Runだけで高信頼性を証明せず、未実測の新閾値を作らない |
| [Intrinsic self-correction, ICLR 2024, §3–5 / Limitations](https://arxiv.org/pdf/2310.01798) | 対象モデル・推論課題では外部Feedbackなしの自己修正が改善せず、悪化する場合がある | §11の自己採点禁止、反例・決定論的検査を根拠にする方針を支持 | すべての現行LLM・文章修正・コード修正が不可能という結論ではない。LLMレビューは候補発見に利用できる |

### 研究から証明されない点

- ActionContractの正しさは登録・Source検証と試験で担保する必要がある。名前だけで正しい検証器にはならない。
- false / unknownの区別、探索上限8 / 64 / 32、情報取得3回は本製品の規範的選択であり、研究から導かれた最適値ではない。
- 観測不能なunknownでは、安全な準備経路が実世界に存在しても停止する場合がある。限定モデルの既知の制約として扱い、完全プランナーと称さない。
- Goalの最終状態に加えScope、Approval、単回Dispatch、情報流出の禁止を含む実行履歴を検査する。
- Secret / Lease / Fencing / TPM消去方式の実装や実機適格性を、上記AI論文で検証したことにはならない。D4は引き続き`NOT_EVALUATED`。

## 3. 矛盾の反例と修正内容

旧位置は更新前の章を指す。旧規則の履歴は統合Draft §41へ限定し、新Runtimeの義務として重ねない。

| ID | なぜ問題か・最小反例 | 今回の修正 | 主な確認先 |
| --- | --- | --- | --- |
| C-01 | Goal証拠がunknownで観測には準備Sessionが必要。旧Read-only調査経路では適法な準備も排除される | Modeを廃止。GoalとAction前提を分けて共通候補化・通常認可へ | §3 / §4.2 / §24.1 / §26、AC-02〜04 |
| C-02 | 新仕様で廃止したRouting Headを旧Plan / Envelope / Digest / Witnessが要求し、新Planを保存・認可できない | 旧Field / Class / 現行DB一覧を削除。契約・前提Digest、Mission / Epoch、Budget、Claimへ保護を分担。Witness Policyは新v5へ移行 | §6 / §8 / §22 / §32 / §34.2、AC-13 / 17〜19 |
| C-03 | 同じEvidenceでもLLM Confidenceの変動でGoal合否が変わる | minimum_confidenceを現行Schemaから除去。LLM値はllm_confidence補助Metadataへ限定 | §11 / §16 / §24、AC-07 |
| C-04 | 未確認Observation一件でconfirmedを矛盾化し、Goalへ影響できる | ObservationにはConflict参照だけ追加。検証済み根拠同士のConflictとRuleに基づく訂正を区別 | §11 / §16.3、AC-05〜06 |
| C-05 | 新仕様ではObservationを未確認Contextとして読めるが旧internal_knowledgeは全件にFactProofと確定Headを要求する | 区分別Grant / Read検査。確定ProjectionからObservation / Hypothesisを除外し、通常Audit・読取認可を維持 | §16.4 / §18 / §22、AC-08 / 18 |
| C-06 | all(false, unknown)を一律Handlerへ送ると新仕様に不一致。集約boolでは未達と不明も区別できない | 集約statusを三値化、all / anyの表へ統一。個別unknown保持、改ざん・認可異常は集約外のSecurity Error | §24 / §24.1、AC-10 |
| C-07 | 図をそのまま実装するとAnalyzer失敗で検証済みFact保存まで止まる | Ingestion / Normalizer / Knowledge Serviceの確定処理をAnalyzerから独立させる | §11 / §26、AC-15 |
| C-08 | 本文を修正しても旧F3 / F4 / D7受入が旧Mode復帰を要求し、両立しない | Phase内AI受入、D7 / F3 / F4、D11 Corpus割当て、移行規定を新仕様へ統合 | §36 / §37 / §38、AI制御仕様 §12 |

一つのexact ToolRefに一つの契約、Branch単位の循環検出、予測効果のMemo混入禁止、Candidateの閉じたSchemaと
Source BindingもAI制御仕様§5.3へ明記した。実装境界の明確化であり、新しい権限ServiceやLLM多数決は追加していない。

## 4. 次工程の作業一覧

「完了」は記載成果物だけを意味し、製品PhaseのPASSではない。

| 順序 | 作業 | 成果物 / 終了条件 | 現状 |
| --- | --- | --- | --- |
| W1 | 一次研究との比較 | 主張・対応・限界を本Reportに記録 | 完了 |
| W2 | Draftの統合 | Schema、図、Aggregate / Digest / Witness、受入から旧AI契約を整理 | 完了。下記範囲限定の検査を実行 |
| W3 | 再実行可能な設計検査 | 参照モデル列挙、接続Field・廃止Runtime契約・リンク・構文検査 | 完了。Scriptをdocs/reviewへ保存 |
| W4 | 実装へ渡す試験単位の整理 | 次節T1〜T8をAC / Owner / Oracleへ対応付け | 作業分解完了。製品テストの実装・実行は未着手 |
| W5 | 正本採用のレビューと整合反映 | SystemDesign.md、受入・安全条件、Threat Model、Phase Promptへ承認済み仕様を反映。Schema / Catalog / Corpusも一変更単位にする | 後続の明示承認でAGENTS.mdを含む文書反映済み。消去規則の不一致は解消。正式レビュー・マージと実Schema / Catalog / Corpus移行は未実施 |
| W6 | 正式な実装再開権限の確認 | Current PR / full HEAD / Phase / blocking Gate / incorporated designへBindingした単回Design Approvalを検証 | 未実施。本タスクではGitHubの現行権限を取得・変更していない |
| W7 | 現Phaseの安全基盤実装・Gate検査 | 認可済みPhase 0Cの不変条件ファミリー全体とState-machine試験を完了 | 未着手。Phase順序を飛ばさない |
| W8 | Phase 1のAI制御をTest Doubleで実装 | T1〜T8と全ACの独立Oracle、Positive / Negative / Failure-path / Stateful試験 | 未着手。Phase 0C PASSとPhase 1権限の後 |
| W9 | Phase 2の実LLM品質評価 | 10 Family × 10 Fixture × 3 Run、既存Gateとpass^3等の診断を報告 | 未着手。実LLM能力・未知入力への性能は未検証 |

W5でrequirements.mdのLoop権限を緩めたり、Phase構成を変更したりする必要はない。
正本のrequirements / acceptance / safety / phase間で競合した場合は反映を止め、該当箇所を承認者へ提示する。
現状SnapshotはPhase 0CのDesign Stopを記録するが、Current-HEAD権限の代わりにはならない。
[ステータス文書](../implementation-status.md)に従い、Runner起動、Generic Resume、PR Merge / Pushは行っていない。

## 5. 実装へ渡す試験単位

架空Entity / Sourceと安全なAdapter Doubleだけを使用する。正解の環境State・許される履歴はFixture側が所有し、
LLM・製品Goal Evaluator自身をOracleにしない。

| 単位 | 対象Owner・作業 | 必須Oracle / Fault | AC対応 |
| --- | --- | --- | --- |
| T1 | Goal Evaluator / Controller | 三値表、初回達成のLLM / Dispatch 0回、優先分岐、全停止実装のUtility失敗 | 01, 10, 20 |
| T2 | Registry / Candidate Service / Precondition Evaluator | 準備→実結果確認→観測、false / unknown、循環・共有前提・探索限界、Scope不足の実Call 0 | 02, 03, 04, 11 |
| T3 | Knowledge / Reducer / Context Authorization | Confidenceだけ変更してもGoal不変、未確認ConflictでFact不変、区分偽装・Grant不在拒否、Head Rollback停止 | 05, 06, 07, 08, 18 |
| T4 | Gateway / Planner State / Mission Budget | Context Request・無効Action・仮説往復で枠消費、別Operation Reset拒否、Pause / Resumeで履歴維持 | 12, 16 |
| T5 | Policy / Executor / Dispatch Aggregate | 前提失効・Epoch / Approval変更・同時Claim、最後の枠の勝敗、Claim後Crash / 不明結果で再送0 | 13, 14, 17 |
| T6 | Secure Ingestion / Analyzer | Fact保存後Analyzer失敗でFact不変、Raw非公開、元Action再実行0、非信頼指示によるFact / Goal / Scope変更0 | 09, 15 |
| T7 | Migration / Versioned History Loader | 旧mode / Head / Confidence付き権限拒否、消費履歴維持、旧Executionの回収・消去のみ、新権限補完0 | 19 |
| T8 | Evaluation Harness / Corpus | 正常時・攻撃下Utility、安全性、履歴、pass^3、全Runの構成Digest・分母・失敗を記録 | 全AC、D11 |

最初の実装SliceはT1＋T2の決定論的な「未知Goal→前提確認→許可された準備→検証済み観測→達成」とする。
Scope拒否、Source失効、結果不明の対になる失敗Traceも固定する。これはPhase 1内部の着手順序であり、
Phase 0Cより前へ新しいThin-slice Gateを追加する指示ではない。
具体ToolごとのActionContract / Evidence Rule / Schema / Fixtureが揃うまでそのToolを有効化しない。

## 6. 実行した検証と未実行項目

検査Script: [validate_ai_control_design.py](validate_ai_control_design.py)

```text
.venv/bin/python docs/review/validate_ai_control_design.py
```

最終検査結果（2026-09-06、上記Script exit 0）:

| 検査 | 結果 |
| --- | --- |
| 3文書のリンク / Fence / 不変条件対応 | PASS。AI-01〜12を全20 Scenarioへ対応。20件の製品Test PASSではない |
| 三値Goal参照モデル | PASS。1〜4条件の240組合せ、可能な真偽の世界を列挙するOracle |
| Controller参照モデル | PASS。384組合せ・9分岐到達。unknownとnot_achievedの共通経路128組合せ |
| 不正入力・新旧Schema整合 | PASS。不正入力34件拒否、廃止Runtime契約12パターン、接続Model 5種 |
| Python例の構文 | PASS。AI仕様1 Block、統合Draft 50 Block。実Schema生成 / 型検査ではない |
| 差分Whitespace | 下記4コマンドとも診断出力なし。exit 1はno-indexで差分があるため |
| 既存作業の保全 | 正本等11ファイルの作業前後SHA-256一致。統合Draft内の安全基盤7領域も本文一致 |

```text
git diff --no-index --check /tmp/redteam-ai-reconcile-6yCzyH/SystemDesign_update.before.md SystemDesign_update.md
git diff --no-index --check /tmp/redteam-ai-reconcile-6yCzyH/SystemDesign_AI_Control.before.md SystemDesign_AI_Control.md
git diff --no-index --check /dev/null docs/review/ai-control-research-review.md
git diff --no-index --check /dev/null docs/review/validate_ai_control_design.py
```

一時Backupは今回の差分確認専用。常設の設計検査ScriptはBackupなしで再実行できる。
保全対象11件はAGENTS.md、SystemDesign.md、docs/requirements.md、docs/acceptance-criteria.md、
docs/implementation-status.md、docs/safety-invariants.md、docs/threat-model.md、
docs/review/phase-0c-coherent-redesign.md、prompts/phases/phase-0c.md、phase-1.md、phase-2.md。
本文一致7領域は統合Draftの§9〜10、§12〜15、§19、§21、§23、§29〜31、§33〜34.1.1。
§34.2等のAI接続を変更した範囲まで未変更と主張しない。

Goal Oracleはunknownを真偽の全組合せへ展開して期待値を算出する。
Controller検査は判断表との有限照合であり、仕様自体の正しさや外部状態を独立証明するものではない。
廃止語・Field検査も完全な意味的整合性証明ではなく、今回の反例に対する文書Drift検出である。

未実行: 製品テスト、Lint / 型検査 / Coverage / Phase Gate、AC-01〜20のIntegration Test、前提探索実装、
実Local LLM、実Adapter、TPM / D4実機Qualification。製品コード・CI・正本の保護文書は今回変更していない。

## 7. 残る採用条件

今回の対象範囲で確認した新旧AI規範の衝突は本文から解消したが、以下は未完了である。

1. 全接続Modelの実Schema生成・Strict境界試験と、具体Tool契約の適格性。
2. Current Source / Claim / Witnessを含む実装の競合・再起動・失効試験。
3. 実Local LLMでの正常達成能力とInjection下の達成能力。
4. 正本・移行計画の人間レビューと正式Phase再開権限、D4の実機保証。

未検証であることを「さらに別のLLM制御方式が必要」と即断しない。
追加仕様が必要ならAI制御仕様§11.2に従い不変条件・初期状態・遷移・期待との差を示す反例を先に記録する。
