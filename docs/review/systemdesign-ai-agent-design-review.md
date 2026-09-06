# SystemDesign.md AIエージェント設計レビュー

## メタ情報

- レビュー対象: `SystemDesign.md`(レッドチーム演習支援AIエージェント 要件定義)
- レビュー日: 2026-09-03
- レビュー観点: **AIエージェントとしての設計品質および全体構成**
- 除外範囲: セキュリティ機構そのものの妥当性(暗号鍵・TPM・Quarantine・監査整合性等)は本レビューの評価対象外
- 補足: 参照した仕様は全文通読済み。Mission / Goal / Context / ループの各モデルは実テキストで確認。定量値は `SystemDesign.md` および `src/` の実測に基づく。

---

## 1. 総評

設計の一貫性と規律は非常に高い。「AI=考える / プログラム=状態管理・制約確認・実行」という分離、LLMを認可判断から排除する原則、責務境界の固定、Source of Truthの単一化、Retryの三分類、三値Goal評価は、いずれも堅実で高品質である。Revision Summaryにより主要な論理矛盾は既に解消済みで、現行テキストに致命的な内部矛盾は見当たらない。

一方で二つの構造的な偏りがある。

1. **設計品質面**: エージェントが「賢く・効率的に動く」ための設計投資が、統治・整合性機構に比べて相対的に薄い。弱点は **Context設計・Plannerの情報環境・失敗からのリカバリ** に集中している(第3章)。
2. **構成面**: 分割の軸がデータ型・バインディング単位に寄りすぎ、**トランザクション境界・平面バランス・Phase荷重・エージェント本体**という大きな構造への配慮が相対的に薄い(第4章)。

---

## 2. 強み

### エージェント設計としての強み

- **責務境界の固定**(`Planner=Proposal / Policy=Authorization / Executor=Enforcement`)が徹底され、LLM出力を実行根拠にしない原則がモデル定義(Adapter/Risk/System IDをProposalから排除)まで一貫している。
- **三値Goal評価**(`achieved / not_achieved / indeterminate`)で「未達」と「判定不能」を丸めない設計は、この種のエージェントで頻繁に問題になる箇所を正しく捉えている。
- **型付きSuccessCondition**(Windows Token / AD Group SID / Linux UID/Capabilityを一次元Privilegeで比較しない)はAD/Linuxの権限の現実に即した優れた設計。
- **ループ有限化**(多様な上限 + Action Fingerprintによる同一行動検出)が堅実。

### 構成としての強み

- **単一オーケストレーション権威**(原則 #18): Workflow/State/Checkpoint/InterruptをLangGraphに一元化し、競合するワークフローエンジンを持たない。
- **Source of Truth表(17.1)**: 38の所有を明示し二重管理を構造的に禁止。復旧時の優先順位(Checkpoint → DB → Adapter)まで規定。
- **Calculate / Persist分離パターン**の反復適用(pure node + idempotent upsert)が一貫した設計語彙になっている。
- **Snapshotはdigestだけでなく生成元Immutable Snapshotも保持**し、「digestだけ残して根拠を失う」アンチパターンを構造的に回避。

---

## 3. 設計品質レビュー(コンポーネント挙動)

### C1. Context取得が完全に決定論的で、適応的リトリーバルの経路がない 【High】

**問題**: Context SelectorはIndex Metadataのみを読む決定論的コンポーネントで、Plannerが見る知識は `Mission / Current Target / Candidate Session / OperationalPhase` から機械的に選ばれる(Section 18)。意味検索や関連度ランキングの規約は仕様化されておらず、Plannerが「特定の情報がもっと欲しい」を表明する経路が存在しない(明示的なdiscoveryアクションを取る以外に)。

**影響**: リコール不足。既にKnowledge Baseにある事実をPlannerが見落とし、不要な再調査アクションを繰り返す/判断精度が落ちる。Section 30は「不要な情報による判断精度低下の防止」を掲げるが、逆方向の「必要情報の取りこぼし」への対策が手薄。

**提案**: (a) Selectorの候補選定・ランキング規約(型ごとの関連度、上限、優先順位)を仕様に明示する。(b) Plannerが構造化された「情報要求ヒント」を提案でき、次IterationのSelector入力にだけ反映する限定フィードバックを検討。認可判断に使わずretrievalヒントに限定すれば、LLM不信の原則と両立する。

### C2. Plannerに永続的な計画・作業記憶がなく、戦略連続性がKnowledge Base依存 【High】

**問題**: 仕様全体を検索しても `rationale / reasoning / hypothesis / strategy / scratchpad` に相当するフィールドは皆無。意図の担い手は `Mission.objectives`(静的・人間定義)と提案ごとの `objective: str`(揮発)だけ。Plannerは毎Iteration、confirmed findings + 直前result reference + phaseから戦略をゼロから再導出する。

**影響**: 多段の攻撃連鎖(Kerberoastingの途中段階、ADCS悪用の準備、あと1ホップの横展開など)で「今どの戦略の何ステップ目か」を保持できず、thrashや戦略のブレが起きやすい。`max_same_action_retries=2` で早期停止し、`max_iterations=50` と相まって複雑シナリオでは進行が滞りやすい。原則 #19「同じ情報に複数のSource of Truthを作らない」との意図的なトレードオフだが、安全側に振りすぎてエージェント有効性を削っている。

**提案**: 「Working Hypothesis / Plan Thread」をconfirmed findingとは別provenanceの一級Knowledge Baseエンティティとして持たせ、Contextに含める。決定論プログラム(Reducer/Manager)が管理する構造化状態なので、LLMの自由メモリを作ることにはならず原則 #19とも両立する。

### C3. Plannerへのフィードバックが薄く、DENY / 利用不能の理由が不可視 【High】

**問題**: Plannerが見るのはAvailableToolSnapshot(利用可能Toolのみ)とRedactedなScope/Policy Summaryだけ。なぜToolが除外されたか、なぜ前回DENYされたかをPlannerは知らない。`max_consecutive_policy_denials=3` は低く、理由を見られないPlannerが近い提案を数回出して停止 → Human介入頻度が上がり自律性が落ちる。

**影響**: 「失敗して回避する」能力が制約される。`Scope False-Allow=0` は達成できても、「Scope内で有効な提案に収束できるか」は別問題で、そこが設計上手薄。

**提案**: システム内には既に構造化reason code(`PolicyDecision.reason_codes`、`GoalReasonCode`)がある。これらをredactedでPlanner Contextへ返すフィードバックチャネルを定義し、提案改善のヒントに限定する(認可には使わせない)。

### C4. Knowledge Reducerの決定論的エンティティ解決が過小仕様 【Medium-High】

**問題**: Analyzerは `subject_ref / object_ref: str` をLLM生成し、Reducerが「重複排除・Conflict検出」を決定論的に行う設計(Section 11)。しかし異種ツール出力間のエンティティ解決(`DC01` == `dc01.corp.local` == SID)は本質的に難しく、ref → Knowledge Base正規エンティティの解決契約が未定義。LLMがIteration間でrefをブレさせると、dedup失敗(Knowledge Base肥大)か誤マージ(誤findings)。

**影響**: Goal Evaluatorはconfirmed findingに依存するため、エンティティ解決の質がGoal判定とPlanner判断の両方に直結。ここが弱いとエージェント全体の信頼性が崩れる。

**提案**: (a) 型ごとの正規化キー(HostはFQDN/SID優先、PrincipalはSID優先など)とref解決アルゴリズムを仕様化。(b) 曖昧一致はconfirmedへ昇格させず「候補マージ」状態に留め、純決定論で解けない部分は明示的に別ルート(Human/追加検証)へ回す。

### C5. Plannerがresultを直接見ず、Analyzer→Reducer→Knowledge Baseのラグを挟む 【Medium】

**問題**: PlannerのCurrent Stateは「直前の正規化済みResult Reference」であり、生に近い出力は見ず、confirmed findingに落ちた情報だけが次IterationのContextに乗る。findingに昇格しなかった微妙なシグナル(エラーメッセージ中のヒント、部分列挙結果)がPlannerに届かない。

**影響**: 判断精度、特に失敗のリカバリ。Tool Error時は「Analyzerへ返して再計画」とあるが、失敗が一級findingとして確実にContext化される保証が読み取れない。

**提案**: 直近N件のExecutionResult要約(redacted)をContextに必ず含める、または失敗を `finding_type=execution_failure` 等で確実にKnowledge Base化し、ループ検知とPlannerの回避判断の両方に使う。

### C6. ローカルLLMへの構造化出力要求が高難度で、実現性リスク 【Medium】

**問題**: ExecutionPlanProposal(`CanonicalJsonObject` arguments、`strict=True` / `extra="forbid"`)やGoalのDiscriminated Unionなど、要求スキーマが複雑。Qwen/Llama系ローカルモデルはstrictなdiscriminated union + no-coercionで失敗しやすく、`max_validation_retries=3` でhard-failする。Capability Check(Section 6.2)はあるものの「合格 = 実運用で安定」を保証しない(Canaryは限定的)。

**影響**: エージェントの基本動作の安定性。Phase 1はMock Plannerなので、実Plannerの振る舞いはPhase 2まで検証されず、設計妥当性の検証が後ろ倒しになっている。

**提案**: 実モデル × 実Plannerスキーマの負荷/多様性テストをPhase 2前倒しで実施。緩和策(Toolごとにargumentsを小さく分ける、複雑Unionを段階生成する)を設計に織り込む。

### C7. Analyzerの `goal_evidence` と型付きGoal Conditionの接続が未定義 【Medium】

**問題**: Analyzerは `EvidenceCandidate.claim: str`(自由文字列)を出力するが、Goal Evaluatorは型付き `SuccessCondition` を決定論評価する。自由文字列claim → 型付きcondition_idへの対応経路が仕様化されていない。`EvidenceCandidate.condition_id` は存在するのでLLMがconditionを指名する想定に見えるが、その突合と検証ルール(誤指名の扱い)が不明確。

**提案**: Analyzer evidence → Knowledge Reducer → 型付きcondition評価の接続を、`condition_id` 突合と検証ソース(Session Manager/Artifact Store等)の対応表として明示する。

### C8. OperationalPhaseの意味が弱い 【Low】

Planner提案の分類ラベルに過ぎず、認可もRiskも特化挙動も駆動しない(将来のサブエージェントまで)。MVPでは実質vestigial。「Planner Contextのヒント兼監査ラベル」と割り切る旨を明記するか、明らかに不合理なPhase遷移(初手で `DOMAIN_CONTROL` 等)をループ監視の弱シグナルに使う程度に留めるのが妥当。

### C9. 自律性 vs Fail-Closedの姿勢を明示すべき 【Low】

Error taxonomyの多くがPAUSED / Human Reviewへ落ちる。ドメイン上正しい判断だが、「自律支援エージェント」という目的と頻繁な人手介入は緊張関係にある。有人監視を前提とする運用モデルを非機能要件に明記し、期待値(どのクラスの停止がどの程度の頻度か)を揃えるべき。

---

## 4. 構成レビュー(全体アーキテクチャ)

### 定量スナップショット

| 指標 | 値 | 出典 |
|---|---|---|
| Source of Truth(データ所有)の数 | 38 | Section 17.1 |
| Repository型(概念) | 40+(うち数個は役割総称) | 全文 |
| 推奨ツリーの .py モジュール数 | 101 / 約17機能パッケージ | Section 35 |
| 型付きErrorクラス | 35 | Section 28 ほか |
| 異なるdigestフィールド | 44 | 全モデル |
| 現行実装の .py | 約60(編成は仕様と相違) | `src/` 実測 |

全体構成は「単一エンジン(LangGraph)が統べる厳密な直線パイプライン」+「超細粒度の永続化層」+「digestによる密なバインディング網」で組み立てられている。三平面 — 知性層(agents/)/ 制御・認可層(policy, mission, tools, context)/ 永続実行・データ保護層(executor, storage, adapters, sandbox, logging)— の分離は明確。

### S1. Phaseへの荷重がPhase 0Cに偏在し、エージェント本体が最重フェーズの後ろに置かれている 【High】

**問題**: Phase構成 0A→0B→0C→1→…→5 のうち、0Cが突出して過積載。Artifact Store / Secure Ingestion / Quarantine / Encryption Key Provider / TPM witness / Secret版管理ライフサイクル / Redaction / Audit hash chain / Sandbox interface / lease+fencing を一つのフェーズに束ねている。実際、プロジェクトが停止(Design Stop)しているのも0C(coherent-redesign v3)。

**構造的含意**: エンドツーエンドのエージェントループ(Phase 1)は、Phase 1のループ図にSecure Ingestion / Encrypted Quarantineが含まれるため、最重・最難・現在ブロック中の0Cを依存として要求する。つまり「このエージェント構成は実際に機能するのか」という検証が、セキュリティ基盤の全実装の後ろに構造的にゲートされている。安全性のde-riskとしては正しい順序だが、エージェント(知性層)のde-riskとしては逆順。

**提案**: (a) 0Cを「取込・監査の最小実体」と「暗号鍵・TPM・leaseのProduction堅牢化」に分割し、後者をPhase 1の後ろへ回す。(b) あるいはmock Secure Ingestionで通す薄い縦スライスを0C完了前に一度貫通させ、エージェント構成の妥当性を早期に確認する。

### S2. 永続化層が「データ型」で分割されており、トランザクション境界と一致していない 【Medium-High】

**問題**: 38のSoT / 40+リポジトリはデータ型ごとに切られている。しかし仕様は随所で複数リポジトリの同一トランザクションcommitを要求する:

- Dispatch Claim消費 + 現在 `CONFIRMED` 検証(Secret Version Repo + Lifecycle Event Repo + Claim Repo)を同一OCC
- `mission_state_version` + `authorization_epoch` を同一Transaction
- Auditの採番 + 直前Hash取得 + Insert + Chain Head更新を同一Transaction

論理的に独立分割したリポジトリ群が、実は同じ整合性境界を共有している。分割軸(データ型)と一貫性境界(トランザクション)がずれると、実装で「どのリポジトリが一緒にcommitすべきか」が散在し、境界越えの整合性が事故りやすい。

**提案**: リポジトリをトランザクション/集約(aggregate)境界で束ね直す。例: `Execution Dispatch Aggregate`(execution state + dispatch claim + secret version binding)を一つの整合性ユニットとして定義し、内部リポジトリはその配下に置く。SoT表は所有の明示には有効なので残しつつ、「同一Transactionで動く集合」を別図で規定するのが健全。

### S3. 44のdigestが形成する密なバインディング網に、単一の規範的カタログがない 【Medium-High】

**問題**: `authorization_digest` はMission/Epoch/proposal/ToolRef/Adapter/Session/引数/Targets/DataAccess/Risk/Policy/Registry/Snapshot/各種Capability digest… を含む、といった多対多のバインディングが44のdigestとして全セクションに散在。あるSecurity-relevantフィールドの変更が、複数コンポーネントのdigest再計算に波及するimplicit coupling。各digestの対象フィールド集合は正しく定義されているが、テキスト上に分散しており、単一の規範的「digestカタログ」がない。実装では `canonical/digest.py` と `policy/digests.py` に分かれ、真実源が二重化しかねない。

**提案**: 正規のdigestカタログ(digest名 → 対象フィールド集合 → 除外フィールド → canonicalization規則)を単一表として規定し、canonicalization/digestを一つのモジュールが所有する。digestは本システムの主要な結合手段であり、ここを一元管理しないと構成の整合性が崩れる。

### S4. オーケストレーションハブへの集中(1 Iteration ≈ 15+ ノード) 【Medium】

**問題**: Planner前だけでSession Refresh → Selector → CalcAuth → PersistAuth → Builder → CalcAvail → PersistAvail → Snapshotの8段、後段にRevalidation → Policy → Executor → Quarantine → Ingestion → Analyzer系 → Reducer → Goal。1反復で15以上のノードと15以上のリポジトリに触れる直線グラフ。原則 #18で制御をLangGraphに集中させた結果、`graph.py / routing.py` が全条件分岐・全エラー経路を抱える複雑性ホットスポット(hub)になる。

**提案**: LangGraphは「フェーズ遷移の粗い骨格」に留め、Planner前の8段のような決定論的で不可分な系列を一つの複合ノード(サブグラフ or 決定論オーケストレータ)に凝集させる。制御の一元性(#18)は保ったまま、トップレベルグラフのノード数を減らせる。

### S5. 知性層がモジュール比で約3%しかない — 構成がエージェント本体に投資していない 【Medium】

**問題**: `agents/`(planner, analyzer, analysis_repository)は101モジュール中わずか3。設計品質面の弱点(C1〜C3: Plannerの情報環境)は構造レベルでも裏付けられる — 構成の重心が制御・データ保護に寄り、エージェントの判断品質を支える構造(Context戦略・作業記憶・フィードバック)に対応するモジュールがそもそも存在しない。

**提案**: 知性層に「Planner Information Environment」を担う構造(例: `agents/planner_context.py`、Knowledge Base内のPlan-Threadエンティティ)を構成要素として明示し、制御層と対等に設計対象へ引き上げる。

### S6. 推奨ツリー(Section 35)と実装ツリーの構造乖離 【Medium】

**問題**: 実装は既にSection 35と別編成。

- モデル: 仕様は各ドメイン配下(`mission/models.py`, `policy/models.py`…)、実装は中央集約 `models/` に13分割。
- リポジトリ: 仕様はドメイン配下に個別(`executor/result_repository.py`…)、実装はフラットな `repositories/` パッケージ。

どちらも合理的な選択(層で束ねる vs ドメインで束ねる)だが、規範文書と実コードの構成が矛盾している。

**提案**: 実装の編成(中央 `models/` + フラット `repositories/`)が意図的ならSection 35を実態へ更新する。そうでなければ整合させる。「推奨」の位置づけ(規範か参考か)も明記すべき。

### S7. パッケージ凝集度の偏り 【Low-Medium】

**問題**: `policy/` が認可(engine, scope, data_access, target_normalizer)+ Context認可(context_authorization)+ 承認(approval, request/record repo)+ execution_predicate + digestsを一手に持ち肥大。一方 `executor/` はディスパッチ制御 + result ingestion state + normalization + raw_result_sink + reconciliationを混載。Context認可・Human Approvalは独立性が高く、IngestionはExecutorと関心が別。

**提案**: `context/`(認可含む)と `approval/` を `policy/` から独立させ、Ingestionを `executor/` から `ingestion/` へ分離すると、平面間の境界がモジュール境界に一致する。

### S8. Composition Root / DI配線の構成が未設計 【Low-Medium】

**問題**: 仕様は「Composition Rootで固定したAdapter Dispatch Port」「Composition Root fixed Trusted Clock」等、Composition Rootを信頼アンカーとして多用するが、そのComposition Root自身が100+モジュール・40+リポジトリ・複数Key Domain・TPMをどう配線するかは設計されていない(`main.py` が1つあるのみ)。細粒度分割の必然的コストで、配線の複雑さと「どこで何を固定するか」の一貫性が実装リスクになる。

**提案**: Composition Rootを独立した設計対象として節を起こし、(a) 各Trusted依存(Clock/Port/Key Provider/TPM Witness)の生成・固定点、(b) リポジトリのライフサイクルとトランザクション境界の注入、(c) 起動時Capability/Provisioning検査の順序、を規定する。

---

## 5. 優先度サマリ

### 設計品質(コンポーネント挙動)

| # | 指摘 | 優先度 | 主リスク |
|---|---|---|---|
| C1 | 決定論Contextに適応的retrieval経路なし | High | リコール不足・非効率 |
| C2 | Plannerに永続的計画・作業記憶なし | High | 戦略連続性の喪失・thrash |
| C3 | DENY/除外理由がPlannerに不可視 | High | 収束不能・自律性低下 |
| C4 | 決定論エンティティ解決の過小仕様 | Medium-High | Goal判定/Knowledge Baseの信頼性 |
| C5 | Plannerが生resultを見ずラグを挟む | Medium | 失敗リカバリの弱さ |
| C6 | ローカルLLMのstrict構造化出力の実現性 | Medium | 基本動作の安定性 |
| C7 | Analyzer evidence↔型付きCondition接続未定義 | Medium | Goal接続の穴 |
| C8 | OperationalPhaseの意味が弱い | Low | 仕様の冗長 |
| C9 | 自律性 vs Fail-Closed姿勢の未明示 | Low | 期待値のズレ |

### 構成(全体アーキテクチャ)

| # | 指摘 | 優先度 | 主リスク |
|---|---|---|---|
| S1 | Phase 0C過積載・エージェント本体が後段にゲート | High | 検証順序の逆転・停滞 |
| S2 | データ型分割とトランザクション境界の不一致 | Medium-High | 越境整合性の事故 |
| S3 | digest網の密結合・規範カタログ不在 | Medium-High | 真実源の二重化 |
| S4 | オーケストレーションハブへの集中 | Medium | 複雑性ホットスポット |
| S5 | 知性層が構成上marginal(約3%) | Medium | 判断品質への投資不足 |
| S6 | 仕様ツリー vs 実装ツリーの乖離 | Medium | 規範と実装の矛盾 |
| S7 | policy/・executor/ の凝集度偏り | Low-Medium | 境界の不一致 |
| S8 | Composition Root/DI配線が未設計 | Low-Medium | 起動・配線の実装リスク |

---

## 6. 結論

本設計は「安全性のための分割規律」としては非常に高品質であり、SoTの明示・単一オーケストレーション・Calculate/Persistパターンは模範的である。

改善の重心は二つ。

1. **エージェント本体の情報環境(C1〜C3)** — 共通根は「Plannerが何を見て、何を記憶し、何のフィードバックを得るか」が設計されていないこと。この3点はセキュリティの骨格を崩さず実効性を大きく引き上げられる。次点でC4/C7(Analyzer/Reducer → Knowledge Base → Goalの知識確定パイプラインの穴)。
2. **構成の束ね直し(S1〜S3)** — Phase分割の見直しで縦スライスを早期に貫通させ(S1)、集約とdigestカタログで細粒度分割を整合性境界に束ね直す(S2/S3)。安全性の骨格を崩さずに構成の「重さ」を実装可能な形へ整理できる。
