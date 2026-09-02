# レッドチーム演習支援AIエージェント 要件定義

# 1. 目的

許可されたレッドチーム演習環境において、攻撃ライフサイクル全体を技術的に支援するAIエージェントを構築する。

対象範囲は、初期アクセス後の処理だけに限定せず、以下を含む。

* 初期侵入に必要な情報収集・判断の支援
* 対象システムの調査
* 現在取得しているアクセス権限・セッションの把握
* Windows / Active Directory 環境における権限拡大の支援
* Linux環境における権限拡大の支援
* 複数ホスト間でのアクセス範囲拡大の支援
* C2セッションを利用した操作
* 演習中に取得した情報の整理
* 現在の状況に応じた次の行動の計画
* 演習ゴールへの到達判定

ゴールは演習ごとに設定可能とする。

例:

* Active Directory環境で指定されたPrincipal ContextおよびGroup条件への到達
* Linux環境でroot権限への到達
* 指定ホストへのアクセス確立
* 指定された演習フラグ・条件の達成

本システムは、**明示的に許可された演習環境のみを対象とする**。

「初期侵入の支援」には、許可済みの情報収集および登録済みToolの選択・実行を含む。ただしMVPでは、実環境向けPayload生成、Implant生成、配布基盤の構築を実装しない。Mission開始時にSessionが存在しない状態を許容し、Operatorによる初期Session登録、または許可済みLocal / MCP Toolによる処理から開始可能とする。

将来、Payload生成や配布を対象に加える場合は、専用Tool、Scope Rule、Risk定義、Human Approval、監査要件を追加した上で明示的に有効化する。汎用シェルや自由形式コマンドを、この代替として自動実行させてはならない。

---

# 2. 基本設計方針

AIにすべてを実行させるのではなく、以下の2種類に処理を分離する。

## 2.1 AIを使用する処理

AIは主に「判断・分析」を担当する。

* Planner
* Analyzer

## 2.2 決定論的なプログラムとして実装する処理

正確性が要求される処理はLLMに任せない。

* Executor
* Session Manager
* Knowledge Base
* Knowledge Reducer
* C2 Adapter
* MCP / Tool Adapter
* Tool Availability Resolver
* Context Selector
* Scope / Policy Engine
* Context Authorization / Context Builder
* Goal Evaluator
* Mission Manager
* Execution State Manager
* Secure Ingestion / Sandbox Manager
* Artifact / Secret Store
* Audit Logger

基本方針は以下とする。

> AI = 考える
> プログラム = 状態を管理する・制約を確認する・実行する

責務境界を以下に固定する。

```text
Planner = Proposal
Policy Engine = Authorization
Executor = Enforcement
Analyzer = Observation Extraction
Knowledge Reducer = Knowledge Validation
```

## 2.3 判断権限と信頼境界

各コンポーネントの判断権限を以下に固定する。

| コンポーネント | 権限 |
|---|---|
| Mission / Operator | 許可Scope、禁止Scope、Goal、Approval Policyを定義する |
| Planner | 次に実施したい候補Actionを提案する |
| Tool Registry | Tool固有のAdapter、最低Risk、Schema、副作用、承認要件を定義する |
| Tool Availability Resolver | Registry、Adapter、Session、Mission Scope互換性、Policyから計画候補として提示可能なToolを算出する。具体TargetをALLOWしない |
| Context Selector | 許可されたIndex MetadataだけからContext認可候補のResource Referenceを決定論的に選ぶ |
| Context Authorization | Planner / Analyzer用ContextのRead Authorizationを発行する |
| Context Builder | 有効なGrantの範囲でRedacted Contextを構築する |
| Policy Engine | 実ターゲットと引数を正規化し、ALLOW / REQUIRE_APPROVAL / DENYを最終決定する |
| Executor | 有効なPolicyDecisionと一致するActionだけを実行する |
| Adapter | 信頼済みExecutionRequestをProviderへ変換し、Raw ContentをQuarantine SinkへStreamingしてControl Metadataだけを返す |
| Secure Ingestion | Raw Resultを分類・Secret分離・Redactionし、安全な参照を生成する |
| Analyzer | 非信頼の実行結果から候補Observationを抽出する |
| Knowledge Reducer | 候補Observationを検証・重複排除し、Knowledge Baseへ反映する |
| Session Manager | trusted Adapterから確認したCurrent Runtime Contextを管理する |
| Goal Evaluator | 確定済みEvidenceのみからGoalを判定する |
| Sandbox | Logical Authorizationに加えてProcess / Filesystem / Network制約をEnforceする |

PlannerおよびAnalyzerの出力は、Pydantic Validationに成功しても信頼済みとはみなさない。LLMが生成したRisk、承認要否、Scope判定、Goal達成判定を実行許可の根拠にしてはならない。

## 2.4 Design Principles

1. LLMは信頼しない
2. LLMは実行許可を決定しない
3. PlannerはActionを提案するだけとする
4. Policy Engineのみが実行許可を決定する
5. ExecutorはPolicyDecisionをEnforceする
6. Adapterは特定製品との差異を吸収する
7. External Side EffectはExecution Stateで管理する
8. 不明な実行結果を成功・失敗と推測しない
9. 確認できない副作用Actionは自動再送しない
10. Analyzerの出力を事実として直接保存しない
11. Knowledge ReducerがProvenance付きで知識を確定する
12. Session Runtime StateはSession ManagerをSource of Truthとする
13. GoalはLLMではなく決定論的に判定する
14. SecretをLLM Contextへ渡さない
15. Tool Outputは非信頼入力として扱う
16. Scopeが判定できなければDefault Denyする
17. C2 / MCP / LLMを交換可能にする
18. LangGraphのみをWorkflow Engineとして使用する
19. 同じ情報に複数のSource of Truthを作らない
20. Graph Node RetryとExecution Retryを区別する
21. Pure Node Retry、Persistent State Mutation Retry、External Execution Retryを区別する
22. 一時AuthorizationをMission Revision、Authorization Epoch、TTLへBindingする
23. Tool Availabilityは候補提示、具体Target AuthorizationはPolicy Engineの責務とする
24. `frozen=True`だけをIntegrity GuaranteeとせずCanonical Digestを使用直前に再検証する
25. `AUTHORIZED`は実行候補の認可済み状態であり、Secret平文取得またはProvider送信の権限として扱わない
26. Pre-dispatch成功後の外部送信、Secret解決、Result Collectionは、Repositoryへ永続化した目的別・単回のAuthority RecordへBindingする
27. Secure Ingestionは呼出側が持ち込むReceipt、Quarantine Reference、Publication Objectから権限を組み立てず、Trusted Repositoryから完全なBindingを解決する
28. Quarantineを消去する前に、Redacted Artifact、Secret Reference、Secure Ingestion ManifestをDurableに確定する
29. Audit HeadとWrapped Key StateのGeneration Commitは、Generation番号だけでなくState DigestとImmutable Blob Identityへ外部CAS AnchorをBindingする

---

# 3. 全体アーキテクチャ

```text
                        Operator
                           |
                           v
                    Mission Manager
                           |
                           v
                       LangGraph
                           |
                           v
                   Session Refresh
                           |
                           v
                    Context Selector
                           |
                           v
               Context Authorization
                    /              \
                   v                v
          DataAccessGrant   SessionContextGrant
                    \              /
                     +------+------+
                            |
                            v
                    Context Builder
                           |
                           v
              Tool Availability Resolver
                           |
                           v
                 AvailableToolSnapshot
                           |
                           v
                        Planner
                           |
                           v
               ExecutionPlanProposal
                           |
                           v
          Application creates ExecutionPlan
                           |
                           v
       AvailableToolSnapshot Revalidation
                           |
                           v
                    Policy Engine
                  /          |          \
               DENY   REQUIRE_APPROVAL  ALLOW
                             |            |
                             v            |
                     ApprovalRequest      |
                             |            |
                             v            |
                     ApprovalRecord       |
                             |            |
                             +------------+
                           |
                           v
                        Executor
                           |
                           v
              Pre-dispatch Enforcement
                           |
                           +----> BLOCKED（No Provider Call）
                           |
                           v
                    ExecutionAdapter
                    /       |       \
                   v        v        v
            C2 Adapter MCP Adapter Local Adapter
                   \        |        /
                    +-------+-------+
                           |
                           v
             Raw Result Chunk Streaming
                           |
                           v
           Encrypted Raw Result Quarantine
                           |
                           v
                   Secure Ingestion
                     /            \
                    v              v
          Redacted Artifact    Secret Store
                    |              |
                    |        SecretReference
                    |              |
                    |       SecretDiscoveryReference
                    |              |
                    v              |
    ExecutionResult Normalization (Application)
                    |              |
                    v              |
             ExecutionResult      |
                    |              |
                    v              |
         Analyzer Context Selector |
                    |              |
                    v              |
       Analyzer Context Authorization
             /             \       |
            v               v      |
  DataAccessGrant  SessionContextGrant
             \             /       |
              +-----+-----+         |
                    |               |
                    v               |
          Analyzer Context Builder |
                    |              |
                    v              |
                 Analyzer          |
                    |              |
             CandidateObservation  |
                    |              |
                    +-------+------+
                           |
                           v
                   Knowledge Reducer
                           |
                           v
                    Knowledge Base
                           |
                           v
                    Session Refresh
                           |
                           v
                     Goal Evaluator
                    /       |       \
                   v        v        v
       NOT_ACHIEVED  INDETERMINATE  ACHIEVED
              |            |           |
              v            v           v
       Next Iteration  Indeterminate FINALIZING
                          Handler          |
                         /      \          v
                        v        v     COMPLETED /
                 Bounded     PAUSED /  HUMAN REVIEW
                 Refresh /   Human Review
              Reconciliation

Session Manager = Session Runtime StateのSource of Truth

Planner / Analyzer --> Pydantic AI --> vLLM --> Local LLM

Shared deterministic services:

- Mission Manager
- Policy Engine
- Tool Registry
- Tool Availability Resolver
- Context Selector
- Context Authorization Service
- Context Builder
- Session Manager
- Execution State Manager
- Knowledge Reducer
- Goal Evaluator
- Secure Ingestion
- Encrypted Raw Result Quarantine
- Sandbox Manager
- Indeterminate Handler
- Artifact Store
- Secret Store
- Encryption Key Provider
- LLM Profile Repository / Capability Checker
- Audit Logger
```

---

# 4. 使用技術

## 4.1 言語

Python 3.12以降を基本とする。

---

## 4.2 オーケストレーション

LangGraphを使用する。

LangGraphは以下を担当する。

* Planner / Executor / Analyzer間の状態遷移
* 条件分岐
* ループ
* エラー処理
* リトライ
* Checkpoint
* Human-in-the-loop
* 最大ステップ数制御
* ワークフロー停止・再開

LangGraphのみを、Workflow、Orchestration、State Transition、Checkpoint、Interrupt、Resumeの責任主体とする。Pydantic AIやAdapterへWorkflow Control Stateの管理を分散させない。

LangGraphのRetryは副作用を持たないNode / Workflow / Infrastructure Errorだけを対象とする。Planner / Analyzer出力のValidation Retryは単一Node呼び出し内でPydantic AIが有限回実施し、上限到達後はLangGraphへ明示的なErrorを返す。

LangGraph Automatic Retryを使用可能なNode:

```text
Planner
Analyzer
Context Selector（Index MetadataのRead-only処理）
CalculateContextAuthorization
CalculateToolAvailability
Context Builder（Read-only）
AvailableToolSnapshot Revalidation（Pure Validation）
Pure Validation Node
Pure Read-only Node
```

LangGraph Automatic Retryを禁止する処理、または明示的なIdempotent Upsert Contractを必須とする処理:

```text
PersistContextAuthorization
PersistAvailableToolSnapshot
Audit Write
Mission State Update
Execution State Update
RawResultSink Write / Commit / Abort
Executor Dispatch
C2 submit
MCP Side-effect Call
Local Side-effect Execution
Adapter Task Cancel / External Task Mutation
External Write
```

Context AuthorizationとTool Availabilityは計算と永続化を分離する。

```text
CalculateContextAuthorization
        |
        v
PersistContextAuthorization

CalculateToolAvailability
        |
        v
PersistAvailableToolSnapshot
```

Persistence Nodeを自動Retry可能にする場合は、入力Digestから生成したDeterministic ID、Database Unique Constraint、同じPayloadだけを受理するIdempotent Upsertをすべて必須とする。同じIDへ異なるPayloadが来た場合は`DigestIntegrityError`としてFail Closedする。Operation IDはMission ID / Revision、Authorization Epoch、run_id、Node名、Iteration、入力Digestから生成し、同一Node Retryで変化させない。`issued_at / created_at / expires_at`は最初のInsertで固定し、Conflict時に現在時刻で再計算せず保存済みRecordを返す。新しいRandom IDを生成するPersistence処理、Audit Sequence採番、Mission / Execution State遷移はLangGraph Automatic Retryの対象にしない。

External ExecutionのRetryはExecution State Machine、Tool Idempotency、Idempotency Key、Adapter Reconciliation、Policy Revalidationを必ず通す。

> Graph Node Retry != Execution Retry

> Pure Node Retry != Persistent State Mutation Retry != External Execution Retry

基本ワークフローは以下。

```text
START
  |
  v
Load State
  |
  v
Session Refresh
  |
  v
Context Selector
  |
  v
Calculate / Persist Context Authorization
  |
  +--> DataAccessGrant
  +--> SessionContextGrant
  |
  v
Context Builder
  |
  v
Calculate / Persist Tool Availability
  |
AvailableToolSnapshot
  |
  v
Planner
  |
  v
ExecutionPlanProposal
  |
  v
Application creates ExecutionPlan
  |
  v
AvailableToolSnapshot Revalidation
  |
  v
Policy Engine
  |
  +------ DENY ----------------> STOP / Session RefreshからRe-plan
  |
  +------ REQUIRE APPROVAL ----> ApprovalRequest / Human Approval
  |                                  |
  |                             Reject / Expire --> STOP / Session RefreshからRe-plan
  |                                  |
  |                           ApprovalRecord
  |                                  |
  +----------------------------------+
  |
  v
Executor
  |
  v
Pre-dispatch Enforcement
  |
  +------ BLOCKED ----------> No Provider Call / No ExecutionResult
  |
  v
ExecutionAdapter / Raw Result Streaming
  |
  v
Encrypted Raw Result Quarantine
  |
  v
Secure Ingestion / ExecutionResult Normalization
  |
  v
Analyzer Context Selector / Calculate & Persist Authorization / Context Builder
  |
  v
Analyzer
  |
  v
Knowledge Reducer
  |
  v
Session Refresh
  |
  v
Goal Evaluator
  |
  +------ ACHIEVED ----> FINALIZING ----> COMPLETED / HUMAN REVIEW
  |
  +------ NOT ACHIEVED ------------------> Next Iteration / Session Refresh
  |
  +------ INDETERMINATE -----------------> Indeterminate Handler
                                               |
                                               +--> Bounded Refresh / Reconciliation
                                               +--> PAUSED / Human Review
```

---

# 5. LangChainの位置付け

LangChainは必須とはしない。

必要に応じて以下に利用する。

* LLMインテグレーション
* Tool abstraction
* Message abstraction
* MCPなど外部ツールとの連携

オーケストレーションそのものはLangGraphで実装する。

したがって構成は、

```text
LangGraph
   |
   +-- Pydantic AI Agent
   |
   +-- optional LangChain components
```

とする。

---

# 6. Pydantic AI

PlannerおよびAnalyzerの実装にはPydantic AIを使用する。

目的はLLMに自由な文章を返させるのではなく、構造化されたデータとして結果を取得することである。

Pydantic AIの責務は以下に限定する。

* Planner / AnalyzerのLLM Invocation
* Structured Output
* Output Validation
* Validation Retry

MVPではPydantic AI側のGraph、Durable Execution、Workflow Orchestration機能を使用しない。同一システム内に複数のWorkflow Engineを導入しない。

ToolとPlanの識別Model例:

```python
class StrictBoundaryModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

class StrictImmutableBoundaryModel(StrictBoundaryModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

class ToolRef(StrictImmutableBoundaryModel):
    tool_id: str
    registry_revision: int

class ExecutionPlanProposal(StrictImmutableBoundaryModel):
    objective: str
    phase: "OperationalPhase"

    tool_ref: ToolRef

    requested_targets: tuple["TargetReference", ...]
    session_id: str | None

    arguments: CanonicalJsonObject

class ExecutionPlan(BaseModel):
    plan_id: str
    mission_id: str
    mission_revision: int
    observed_mission_state_version: int
    observed_authorization_epoch: int
    run_id: str
    thread_id: str
    proposal: ExecutionPlanProposal
    proposal_digest: str
    available_tool_snapshot_id: str
    available_tool_snapshot_digest: str
    session_security_context_digest: str
    adapter_capabilities_digest: str
    sandbox_capabilities_digest: str
    remote_mcp_trust_policy_digest: str
    created_at: datetime
```

Trust Boundaryを越える次のModelは`StrictBoundaryModel`を直接または同等設定で継承し、未知Fieldを破棄せず`PydanticBoundaryValidationError`として拒否する。

```text
ExecutionPlanProposal
AnalysisResult
Mission
PolicyDecision
ApprovalRequest
ApprovalRecord
ContextDataAccessGrant
SessionContextGrant
AvailableToolSnapshot
ExecutionRequest
AdapterRawResult
SecureIngestionResult
```

これらから到達可能な`ToolRef`、Target / Scope Rule、DataAccessGrant、Artifact Reference等のNested Modelにも同じ`extra="forbid"`とStrict型検証を適用する。Outer ModelだけをStrict化してNested Modelの未知Fieldや型Coercionを許してはならない。内部Repository専用Recordや計算途中のValue Objectまで一律にStrict化する必要はないが、Trust Boundary Modelとの変換点を明示する。

`CanonicalJsonObject`はJSON Schema上はObjectとして表現し、Validation後はKey順に正規化した再帰的Immutable Value Objectとして保持する。文字列`"3"`から整数`3`、文字列`"true"`からBoolean`true`等への暗黙Coercionを許さない。`adapter`、`risk`、`approval`、`scope`、`plan_id`、`execution_id`その他の未定義FieldをExecutionPlanProposalへ追加した出力は、値を捨てて続行せずValidation Errorにする。

`observed_mission_state_version`はPlan作成時のLifecycle State観測値であり、OCC競合検出とAuditにだけ使用する。Authorization Bindingは`mission_revision`へ行い、この観測値をproposal_digestまたはauthorization_digestへ含めない。Executorは別途、Pre-dispatch時点のMission Stateが`RUNNING`であることをMission State Repositoryから確認する。

`JsonValue`はJSON標準の`null / boolean / number / string / array / object`だけを許可し、任意のPython Object、実行可能Object、未検証のByte列を許可しない。

Model例で後続Sectionに定義される型はForward Referenceとして表記している。実装では全Alias定義後にPydanticの`model_rebuild()`相当を実行し、未解決Referenceが1件でもあれば起動時にFail Closedする。

`ExecutionPlanProposal.requested_targets`はPlannerが示す候補であり、Scope判定の根拠として信頼しない。Policy EngineはTool RegistryのTarget Extractorを使用して`arguments`、Session、名前解決結果、Redirect先を含む実ターゲットを抽出・正規化する。

Risk LevelおよびApproval RequirementはExecutionPlanProposalへ含めない。Tool RegistryとPolicy Engineが決定する。

AdapterもExecutionPlanProposalへ含めない。PlannerはToolRefを提案するだけとし、Tool Registryに登録された信頼済み`adapter`定義をExecutorが参照して実行経路を決定する。PlannerがC2 / MCP / Localの実行経路を上書きできるFieldを設けない。

LLMが生成するのは`ExecutionPlanProposal`だけとする。`plan_id`、`execution_id`、`decision_id`、`approval_id`、`run_id`、`thread_id`、`grant_id`、`snapshot_id`、`ingestion_id`、Artifact / Secret Reference ID、TimestampはApplicationまたは該当する信頼済みServiceが生成する。ApplicationはProposalのSchema、ToolRef、Snapshot Bindingを検証した後に`ExecutionPlan`を作成する。

ApplicationはExecutionPlanProposalのCanonical JSONから`proposal_digest`を生成する。proposal_digestはLLM Proposal自体を識別し、Resolved Adapter、Normalized Target、DataAccessGrant、Risk、Policy判断を含めない。Policy Engineが解決した実行意図はSection 22の`authorization_digest`で別に識別する。

```text
ExecutionPlanProposal
   |
   | tool_ref
   v
Tool Registry
   |
   | adapter
   v
Executor
   |
   v
ExecutionAdapter
   |
   +-- C2 Adapter
   +-- MCP Adapter
   +-- Local Tool Adapter
```

## 6.1 Structured Output方式

PlannerおよびAnalyzerは以下の経路で構造化出力を生成する。

```text
Pydantic AI
    |
Pydantic Model
    |
JSON Schema
    |
vLLM OpenAI-compatible API
    |
Structured Output
```

第一候補はPydantic AIのNative Structured Output相当の方式とする。使用モデルとvLLMの組み合わせで正常動作しないことをCapability Checkで確認した場合に限り、Pydantic AIのTool Output等へFallbackできる。Fallback方式は設定とAudit Logへ記録し、自由形式Textを構造化出力として受け入れてはならない。

選択したOutput方式はMission Revision中で固定する。実行中にNative方式が失敗しても暗黙にFallbackへ切り替えず、MissionをPAUSEDにしてCapability Checkと設定Revision更新を行う。

PydanticによるValidationを必ず実施する。

Validationに失敗した場合は有限回の再生成を実施する。

リトライ回数は設定可能とし、初期値は以下とする。

```text
max_validation_retries = 3
```

`max_validation_retries`はPydantic AI Structured Output / Output Validation専用のRetry Budgetである。HTTP Transport RetryでもLangGraph Node Retryでもなく、概念的には次のOutput-specific設定へMappingする。

```python
Agent(
    retries={
        "output": 3
    }
)
```

使用するPydantic AI VersionでAPI形状が異なる場合は、同じ意味を持つOutput-specific Retry設定へMappingする。Global Retry、HTTP Retry、Tool Execution Retryへ読み替えてはならない。設定、Metric、Auditでは`pydantic_output_retries`、`http_transport_retries`、`langgraph_node_retries`を別々に記録する。

上限を超えた場合は無限にLLMを呼び続けず、LangGraph側へエラーを返す。

## 6.2 Structured Output Capability Check

起動時に、実際のPlanner / Analyzer Schemaに近いCanary SchemaをvLLMへ送信し、最低限以下を検証する。

```text
Nested Model
Enum
Optional Field
List
Discriminated Union
JSON Schema Validation
Unknown Field Rejection
Strict Type / No Coercion
Validation Retry
Timeout
Cancellation
```

CanaryにはExecutionPlanProposalへ未定義の`adapter`等を混入したCase、および整数・Boolean Fieldへ文字列を返すCaseを含め、Pydantic Boundaryがそれらを拒否することを検証する。単にJSON Objectを返せるだけでは合格としない。Native Structured Outputと設定済みFallbackの双方が不合格の場合、そのLLMを使用不可としMissionを開始しない。Capability Check結果にはLocalLLMProfile Digest、Model Hash、vLLM Version、Schema Version、選択したOutput方式を記録する。

---

# 7. ローカルLLM

LLMはローカル環境で実行可能な構成とする。

推論サーバーとしてvLLMを使用する。

構成:

```text
AI Agent
    |
OpenAI-compatible API
    |
   vLLM
    |
Local LLM
```

モデルについては特定モデルに依存させない。

ただし、使用するモデルは以下のCapability Contractを満たす必要がある。

* Section 6.2のStructured Output Capability Checkに合格する
* 設定されたContext長とOutput長を満たす

Capabilityを満たさないモデルは起動時検査で拒否する。特定モデル非依存とは、すべてのモデルで無条件に動作することを意味しない。

vLLMのNetwork公開条件はSection 38のSecurity要件に従う。

候補:

* Qwen系
* Llama系
* その他Tool Calling / Structured Outputに適したローカルモデル

LLMの設定は設定ファイルから変更可能とする。

例:

```yaml
llm:
  provider: vllm
  wire_api: chat_completions
  base_url: http://localhost:8000/v1
  model: qwen
  temperature: 0.1
  max_tokens: 4096
```

MVPのWire APIは`chat_completions`へ固定する。Pydantic AIからは概念的に`OpenAIChatModel`と、管理された`base_url`を持つ`OpenAIProvider`へMappingする。Responses APIや別Wire APIへ実行中に暗黙Fallbackしてはならない。

```python
class LocalLLMProfile(StrictImmutableBoundaryModel):
    profile_type: Literal["vllm"] = "vllm"
    profile_revision: str
    profile_digest: str
    wire_api: Literal["chat_completions"]
    structured_output_mode: str
    tool_output_support: bool
    system_message_handling: str
    max_context_tokens: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    model_name: str
    model_hash: str
    chat_template_digest: str | None
    tokenizer_revision: str

class MockAgentProfile(StrictImmutableBoundaryModel):
    profile_type: Literal["mock"] = "mock"
    profile_revision: str
    profile_digest: str
    implementation_digest: str

AgentModelProfile = Annotated[
    LocalLLMProfile | MockAgentProfile,
    Field(discriminator="profile_type")
]
```

LocalLLMProfileはWire API、Structured Output Mode、Tool Output Support、System Message Handling、Max Context、Max Output Tokens、Chat Template、Tokenizer / Template RevisionをVersion管理する。`profile_digest`はDigest Field自身を除くCanonical Profileから生成する。Section 6.2のCapability Check Resultは`profile_digest`へBindingし、Profile本体と検査結果を保存する。MockAgentProfileはPhase 0A〜1の決定論的Mockだけに使用し、本番MissionまたはPhase 2以降でLocal LLM Capability Checkを迂回するために選択してはならない。Mission開始時にProfile Revision / DigestをMission Revisionへ固定し、Mission中のModel、Wire API、Chat Template、Tokenizer、Output Modeの暗黙変更は`LLMProfileMismatchError`としてFail Closedする。変更が必要な場合はMissionをPAUSEDにし、Capability Check済みのProfileを用いて新しいMission Revisionを作成する。旧RevisionのCheckpoint、Grant、Snapshot、PolicyDecision、ApprovalRequest、ApprovalRecordを新Revisionへ継承してはならない。

Profile Validationでは`max_output_tokens <= max_context_tokens`を要求し、`structured_output_mode`と`system_message_handling`はVersion付きAllowlistから選ぶ。`chat_template_digest=None`は、vLLMが外部Templateを使用せずModel Hashへ内蔵Templateが固定されることをCapability Checkで確認してProfileへ記録できる場合だけ許可し、単なる取得失敗ではDefault Denyする。

---

# 8. Planner

Plannerは「次に何をするべきか」を決定するAIエージェントである。

Planner自身はコマンドを実行してはいけない。

入力:

```text
Mission
Current State
Planner Context（ContextDataAccessGrantで構築済み）
AvailableToolSnapshot
Allowed / Prohibited Scope Summary
Policy Summary
```

Plannerへ渡すScopeおよびPolicyは判断支援用のRedacted Summaryであり、実行許可そのものではない。Toolに関してPlannerへ渡してよい情報は、Tool Availability Resolverが生成したVersion付き`AvailableToolSnapshot`だけとする。Tool Registry全体や利用不能Toolを直接渡さない。

`Current State`はIteration、OperationalPhase、直前の正規化済みResult Reference等のWorkflow Control情報に限定する。Knowledge Base Record、Artifact本文、Session Provider Raw DataをCurrent State経由で迂回して渡してはならない。

出力:

```text
ExecutionPlanProposal
```

Planner呼び出し前にSession Refresh、Context Selector、Calculate / Persist Context Authorization、Context Builder、Calculate / Persist Tool Availabilityを完了していなければならない。PlannerはKnowledge Base、Artifact、Reportへ直接アクセスしない。

Planner出力を受けたApplicationはSystem IDを付与してExecutionPlanを生成し、その後にAvailableToolSnapshot RevalidationとPolicy Engineへ渡す。

Plannerは演習全体を一度に生成するのではなく、基本的には**次に実行すべき1アクション**を決定する。

これにより、

```text
Session Refresh
       ↓
Context Selector
       ↓
Calculate / Persist Context Authorization
       ↓
Context Builder
       ↓
Calculate / Persist Tool Availability
       ↓
AvailableToolSnapshot
       ↓
Planner
       ↓
ExecutionPlanProposal / Application creates ExecutionPlan
       ↓
AvailableToolSnapshot Revalidation
       ↓
Policy Engine
       ↓
Executor
       ↓
Observation / Session Refresh
```

という閉ループ構造を実現する。

Plannerが担当する判断例:

* 現在どのフェーズにいるか
* 次に何を確認すべきか
* どの既存セッションを使用するか
* AvailableToolSnapshot内のどのToolRefを使用するか
* 追加調査が必要か
* 現在の情報だけで次の判断が可能か

---

# 9. Executor

ExecutorはAIに自由な操作をさせるコンポーネントではない。

Plannerが生成したExecutionPlanとPolicy Engineが発行したPolicyDecisionを検証し、適切なAdapterへ処理を渡す。

実行先AdapterはExecutionPlanではなく、PolicyDecisionが参照するTool Registry Revisionの`ToolDefinition.adapter`から解決する。

```text
ExecutionPlan
      |
      v
PolicyDecision
      |
      v
   Executor
      |
      +------ ExecutionAdapter
                 |
                 +-- C2 Adapter
                 +-- MCP Adapter
                 +-- Local Tool Adapter
```

Executorの役割:

1. ExecutionPlanおよびTool引数SchemaのValidation
2. ToolRefがRegistry Revisionの登録内容と一致することの確認
3. ToolがPolicyDecisionに記録されたAvailableToolSnapshotへ含まれることの確認
4. proposal_digestおよびauthorization_digestとPolicyDecisionの照合
5. PolicyDecision / ApprovalRequest / ApprovalRecordの期限、Mission Revision、Authorization Epoch、Scope、ImmutableなApproval Execution Predicateの再確認
6. ExecutionRecordを`PLANNED`として作成・永続化
7. Tool Registryから実行先Adapterを再解決し、Executable Predicate成立時だけ`AUTHORIZED`へ遷移
8. Mission State / Validity、Authorization Epoch、Session Freshness、Adapter / Sandbox / Remote MCP Trust Capability、Canonical DigestのPre-dispatch Check
9. Pre-dispatch失敗時の`AUTHORIZED -> BLOCKED`永続化
10. Pre-dispatch成功時に、Execution、PolicyDecision、Tool、Adapter、Approval、TTLへ完全Bindingした単回`DispatchClaim`を同一Transactionで永続化し、`DISPATCH_CLAIMED`へ遷移
11. 有効なDispatch Claimを持つTrusted Adapter ChannelだけへのJust-in-time Secret Injection
12. Idempotency Key付き要求の送信と、結果不明時のReconciliation
13. Task状態、Timeout、Cancellationの管理
14. Result取得開始時にTrusted Tool Definition、Collection開始時刻、Retention、Size上限へBindingした`ResultCollectionAuthority`を永続化
15. Authority-bound RawResultSinkを用いたEncrypted QuarantineへのChunk StreamingとReceipt取得
16. Metadata-only AdapterRawResult取得
17. Result Ingestion State更新とRepository-bound Secure Ingestionの実行
18. Durable Secure Ingestion Manifest確定後のQuarantine消去
19. PolicyDecision、Normalized Target、SecureIngestionResultを統合したExecutionResult生成
20. Audit Logへの記録

PolicyDecisionが存在しない、Decisionが`DENY`、または`REQUIRE_APPROVAL`が未承認 / 拒否済みの場合はExecutionRecordを作成せずAuthorization Gateで拒否または待機する。Executable Predicateを満たすDecisionに対してだけExecutionRecordを`PLANNED`で作成し、Registry BindingとPredicateを同一OCC処理で再検証して`AUTHORIZED`へ遷移する。`PLANNED`からのCrash RecoveryはProvider未送信としてPolicy Revalidationを行い、暗黙Dispatchしない。

`AUTHORIZED`は、保存済みPolicyDecisionを実行候補へBindingした状態であり、Secret Valueを復号する権限、Raw Result Sinkを発行する権限、Provider APIを呼ぶ権限のいずれも表さない。`AUTHORIZED`後にAuthorization Epoch / TTL / authorization_digest、その他Pre-dispatch条件が不一致になった場合は`BLOCKED`へ遷移させる。Approval後もPolicyDecisionを書き換えてはならない。

Provider APIを呼ぶ直前にMission State Repositoryから`state=RUNNING`、現在Epoch、`valid_from <= current_time < valid_until`を再確認する。成功時は、同じOCC TransactionでExecutionを`DISPATCH_CLAIMED`へ遷移し、目的限定・単回・短寿命のDispatch Claimを作成する。Secret Valueが必要な場合も、Secret Storeの公開`resolve()`からbytesをApplication Callerへ返さず、Dispatch ClaimへBindingされたTrusted Adapter Channelへだけ注入する。Claim確定後のCrashまたは送信結果不明はReconciliationへ進め、Provider Submitを自動再送しない。

Local Tool AdapterではTool Registryに登録された型付きToolだけを実行可能とする。任意文字列をOS Shellへ渡す汎用Toolは自動実行モードで提供しない。

ExecutorのDispatch処理へLangGraph Automatic Retryを設定してはならない。Dispatch後の例外はExecution State MachineとAdapter Reconciliationへ渡す。

---

# 10. Raw Result Streaming / ExecutionResult

ProviderのRaw Content、Adapterが返すControl Metadata、Applicationが生成する正規化済みExecutionResultを分離する。

```text
C2 / MCP / Local Tool
        |
        v
Adapter
        |
        v
RawResultSinkへChunk Streaming
        |
        v
Encrypted Raw Result Quarantine
        |
        v
RawResultReceipt / AdapterRawResult（Metadata only）
        |
        v
Secure Ingestion
        |
        v
ExecutionResult
        |
        v
Analyzer
```

Raw Result Streaming Model例:

```python
class RawArtifactMetadata(StrictImmutableBoundaryModel):
    artifact_sequence: int = Field(ge=0)
    suggested_name: str | None
    media_type: str | None
    declared_size: int | None = Field(default=None, ge=0)

class RawResultReceipt(StrictImmutableBoundaryModel):
    receipt_id: str
    execution_id: str
    quarantine_id: str
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)
    artifact_count: int = Field(ge=0)
    ciphertext_digest: str
    committed_at: datetime

class AdapterRawResult(StrictImmutableBoundaryModel):
    execution_id: str
    provider_task_id: str | None
    provider_status: str
    receipt: RawResultReceipt
    exit_code: int | None
    started_at: datetime
    finished_at: datetime

class RawResultSink(Protocol):
    async def write_stdout(self, chunk: bytes) -> None:
        ...

    async def write_stderr(self, chunk: bytes) -> None:
        ...

    async def write_artifact(
        self,
        metadata: RawArtifactMetadata,
        chunks: AsyncIterator[bytes],
    ) -> None:
        ...

    async def commit(self) -> RawResultReceipt:
        ...

    async def abort(self) -> None:
        ...
```

`AdapterRawResult`は互換用語として維持するが、Raw bytesやProvider一時Pathを含まないControl MetadataとReceiptだけのModelへ再定義する。Raw ContentはProviderからChunk単位で、Executorが生成した`RawResultSink`へ直接書き込む。Adapter、Executor、Application Serviceがstdout / stderr / Artifact全体をMemoryへ集約してからQuarantineへ保存する実装を禁止する。

RawResultSinkはChunkごとにSize Limit、Quota、暗号化、Integrity更新を適用する。`commit()`はQuarantineのDurable Commitが完了した後にだけReceiptを返し、同じExecution / Sink IDに対する再呼出しは同一Receiptを返すIdempotent操作とする。`abort()`はRaw Result Quarantine Stateを`RECOVERY_REQUIRED`または`ABORTED`へ遷移させ、未検査Contentを通常ArtifactへFallbackしない。通常Application DatabaseにはReceipt / Quarantine Metadataと暗号化Storage Handleだけを保存し、Raw stdout / stderr、Raw Artifact Body、Raw Secretを保存しない。

Sink Commit後かつAdapterRawResult Metadata受領前にCrashした場合、Executorは保存済みReceiptと同じProvider Task IDを用いてControl Metadataだけを再照会するか、同じCommitted Sinkへの`collect_result()`をIdempotentに再開する。Provider Actionを再Submitしてはならない。Control Metadataを再構築できないFieldは推測せず、Result Ingestionを安全に継続できる最小MetadataとReconciliation Resultを保存してHuman Review対象にする。

Applicationが生成するResult例:

例:

```python
class ExecutionResult(StrictImmutableBoundaryModel):
    execution_id: str
    provider_task_id: str | None

    adapter_id: str
    tool_ref: ToolRef
    policy_decision_id: str
    secure_ingestion_id: str

    normalized_targets: tuple["NormalizedTarget", ...]
    session_id: str | None

    status: Literal[
        "SUCCEEDED",
        "FAILED",
        "CANCELLED"
    ]

    timed_out: bool

    started_at: datetime
    finished_at: datetime

    stdout_preview: str | None
    stderr_preview: str | None

    redacted_artifacts: tuple["ArtifactReference", ...]

    exit_code: int | None
```

ExecutorはRawResultReceipt、AdapterRawResultのControl Metadata、PolicyDecision、Normalized Target、SecureIngestionResult内のRedacted Artifact、Execution Metadataを統合してExecutionResultを生成する。`detected_secrets`はExecutionResultへ埋め込まず、信頼済みMetadata経路でKnowledge Reducerへ渡す。AdapterはPolicyDecision由来のTarget、Risk、Approval、Data Accessを生成または上書きしてはならない。

C2、MCP、ローカルToolなどの違いとRaw OutputをAnalyzerから隠蔽する。

`stdout_preview`および`stderr_preview`はサイズ制限とSecret Redactionを適用した表示用データとする。完全な出力が必要な場合も、Artifact Policyに従ってRedaction・分類・暗号化した上でArtifact Storeへ保存する。

Section 10.1のPre-dispatch `AUTHORIZED -> BLOCKED`ではProvider ResultもSecure Ingestionも存在しないためExecutionResultを生成しない。ProviderがDispatch後にCallを拒否した場合は、Providerから確認した失敗としてExecutionResultの`FAILED`とProvider Reason Metadataで表現し、Pre-dispatch `BLOCKED`と混同しない。Timeout等でExternal Executionの結果自体を確認できない場合もExecutionResultを捏造せず、ExecutionRecordの`OUTCOME_UNKNOWN`で表現して自動再実行しない。

Execution RecordではProvider Execution StateとResult Ingestion Stateを分離する。

```python
ProviderExecutionState = Literal[
    "PLANNED",
    "AUTHORIZED",
    "DISPATCH_CLAIMED",
    "DISPATCHED",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "BLOCKED",
    "CANCEL_REQUESTED",
    "CANCELLED",
    "RECONCILING",
    "OUTCOME_UNKNOWN"
]

PreDispatchBlockReason = Literal[
    "SESSION_STALE",
    "MISSION_NOT_RUNNING",
    "POLICY_STALE",
    "SNAPSHOT_STALE",
    "SANDBOX_CAPABILITY_MISMATCH",
    "ADAPTER_CAPABILITY_MISMATCH",
    "APPROVAL_INVALID",
    "AUTHORIZATION_TTL_EXPIRED",
    "AUTHORIZATION_EPOCH_MISMATCH",
    "REMOTE_MCP_TRUST_MISMATCH",
    "ENCRYPTION_KEY_UNAVAILABLE",
    "MISSION_EXPIRED",
    "DIGEST_INTEGRITY_FAILURE"
]

ResultIngestionStatus = Literal[
    "NOT_AVAILABLE",
    "PENDING",
    "INGESTING",
    "INGESTED_DURABLE",
    "DELETE_PENDING",
    "QUARANTINE_ERASED",
    "SUCCEEDED",
    "FAILED",
    "QUARANTINED"
]

class ExecutionRecord(BaseModel):
    execution_id: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    plan_id: str
    policy_decision_id: str
    proposal_digest: str
    authorization_digest: str
    tool_ref: ToolRef
    resolved_adapter_id: str
    idempotency_key: str
    adapter_capabilities_digest: str
    sandbox_capabilities_digest: str
    remote_mcp_trust_policy_digest: str
    provider_execution_state: ProviderExecutionState
    pre_dispatch_block_reason: PreDispatchBlockReason | None
    result_ingestion_state: ResultIngestionStatus
    raw_result_quarantine_id: str | None
    provider_task_id: str | None
    created_at: datetime
    updated_at: datetime
```

```python
class DispatchClaim(StrictImmutableBoundaryModel):
    claim_id: str
    execution_id: str
    execution_state_version: int
    policy_decision_id: str
    authorization_digest: str
    mission_revision: int
    authorization_epoch: int
    tool_ref: ToolRef
    resolved_adapter_id: str
    approval_request_id: str | None
    approval_record_id: str | None
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None

class ResultCollectionAuthority(StrictImmutableBoundaryModel):
    collection_id: str
    execution_id: str
    provider_task_id: str
    tool_ref: ToolRef
    tool_registry_digest: str
    max_output_bytes: int = Field(gt=0)
    collection_started_at: datetime
    retention_until: datetime
    sink_id: str
    lease_expires_at: datetime
```

`DispatchClaim`と`ResultCollectionAuthority`はBearer Tokenではない。CallerがObjectまたはIDを提示しただけでは権限を得られず、各ServiceはExecution IDからTrusted RepositoryのCurrent Recordをロードし、Execution State Version、現在Mission、Decision、Tool Registry、Adapter、Approval、TTL、Claim未消費を再検証する。呼出側がClaimのField、Tool上限、Retention時刻、Receipt、Quarantine Referenceを差し替えるInterfaceを禁止する。

Result Ingestion State Machine:

```text
NOT_AVAILABLE
      |
      v
PENDING
      |
      v
INGESTING
   |        \
   v         v
INGESTED_   FAILED
DURABLE       |
   |          +--> PENDING（明示的な同一Result再取込）
   v          +--> QUARANTINED
DELETE_PENDING
   |
   v
QUARANTINE_ERASED
   |
   v
SUCCEEDED
```

`ProviderExecutionState=SUCCEEDED`かつ`ResultIngestionStatus=FAILED`は合法であり、`OUTCOME_UNKNOWN`ではない。Secure Ingestion失敗はProviderで確認済みの状態を推測変更せず、MissionをPAUSEDにする。ExecutionResultは生成せず、同じActionを結果取得目的で再実行しない。`OUTCOME_UNKNOWN`はExternal Execution自体の結果が確認不能な場合だけ使用する。

`INGESTED_DURABLE`は、Redacted Artifact、Secret Reference、Redaction MetadataおよびそれらのDigestを列挙する`SecureIngestionManifest`がDurable RepositoryへCommitされ、全参照をread-back検証できたことを表す。QuarantineのDeletion Intentはこの状態以後にだけ作成できる。`QUARANTINE_ERASED`後にCrashしても、ExecutionResultはManifestから再構築し、復号やProvider Result取得を再実行しない。

## 10.1 Execution State Machine

副作用を伴う操作の二重実行を防ぐため、実行状態を永続化する。

```text
PLANNED
  |
AUTHORIZED
  +--------> BLOCKED
  |           （Provider未送信・Terminal）
  |
  v
DISPATCH_CLAIMED
  |  （単回Claim確定。Submitを自動再試行しない）
  +--------> RECONCILING
  |
  v
DISPATCHED
  +--------> RUNNING
  |             |
  |             +-- SUCCEEDED
  |             +-- FAILED
  |             +-- CANCEL_REQUESTED
  |             +-- CANCELLED
  |             +-- OUTCOME_UNKNOWN
  |
  +--------> RECONCILING
                  |
                  +-- DISPATCHED / RUNNING
                  +-- SUCCEEDED / FAILED / CANCELLED
                  +-- OUTCOME_UNKNOWN
```

`AUTHORIZED -> BLOCKED`はApplicationのPre-dispatch Enforcementが実行を停止し、Provider APIを一度も呼び出していないTerminal Stateである。`pre_dispatch_block_reason`を必須とし、`SESSION_STALE`、`MISSION_NOT_RUNNING`、`POLICY_STALE`、`SNAPSHOT_STALE`、`SANDBOX_CAPABILITY_MISMATCH`、`ADAPTER_CAPABILITY_MISMATCH`、`APPROVAL_INVALID`、`AUTHORIZATION_TTL_EXPIRED`、`AUTHORIZATION_EPOCH_MISMATCH`、`REMOTE_MCP_TRUST_MISMATCH`、`ENCRYPTION_KEY_UNAVAILABLE`、`MISSION_EXPIRED`、`DIGEST_INTEGRITY_FAILURE`のVersion付きAllowlistから記録する。`provider_task_id`と`raw_result_quarantine_id`は`None`、Result Ingestion Stateは`NOT_AVAILABLE`とし、ExecutionResultを生成しない。`AUTHORIZED`中はSecret解決も禁止する。

BLOCKED Executionを後からAUTHORIZEDへ戻して再利用してはならない。Refresh / 再認可後に同じ提案を実行する場合も、新しいExecution ID、ExecutionRecord、PolicyDecision、および必要なApprovalRequest / ApprovalRecordを作成し、旧BLOCKED Recordとの関連をAuditする。

Pre-dispatch CheckはExecutionRecordを`AUTHORIZED`で永続化した後、Mission State / Validity、Authorization Epoch、PolicyDecision / Approval BindingとTTL、Session Freshness、AvailableToolSnapshot、Adapter / Sandbox Capability、Remote MCP Trust、必要なQuarantine / Secret Key Availability、Canonical Digestを再検証する。失敗時は同一TransactionまたはOCC Commandで`BLOCKED`へ遷移させ、Dispatch関数へ到達させない。Mission期限切れではReasonを`MISSION_EXPIRED`として`BLOCKED`にした上で、Mission Managerへ共通FINALIZING開始を要求する。

成功時はExecutionの`AUTHORIZED -> DISPATCH_CLAIMED`とDispatch Claim永続化を同じOCC Transactionで行う。`DISPATCH_CLAIMED`は「Providerが受理済み」を意味せず、「外部送信の単回試行をClaimしたため自動再送を禁止する」状態である。ProviderがTask Identityを返した場合だけ`DISPATCHED / RUNNING`へ進み、Crash、Timeout、Transport ErrorでSubmit有無を確認できない場合はClaimとIdempotency Keyを使ったReconciliationへ進む。

`DISPATCHED`または`RUNNING`から`CANCEL_REQUESTED`へ遷移できる。Cancel結果を推測せず、Adapter照合により`RUNNING / CANCELLED / OUTCOME_UNKNOWN`へ遷移する。`RECONCILING`は照会処理中のApplication Stateであり、外部Taskを再送する権限を持たない。

ExecutorはAdapterへ送信する前に`execution_id`、`proposal_digest`、`authorization_digest`、`policy_decision_id`、`idempotency_key`を同一Transactionで永続化する。

Idempotency KeyはApplicationがMission ID / Revision、Execution ID、authorization_digest、Resolved Adapter IDへBindingして生成し、Execution Record作成後はImmutableとする。Reconciliationまたは許可されたExecution Retryで新しいKeyを発行してはならない。Operatorが別Executionとして再承認した場合は新しいExecution IDとKeyを発行し、旧Executionとの関連をAuditする。

Checkpointからの再開時は、`DISPATCH_CLAIMED`、`DISPATCHED`または`RUNNING`のExecutionを新規送信せず、AdapterのTask状態と照合する。状態を照合できない場合は`OUTCOME_UNKNOWN`とする。非冪等Toolまたは高Risk Toolの`OUTCOME_UNKNOWN`はHuman Reviewなしに再実行してはならない。

## 10.2 Dispatch Claim / Secret Injection

Secret Valueを必要とするExecutionでも、Plan、PolicyDecision、ExecutionRequest、Graph StateはSecret Referenceだけを保持する。Secret解決は`DISPATCH_CLAIMED`かつ未消費・未失効のDispatch Claimに対してだけ許可し、`AUTHORIZED`、`BLOCKED`、`RUNNING`、Terminal Stateからの直接解決を拒否する。

Secret StoreはApplication Callerへ平文bytesを返す汎用`resolve(reference, execution_id)`を公開しない。`SecretInjectionBroker`がTrusted RepositoryからCurrent Dispatch Claim、PolicyDecision内のexact DataAccessGrant、Current Secret Metadata、Mission State、Tool、Adapter Channelをロードし、固定されたTrusted Adapter Channelへだけ値を渡す。Callerが任意Consumer、Callback、Environment名、Command Line、Endpointを指定できるInterfaceを禁止する。Phase 0CのTest Doubleも同じInterfaceを使用し、受信値をLog、Snapshot、Exceptionへ出力しない。

解決された値のLifetimeは1回のAdapter Submit呼出しに限定する。成功・失敗・Cancellationに関係なくBufferを破棄し、Claimを消費済みとして記録する。Secret Injection後にSubmit結果が不明な場合も、同じClaimでSecretを再解決・再送せずReconciliationへ進む。

## 10.3 Result Collection Authority

Result CollectionはProvider Executionとは別の回復可能な処理である。Executorは`collect_result()`を呼ぶ前にTrusted Clockから`collection_started_at`を取得し、Current Execution、Provider Task、PolicyDecision、exact ToolRef、Tool Registry Digest、`ToolDefinition.max_output_bytes`、Sink IDへBindingした`ResultCollectionAuthority`をTransactionally永続化する。

```text
retention_until = min(
    collection_started_at + quarantine_retention_policy,
    mission.valid_until,
)
max_result_bytes = min(
    ToolDefinition.max_output_bytes,
    system_hard_output_cap,
)
```

`mission.valid_until <= collection_started_at`、Tool Definition欠落、Registry Revision不一致、Provider Task不一致では新しいSinkを発行しない。RetentionはExecution作成時刻から計算せず、Authority作成時に一度だけ確定してRepositoryへ保存し、Crash Resume時に再計算しない。Global設定またはCaller引数でTool固有上限を拡大できず、System Hard Capは上限を狭める目的にだけ使用できる。

RawResultSink FactoryはExecution IDだけから暗黙にBindingを再構築せず、有効なCurrent ResultCollectionAuthorityをRepositoryからロードする。Lease期限切れ後の再開は同じ`collection_started_at`、`retention_until`、Tool上限、Sink IDおよびResume Cursorを維持し、External Actionを再Submitしない。

---

# 11. Analyzer

AnalyzerはExecutorの実行結果を解析するAIエージェントである。

入力:

```text
ExecutionPlan
ExecutionResult
Analyzer Context（ContextDataAccessGrantで構築済み）
```

出力:

```text
AnalysisResult
```

例:

```python
class CandidateObservation(StrictImmutableBoundaryModel):
    observation_type: Literal["asset", "identity", "relationship", "finding"]
    subject_ref: str
    predicate: str
    object_ref: str | None
    attributes: CanonicalJsonObject
    source_artifact_ids: tuple[str, ...]
    confidence: float = Field(ge=0.0, le=1.0)

class CandidateSessionObservation(StrictImmutableBoundaryModel):
    session_ref: str
    observed_principal_ref: str | None
    observed_status: Literal["active", "stale", "lost", "terminated", "unknown"] | None
    refresh_reason: str
    source_artifact_ids: tuple[str, ...]

class EvidenceCandidate(StrictImmutableBoundaryModel):
    condition_id: str
    source_artifact_ids: tuple[str, ...]
    claim: str

class AnalysisResult(StrictImmutableBoundaryModel):
    status: Literal["parsed", "partial", "rejected"]

    observations: tuple[CandidateObservation, ...]

    session_observations: tuple[CandidateSessionObservation, ...]

    artifacts: tuple["ArtifactReference", ...]

    goal_evidence: tuple[EvidenceCandidate, ...]
```

Analyzerは原則として「次の攻撃方法」を決定しない。

Analyzerの責務は、

```text
結果
↓
Observation候補
↓
構造化データ
```

への変換である。

次の行動の決定はPlannerへ戻す。

Tool出力、Webページ、ファイル、C2出力、MCP応答は非信頼データとして扱う。Context BuilderはSystem InstructionとTool出力を明確に分離し、Tool出力中の命令文をAgentへの指示として扱わせない。

Analyzer呼び出し前に`analyzer_context`用ContextDataAccessGrantを発行し、Context Builderを通す。AdapterRawResult、Encrypted Raw Artifact、Raw SecretをAnalyzerへ直接渡してはならない。

AnalysisResultはKnowledge Baseへ直接書き込まない。決定論的なKnowledge Reducerが以下を実施する。

* Schema、Target、Session、Artifact参照の整合性検証
* 重複排除と既存情報とのConflict検出
* `source_execution_id`、`artifact_id`、抽出時刻の付与
* `inferred`と`confirmed`の区別
* Secretらしき値のSecret Storeへの隔離

Secure Ingestionが生成したSecretDiscoveryReferenceはAnalysisResultと独立した信頼済みMetadataとしてKnowledge Reducerへ渡す。AnalyzerがSecret Valueを再抽出する設計にしない。

Goal Evaluatorは、Analyzerが出力した文字列だけを成功根拠にしてはならない。

Finding TypeごとにConfirmation Ruleを定義する。例えば、Session存在はSession Manager、Exit CodeはAdapter、Artifact HashはArtifact Storeの決定論的検証で`confirmed`にできる。LLMのConfidence値だけで`inferred`から`confirmed`へ昇格させてはならない。

既存Findingと矛盾するObservationは上書きせず、双方のProvenanceを保持して`contradicted`として関連付ける。単に新しい情報であることだけを理由に既存のConfirmed Findingを置き換えない。

AnalyzerはSession Runtime Stateを直接変更しない。`session_observations`はSession Refreshを要求する候補情報としてのみ扱う。

```text
ExecutionResult
       |
       v
Analyzer
       |
CandidateSessionObservation
       |
       v
Session Manager Refresh
       |
       v
C2 Adapter
       |
       v
Confirmed Session Runtime State
```

Analyzerが権限変更を推測しても、C2 Adapterまたは信頼済みAdapterから取得した情報で確認できるまでSessionのUser、Privilege、Integrity、Statusを更新してはならない。

---

# 12. C2

C2フレームワーク自体をAIエージェント内に実装しない。

C2は独立した実行インフラとして動作させる。

```text
AI Agent
   |
C2 Adapter
   |
C2 API
   |
C2 Server
   |
C2 Session / Agent
```

AIは、人間のオペレーターがC2のCLIやGUIから実施していた操作を、APIを通して行う。

C2の通信処理やエージェントとの通信はC2フレームワーク側が担当する。

---

# 13. C2 Adapter

特定のC2製品にPlannerやExecutorを依存させない。

共通インターフェースを定義する。

概念例:

```python
class AdapterCapabilities(StrictImmutableBoundaryModel):
    adapter_id: str
    adapter_type: Literal["c2", "mcp", "local"]
    capability_revision: str
    capabilities: frozenset[str]
    supported_os: frozenset[str]
    supported_architectures: frozenset[str]
    reconciliation: bool
    cancellation: bool
    provider_deduplication: bool
    result_streaming: bool
    result_resume: bool
    durable_result_collection: bool
    max_output_bytes: int = Field(gt=0)
    provider_tool_catalog_digest: str | None
    observed_at: datetime

class ExecutionRequest(StrictImmutableBoundaryModel):
    execution_id: str
    request_digest: str
    mission_revision: int
    authorization_epoch: int
    tool_ref: ToolRef
    policy_decision_id: str
    provider_operation: str
    session_id: str | None
    normalized_targets: tuple["NormalizedTarget", ...]
    arguments: CanonicalJsonObject
    timeout_seconds: int = Field(gt=0)

class TaskHandle(StrictImmutableBoundaryModel):
    execution_id: str
    task_id: str
    provider_task_id: str | None
    state: Literal["queued", "running", "completed"]
    submitted_at: datetime

class TaskStatus(StrictImmutableBoundaryModel):
    task_id: str
    state: Literal[
        "queued",
        "running",
        "succeeded",
        "failed",
        "cancelled",
        "unknown"
    ]
    updated_at: datetime

class CancelResult(StrictImmutableBoundaryModel):
    task_id: str
    requested: bool
    confirmed: bool

class ReconciliationResult(StrictImmutableBoundaryModel):
    execution_id: str
    status: Literal[
        "NOT_FOUND",
        "QUEUED",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "UNKNOWN",
        "UNSUPPORTED"
    ]
    provider_task_id: str | None
    checked_at: datetime

class ExecutionAdapter(Protocol):

    async def get_capabilities(self) -> AdapterCapabilities:
        ...

    async def submit(
        self,
        request: ExecutionRequest,
        idempotency_key: str
    ) -> TaskHandle:
        ...

    async def get_task(
        self,
        task_id: str
    ) -> TaskStatus:
        ...

    async def collect_result(
        self,
        task_id: str,
        sink: RawResultSink,
    ) -> AdapterRawResult:
        ...

    async def cancel_task(
        self,
        task_id: str
    ) -> CancelResult:
        ...

    async def reconcile(
        self,
        execution_id: str,
        idempotency_key: str
    ) -> ReconciliationResult:
        ...

class C2Adapter(ExecutionAdapter, Protocol):

    async def list_sessions(self) -> list[Session]:
        ...

    async def get_session(
        self,
        session_id: str
    ) -> Session:
        ...
```

Adapter継承関係を以下に固定する。Session列挙・取得はC2Adapter固有Extensionであり、Executor Coreの共通Dispatch Contractへ混在させない。

```text
ExecutionAdapter
   |
   +-- C2Adapter
   |      |
   |      +-- list_sessions()
   |      +-- get_session()
   |
   +-- MCPAdapter
   |
   +-- LocalToolAdapter
```

ExecutionRequestはExecutorがExecutionPlan、PolicyDecision、Tool Registryから生成する信頼境界内のRequestである。`policy_decision_id`からImmutableなPolicyDecisionを取得し、`authorized_data_access`を含むExecution Authorization Envelope全体を検証する。独立したDataAccessGrant IDをExecutionRequestへ渡したり、DataAccessGrant EntryをBearer Tokenとして扱ったりしない。

`provider_operation`はTool Registryの`provider_tool_name`から設定し、Planner入力から直接取得しない。Secret Valueが必要な場合は、Section 10.2のSecretInjectionBrokerがCurrent Dispatch ClaimとPolicyDecision Envelopeを検証し、実行直前にRegistry固定のTrusted Adapter Channelへ注入する。Executor / Adapterの汎用APIからSecret平文を返さず、永続化するExecutionRequestへ値を埋め込まない。

Adapterの公開Interfaceから任意Provider Method、任意Endpoint、自由形式Commandを呼び出せるようにしない。AdapterはToolRef、Provider Operation、Session、Normalized TargetのRegistry Bindingを再検証し、不一致をProviderへ送信しない。Providerから得たStatus、Session Metadata、Resultは信頼済みControl Responseと非信頼Payloadを分離して正規化する。

同期的なC2 APIは、完了済み`TaskHandle`を返すことで同じInterfaceへ適合させる。AdapterはProvider側Task IDと`execution_id`の対応を永続化し、可能な場合は同じIdempotency Keyによる重複送信を抑止する。

`AdapterCapabilities`には、Session照会、Task照会、Reconciliation、Cancel、Provider側Deduplication、Result Streaming / Resume、Durable Result Collection、対応OS / Architecture、最大Output Size等を含める。起動時にCapabilityを検査し、Tool Availability Resolverへ渡す。`adapter_capabilities_digest`はAdapter ID順にSortしたSecurity-relevant Fieldから生成し、`observed_at`等のTelemetry Timestampを含めない。Quarantine-aware Streamingに対応せず、またResult再取得またはAdapter内Durable StagingによるCrash RecoveryもできないAdapter / Toolは、Crash-safe Result取得要件を満たさないためAvailableToolSnapshotから除外する。

`submit()`受付後、`TaskHandle`受信前にProcessが停止した場合、Executorは`execution_id`と`idempotency_key`で`reconcile()`を呼び出す。`UNSUPPORTED`または確定不能な`UNKNOWN`の場合はExecutionを`OUTCOME_UNKNOWN`へ遷移させ、Human Reviewなしに再送しない。

不確実なSubmit後の`NOT_FOUND`も、Provider契約が強い一貫性を保証しない限り未実行の証明とはみなさない。Bounded Retryで照会しても確認できなければ`OUTCOME_UNKNOWN`とする。

本システムは外部Providerを含む厳密なExactly Once Executionを保証しない。基本原則は「確認できない副作用Actionは自動再送しない」とする。

C2 AdapterはRaw ContentをExecutor発行のRawResultSinkへStreamingし、Contentを含まないAdapterRawResultだけを返す。ExecutionResultは生成しない。同じ境界をMCP AdapterとLocal Tool Adapterにも適用する。

ExecutionAdapterを共通Contractとし、C2 / MCP / Local Tool AdapterはCapability取得、Dispatch、Quarantine-aware Streaming、Control Metadata、対応可能なCancellation、`execution_id / idempotency_key`によるReconciliationを共通の意味へ正規化する。ProviderがReconciliationを実装できない場合はCapabilityを`UNSUPPORTED`として申告し、Dispatch後の不確実な障害を`OUTCOME_UNKNOWN`へ遷移させる。同期Local Processでも、開始後に終了状態を確認できない副作用Executionを単なるTool Errorとして再送してはならない。

RawResultSinkはExecutorがExecution ID、Mission、Quarantine Key Domain、Size LimitへBindingして生成する。Adapterが別Sinkや通常Fileへ切り替えることを禁止する。Streaming途中のError / Crashは`RawResultStreamingError`とし、Quarantine MetadataとChunk Integrity Stateから同じProvider TaskのResult取得だけを再開する。Provider Taskを再SubmitしてResultを作り直してはならない。

C2固有APIはAdapter内部に閉じ込める。

将来的には、

```text
C2Adapter
   |
   +-- C2-A Adapter
   +-- C2-B Adapter
   +-- Mock C2 Adapter
```

のように差し替え可能とする。

---

# 14. Session Manager

Session ManagerはAIエージェントにしない。

決定論的なPythonサービスとして実装する。

Session ManagerおよびそのApplication Database RepositoryをSession Runtime StateのSource of Truthとする。Analyzer、Planner、Graph StateはSession Recordを直接更新できない。

Session ManagerはCurrent Runtime / Execution Contextだけを管理する。

```text
Session Stable ID
C2 Provider
Host
IP
Hostname
OS
Architecture
Session Capabilities
Current Principal SID / UID
Effective UID / GID
Current Windows Token
Integrity Level
Enabled Token Privileges
Current Token Groups
Current Linux Capabilities
Domain
Last Seen
Session Status
Parent Session
Network Context
```

Session Statusは`active / stale / lost / terminated / unknown`のEnumとして正規化する。C2固有StatusをPlannerへ直接公開しない。

Session ManagerはC2 Adapterから定期的または必要時に情報を取得する。

SessionにはProvider内IDとは別に内部のStable IDを割り当てる。`last_seen`、`refreshed_at`、`stale_after`を保持し、期限を超えたSessionをActiveとしてPlannerへ渡さない。SessionとHost、Current Principal、Network Contextの対応にはSourceと更新時刻を持たせる。

Principalの一般的なAD Group Membership、Local Group Membership、Delegation、Trust、Account Relationship等の発見事実はKnowledge Baseが管理する。Session Managerへ複製して別のSource of Truthを作らない。

`stale_after`はC2 Providerごとに設定し、Goal EvaluatorがSession存在を判定する直前にもRefreshする。Refreshに失敗したSessionをGoal達成の根拠にしてはならない。

Plannerが指定した`session_id`は、Policy EngineがMission、Target Host、現在のSession状態と照合する。SessionがScope内Host上に存在することだけを理由に、そのSessionから到達可能な全Targetを許可してはならない。

Context BuilderはSession Managerの確認済みRuntime StateからPlanner用の許可済みViewを構築し、PlannerはそのViewによって、

```text
現在どのセッションが存在するか
どのホストにアクセス可能か
どのユーザー権限なのか
```

を把握する。

---

# 15. Knowledge Base

Session Managerとは別にKnowledge Baseを構築する。

Session Manager:

```text
現在存在するアクセス経路・セッション
```

Knowledge Base:

```text
演習中に判明した事実
```

を管理する。

---

# 16. Knowledge Baseで管理する情報

最低限以下を管理する。

## Assets

```text
Host
IP
Hostname
OS
Domain
Services
Network
Role
```

## Accounts

```text
Username
Domain
Account Type
Principal ID / SID / UID
Credential Reference
```

Knowledge BaseはDiscovered Identity / Infrastructure Factsを管理する。現在のSession Token、Effective UID等のRuntime値は保存元にせず、必要な場合はSession Stable IDへのRelationshipとして参照する。

認証情報そのものはAudit Log等に平文で保存しない。

秘密情報を扱う場合はSecret Storeへの参照IDを保存する。

## Relationships

例:

```text
User -> Host
Host -> Network
Session -> Host
Account -> Group
Principal -> AD Group
Principal -> Local Group
Principal -> Host
Principal -> Domain
Delegation
Trust
Account Relationship
Host -> Domain
```

設計上の区分:

```text
Session Manager
= 今このSessionが何として実行されているか

Knowledge Base
= 演習中に発見したIdentity / Infrastructure Fact
```

## Findings

```text
Finding ID
Type
Target
Evidence
Confidence
Source
Source Execution ID
Artifact ID
Verification State: inferred / confirmed / contradicted
Timestamp
```

## Executions

```text
ExecutionPlanProposal
ExecutionPlan
ExecutionResult
AnalysisResult
Timestamp
```

---

# 17. Graph State

LangGraph内では短期的な実行状態を保持する。

例:

```python
class AgentState(TypedDict):

    mission_id: str
    mission_revision: int
    observed_mission_state_version: int
    observed_authorization_epoch: int
    llm_profile_digest: str
    run_id: str
    thread_id: str

    current_phase: OperationalPhase

    current_plan_id: str | None
    available_tool_snapshot_id: str | None
    policy_decision_id: str | None
    pending_approval_request_id: str | None
    pending_approval_id: str | None
    current_execution_id: str | None
    last_execution_id: str | None
    last_analysis_id: str | None

    iteration: int

    status: Literal[
        "RUNNING",
        "PAUSED",
        "WAITING_APPROVAL",
        "RECONCILING",
        "HANDLING_INDETERMINATE",
        "FINALIZING",
        "WAITING_HUMAN_REVIEW",
        "COMPLETED",
        "COMPLETED_WITH_UNRESOLVED_EXECUTIONS",
        "FAILED",
        "ABORTED"
    ]
    workflow_started_at: datetime
    active_runtime_seconds: float
```

大量のツール出力をGraph Stateへ直接保存しない。

Tool出力はSecure Ingestion Pipelineを経由してArtifact Storeへ保存し、Stateには参照のみ保存する。

ExecutionPlan、ExecutionResult、AnalysisResultの本体もApplication Databaseの各Repositoryへ保存し、Graph StateにはIDだけを保持する。Checkpoint上のCached ObjectをMission、Execution、KnowledgeのSource of Truthとして扱わない。

Graph StateとExecution Stateは別に管理する。Graph Checkpointを復元しても、Execution Stateを確認せずにAdapterへ再送してはならない。

## 17.1 Source of Truth

Source of Truthを以下に固定し、同じ情報へ複数のSource of Truthを作らない。

| Data | Source of Truth |
|---|---|
| Workflow Control State | LangGraph Checkpoint |
| Mission Configuration / Revision | Mission Revision Repository |
| Mission Lifecycle / OCC Version / Authorization Epoch | Mission State Repository |
| Provider Execution State | Execution Repository |
| Current Dispatch Claim / Consumption | Dispatch Claim Repository |
| Result Collection Start / Tool Limit / Retention / Sink Binding | Result Collection Authority Repository |
| Result Ingestion State | Result Ingestion Repository |
| Durable Secure Ingestion Output | Secure Ingestion Manifest Repository |
| Quarantine Erasure Progress | Quarantine Deletion Intent Repository |
| Raw Result Ciphertext | Encrypted Raw Result Quarantine |
| Raw Result Receipt / Quarantine Metadata | Result Ingestion / Quarantine Metadata Repository |
| C2 Session Runtime State | Session Manager / trusted Adapter |
| Discovered Facts | Knowledge Base |
| Tool Metadata | Tool Registry |
| Tool Availability | Immutable AvailableToolSnapshot |
| Adapter Capability Snapshot | Adapter Capability Snapshot Repository |
| Sandbox Capability Snapshot | Sandbox Capability Snapshot Repository |
| Session Security Context Snapshot | Session Security Context Snapshot Repository |
| Authorization | PolicyDecision / ContextDataAccessGrant |
| Approval Presentation | Approval Request Repository |
| Human Approval Decision | Approval Record Repository |
| Secret Value | Secret Store |
| Artifact Metadata | Artifact Store / Artifact Repository |
| MCP Discover Result | MCP Discover Result Repository |
| Local LLM Profile / Capability Result | LLM Profile Repository |
| Encryption Key Material | External Key Provider |
| Encryption Key Metadata | Key Metadata Repository |
| Audit / Wrapped Key Committed Generation | External digest/blob-bound Generation Anchor Store |
| Audit Event / Mission Chain Sequence | Tamper-evident Audit Store |

`Session Manager / trusted Adapter`は二重管理を意味しない。External RuntimeについてはProviderが上流の事実源であり、Application内ではSession ManagerがRefresh結果を正規化して保持する唯一のSession Runtime Stateとする。Analyzer、Knowledge Base、Checkpointが別のSession Runtime Stateを保持して上書きしてはならない。Authorizationについては、PolicyDecisionがExecution Authorization、ContextDataAccessGrantがLLM Context用Read AuthorizationのSource of Truthであり、同じ操作を重複して許可するものではない。CapabilityやSecurity ContextはDigestだけでなくDigest生成元のImmutable Snapshotも保持し、後から判断根拠を再構築できるようにする。

Context Resource IndexはArtifact Repository、Knowledge Base等から生成する検索用Derived Viewであり、新しいSource of Truthではない。Indexと原RepositoryのVersion / Digestが一致しない候補はContext Authorizationで拒否し、原RepositoryからIndex Metadataだけを再構築する。本文へFallbackして候補探索してはならない。

Workflow Resume時は以下の順序でReconciliationする。

```text
LangGraph Checkpoint
        |
        v
Application Database
        |
        v
External Adapter
```

External Side EffectについてはApplication DatabaseおよびAdapter側の確認結果をGraph Stateより優先する。例えばGraph Stateが`RUNNING`でもApplication Databaseが`OUTCOME_UNKNOWN`の場合、Executorを再送せず`OUTCOME_UNKNOWN`としてHuman Reviewへ送る。

Checkpoint復元後は、未完了ExecutionをDBから列挙し、Adapterの`reconcile()`を実行してから通常のGraph遷移を再開する。

## 17.2 LangGraph thread_id Lifecycle

`run_id`はApplicationが生成し、Checkpointの`thread_id`を以下へ固定する。

```text
thread_id = mission_id : mission_revision : run_id
```

Mission IDとrun_idは`:`を含まないApplication発行ID Grammarへ固定し、Mission Revisionは非負整数のCanonical Decimalとする。別のID形式を採用する場合は長さPrefix等の衝突しないCanonical Encodingを仕様化する。

異なるMission間、または異なるMission Revision間でthread_idを共有してはならない。Mission Revision変更時は新しいrun_idとthread_idを生成し、必要なApplication Stateだけを各Repositoryから明示的に再構築する。旧RevisionのCheckpointを暗黙にCopy、Merge、Resumeしてはならない。

CheckpointをLoadする際はthread_id内のMission ID / RevisionとMission Repositoryを照合し、不一致は`MissionRevisionConflictError`としてFail Closedする。

`observed_mission_state_version`と`observed_authorization_epoch`はCheckpoint作成時に観測したCacheであり、OCCまたはAuthorization EpochのSource of Truthではない。Resume時はMission State Repositoryから現在値を読み直し、Epoch不一致なら古いGrant、Snapshot、Decision、ApprovalRequest、ApprovalRecordをStateから除去してSection 21.1のResume再認可Flowへ進む。

## 17.3 Graph State / Mission State Mapping

Graph StateとMission Stateの対応を以下に固定する。

| Graph State | Mission State | 意味 |
|---|---|---|
| Active Workflowなし | `DRAFT`または`VALIDATED` | Workflow開始前。Checkpointを作成しない |
| `RUNNING` | `RUNNING` | 通常実行 |
| `PAUSED` | `PAUSED` | OperatorまたはBounded Recovery上限による一時停止 |
| `WAITING_APPROVAL` | `RUNNING` | Approval待ち。Missionは実行中だが新規Dispatchは停止 |
| `RECONCILING` | `RUNNING`または`FINALIZING` | 外部状態照合中 |
| `HANDLING_INDETERMINATE` | `RUNNING` | Bounded Refresh / Reconciliation中。新規副作用Dispatchは禁止 |
| `FINALIZING` | `FINALIZING` | 終了処理中 |
| `WAITING_HUMAN_REVIEW` | `WAITING_HUMAN_REVIEW` | Operator判断待ち |
| `COMPLETED` | `COMPLETED` | 正常完了 |
| `COMPLETED_WITH_UNRESOLVED_EXECUTIONS` | `COMPLETED_WITH_UNRESOLVED_EXECUTIONS` | 未解決ExecutionをOperatorが明示的に受理 |
| `FAILED` | `FAILED` | Recovery不能な内部障害 |
| `ABORTED` | `ABORTED` | OperatorまたはPolicyによる終了 |

Graph State変更だけでMission Stateを暗黙更新してはならない。Mission Lifecycle変更はMission Managerが`expected_mission_state_version`を検証してMission State RepositoryへCommitし、成功後にGraph Stateを対応状態へ進める。Commit失敗またはMapping不能な組み合わせはFail Closedし、GraphをDispatch可能状態へ進めない。

---

# 18. Context Selector / Authorization / Builder

LLMにKnowledge Base全体を毎回投入しない。

Planner / Analyzerへ渡す候補Resourceを決定論的なContext Selectorで選び、Policy Engineが候補ReferenceをAuthorizationし、Context Builderが許可済みContentだけを取得する。Context Selector、Context Authorization、Context BuilderのどれにもLLMを使用しない。

```python
class CandidateContextResource(StrictImmutableBoundaryModel):
    resource_id: str
    resource_type: Literal[
        "artifact",
        "secret_reference",
        "local_artifact",
        "report",
        "internal_knowledge"
    ]
    mission_id: str
    target_references: tuple["TargetReference", ...]
    verification_state: str
    observed_at: datetime
    classification: str
    summary_metadata: CanonicalJsonObject
```

Context SelectorはMission、Current Target、Workflowが参照中のCandidate Session Reference、Operational PhaseからRepositoryのIndex MetadataだけをQueryし、Candidate Resource Referencesを生成する。この時点のSession Referenceは認可済みViewではなく候補Keyにすぎない。読取可能FieldはResource ID / Type、Mission ID、Target Reference、Verification State、Timestamp、Classification、Size等のSummary Metadataに限定する。Artifact Body、Secret Value、Encrypted Raw Artifact、Raw Tool Output、Knowledge本文、未許可Resource Contentへアクセスしてはならない。

Context Selectorの候補化はRead Authorizationではない。Context AuthorizationはCandidate ReferenceをMission Data Access Policy、Classification、Service Identity、Authorization Epochへ照合する。候補外ResourceをGrantへ追加せず、候補化されたことだけを理由に許可しない。Context Selectionに失敗した場合は`ContextSelectionError`としてFail Closedし、Context Builderが全文検索へFallbackしてはならない。

`CalculateContextAuthorization`は候補ReferenceからGrant ContentとCanonical Digestを計算するPure Nodeであり、ID生成やDB Writeを行わない。`PersistContextAuthorization`はSection 4.2のOperation IDにMission ID / Revision、Authorization Epoch、Service Identity、Policy Version、Candidate Set Digest、Grant Content DigestをBindingしてDeterministic Grant IDを生成し、Unique Constraint付きIdempotent Upsertを行う。同じ入力のRetryで別Grantを作成してはならず、同じIDに異なるContentがある場合は`DigestIntegrityError`とする。

```text
Planner Context:

Mission / Session Refresh
        |
        v
Context Selector
        |
Candidate Resource References
        |
        v
Calculate / Persist Context Authorization
        |
ContextDataAccessGrant(planner_context)
        |
        v
Context Builder
        |
        v
Planner Context
        |
        v
Planner

Analyzer Context:

ExecutionResult
        |
        v
Context Selector
        |
Candidate Resource References
        |
        v
Calculate / Persist Context Authorization
        |
ContextDataAccessGrant(analyzer_context)
        |
        v
Context Builder
        |
        v
Analyzer
```

目的:

* Context Window削減
* 推論速度向上
* LLMの混乱防止
* 不要な情報による判断精度低下の防止

Context BuilderはGrantのService Identity、Mission ID / Revision、Authorization Epoch、Policy Version、期限、Resource、Operation、SessionContextGrant、保存済みCanonical Digestを検証する。GrantにないKnowledge Base、Artifact、Report、Internal Knowledge、Secret Reference Metadataへアクセスしてはならない。`secret_reference`への`read`は値を含まないMetadata取得だけを意味し、`resolve`とは別Operationとする。

Session Runtime StateはData Access PolicyのArtifact系Resourceではないため、Context AuthorizationはMissionのExecution ScopeとSession Scopeを用いてPlanner / Analyzerへ公開可能なSession Viewを決定し、SessionContextGrantへ固定する。`authorized_session_ids`にないSession、Scope外Session、Provider固有Raw State、期限切れSessionをContextへ含めてはならない。Session Security Context Digestが一致しない場合はGrantを再発行するまでContextを生成しない。

Context BuilderはSecret Referenceを値へ解決せず、Encrypted Raw ArtifactとRaw Tool Outputを読み取らない。各Context要素にSource、Verification State、Timestampを付与し、System Instructionと非信頼のTool / Redacted Artifact内容を別フィールドおよび明確なDelimiterで分離する。Context Sizeと各Artifactからの抽出量に上限を設ける。

---

# 19. MCP / Tool Adapter

C2だけですべての処理を行う必要はない。

Executorは複数の実行バックエンドを利用可能とする。

```text
Executor
   |
   v
ExecutionAdapter
   |
   +-- C2 Adapter
   +-- MCP Adapter
   +-- Local Tool Adapter
```

MCP Adapterでは許可されたMCP Serverを接続可能とする。

例:

```text
Security Testing MCP
Filesystem MCP
Asset Management MCP
Analysis MCP
```

具体的なツール名をPlannerへ直接ハードコードしない。

Tool Registryを実装し、

```text
ToolRef
Display Name / Version
Description
Parameters
Adapter
Minimum Risk Level
Approval Rule
Side Effect
Idempotency
Target Extractor ID
```

を管理する。

Tool RegistryはPolicy Engineが使用する信頼済み設定であり、Plannerから変更できない。起動時にSchemaを検証し、Mission開始時のRegistry VersionおよびDigestをAudit Logへ保存する。

MCP Serverから`tools/list_changed`またはTool Schema変更通知を受けても、信頼済みTool Registryを自動更新しない。更新手順はSection 19.1のCandidate Definition Flowへ統一する。

MCP Serverが申告するRisk、Approval Requirement、Side Effectは候補Metadataとしてのみ扱う。最終値はローカルの信頼済みTool RegistryとPolicy Engineが決定する。

## 19.1 MCP Protocol / Durable Task境界

各MCP ServerはApplicationが発行したStable Internal IDで識別し、接続時の表示名やNetwork AddressをIDとして使用しない。MCP Protocol RevisionはDiscovery後に設定値と完全一致を検証してPinする。古いRevisionへの暗黙Fallback、未知Revisionへの自動Upgrade、Capabilityの推測を行わない。

MVPのBaseline設定は`2026-07-28`とし、Serverごとの設定に明示する。このRevision指定だけでTasks Extensionが利用可能とはみなさず、Server、Extension、Python Client実装のCapability Checkを別途必須とする。Baselineを変更する場合はConfiguration Revision、Compatibility Test、Administrator Reviewを必要とし、実行中Missionへ暗黙適用しない。

概念例:

```python
class MCPServerCapabilities(StrictImmutableBoundaryModel):
    tools_list_changed_subscription: bool
    cancellation: bool
    task_extension: bool
    reconciliation: bool

class MCPTransportIdentity(StrictImmutableBoundaryModel):
    transport_type: Literal["stdio", "streamable_http"]
    identity_type: str
    identity_value: str

class MCPLogicalServerInfo(StrictImmutableBoundaryModel):
    server_name: str
    server_version: str | None
    server_info_digest: str

class RemoteMCPEnforcementCapabilities(StrictImmutableBoundaryModel):
    scope_enforcement: bool
    authentication_authorization: bool
    audit: bool
    network_egress_enforcement: bool
    sandbox_process_isolation: bool
    stable_transport_identity: bool

class MCPServerConfig(StrictImmutableBoundaryModel):
    server_id: str
    protocol_revision: str
    transport: Literal["stdio", "streamable_http"]
    execution_location: Literal[
        "local_process",
        "managed_remote",
        "untrusted_remote"
    ]
    configured_transport_identities: tuple[MCPTransportIdentity, ...]
    tool_list_revision: str
    required_capabilities: MCPServerCapabilities
    task_extension_id: str | None
    task_extension_version: str | None
    task_implementation_mode: Literal["native", "custom", "disabled"]

class MCPDiscoverResult(StrictImmutableBoundaryModel):
    discover_result_id: str
    server_id: str
    logical_server_info: MCPLogicalServerInfo
    verified_transport_identities: tuple[MCPTransportIdentity, ...]
    reported_protocol_revision: str
    transport: Literal["stdio", "streamable_http"]
    reported_capabilities: MCPServerCapabilities
    remote_enforcement_capabilities: RemoteMCPEnforcementCapabilities | None
    tool_list_revision: str
    task_extension_id: str | None
    task_extension_version: str | None
    task_implementation_mode: Literal["native", "custom", "disabled"]
    client_sdk_name: str
    client_sdk_version: str
    discover_digest: str
    verified_at: datetime
```

MCP Config Validationでは`local_process`をstdio、`managed_remote / untrusted_remote`をStreamable HTTPへ対応付け、矛盾する組合せを拒否する。stdioはAbsolute PathとExecutable SHA-256、RemoteはConfigured URLと少なくとも1つの暗号学的Transport Identityを必須とする。`identity_type`はTransportごとのVersion付きAllowlistから選び、自由文字列をTrust判定ロジックへ直接使用しない。

初回接続手順を以下へ固定する。`server/discover`は論理的なDiscovery Stepを表し、使用SDKではProtocol Initialization / Discovery APIへ明示的にMappingする。

```text
Initial Connection / Process Spawn
       |
       v
Transport Identity確認
       |
       +-- configured identityと一致しない
       |       |
       |       v
       |    FAIL CLOSED
       |
       v
server/discover またはProtocol-equivalent initialize
       |
       v
Reported Protocol Revision確認
       |
       +-- configured revisionと一致しない
       |       |
       |       v
       |    FAIL CLOSED
       |
       v
Logical Server Info / Capabilities取得
       |
       v
検証済みDiscover Result保存
       |
       v
Subsequent Connection
```

MCP Logical IdentityとTransport Identityを分離する。Logical IdentityはMCP Discover / initializeの`serverInfo`等の非暗号学的Metadataであり、接続先をTrustする唯一の根拠にしない。Transport Identityは接続またはProcess Spawn前後にApplicationが外部Trust Boundaryとして検証する。

Remote Streamable HTTPではConfigured URL、TLS Certificate Fingerprint、SPKI Fingerprint、OAuth Resource Identity、mTLS Peer Identity等から設定で必須としたIdentityを検証する。stdioではExecutable Absolute Path、Executable SHA-256、Command Configuration Digest、Package / Binary Versionを検証する。PATH検索結果、表示名、MCP自己申告Versionだけで同一Serverとみなしてはならない。

以降の接続は、保存済みDiscover ResultへPinしてTransport IdentityとLogical Server Infoを再確認する方式、または毎回検証して完全一致を確認する方式のどちらかを設定で固定する。Discover ResultにはApplicationのServer Stable ID、Logical Server Info、Transport Identity、Reported Revision、Transport、Capabilities、Tool List Revision、SDK Name / Version、Task Implementation Mode、検証日時、Digestを保存する。Revision不一致は`MCPProtocolRevisionMismatchError`、Logical Identity不一致は`MCPServerIdentityMismatchError`、Transport Identity不一致は`MCPTransportIdentityMismatchError`としてFail Closedする。Logical Identityが一致してもTransport Identityが一致しなければ接続・Tool Availability・Dispatchを許可しない。

MCP Tasks ExtensionはOptional Capabilityとする。使用中のMCP Python SDKが`io.modelcontextprotocol/tasks`をNative Supportしない場合は、検証済みCustom Low-level Implementationを明示的に使用するか、Tasks ExtensionをDisabledとして運用する。

```text
Native SDK Supportあり + Capability Check合格
        -> task_implementation_mode = native

検証済みCustom Implementationあり
        -> task_implementation_mode = custom

どちらもない
        -> task_implementation_mode = disabled
        -> task_extension = false
```

Serverの自己申告だけでTask CapabilityをTrueにしてはならない。Server Capability、Task Extension ID / Version、Client実装Capabilityの積集合が検証できた場合だけ`task_extension=true`とする。不一致は`MCPTaskCapabilityError`として該当CapabilityをDefault Denyする。Task CapabilityがないSide-effect Callの不確実なTimeoutは`OUTCOME_UNKNOWN`とし、自動再送しない。

MCP設定Validationでは、`task_implementation_mode="disabled"`なら有効Capability上の`task_extension=false`を強制する。`native`または`custom`でTaskを有効にする場合はExtension ID / Version、Client Capability Check Result、Server Reportのすべてを必須とし、欠落や不一致を起動前に拒否する。

起動時にProtocol Revision、Transport、Server Capabilities、Tool List Revision、Subscription Capability、Task Extension Capability、Cancellation Capabilityを検査し、結果を`AdapterCapabilities`へ反映する。設定とHandshake結果が一致しない場合、該当CapabilityをDefault Denyし、必須Capabilityの不一致ではServerを使用不可とする。

MCP AdapterはC2 Adapterと同じExecution State境界へ従い、Raw ContentをRawResultSinkへStreamingしてMetadata-onlyの`AdapterRawResult`だけを返す。Long-running Operationを利用する場合は、Task Extension ID、Extension Version、Server CapabilityをExecution Recordへ固定し、Tool呼び出し時に再検証する。Task CapabilityがないServerにTask照会、Task Cancellation、Task Reconciliation APIを呼び出してはならない。

MCP Tool Callの結果受信前にTimeoutまたはProcess Crashが発生した場合は、次の順で扱う。

```text
Task / Reconciliation Capabilityあり
        -> bounded reconciliation
        -> confirmed state または OUTCOME_UNKNOWN

Task / Reconciliation Capabilityなし
        -> 副作用なしを証明できない
        -> OUTCOME_UNKNOWN
        -> Human Review
```

Provider側で実行されていないことを確認できない副作用Callを自動再送しない。Read-onlyかどうかはMCP Serverの自己申告ではなく、信頼済みTool RegistryのSide Effect定義で判定する。

Tool変更のSubscriptionは変更検知にだけ使用する。通知または定期`tools/list`との差分はCandidate Definitionとして隔離し、Administrator Reviewを通過するまでTool Availabilityへ反映しない。

MCP AdapterはLive Tool List RevisionとSchema Digestから`provider_tool_catalog_digest`を生成する。Live Catalog変更は安全のため既存SnapshotのAdapter Capability BindingをStaleにできるが、信頼済みTool Registryを更新する権限は持たない。承認済みDefinitionとLive Schemaが一致するまで該当ToolをDispatchしない。

Candidate Tool Definitionは非信頼入力としてSize Limit、JSON Schema Validation、文字列Sanitizationを適用し、管理者画面で命令として解釈しない。承認前のDescriptionやParameter SchemaをPlanner / Analyzer Contextへ渡してはならない。

```text
MCP Tool Change
       |
       v
Candidate Tool Definition
       |
       v
Administrator Review
       |
       v
Tool Registry New Revision
       |
       v
Registry Digest変更
       |
       v
AvailableToolSnapshot失効
       |
       v
PolicyDecision失効
```

## 19.2 Remote MCP Trust Policy

MCP ServerのExecution Locationを`local_process / managed_remote / untrusted_remote`に分類し、Tool RegistryとMCP Server Configへ固定する。MCP Server自身がTrust Levelを変更できないようにする。

### local_process

Section 19.3のLocal Sandbox要件を適用し、stdio Executable / Command ConfigurationのTransport Identityを検証する。

### managed_remote

High Risk、State Change、Destructive、Secret Resolveを許可し得るのは、Remote側のScope Enforcement、Authentication / Authorization、Audit、Network Egress Enforcement、Sandbox / Process Isolation、Stable Transport Identityをすべて検証できる場合だけとする。CapabilityはMCP Serverの自己申告だけで確定せず、Administrator承認済みDeployment Evidence、Remote Platform Configuration、Attestationまたは契約したControl Planeから検証し、Capability SnapshotとDigestを保存する。不足があれば対象ToolをAvailableにしない。

### untrusted_remote

`state_change`、`destructive`、`high risk`、Secret `resolve`をDefault Denyする。Read-onlyかつSecretを必要としないToolだけを、AdministratorがServer / Tool単位で明示許可した場合に候補化できる。Mission PolicyやPlannerはこの制限を緩和できない。

Local SandboxはRemote MCP Server内部のEgress、Filesystem、ProcessをEnforceできないため、Remote Enforcement Capabilityの代替として扱わない。Tool Availability ResolverはExecution Location、Remote Trust Policy、検証済みCapability Snapshotを計画候補判定へ含め、Policy EngineとExecutorは具体ActionおよびPre-dispatch時に再検証する。不一致は`RemoteMCPTrustError`としてFail Closedする。

Remote MCP Trust Policyと検証済みCapability SnapshotはCanonical化して`remote_mcp_trust_policy_digest`を生成し、AvailableToolSnapshot、PolicyDecision、ExecutionRecordへBindingする。PolicyまたはCapability変更時は古いSnapshot、Decision、ApprovalRequest、ApprovalRecordを失効させる。

MCP以外または`local_process`だけのSnapshotでもFieldを省略せず、仕様固定したCanonical `not_applicable` ValueのDigestを使用する。空文字列、`null`、実装ごとの既定値を混在させない。

## 19.3 Sandbox境界

Policy EngineはLogical Authorizationを担当し、OS / Container / Network SandboxはTool内部の誤動作またはRegistry定義違反に対するDefense-in-Depth Enforcementを担当する。SandboxがPolicy Engineの代わりにScopeや承認を決定してはならない。

Local Toolおよび外部Processとして起動するMCP Server向けに、以下を表現できるSandbox Interface、Sandbox Policy、Sandbox Capabilityを定義する。

```python
class SandboxRequirement(StrictImmutableBoundaryModel):
    dedicated_os_user: bool
    process_isolation: bool
    container_or_namespace: bool
    filesystem_allowlist_required: bool
    network_egress_control_required: bool
    environment_allowlist_required: bool
    secret_injection_control_required: bool
    cpu_limit_required: bool
    memory_limit_required: bool
    process_limit_required: bool

class SandboxCapabilities(StrictImmutableBoundaryModel):
    dedicated_os_user: bool
    process_isolation: bool
    container_or_namespace: bool
    filesystem_allowlist: bool
    network_egress_control: bool
    environment_allowlist: bool
    secret_injection_control: bool
    cpu_limit: bool
    memory_limit: bool
    process_limit: bool

class SandboxPolicy(StrictImmutableBoundaryModel):
    sandbox_id: str
    filesystem_allowlist: tuple[str, ...]
    allowed_egress_targets: tuple["NormalizedTarget", ...]
    allowed_environment_keys: frozenset[str]
    cpu_limit_millis: int | None
    memory_limit_bytes: int | None
    process_limit: int | None
```

ExecutorはDispatch前にTool Registryの`SandboxRequirement`と実行環境の`SandboxCapabilities`を照合する。要求を満たさないToolはPolicyDecisionがALLOWでも実行しない。High RiskのLocal Toolおよび外部Process型MCP ToolはSandbox Requirementを必須とし、未定義またはCapability不足ならDefault Denyする。

AvailableToolSnapshot発行後にSandbox Capability Digestだけが変化した場合は`SandboxCapabilityStaleError`として区別し、古いSnapshotとPolicyDecisionを使用せず、Capability Snapshot取得とTool Availability解決からやり直す。単にErrorを無視して同じPolicyDecisionをDispatchしてはならない。

`SandboxCapabilities`はToolまたはMCP Serverの自己申告ではなく、信頼済みSandbox Managerが実際のProcess / Container / Network設定から確認して発行する。Capability DigestをExecutionRecordへBindingし、Pre-dispatch時の設定差分で実行を拒否する。

Filesystem AllowlistはCanonical PathとSymlink解決後に評価し、Network Egress ControlはPolicyDecisionのNormalized Targetへ限定する。Environment VariableはAllowlist方式とし、Secret Valueは全環境へ一括展開せず、PolicyDecisionの有効なDataAccessGrantとSecret Injection Controlを満たすExecutor / Adapterへ実行単位で注入する。CPU、Memory、Process数にはTool RegistryまたはGlobal Policyの上限を適用する。

MVPではSandbox InterfaceとCapability Checkを実装境界とし、個別Isolation MechanismはPhaseごとの明示的な受入条件に従って追加する。未実装のSandbox Capabilityを利用可能とみなしてはならない。

---

# 20. Tool Registry

例:

```python
TargetExtractorId = Literal[
    "network_target_v1",
    "session_target_v1",
    "host_target_v1",
    "artifact_target_v1"
]

class ToolDefinition(StrictImmutableBoundaryModel):

    tool_ref: ToolRef
    display_name: str
    version: str

    description: str

    adapter: Literal[
        "c2",
        "mcp",
        "local"
    ]
    adapter_id: str
    provider_tool_name: str
    provider_definition_revision: str | None
    provider_schema_digest: str

    minimum_risk_level: Literal[
        "read",
        "low",
        "medium",
        "high"
    ]

    approval_rule: Literal[
        "policy",
        "always"
    ]

    side_effect: Literal[
        "read_only",
        "state_change",
        "destructive"
    ]

    idempotency: Literal[
        "idempotent",
        "provider_deduplicated",
        "non_idempotent"
    ]

    parameter_schema: CanonicalJsonObject
    target_mode: Literal["required", "optional", "none"]
    target_extractor_id: TargetExtractorId | None
    default_timeout_seconds: int = Field(gt=0)
    max_timeout_seconds: int = Field(gt=0)
    max_output_bytes: int = Field(gt=0)
    secret_argument_paths: tuple[str, ...]
    requires_session: bool
    supported_os: frozenset[Literal["windows", "linux", "macos", "other"]]
    supported_architectures: frozenset[str]
    required_adapter_capabilities: frozenset[str]
    required_session_capabilities: frozenset[str]
    required_data_access_types: frozenset[str]
    sandbox_requirement: SandboxRequirement | None
```

`tool_id`はApplicationが発行するGlobal Stable IDとし、Adapter、MCP Server、表示名に依存して再利用しない。複数MCP Serverが同じ`display_name`を公開しても別のTool IDを割り当てる。`adapter_id`はApplicationが管理するC2 Provider、MCP Server、Local RuntimeのStable IDとし、`provider_tool_name`はAdapter内部でだけ使用する。`provider_definition_revision`と`provider_schema_digest`はAdministratorが承認したProvider定義へ固定する。`registry_revision`はToolDefinitionを承認したRegistry Revisionへ固定する。

Registry DigestはToolDefinitionをToolRef順、意味上順序を持たないSet / Listを仕様化したKey順にSortし、Parameter Schemaを含む全FieldをCanonical JSON化して生成する。`adapter_id`、`provider_tool_name`、Sandbox RequirementもDigest対象とし、表示順やSerialization実装の差だけでDigestが変化しないようにする。

`parameter_schema`はVersion固定したJSON Schemaとして扱う。Tool Registry自体をPlannerへ渡さない。

Target ExtractorはAuthorization Kernelの一部であり、信頼済みTarget Extractor Registryから`target_extractor_id`で解決する。任意Import PathからのDynamic Import、任意Python Expression、lambda、MCP / Pluginが提供する未承認Extractorを禁止する。未登録ID、Version不一致、Extractor実行失敗、Target抽出の不完全性は`TargetExtractorResolutionError`としてFail Closedする。

新しいExtractorはApplication Releaseに含めるか、Code Digest、署名、対応Schema、Testを管理者が承認したExtensionとしてRegistry Revisionへ追加する。設定ファイルだけでScope Enforcement Codeを差し替えてはならない。

Executorは`arguments`を`parameter_schema`で再検証する。`target_mode="required"`でTarget Extractor IDがない、Targetを抽出できない、または副作用を判定できないToolは登録時に拒否する。Targetを持たない純粋な解析Toolは`target_mode="none"`として明示し、入力Artifactへのアクセス権を別途検証する。

Tool Registry Validationでは`default_timeout_seconds <= max_timeout_seconds`、正のOutput Limit、Risk / Side EffectとSandbox Requirementの整合も検証する。不正なToolDefinitionをRegistry Revisionへ含めてはならない。

`minimum_risk_level`は下限であり、Policy Engineは引数、Target数、Session権限、Side Effect、Mission制約に応じてRiskを引き上げることができる。引き下げてはならない。

## 20.1 Tool Availability Resolver

Tool Availability ResolverはLLMを使用しない決定論的コンポーネントとする。以下の積集合から現在計画候補として提示可能なToolを算出する。これはExecution Authorizationではない。

```text
Tool Registry
        ∩
Adapter Capabilities
        ∩
Current Session Capabilities
        ∩
Required Sandbox Capabilities
        ∩
Mission Policy
        ∩
Mission Scope Compatibility
        ∩
Implemented Scope Capability
        ∩
MCP Execution Location / Trust Policy
```

```text
Tool Registry
        |
        v
Tool Availability Resolver
        ^
        |
        +-- AdapterCapabilities
        +-- SandboxCapabilities
        +-- Session Runtime State
        +-- Mission
        +-- Policy
        +-- MCP Trust Policy
        |
        v
AvailableToolSnapshot
        |
        v
Planner
```

Workflow上の順序は以下に固定する。上図の積集合はResolver内部の入力関係であり、Planner後にResolverを初回実行することを意味しない。

`CalculateToolAvailability`は入力SnapshotからAvailable Tool SetとCanonical Digestを計算するPure Nodeであり、ID生成やDB Writeを行わない。`PersistAvailableToolSnapshot`はSection 4.2のOperation IDにMission Revision、Authorization Epoch、Registry / Policy / Scope / Session / Adapter / Sandbox / Remote Trust Digest、Available Tool Set DigestをBindingしてDeterministic Snapshot IDを生成し、Unique Constraint付きIdempotent Upsertを行う。同じ入力のRetryで別Snapshotを作成してはならない。

```text
Session Refresh
       -> Context Selector
       -> CalculateContextAuthorization
       -> PersistContextAuthorization
       -> Context Builder
       -> CalculateToolAvailability
       -> PersistAvailableToolSnapshot
       -> AvailableToolSnapshot
       -> Planner
       -> AvailableToolSnapshot Revalidation
       -> Policy Engine
       -> Executor
```

出力例:

```python
class AvailableToolView(StrictImmutableBoundaryModel):
    tool_ref: ToolRef
    display_name: str
    version: str
    description: str
    parameter_schema: CanonicalJsonObject
    requires_session: bool
    eligible_session_ids: tuple[str, ...]

class AvailableToolSnapshot(StrictImmutableBoundaryModel):
    snapshot_id: str
    snapshot_digest: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    registry_digest: str
    policy_version: str
    execution_scope_digest: str
    session_security_context_digest: str
    adapter_capabilities_digest: str
    sandbox_capabilities_digest: str
    remote_mcp_trust_policy_digest: str
    tools: tuple[AvailableToolView, ...]
    created_at: datetime
    expires_at: datetime
```

Plannerへは`AvailableToolSnapshot`だけを渡し、Adapter名、利用不能Tool、RegistryのRisk内部値を公開する必要はない。PlannerはSnapshot内の完全なToolRefをそのまま提案し、表示名やVersionからToolを暗黙解決してはならない。

`execution_scope_digest`はMission Revisionに定義されたAllowed / Prohibited Execution Scopeと実装済みScope CapabilityのCanonical Digestであり、Plannerが後から提案する具体的TargetのALLOW結果ではない。具体的TargetやNormalized TargetをSnapshot Digestへ先取りして含めない。

Snapshot Digest生成前にToolを`tool_id / registry_revision`、`eligible_session_ids`をStable IDで決定論的にSortする。Snapshotを発行後に変更してはならない。

Policy Engineは、提案ToolRefが有効期限内のSnapshotへ含まれることを再確認する。Mission Revision、Authorization Epoch、Policy Version、Registry Digest、Execution Scope Digest、Session Security Context Digest、Adapter Capabilities Digest、Sandbox Capabilities Digest、Remote MCP Trust Policy Digestの変化でSnapshotを失効させる。

`session_security_context_digest`にはSnapshot評価対象のSessionをStable ID順にSortし、各SessionのStable ID、Host、OS、Architecture、Current Principal、Effective Privilege Context、Session Capabilities、Network Context、Security-relevant Statusだけを含める。`last_seen`、`refreshed_at`、Telemetry Timestampは含めない。FreshnessはPolicy RevalidationとExecutor Pre-dispatch Checkで別途確認する。

`sandbox_capabilities_digest`は信頼済みSandbox Managerが確認したSandbox有効状態、Egress Control、Filesystem Allowlist、Process / Container Isolation、Secret Injection Capability、CPU / Memory / Process Limit Capabilityから生成する。これらの変更でSnapshotを失効させる。Observation時刻やTelemetry TimestampはDigestへ含めない。

AvailableToolSnapshotのBindingを以下へ固定する。

```text
Mission Revision
Authorization Epoch
Tool Registry Digest
Policy Version
Execution Scope Digest
Session Security Context Digest
Adapter Capabilities Digest
Sandbox Capabilities Digest
Remote MCP Trust Policy Digest
```

Planner前のTool Availabilityは具体的TargetやArgumentsをまだ持たないため、実TargetのScope内判定を行わない。Resolverが評価するのは「Toolが要求するTarget Typeに対応するMission Scopeが1件以上存在するか」「Target Extractor / Normalizerが実装済みか」「利用可能なSession / Adapter / Sandbox / Remote Trust Capabilityがあるか」という計画候補としての互換性だけである。

```text
Tool Availability Resolver
= このToolを計画候補として提示可能か

Policy Engine
= Plannerが提案した具体的Actionを許可可能か
```

例えばNetwork Targetを必要とするToolは、Missionに実装済みのNetwork Scopeが1件以上あり、Trusted Target Extractorが利用できる場合にだけ候補化できる。ただし具体的IPがScope内であるとのALLOW判断は行わない。実Targetは`ExecutionPlanProposal -> Target Extractor -> Target Normalizer -> Policy Engine`の順で抽出・正規化し、Policy Engineだけが最終判定する。

現在のPolicy Engineが必要なScope Typeを実装していないToolもSnapshotから除外する。これにより、必ずDENYになるToolをPlannerが繰り返し提案することを防ぐ。

MCP等のLive Provider Schema / Tool List Revisionが承認済み`provider_definition_revision`または`provider_schema_digest`と一致しないToolはSnapshotから除外し、Section 19.1のCandidate Definition Flowへ送る。Live Schemaを暗黙に採用してはならない。

Tool Availabilityは実行許可ではない。Snapshotに含まれるToolであっても、具体的引数とTargetに対するPolicyDecisionがなければExecutorは実行しない。

## 20.2 AvailableToolSnapshot Revalidation

Planner実行後は新しいSnapshotを生成せず、Proposalが参照した既存Snapshotを再検証する。以下を確認する。

* Snapshot ID / DigestとExecutionPlanのBinding
* ToolRefがSnapshot内に存在すること
* 選択Sessionが`eligible_session_ids`に含まれること
* Snapshotの期限
* Mission Revision、Authorization Epoch、Registry Digest、Policy Version、Execution Scope Digest
* Session Security Context Digest、Adapter Capabilities Digest、Sandbox Capabilities Digest、Remote MCP Trust Policy Digest

不一致時は`AvailableToolSnapshotStaleError`としてFail Closedし、ProposalをPolicy Engineへ渡さない。次のPlanner呼び出し前にSession Refresh、Context Selector、Calculate / Persist Context Authorization、Context Builder、Calculate / Persist Tool Availabilityを行う。

---

# 21. Mission

演習開始時にMissionを定義する。

Execution ScopeとData Access Policyを分離し、自由文字列ではなく型付きRuleとして定義する。

例:

```python
class NetworkScopeRule(StrictImmutableBoundaryModel):
    type: Literal["network"]
    cidrs: tuple[str, ...] = Field(min_length=1)
    ports: tuple[int, ...] | None = None
    protocols: tuple[str, ...] | None = None

class HostnameScopeRule(StrictImmutableBoundaryModel):
    type: Literal["hostname"]
    hostname: str
    ports: tuple[int, ...] | None = None

class DomainScopeRule(StrictImmutableBoundaryModel):
    type: Literal["domain"]
    domain: str
    include_subdomains: bool = False

class UrlScopeRule(StrictImmutableBoundaryModel):
    type: Literal["url"]
    scheme: Literal["http", "https"]
    hostname: str
    port: int | None = None
    path_prefix: str = "/"

class HostScopeRule(StrictImmutableBoundaryModel):
    type: Literal["host"]
    host_id: str

class SessionScopeRule(StrictImmutableBoundaryModel):
    type: Literal["session"]
    session_id: str

class RemoteFilesystemScopeRule(StrictImmutableBoundaryModel):
    type: Literal["remote_filesystem"]
    host_ref: str
    path_prefix: str

ExecutionScopeRule = Annotated[
    NetworkScopeRule
    | HostnameScopeRule
    | DomainScopeRule
    | UrlScopeRule
    | HostScopeRule
    | SessionScopeRule
    | RemoteFilesystemScopeRule,
    Field(discriminator="type")
]

class IpTargetReference(StrictImmutableBoundaryModel):
    type: Literal["ip"]
    address: str

class NamedTargetReference(StrictImmutableBoundaryModel):
    type: Literal["hostname", "domain", "url"]
    value: str

class HostTargetReference(StrictImmutableBoundaryModel):
    type: Literal["host"]
    host_id: str

class SessionTargetReference(StrictImmutableBoundaryModel):
    type: Literal["session"]
    session_id: str

class RemoteFilesystemTargetReference(StrictImmutableBoundaryModel):
    type: Literal["remote_filesystem"]
    host_ref: str
    path: str

TargetReference = Annotated[
    IpTargetReference
    | NamedTargetReference
    | HostTargetReference
    | SessionTargetReference
    | RemoteFilesystemTargetReference,
    Field(discriminator="type")
]

class NormalizedTarget(StrictImmutableBoundaryModel):
    type: Literal[
        "ip",
        "hostname",
        "domain",
        "url",
        "host",
        "session",
        "remote_filesystem"
    ]
    canonical_value: str
    host_ref: str | None = None
    port: int | None = None
    protocol: str | None = None
    resolved_addresses: tuple[str, ...] = ()
    source: Literal["plan", "argument", "session", "dns", "redirect"]

DataAccessOperation = Literal["read", "write", "export", "resolve"]

class DataAccessRule(StrictImmutableBoundaryModel):
    resource_type: Literal[
        "artifact",
        "secret_reference",
        "local_artifact",
        "report",
        "internal_knowledge"
    ]
    resource_pattern: str
    operations: frozenset[DataAccessOperation] = Field(min_length=1)

class DataAccessPolicy(StrictImmutableBoundaryModel):
    allowed: tuple[DataAccessRule, ...]
    prohibited: tuple[DataAccessRule, ...]

class ApprovalPolicy(StrictImmutableBoundaryModel):
    require_for_risk: frozenset[Literal["read", "low", "medium", "high"]]
    require_for_side_effect: frozenset[Literal["read_only", "state_change", "destructive"]]
    approval_ttl_seconds: int = Field(gt=0)
    count_approval_wait_in_runtime: bool

MissionLifecycleState = Literal[
    "DRAFT",
    "VALIDATED",
    "RUNNING",
    "PAUSED",
    "FINALIZING",
    "WAITING_HUMAN_REVIEW",
    "COMPLETED",
    "COMPLETED_WITH_UNRESOLVED_EXECUTIONS",
    "FAILED",
    "ABORTED"
]

class Mission(StrictImmutableBoundaryModel):

    mission_id: str
    mission_revision: int = Field(ge=1)
    mission_state_version: int = Field(ge=0)
    authorization_epoch: int = Field(ge=0)
    state: MissionLifecycleState

    llm_profile_revision: str
    llm_profile_digest: str

    description: str
    authorization_reference: str
    authorized_by: str
    valid_from: datetime
    valid_until: datetime

    allowed_execution_scope: tuple[ExecutionScopeRule, ...] = Field(min_length=1)

    prohibited_execution_scope: tuple[ExecutionScopeRule, ...]

    data_access_policy: DataAccessPolicy

    objectives: tuple[str, ...]

    success_conditions: tuple["SuccessCondition", ...] = Field(min_length=1)
    success_mode: Literal["all", "any"] = "all"

    max_iterations: int = Field(gt=0)

    max_runtime_minutes: int = Field(gt=0)

    approval_policy: ApprovalPolicy
```

MissionはLLMではなく人間が定義する。

`Mission`はMission Revision RepositoryとMission State Repositoryを結合したApplication Read Modelである。設定本体とLifecycle Stateの永続化責務を1つのTableへ戻してはならない。

`mission_revision`と`mission_state_version`の意味を分離する。

```text
mission_revision
= Scope / Goal / Approval Policy / Authorization設定のRevision

mission_state_version
= Mission State RepositoryのOptimistic Concurrency Control用Version

authorization_epoch
= 同一Mission Revision内の一時Authorization世代
```

Scope、Goal、Approval Policy、Data Access Policy、Local LLM Profile等のMission設定を変更した場合だけ`mission_revision`を増加させる。Lifecycle変更では`mission_revision`を変更せず、`mission_state_version`を増加させる。`authorization_epoch`は設定RevisionでもOCC Versionでもなく、短寿命Authorizationを一括失効させる単調増加Counterとする。

thread_id、ExecutionPlan、PolicyDecision、AvailableToolSnapshot、ApprovalRequest、ApprovalRecord、ContextDataAccessGrant、authorization_digestは`mission_revision`へBindingする。AvailableToolSnapshot、ContextDataAccessGrant、PolicyDecision、ApprovalRequest、ApprovalRecord、authorization_digestはさらに`authorization_epoch`へBindingする。`proposal_digest`はLLM ProposalそのもののDigestでMission Stateを含めず、ExecutionPlanとauthorization_digestがMission Bindingを与える。OCCに使用する`mission_state_version`をAuthorization Digestへ混在させてはならない。

次の場合はMission State RepositoryのOCC Transactionで`authorization_epoch`と`mission_state_version`を増加させる。

```text
RUNNING -> PAUSED
Emergency Stop開始
OperatorによるAuthorization Invalidation
PAUSED -> RUNNING前のSecurity-relevant Resume Boundary
```

PAUSED中は新しいExecution Authorization、Approval、Planner / Analyzer Context Grantを発行しない。Resume時は最終的なAuthorization Epochを確定した後、Session Refresh、Context Selector、Context Authorization、AvailableToolSnapshot生成、Planner Proposalの再評価、Policy Check、必要なApprovalを順にやり直す。PAUSED前のPlanを参考情報として表示してもよいが、古いGrant、Snapshot、PolicyDecision、ApprovalRequest、ApprovalRecordをDispatchに再利用してはならない。

Mission Validationでは最低限以下を強制する。

* `success_conditions`が1件以上であること
* `condition_id`が同一Mission Revision内で一意であること
* `valid_from < valid_until`であること
* `max_iterations > 0`かつ`max_runtime_minutes > 0`であること
* `approval_ttl_seconds > 0`であること
* `allowed_execution_scope`が1件以上であること
* `mission_revision >= 1`かつ`mission_state_version >= 0`であること
* `authorization_epoch >= 0`であること
* `llm_profile_revision / llm_profile_digest`が保存済みAgentModelProfileと一致し、LocalLLMProfileの場合は合格済みCapability Check Resultとも一致すること

Goal Condition固有のValidation、Scope Ruleの解釈可能性、Authorization Referenceも同じValidation Pipelineで検査する。1件でも失敗したMissionは`VALIDATED`へ遷移できず、`MissionValidationError`としてFail Closedする。`all([])`または`any([])`をGoal判定に使用できる状態を作ってはならない。

Phase 0A〜1のMock Planner / Analyzerでは、実LLMを呼ばない固定MockAgentProfileをRepositoryへ明示登録する。空Digestや未登録ProfileでValidationを迂回してはならない。

`allowed_execution_scope`は1件以上を必須とし、空または解釈不能なRuleを許可しない。AllowedとProhibitedが競合する場合は常にProhibitedを優先する。

Execution Scopeは外部または対象環境へ作用するTargetを制御する。Artifact、Secret Reference、Report、Internal Knowledgeへの読み書きはExecution Scopeへ混在させず、Data Access Policyで制御する。Secretの`resolve`は信頼済みExecutor / Adapterにだけ許可し、Planner / Analyzerには許可しない。

Data Access PolicyもDefault Denyとし、明示的なAllowed RuleがないOperationを拒否する。AllowedとProhibitedが競合する場合はProhibitedを優先する。

`resource_pattern`のGrammarと正規化規則はResource TypeごとにVersion固定し、任意Regexとして評価しない。解釈不能または未実装のPatternはDENYする。

Remote Filesystemは`host_ref`と`path_prefix`の両方を必須とする。Hostが不明な`/tmp/test`等のPathだけではScope判定せずDENYする。

MVPでPolicy Engineが実装必須とするExecution Scope TypeはIP / CIDR、Host ID、Session IDとする。Hostname、Domain、URL、Redirect、Remote Filesystem等の未実装Typeは、Schemaが定義済みでも必ずDefault Denyする。後続Phaseで有効化する際は正規化処理と境界Testを追加する。

Hostname / Domain / URL対応を有効化した場合は実行直前に名前解決し、解決された全IPを再評価する。実行時は検査済みIPへ接続先を固定し、DNS再解決によるScope迂回を防ぐ。

HTTP等の自動Redirectは既定で無効化する。Redirectを許可するToolは遷移先ごとにPolicy Engineへ再照会し、ALLOWを得るまで追従してはならない。C2 Session経由で新しいTargetが判明した場合も送信前に再評価し、Scope外または判定不能ならDENYとする。

Execution Scope RuleはTypeごとに正規化する。IP / CIDRはCanonical表現、Hostname / Domainは小文字およびIDNA、URLはScheme・Host・Port、Remote FilesystemはHost上の実体Pathとして比較する。`..`、Symlink、別名表現、IPv4-mapped IPv6等を使ったScope迂回を許可しない。型と矛盾するRuleはMission Validationで拒否する。

Missionには演習許可を追跡できる`authorization_reference`と有効期間を必須とする。Mission Managerは開始時および各Policy Check時に有効期間を検査し、期間外では新規ExecutionをDENYする。

短寿命AuthorizationのTTL Invariantを以下へ固定し、発行ServiceとRepository Constraintの双方で検証する。

```text
ContextDataAccessGrant.expires_at <= Mission.valid_until
AvailableToolSnapshot.expires_at <= Mission.valid_until
PolicyDecision.expires_at <= Mission.valid_until
ApprovalRequest.expires_at <= Mission.valid_until
ApprovalRecord.expires_at <= Mission.valid_until
ApprovalRequest.expires_at <= PolicyDecision.expires_at
ApprovalRecord.expires_at <= ApprovalRequest.expires_at
ApprovalRecord.expires_at <= PolicyDecision.expires_at
```

発行要求のTTLが上限を超える場合はMission期限へ暗黙Clampして成功扱いにせず、呼出側が有効期限を認識できる型付きResultとして明示的に短縮するか、Validation Errorで拒否する方式を設定で統一する。Executor Pre-dispatchはRepositoryからMissionを再読込し、必ず`Mission.valid_from <= current_time < Mission.valid_until`を確認する。

`valid_until`到達時はMissionを自動的に`FINALIZING`へ遷移させ、新規Executionを禁止する。共通のFinalization Workflowで実行中TaskのCancelとReconciliationを行い、停止を確認できないTaskは`OUTCOME_UNKNOWN`としてOperatorへ通知する。

## 21.1 Mission Manager

Mission Managerは以下のLifecycleを決定論的に管理する。

```text
DRAFT -> VALIDATED -> RUNNING -> PAUSED -> RUNNING
                         |          |
                         +----------+--> FINALIZING
                                        |       |
                                        |       +--> WAITING_HUMAN_REVIEW
                                        |                  |
                                        |                  +--> COMPLETED_WITH_UNRESOLVED_EXECUTIONS
                                        |
                                        +----------> COMPLETED
                                        |
                                        +----------> ABORTED
                                        |
                                        +----------> FAILED
```

RUNNINGになったMission RevisionのScope、Goal、Approval PolicyはImmutableとする。変更はPAUSED状態で新しいMission Revisionとして作成し、既存Plan、PolicyDecision、未処理Approvalを失効させる。実行中TaskはCancelおよびReconciliationを完了し、`OUTCOME_UNKNOWN`をOperatorが確認するまで新RevisionをRUNNINGにしない。

Mission Repositoryへの状態変更Commandは`expected_mission_state_version`を必須とするOptimistic Concurrency Controlを用い、不一致を`MissionStateVersionConflictError`としてFail Closedする。状態更新が成功した場合だけ`mission_state_version`を1増加させる。OCC競合時に新旧Mission Stateを自動Mergeしたり、`mission_revision`を増加させて回避したりしない。

Authorization Epochを変更するState Commandは`expected_authorization_epoch`も検証し、State VersionとEpochの更新を同一TransactionでCommitする。CheckpointやCacheだけのEpoch値を根拠にAuthorizationを発行せず、Mission State RepositoryをSource of Truthとする。Epoch不一致は`AuthorizationEpochMismatchError`としてFail Closedする。

Mission ManagerはOperator認証、Role Based Access Control、開始・停止権限、Emergency Stopを提供する。Emergency Stop時は新規Executionを禁止し、以下の共通Finalization WorkflowをEmergency Stop理由で開始する。

Goal EvaluatorがGoal達成を返しても即座に`COMPLETED`またはGraphの`END`へ遷移してはならない。Missionはまず`FINALIZING`へ遷移し、共通のFinalization Workflowで以下を実施する。

```text
GOAL ACHIEVED / Mission Expiry / Emergency Stop
       |
       v
FINALIZING
       |
       +-- RUNNING Execution列挙
       +-- DISPATCHED Execution照合
       +-- Adapter Reconciliation
       +-- Policyに基づく必要なTask Cancel
       +-- Session Final Refresh
       +-- Audit Flush
       +-- Audit Chain Verification
       |
       v
COMPLETED / ABORTED / WAITING_HUMAN_REVIEW
```

Goal達成時は、すべてのExternal ExecutionがTerminal Stateになり、必要なCancel、最終Session Refresh、Audit Chain検証が完了した場合にのみ`COMPLETED`とする。未解決の`OUTCOME_UNKNOWN`が1件でも残る場合は通常の`COMPLETED`へ遷移せず`WAITING_HUMAN_REVIEW`とする。Operatorが未解決状態を明示的に受理してMissionを閉じる場合だけ`COMPLETED_WITH_UNRESOLVED_EXECUTIONS`へ遷移でき、受理者、対象Execution、理由をAudit Logへ記録する。

Task CancelもExternal Writeである。Cancel RequestをExecution Repositoryへ永続化してからAdapterへ送り、LangGraph Automatic Retryを適用しない。応答が不明な場合はReconciliationし、停止済みと推測しない。

Mission ExpiryとEmergency Stopも同じFinalization Workflowを再利用する。ただし終了理由と最終状態はそれぞれのPolicyに従い、Goal達成として記録してはならない。Finalization中は新規ExecutionPlanを作成せず、Reconciliation、Cancel、Read-only Refresh、Audit処理だけを許可する。

---

# 22. Scope / Policy Engine

Plannerの出力をそのままExecutorへ渡してはいけない。

必ずPolicy Engineを通す。

```text
Session Refresh
   |
Context Selector
   |
CalculateContextAuthorization
   |
PersistContextAuthorization
   |
Context Builder
   |
CalculateToolAvailability
   |
PersistAvailableToolSnapshot
   |
AvailableToolSnapshot
   |
Planner
   |
ExecutionPlanProposal
   |
Application creates ExecutionPlan
   |
AvailableToolSnapshot Revalidation
   |
Policy Engine
   |
   +-- ALLOW --> Executor
   |
   +-- REQUIRE APPROVAL --> ApprovalRequest + Matching ApprovalRecord --> Executor
   |
   +-- DENY --> Session Refreshから再計画 / STOP
```

確認内容:

* 対象が許可スコープ内か
* 禁止対象ではないか
* 使用ツールがAllowlistに存在するか
* Toolが有効なAvailableToolSnapshotに含まれるか
* Tool Registryが指定するAdapterとCapabilityが利用可能か
* 操作リスク
* Human Approvalの必要性
* 実行回数制限
* Mission制約

Scope判定はLLMではなく決定論的なコードで実装する。

Policy Engineの出力例:

```python
class DataAccessGrant(StrictImmutableBoundaryModel):
    resource_type: Literal[
        "artifact",
        "secret_reference",
        "local_artifact",
        "report",
        "internal_knowledge"
    ]
    resource_id: str
    operations: frozenset[DataAccessOperation]

class SessionContextGrant(StrictImmutableBoundaryModel):
    authorized_session_ids: tuple[str, ...]
    session_security_context_digest: str

class ContextDataAccessGrant(StrictImmutableBoundaryModel):
    grant_id: str
    grant_digest: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    service_identity: Literal[
        "planner_context",
        "analyzer_context"
    ]
    resources: tuple[DataAccessGrant, ...]
    session_context: SessionContextGrant
    policy_version: str
    issued_at: datetime
    expires_at: datetime

class PolicyDecision(StrictImmutableBoundaryModel):
    decision_id: str
    decision_digest: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    plan_id: str
    tool_ref: ToolRef
    proposal_digest: str
    authorization_digest: str
    policy_version: str
    registry_digest: str
    available_tool_snapshot_id: str
    available_tool_snapshot_digest: str
    resolved_adapter: Literal["c2", "mcp", "local"]
    resolved_adapter_id: str
    decision: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    normalized_targets: tuple[NormalizedTarget, ...]
    authorized_data_access: tuple[DataAccessGrant, ...]
    effective_risk: Literal["read", "low", "medium", "high"]
    reason_codes: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
```

PolicyDecisionはImmutableなExecution Authorization Envelopeである。`authorized_data_access`の各DataAccessGrant Entryは、ExecutorがPolicyDecisionから生成したExecutionRequest Envelopeを介し、PolicyDecision ID、Execution ID、Mission Revision、Authorization Epoch、ToolRef、Resolved AdapterとのBindingを検証した場合だけ使用できる。Entry自体に内部IDを付与してもよいが、単独のBearer Tokenとして使用してはならない。1つのExecutable PolicyDecisionから作成できるExecutionRecordは1件だけとし、`executions.policy_decision_id`へUnique Constraintを設定する。許可されたExecution Retryは同じExecution IDを使用し、別Executionが必要なら新しいPlan / PolicyDecision / Approvalを発行する。

Context読取ではContextDataAccessGrantのMission、Service Identity、Policy Version、SessionContextGrant、期限を検証する。Tool実行ではExecutionRequestの`policy_decision_id`からPolicyDecision全体を取得し、DataAccessGrant Entryだけを切り出して別Executionへ流用しない。

`SessionContextGrant.authorized_session_ids`はStable Session IDで決定論的にSortし、`session_security_context_digest`はそのSession集合のSecurity-relevant Fieldから生成する。Context Builderは許可ListにないSession Runtime StateをContextへ含めない。Current Principal、Effective Privilege、Session Capability、Network Context、Security-relevant Status等がGrant発行時から変化した場合は`SessionContextGrantStaleError`としてContextDataAccessGrant全体を失効させる。`last_seen`等のTelemetryだけの変更はDigestへ含めず、Freshnessを別に検証する。

Digestを次の2種類に分離する。

```text
proposal_digest
= ExecutionPlanProposalのCanonical Digest

authorization_digest
= Policy Engineが解決・正規化したAuthorized Execution IntentのCanonical Digest
```

`proposal_digest`はSchema VersionとExecutionPlanProposalをRFC 8785または同等に仕様固定したCanonical JSONへ変換して計算する。意味上順序を持たない`requested_targets`は正規化・Sortし、Tool引数内で順序に意味があるListはSortしない。

`authorization_digest`は少なくともMission ID / Revision、Authorization Epoch、proposal_digest、ToolRef、Resolved Adapter Type / ID、Session、Schema検証済み引数、Normalized Targets、Authorized Data Access、Effective Risk、Side Effect / Approval Rule、Policy Version、Registry Digest、AvailableToolSnapshot ID / Digest、Session Security Context Digest、Adapter / Sandbox Capability Digest、Remote MCP Trust Policy Digestを含む。Mission State Version、Decision ID、Approval ID、Timestamp、Telemetryを含めない。

Human Approvalは`authorization_digest`へBindingし、Executorは現在の信頼済み入力から同じDigestを再計算してPolicyDecisionと照合する。proposal_digestとauthorization_digestを相互代用してはならない。

`decision_digest`は`decision_digest` Field自身を除くPolicyDecision全体のCanonical Digestであり、`authorization_digest`の代替ではない。同様にGrant / Snapshot / Approval Request / Approval RecordのIntegrity Digestは各ObjectのDigest Field自身を除いて計算する。

authorization_digestのCanonicalization前に、意味上順序を持たない`normalized_targets`、`resolved_addresses`、Scope Entry、DataAccessGrantを仕様化したKeyで決定論的にSortする。同じAuthorized Execution Intentから異なるDigestが生成されないことをTestする。現在のPolicy Version、Registry Digest、AvailableToolSnapshotのいずれかがPolicyDecision発行時と異なる場合もDecisionを失効させる。

`frozen=True`だけをIntegrity Guaranteeとみなさない。Security-sensitiveなImmutable Modelでは`list -> tuple`、`set -> frozenset`、mutable `dict -> CanonicalJsonObject`へ変換し、Repository保存前とExecutor / Context Builder使用直前に保存済みCanonical Digestを再計算する。Nested CollectionやObject Graphが変更されてDigest不一致となった場合は`DigestIntegrityError`としてFail Closedする。

再検証時の名前解決結果やSession ContextがPolicyDecision発行時から変化した場合、そのDecisionを失効させてPolicy Checkへ戻す。

Policy EngineはPlannerが指定した`requested_targets`だけでなく、Tool RegistryのTarget Extractorを使い、引数、URL、名前解決結果、Redirect先、Session Network Contextから実際に影響するTargetを列挙する。Targetを完全に抽出できない場合、またはScope Typeが未実装の場合はDefault Denyとする。

Artifact、Secret Reference、Local Artifact、Report、Internal KnowledgeへのアクセスはMissionのData Access Policyと照合し、`DataAccessGrant`としてPolicyDecisionへ固定する。DataAccessGrantがないResourceをExecutor、Context Builder、Artifact Store、Secret Storeが読み書きしてはならない。

Planner / Analyzer呼び出し前のContext Builderについては、Policy Engineが`ContextDataAccessGrant`を別途発行する。Context BuilderはこのGrantで許可されたKnowledge Base、Redacted Artifact、Report、Internal Knowledge、Secret Reference Metadataだけを読み取る。Secretの`resolve`、Encrypted Raw Artifact、Raw Tool OutputはGrant対象外とし常に拒否する。Tool実行時のDataAccessGrantはPolicyDecisionへ含める。

ContextDataAccessGrantの発行はExecutionのPolicy Checkより前に行う独立したRead Authorizationである。Grant不在、期限切れ、Mission Revision / Authorization Epoch / Policy Version不一致、Session Context Digest不一致の場合、Context BuilderはFail ClosedしLLMを呼び出さない。ContextDataAccessGrant、AvailableToolSnapshot、PolicyDecision、ApprovalRequest、ApprovalRecordのTTLはSection 21のMission Validity Invariantを満たさなければ発行・保存できない。

Grantは`issued_at < expires_at`、AvailableToolSnapshotは`created_at < expires_at`を満たさなければならない。境界時刻では失効済みとして扱い、Clock SourceはApplicationの単調時間と監査可能なUTC Wall Clockの役割を分離する。

---

# 23. Human-in-the-loop

高RiskまたはDestructiveな操作は、Global Policyの既定値としてHuman Approvalを必須とする。Mission Policyは承認対象を追加できるが、Global PolicyまたはTool Registryの`approval_rule="always"`を緩和できない。

```text
Planner
   |
Plan
   |
Policy
   |
   v
ApprovalRequest
   |
   v
Human Approval
   |
   +-- Approve --> ApprovalRecord(APPROVED)
   |
   +-- Reject  --> ApprovalRecord(REJECTED)
   |
   +-- Modify  --> New Plan / Decision / ApprovalRequest
```

LangGraphのinterrupt / resume機構を利用可能な設計とする。

ApprovalRequestはHumanへ提示した内容、ApprovalRecordはHumanが行ったDecisionとして分離する。表示内容をApprovalRecordへ複製して別のSource of Truthを作らない。

```text
Approval Request ID
Mission ID / Revision
Authorization Epoch
Authorization Digest
PolicyDecision ID
ToolRef
Tool Display Name
Normalized Targets
ArgumentsのRedacted Summary
Effective Risk / Side Effect
Issued At / Expires At

Approval Record:

Approval ID / Approval Request ID
PolicyDecision ID / Authorization Digest
Decision
Approver ID / Role
Issued At / Expires At
```

Model例:

```python
class ApprovalRequest(StrictImmutableBoundaryModel):
    approval_request_id: str
    request_digest: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    policy_decision_id: str
    authorization_digest: str
    tool_ref: ToolRef
    tool_display_name: str
    normalized_targets: tuple[NormalizedTarget, ...]
    redacted_arguments_summary: str
    effective_risk: Literal["read", "low", "medium", "high"]
    side_effect: Literal["read_only", "state_change", "destructive"]
    issued_at: datetime
    expires_at: datetime

class ApprovalRecord(StrictImmutableBoundaryModel):
    approval_id: str
    record_digest: str
    approval_request_id: str
    approval_request_digest: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    policy_decision_id: str
    authorization_digest: str
    decision: Literal["APPROVED", "REJECTED"]
    approver_id: str
    approver_role: str
    issued_at: datetime
    expires_at: datetime
```

PolicyDecision、ApprovalRequest、ApprovalRecordはすべてImmutableとする。PolicyDecisionは後から作成されるApprovalRequest IDを保持せず、ApprovalRequest側がPolicyDecision IDへBindingする。承認後にPolicyDecisionの`decision`を`ALLOW`へ書き換えてはならない。Executorが実行可能と判断するPredicateを次へ固定する。

```text
Executable :=
    PolicyDecision.decision == ALLOW

OR

    (
      PolicyDecision.decision == REQUIRE_APPROVAL
      AND Matching ApprovalRequest exists
      AND Matching ApprovalRecord exists
      AND ApprovalRecord.decision == APPROVED
      AND ApprovalRequest / ApprovalRecord are not expired
      AND ApprovalRecord.approval_request_id matches
      AND ApprovalRecord.approval_request_digest matches
      AND ApprovalRequest.request_digest is valid
      AND ApprovalRequest.policy_decision_id matches
      AND ApprovalRecord.policy_decision_id matches
      AND ApprovalRequest.authorization_digest matches
      AND ApprovalRecord.authorization_digest matches
      AND Mission Revision matches
      AND Authorization Epoch matches
    )
```

DENY DecisionはApprovalRecordが存在してもExecutableにならない。ApprovalRequestとApprovalRecordはauthorization_digestとAuthorization Epochへ紐付ける。Tool、引数、Target、Session、Risk、Data Access、Mission Revision、Authorization Epoch、Registry / Snapshot Binding、Request表示内容のいずれかが変わった場合は承認を失効させ、Policy Checkと承認をやり直す。`Modify`は元Plan、Request、Decisionを変更せず、新しいPlan ID、PolicyDecision、ApprovalRequest、authorization_digestを発行する。

ApprovalRequestは承認UIへ実際に表示したCanonical Contentから`request_digest`を生成する。ApprovalRecordはOperatorが確認したRequest ID / Digestを保持し、ExecutorはRequest Repositoryから再読込して双方を検証する。不一致は`ApprovalBindingError`としてFail Closedする。

PolicyDecision、ApprovalRequest、ApprovalRecordはそれぞれ`issued_at < expires_at`を満たさなければならず、Section 21のTTL InvariantをRepository保存時にも検証する。期限が同一時刻に達したArtifactは有効とみなさない。

Approval Serviceが利用できない、承認者を認証できない、または承認が期限切れの場合はFail Closedとし、実行を待機または拒否する。承認待ち時間をMission Runtimeへ含めるかは`ApprovalPolicy`で明示する。

---

# 24. Goal Evaluator

ゴール判定は可能な限り決定論的に行う。

`SuccessCondition`は自由記述ではなく、型付きConditionのDiscriminated Unionとして定義する。

例:

```python
class EvidenceReference(StrictImmutableBoundaryModel):
    source_type: Literal["session", "finding", "artifact", "execution"]
    source_id: str
    source_revision: str
    verification_state: Literal["confirmed", "contradicted", "unavailable"]

class SessionExistsCondition(StrictImmutableBoundaryModel):
    type: Literal["session_exists"]
    condition_id: str
    host_ref: str
    principal_ref: str | None = None
    required_status: Literal["active"] = "active"

class WindowsTokenPrivilegeCondition(StrictImmutableBoundaryModel):
    type: Literal["windows_token_privilege"]
    condition_id: str
    session_ref: str
    required_privileges: frozenset[str]
    match: Literal["all", "any"] = "all"
    require_enabled: bool = True

class WindowsLocalGroupCondition(StrictImmutableBoundaryModel):
    type: Literal["windows_local_group"]
    condition_id: str
    host_ref: str
    principal_ref: str
    group_sid: str

class ADGroupMembershipCondition(StrictImmutableBoundaryModel):
    type: Literal["ad_group_membership"]
    condition_id: str
    principal_ref: str
    group_sid: str
    membership: Literal["direct", "transitive"]

class ADPrincipalPrivilegeCondition(StrictImmutableBoundaryModel):
    type: Literal["ad_principal_privilege"]
    condition_id: str
    principal_ref: str
    privilege_identifier: str
    target_ref: str

class ADPrincipalContextCondition(StrictImmutableBoundaryModel):
    type: Literal["ad_principal_context"]
    condition_id: str
    session_ref: str
    principal_ref: str
    required_group_sid: str | None = None
    required_status: Literal["active"] = "active"

class LinuxUidCondition(StrictImmutableBoundaryModel):
    type: Literal["linux_uid"]
    condition_id: str
    session_ref: str
    uid: int
    identity_field: Literal["real", "effective", "saved"] = "effective"

class LinuxGroupCondition(StrictImmutableBoundaryModel):
    type: Literal["linux_group"]
    condition_id: str
    session_ref: str
    gid: int | None = None
    group_name: str | None = None
    membership: Literal["primary", "supplementary", "either"] = "either"

class LinuxCapabilityCondition(StrictImmutableBoundaryModel):
    type: Literal["linux_capability"]
    condition_id: str
    session_ref: str
    required_capabilities: frozenset[str]
    capability_set: Literal["effective", "permitted", "inheritable", "bounding"]
    match: Literal["all", "any"] = "all"

class EvidenceExistsCondition(StrictImmutableBoundaryModel):
    type: Literal["evidence_exists"]
    condition_id: str
    finding_type: str
    target_ref: str
    minimum_confidence: float = Field(ge=0.0, le=1.0)
    required_verification: Literal["confirmed"] = "confirmed"

class ArtifactEvidenceCondition(StrictImmutableBoundaryModel):
    type: Literal["artifact_evidence"]
    condition_id: str
    artifact_type: str
    expected_sha256: str | None = None

SuccessCondition = Annotated[
    SessionExistsCondition
    | WindowsTokenPrivilegeCondition
    | WindowsLocalGroupCondition
    | ADGroupMembershipCondition
    | ADPrincipalPrivilegeCondition
    | ADPrincipalContextCondition
    | LinuxUidCondition
    | LinuxGroupCondition
    | LinuxCapabilityCondition
    | EvidenceExistsCondition
    | ArtifactEvidenceCondition,
    Field(discriminator="type")
]
```

Windows / Active Directory / Linuxの権限を単一の`Privilege Level`や一次元の大小関係で比較しない。Conditionごとに、Session Manager、Knowledge Base、Artifact Store等の許可されたSource of Truthから厳密一致または明示した集合条件で判定する。

`LinuxGroupCondition`は`gid`または`group_name`の少なくとも一方を必須とする。両方を指定した場合は同一の確認済みGroupを指すことを要求し、両方未指定または矛盾する指定をMission Validationで拒否する。他のConditionも空集合、空Identifier、型に合わないSID / UID等を開始前に拒否する。

例として、Linuxのroot到達は`LinuxUidCondition(uid=0, identity_field="effective")`で判定する。Active DirectoryのDomain Admins Context取得は、表示名ではなく既知のGroup SIDを設定した`ADPrincipalContextCondition`で判定する。

`ADPrincipalContextCondition`は、以下をすべて満たす場合にだけ`achieved`とする。

```text
指定SessionがACTIVE
AND
Session Managerが確認したcurrent_principal == principal_ref
AND
Knowledge Baseにprincipal_refのCONFIRMED Group Membershipが存在
AND
そのGroup SID == required_group_sid
```

`required_group_sid`が`None`の場合はSessionとPrincipal Contextの一致だけを評価する。Domain Admins等のGroup権限をGoalとする場合は必ずSIDを指定する。Domain Admin Principalの存在、Credential Reference、Group Membershipを発見しただけでは、そのPrincipalを現在制御しているとは判定しない。別PrincipalのActive Sessionと組み合わせてGoalを達成させてはならない。

未知または未対応のPrivilege Identifier、Group形式、SID形式、UID形式、Capability、Token状態は`indeterminate`として扱い、暗黙的に高権限または達成済みとみなさない。Identifier自体が既知でSource of Truthを正常に確認でき、単に必要な権限が存在しない場合だけ`not_achieved`とする。Mission Validationで検出できる未対応Identifierは開始前に拒否する。

例:

```text
指定SessionのWindows Token Privilege
指定PrincipalのAD Group Membership
Linux SessionのEffective UID
Linux Capability Set
指定HostへのSession存在
指定Evidenceの存在
```

判定結果はConditionごとの三値評価とする。

```python
GoalReasonCode = Literal[
    "CONDITION_MATCHED",
    "CONDITION_ABSENT",
    "SESSION_REFRESH_FAILED",
    "RECONCILIATION_UNAVAILABLE",
    "EVIDENCE_CONTRADICTED",
    "PRINCIPAL_UNCONFIRMED",
    "ARTIFACT_UNVERIFIED",
    "UNSUPPORTED_IDENTIFIER"
]

class ConditionEvaluation(StrictImmutableBoundaryModel):
    condition_id: str
    status: Literal[
        "achieved",
        "not_achieved",
        "indeterminate"
    ]
    reason_code: GoalReasonCode
    evidence_references: tuple[EvidenceReference, ...]

class GoalStatus(StrictImmutableBoundaryModel):
    achieved: bool
    achieved_conditions: tuple[str, ...]  # condition_id
    remaining_conditions: tuple[str, ...]  # condition_id
    indeterminate_conditions: tuple[ConditionEvaluation, ...]
    evidence_references: tuple[EvidenceReference, ...]
```

`achieved_conditions`には`achieved`、`remaining_conditions`には`not_achieved`のCondition IDだけを格納し、`indeterminate`は`indeterminate_conditions`へ理由とEvidenceを保持する。同じConditionを複数のListへ入れない。

`reason_code`はVersion付きAllowlistとし、少なくとも`CONDITION_MATCHED`、`CONDITION_ABSENT`、`SESSION_REFRESH_FAILED`、`RECONCILIATION_UNAVAILABLE`、`EVIDENCE_CONTRADICTED`、`PRINCIPAL_UNCONFIRMED`、`ARTIFACT_UNVERIFIED`、`UNSUPPORTED_IDENTIFIER`を定義する。未知のReason Codeを自由文字列として状態遷移に使用しない。

`not_achieved`は、Source of Truthを正常に確認でき、条件を満たさないことが確定した場合に用いる。`indeterminate`は、Session Refresh失敗、Adapter Reconciliation不能、Contradicted Evidence、Principal未確認、Artifact検証不能等により真偽を安全に決められない場合に用いる。`indeterminate`を`not_achieved`または`achieved`へ丸めてはならない。

`success_mode="all"`では全Conditionが`achieved`の場合にのみGoalを達成する。`success_mode="any"`では1件以上の`achieved`で達成するが、達成条件がなく1件以上の`indeterminate`がある場合はMissionを継続可能と自動判断せず、Policyに従って再Refresh、PAUSED、またはHuman Reviewへ遷移する。

LLMだけで「成功した」と判断させない。Goal Evaluatorは`confirmed`状態のFinding、Active Session、検証済みArtifactなど、Conditionごとに許可されたEvidence Sourceだけを参照する。

## 24.1 Indeterminate Handler

Goal Evaluatorが1件以上の`indeterminate`を返し、MissionのSuccess ModeによりGoalを確定できない場合は、専用の決定論的Indeterminate HandlerへRoutingする。

```text
Goal Evaluator
      |
      +-- ACHIEVED
      |      |
      |      v
      |   FINALIZING
      |
      +-- NOT_ACHIEVED
      |      |
      |      v
      |   Next Iteration
      |
      +-- INDETERMINATE
             |
             v
     Indeterminate Handler
         /          \
        v            v
Bounded Refresh   PAUSED /
Reconciliation    Human Review
```

HandlerはReason Codeごとに許可されたRead-only Session Refresh、Evidence Verification、Adapter Reconciliationだけを実行できる。External Actionの再Dispatchや新規副作用ActionをRecoveryとして実行してはならない。

同じ原因のRetry KeyはMission Revision、Condition ID、Reason Code、関連Session / Execution / Artifact IDとそのSource Versionから決定論的に生成する。`max_indeterminate_retries`の初期値を3とし、同じKeyで上限を超えた場合は再RefreshせずMissionを`PAUSED / WAITING_HUMAN_REVIEW`へ遷移させる。Source of Truthが実質的に変化した場合だけ新しいKeyとして扱い、Timestamp更新だけでCounterをResetしない。

---

# 25. Operational Phase

Plannerは現在の`OperationalPhase`を提案可能とする。

初期分類として以下を用意する。

```python
OperationalPhase = Literal[
    "INITIAL_ACCESS",
    "DISCOVERY",
    "PRIVILEGE_ESCALATION",
    "CREDENTIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "DOMAIN_CONTROL",
    "LINUX_PRIVILEGE_ESCALATION",
    "OBJECTIVE"
]
```

ただし、この順番を固定ワークフローにはしない。

実際の遷移は現在のStateに応じてPlannerが判断する。

OperationalPhaseは計画上の分類であり、実行許可やRiskを変更する権限を持たない。Policy EngineはPhaseに関係なくScopeとTool Policyを適用する。

つまり、

```text
フェーズ = Plannerが判断するコンテキスト

Planner / Executor / Analyzer
      = 共通処理
```

とする。

これによりフェーズごとに同じPlanner / Executor / Analyzerを重複実装しない。

将来的に特定フェーズの精度不足が確認された場合だけ、

```text
AD Planner
Linux PrivEsc Planner
Discovery Planner
```

などの専門サブエージェントへ分離可能とする。

---

# 26. エージェントループ

基本ループ:

```text
1. Mission / Revision / Authorization Epoch / LocalLLMProfile / run_id / thread_idを読み込む

2. Session Refresh: Session Managerがtrusted AdapterからSession Runtime Stateを更新

3. Context Selectorが許可されたIndex MetadataだけからCandidate Resource Referencesを選択

4. CalculateContextAuthorizationが候補ResourceとSession Viewを決定論的に認可

5. PersistContextAuthorizationがSessionContextGrant付きplanner_context用ContextDataAccessGrantを冪等保存

6. Context BuilderがGrant範囲のKnowledge / Redacted Artifact / Authorized Session Viewだけを取得

7. CalculateToolAvailabilityがMission Scope CompatibilityとCapabilityから候補Toolを計算

8. PersistAvailableToolSnapshotがAvailableToolSnapshotを冪等保存

9. PlannerがSnapshot内のToolRefでExecutionPlanProposalを生成

10. ApplicationがSystem ID、Mission Revision、Authorization Epoch、Snapshot Bindingを付けてExecutionPlanを生成

11. AvailableToolSnapshot Revalidation

12. Trusted Target ExtractorとTarget Normalizerを経て、Policy Engineが具体的Target、ToolRef、Data Accessを検証

13. DENYは停止またはSession Refreshから再計画

14. REQUIRE_APPROVALはauthorization_digestへBindingしたApprovalRequestを提示し、ApprovalRecordを待つ

15. ExecutorがImmutableなPolicyDecision、ApprovalRequest / ApprovalRecord、Authorization Epoch、TTL、Freshness、Adapter / Sandbox / Remote MCP Trust DigestからExecutable Predicateを検証

16. ExecutionRecordをPLANNEDとして永続化し、Tool RegistryからAdapter IDを再解決してExecutable Predicate成立時だけAUTHORIZEDへ遷移

17. Pre-dispatch Enforcementを再実施し、不一致ならAUTHORIZED -> BLOCKEDとしてProviderを呼ばない

18. ExecutionAdapterへIdempotency Key付きで送信。Graph Automatic Retryは使用しない

19. Provider ResultをRawResultSinkへChunk Streamingし、Encrypted Raw Result QuarantineへDurable Commitする

20. AdapterはRaw Contentを含まないRawResultReceipt / AdapterRawResult Metadataを返す

21. Result Ingestion StateをPENDING -> INGESTINGとしてSecure Ingestionを実行

22. ExecutorがSecureIngestionResult、PolicyDecision、Normalized TargetからExecutionResultを生成

23. Analyzer Context SelectorがIndex MetadataからCandidate Resource Referencesを選択

24. Analyzer用Context Authorizationを計算・冪等保存し、Context BuilderがAuthorized Contextを生成

25. AnalyzerがCandidateObservationを抽出

26. Knowledge ReducerがCandidateObservationとSecretDiscoveryReferenceを検証

27. Knowledge BaseへConfirmed FindingまたはProvenance付き状態を保存

28. CandidateSessionObservationを契機にSession Managerがtrusted AdapterからRefresh

29. Goal EvaluatorがConditionを三値評価

30. not_achieved
       |
       +--> Session Refresh / Context Selectorから次Iteration

31. indeterminate
       |
       +--> Indeterminate Handler
                 |
                 +--> Bounded Refresh / Reconciliation
                 +--> PAUSED / Human Review

32. achieved
       |
       +--> FINALIZING
                 |
                 +--> Execution Reconciliation / Cancel / Final Refresh / Audit Verification
                 |
                 +--> COMPLETED または WAITING_HUMAN_REVIEW
```

Workflow再開時はPlannerへ進む前に、thread_id、Mission Revision、Authorization Epoch、LocalLLMProfile Digestを照合し、`DISPATCHED`および`RUNNING`のExecutionをApplication DatabaseとAdapterでReconciliationする。未確定Executionが存在する間、同じActionを新規送信しない。Checkpoint内のExecutor Node位置だけを根拠にDispatchを再実行してはならない。PAUSEDからのResumeでは旧EpochのGrant、Snapshot、PolicyDecision、ApprovalRequest、ApprovalRecordを破棄し、Planner前の認可系列を最初から再生成する。

各IterationのPlanner前順序は必ず次で統一する。

```text
Session Refresh
       -> Context Selector
       -> CalculateContextAuthorization
       -> PersistContextAuthorization
       -> Context Builder
       -> CalculateToolAvailability
       -> PersistAvailableToolSnapshot
       -> AvailableToolSnapshot
       -> Planner
       -> AvailableToolSnapshot Revalidation
       -> Policy Engine
       -> Executor
```

Tool Availability Resolverは具体的TargetのScope内判定を行わない。具体的Actionの最終認可はPlanner後のTrusted Target Extractor、Target Normalizer、Policy Engineだけが行う。

---

# 27. 無限ループ防止

以下を必須とする。

```text
max_iterations
max_runtime
max_consecutive_failures
max_consecutive_policy_denials
max_same_action_retries
max_indeterminate_retries
max_validation_retries
```

例:

```yaml
limits:

  max_iterations: 50

  max_runtime_minutes: 120

  max_consecutive_failures: 5

  max_consecutive_policy_denials: 3

  max_same_action_retries: 2

  max_indeterminate_retries: 3

  max_validation_retries: 3
```

Plannerが同一Actionを繰り返した場合も検出する。

同一または同等のScope違反を繰り返す場合、`max_consecutive_policy_denials`でWorkflowを停止し、Operatorへ通知する。DENYされたActionを引数表現だけ変えて再提案することをRetry成功と扱わない。

同一Actionは、ToolRef、Canonicalized Arguments、Normalized Targets、Session IDから生成するAction Fingerprintで判定する。単なるPlan IDの違いで別Actionとして扱わない。

`max_runtime`はActive Runtimeを基本とし、承認待ち時間を含めるかはMissionのApproval Policyに従う。外部Taskの実行待ち時間はActive Runtimeへ含める。Runtime、Iteration、Failure等の停止上限へ到達した場合は新規実行を停止し、停止理由を付けて共通のFINALIZINGへ遷移する。

---

# 28. Error Handling

エラーは型付きTaxonomyとし、Graph Node Retry、Execution Retry、Re-plan、Mission State遷移を混同しない。次の表のAutomatic RetryはSide Effectを持たない同一処理のBounded Retryだけを意味する。

| Error | Automatic Retry | Re-plan | Mission Pause | Human Review | Fail Closed |
| --- | --- | --- | --- | --- | --- |
| `PydanticBoundaryValidationError` | Planner / Analyzer OutputだけPydantic AI Output Retry Budget内で可。その他Boundaryは不可 | Output上限後は不可 | 継続不能時に必要 | Schema / Model不整合時に必要 | Yes |
| `MissionValidationError` | 不可 | 不可 | 開始前のため遷移禁止 | 設定修正が必要 | Yes |
| `ContextSelectionError` | Indexの一時的Read障害だけ有限回可 | 不可 | 継続失敗時に必要 | Index / Policy修正時に必要 | Yes。本文読取へFallbackしない |
| `ContextAuthorizationError` | 一時的なPolicy Store障害のみ有限回可 | 不可 | 継続失敗時に必要 | 必要 | Yes |
| `DataAccessDeniedError` | 不可 | Grant再発行後のみ可 | Policy矛盾時に必要 | Policy矛盾時に必要 | Yes |
| `SessionContextGrantStaleError` | 不可。Session Refresh後に再認可 | 可 | 反復時に必要 | 反復時に必要 | Yes |
| `AvailableToolSnapshotStaleError` | 不可。新Snapshotを再生成 | 可 | 通常不要 | 通常不要 | Yes |
| `SandboxCapabilityStaleError` | 不可。Capability Snapshotを再取得 | 可 | 継続失敗時に必要 | 継続失敗時に必要 | Yes |
| `PolicyDecisionStaleError` | 不可。Policy Checkをやり直す | 可 | 反復時に必要 | 反復時に必要 | Yes |
| `AuthorizationEpochMismatchError` | 不可 | Resume再認可Flowから可 | 必要 | 通常不要 | Yes |
| `MissionTTLExceededError` | 不可 | 不可 | FINALIZINGへ遷移 | 未解決Execution時に必要 | Yes |
| `PreDispatchBlockedError` | 不可 | Reasonに応じてRefresh / 再認可後のみ可 | Security Reasonで必要 | Approval / Trust問題で必要 | Yes。Providerを呼ばない |
| `DigestIntegrityError` | 不可 | 不可 | 必要 | 必要 | Yes |
| `ApprovalBindingError` | 不可 | 新しいPolicy / Approvalからのみ可 | 必要 | 必要 | Yes |
| `RawResultStreamingError` | 同じProvider Task / SinkへのResumeだけ有限回可 | 不可 | 継続失敗時に必要 | 必要 | Yes。External Actionは再Submitしない |
| `SecureIngestionError` | 同一隔離Bufferへの安全な処理だけ有限回可 | 不可 | 必要 | 必要 | Yes。Rawを公開しない |
| `ResultIngestionError` | 同一Quarantineからの処理だけ有限回可 | 不可 | 継続失敗時に必要 | 必要 | Yes。External Actionは再実行しない |
| `RawResultQuarantineError` | Durable Commit前の同一Raw Stream処理だけ安全性を証明できる場合に有限回可 | 不可 | 必要 | 必要 | Yes。通常StoreへFallbackしない |
| `SecretDetectionError` | 検出器の一時障害だけ有限回可 | 不可 | 必要 | 必要 | Yes。未検査Outputを公開しない |
| `AdapterReconciliationError` | Read-only照会だけ有限回可 | 不可 | 必要 | 必要 | Yes。再送しない |
| `StructuredOutputCapabilityError` | 起動時検査の一時障害だけ有限回可 | 不可 | 当該LLMを使用不可 | 設定変更時に必要 | Yes |
| `MissionRevisionConflictError` | 不可 | 不可 | 必要 | 必要 | Yes |
| `MissionStateVersionConflictError` | 最新State再読込だけ可。更新再適用は明示判断 | 不可 | 必要に応じる | 競合継続時に必要 | Yes |
| `TargetExtractorResolutionError` | 不可 | 不可 | 必要 | Registry修正が必要 | Yes |
| `MCPProtocolRevisionMismatchError` | 同じ設定で不可 | 不可 | 必要 | 設定変更が必要 | Yes |
| `MCPServerIdentityMismatchError` | 同じ接続先で不可 | 不可 | 必要 | 接続先確認が必要 | Yes |
| `MCPTransportIdentityMismatchError` | 同じ接続先で不可 | 不可 | 必要 | 接続先 / Binary確認が必要 | Yes |
| `MCPTaskCapabilityError` | 不可 | Task非依存Toolへの再計画のみ可 | 副作用結果不明時に必要 | 副作用結果不明時に必要 | Yes |
| `RemoteMCPTrustError` | 証跡の一時取得障害だけ有限回可 | Read-only代替Toolへ可 | High Risk要求時に必要 | Trust Policy変更時に必要 | Yes |
| `AuditSequenceConflictError` | 同一Event ID / PayloadのIdempotent Insertだけ有限回可 | 不可 | 継続競合時に必要 | Chain修復判断が必要 | Yes |
| `LLMProfileMismatchError` | 不可 | 不可 | 必要 | Profile変更承認が必要 | Yes |
| `EncryptionKeyUnavailableError` | Key Providerの一時障害だけ有限回可 | 不可 | 必要 | Key Recoveryが必要 | Yes |

Mission Validation失敗、Pydantic Boundary Validation失敗、Context Selection / Authorization失敗、PolicyDecision不整合、DataAccessGrant / SessionContextGrant不整合、Mission Revision / State Version / Authorization Epoch不整合、Sandbox Capability不整合、Target Extractor解決失敗、MCP Protocol Revision / Logical / Transport Identity不一致、Remote MCP Trust不足、Digest / Approval Binding不整合、LLM Profile不一致、Encryption Key不足はFail Closedする。Secure Ingestion、Raw Result Streaming / Quarantine、またはSecret Detectionに失敗した場合、Raw OutputをAnalyzer、Planner、通常Application Database、通常Audit Logへ公開して回復してはならない。

`SecureIngestionError`は分類・Redaction・Artifact生成処理の具体的失敗、`SecretDetectionError`はその原因分類、`ResultIngestionError`はResult Ingestion State Machineが処理を完了できなかったことを表す上位Errorとする。`RawResultQuarantineError`はDurable Commit / Integrity / Binding失敗であり、いずれもProvider Execution Stateを`OUTCOME_UNKNOWN`へ書き換えない。`MissionRevisionConflictError`はAuthorization Revision不一致、`MissionStateVersionConflictError`はLifecycle RepositoryのOCC競合に限定する。

`AvailableToolSnapshotStaleError`、`PolicyDecisionStaleError`、`AuthorizationEpochMismatchError`からの再計画は、Session Refresh、Context Selector、Calculate / Persist Context Authorization、Context Builder、Calculate / Persist Tool Availabilityから再開する。古いGrant、Snapshot、Decision、ApprovalRequest、ApprovalRecordを流用しない。

以下は代表的な運用分類である。

## LLM Validation Error

Pydantic AI側で有限回リトライ。

## Tool Error

Analyzerへ結果を返し、再計画。

## Temporary Infrastructure Error

一定回数のみバックオフして再試行。

再試行はToolのIdempotency定義とExecution Stateを確認して行う。送信済みか不明な非冪等Actionを自動再送しない。

HTTP ClientやSDKの暗黙的な自動Retryも同じ制約に従う。非冪等RequestではTransport Layerの自動Retryを無効化するか、Provider側Deduplication Keyを必須とする。

External Executionの再試行は必ずExecution State Machine、Tool Idempotency、Idempotency Key、Adapter Reconciliation、Policy Revalidationを通す。LangGraph Automatic RetryまたはHTTP Client RetryをExecution Retryの代わりにしてはならない。

## Scope Violation

即座に実行拒否。

## C2 Session Lost

Session Manager更新後Plannerへ戻す。

## Unexpected Error

Audit Logを保存し、Workflowを停止する。

## Outcome Unknown

Adapter Timeout、通信断、Checkpoint復旧等により実行結果を確定できない場合に使用する。Human ReviewまたはProviderとのReconciliationが完了するまで同じActionを自動再実行しない。

---

# 29. ログ

すべての処理を追跡可能にする。

記録対象:

```text
Mission
Planner input
Planner output
Policy decision
Executor input
Tool execution
ExecutionResult
Analyzer output
State transition
Goal evaluation
Human approval
Errors
```

認証情報・秘密情報についてはマスキングする。

RedactionはAudit Logへ書き込む前に行い、Planner input、Analyzer input、Exception、Tracebackにも同じ規則を適用する。Secret値を一度平文保存してから後処理で削除する方式は禁止する。

Audit Eventには最低限以下を含める。

```text
Event ID
Mission ID / Revision
Authorization Epoch
Chain Scope / Sequence Number
Plan ID / Proposal Digest / Authorization Digest
PolicyDecision ID
Approval Request ID / Approval ID
Execution ID / Provider Task ID
Actor ID
Event Type
Timestamp
Previous Event Hash
Redaction Metadata
```

Plan、PolicyDecision、Approval、Executionがまだ存在しないEventでは対応IDを`null`とし、該当Objectが存在するEventでの欠落を許可しない。`run_id`と`thread_id`もWorkflow Eventへ記録する。

Audit Logは`Application-level append-only`かつ`Tamper-evident`として設計する。SQLite上のRecordであることだけを理由に完全なImmutable Logとは定義しない。Application APIから既存Eventの更新・削除を禁止し、Event Hash Chainまたは同等の改ざん検出機構を持たせる。保持期間、閲覧権限、Export手順を設定可能とする。

Event HashはRedaction後のAudit Eventを仕様固定したCanonical JSONへ変換し、Previous Event Hashとともに計算する。Chain Verificationは欠落、並べ替え、内容変更、Previous Hash不一致を検出し、FINALIZING時にも実行する。

MVPのHash Chain ScopeはMission単位へ固定する。

```python
class AuditEvent(StrictImmutableBoundaryModel):
    event_id: str
    mission_id: str
    mission_revision: int
    authorization_epoch: int
    chain_scope: Literal["mission"]
    sequence_number: int
    previous_event_hash: str | None
    event_hash: str
    event_type: str
    canonical_payload: CanonicalJsonObject
    occurred_at: datetime
```

Databaseは`mission_id + sequence_number`へUnique Constraintを設定する。MissionごとにGenesis Eventの`sequence_number=1`、`previous_event_hash=None`とし、以降は単調増加させる。

```text
event_hash[n]
= HASH(
    canonical_event_without_event_hash[n]
    + event_hash[n-1]
  )
```

Audit Event追加時はMission Chain RowをLockまたはSQLiteの適切なWrite Transactionで直列化し、`sequence_number`採番、直前Hash取得、Canonical Event Hash計算、Event Insert、Chain Head更新を同一Transactionで行う。Sequence競合は`AuditSequenceConflictError`として扱い、別Sequenceを推測して無制限Retryしない。Persistence Retryを許す場合は同一`event_id`と同一PayloadのIdempotent Insertだけを許可する。

Mission AとMission BのChainは独立して検証できなければならない。将来Global Chainまたは外部Anchorを追加しても、Mission ChainのSequenceとHashを変更・再採番してはならない。

将来は以下の外部Anchorを追加可能とする。

```text
Event Hash Chain
       |
       v
Periodic Chain Head
       |
       v
External Signature
```

Chain Headの外部署名が未実装でも、MVPのEvent Hash Chain検証を省略してはならない。

---

# 30. Observability

最低限以下のメトリクスを記録する。

```text
LLM calls
LLM latency
Tokens
Planner latency
Analyzer latency
Tool execution time
Workflow iteration count
Success / failure
Validation retries
HTTP transport retries / LangGraph node retries
Structured Output mode / Capability Check failure
Pydantic Boundary Validation / Unknown Field / Coercion rejection
LocalLLMProfile mismatch
Tool retries
Session count
Available Tool count / exclusion reason
AvailableToolSnapshot generation latency
Policy allow / approval / deny count
Outcome unknown count
Approval wait time
Scope violation count
Execution reconciliation count
Secret redaction count
Secure Ingestion failure count
Result Ingestion state / retry count
Raw Result Quarantine failure / recovery count
Raw Result streamed bytes / chunk retry / resume count
Pre-dispatch BLOCKED count / reason
Authorization Epoch mismatch / invalidation count
Persistent Upsert conflict count
Context Selection failure / excluded resource reason
MCP Transport Identity / Remote Trust rejection count
Digest Integrity / Approval Binding failure count
Audit Sequence conflict / Chain verification failure
Encryption Key unavailable / rotation state
Indeterminate reason / retry count
Mission Validation failure count
Snapshot stale reason（Session / Adapter / Sandbox / Remote Trust / Authorization Epoch）
```

将来的にLangSmith等のTracing基盤と連携可能な設計とするが、必須要件とはしない。

ローカル環境だけでもログ確認可能にする。

---

# 31. 並列処理

初期MVPではPlanner / Executor / Analyzerを並列実行しない。

```text
AvailableToolSnapshot -> Planner
        -> AvailableToolSnapshot Revalidation -> Policy Engine
        -> Executor -> Raw Result Chunk Streaming -> Encrypted Raw Result Quarantine
        -> RawResultReceipt / AdapterRawResult Metadata
        -> Secure Ingestion
        -> ExecutionResult -> Analyzer Context Selector / Authorization / Builder
        -> Analyzer -> Knowledge Reducer
```

の逐次実行とする。

理由:

* デバッグ容易性
* 状態競合防止
* GPU使用量の予測容易性
* LLM推論の同時実行数抑制

将来的には安全なRead-only処理のみ並列化可能とする。

並列化する場合も、各Actionに独立したPolicyDecisionとExecution IDを必要とする。同一Session、同一Target、同一Artifactへ競合するActionは直列化する。

---

# 32. データストレージ

初期MVPではSQLiteを使用する。

```text
SQLite
 |
 +-- missions
 +-- mission_revisions
 +-- mission_states
 +-- workflow_runs
 +-- sessions
 +-- session_security_context_snapshots
 +-- assets
 +-- accounts
 +-- relationships
 +-- findings
 +-- context_resource_index
 +-- execution_plan_proposals
 +-- execution_plans
 +-- executions
 +-- dispatch_claims
 +-- execution_tasks
 +-- execution_results
 +-- result_collection_authorities
 +-- result_ingestions
 +-- secure_ingestion_manifests
 +-- raw_result_receipts
 +-- raw_result_quarantine_metadata
 +-- quarantine_deletion_intents
 +-- execution_finalizations
 +-- analyses
 +-- goal_evaluations
 +-- policy_decisions
 +-- approval_requests
 +-- approvals
 +-- tool_registry_revisions
 +-- available_tool_snapshots
 +-- adapter_capability_snapshots
 +-- sandbox_capability_snapshots
 +-- mcp_discover_results
 +-- mcp_transport_identity_snapshots
 +-- remote_mcp_trust_snapshots
 +-- llm_profiles
 +-- llm_capability_results
 +-- encryption_key_metadata
 +-- data_access_grants
 +-- context_data_access_grants
 +-- artifacts
 +-- secret_references
 +-- audit_logs
```

将来的にPostgreSQLへ移行可能なRepository Patternを採用する。

Mission Revision / State、Execution Plan Proposal / Plan / Result、Provider Execution State、Result Ingestion State、PolicyDecision、Approval、Goal Evaluation、Capability Snapshot、Audit Eventには対応Repositoryを定義し、更新のTransaction境界を明確にする。SQLiteではForeign Keyを有効化し、必要に応じてWAL Modeを使用する。

LangGraph Checkpoint StoreはApplication Databaseと同じSQLite Instanceを利用してもよいが、論理Schema / Repositoryと責務を分離する。Checkpoint TableをMission、Execution、Session、Knowledge等のSource of Truthとして参照しない。

`missions`はStable Mission IDと作成Metadataを持つRoot、`mission_revisions`はAuthorization設定、LocalLLMProfile Revision / Digest、`mission_revision`を持つImmutable Revision、`mission_states`はLifecycle、`mission_state_version`、`authorization_epoch`を持つOCC Recordとする。これらを相互に代用しない。`workflow_runs`はMission ID、Mission Revision、run_id、thread_idの一意なBindingを保持する。

`dispatch_claims`はPre-dispatch成功時のExecution State Version、PolicyDecision、Authorization Digest、Mission Revision / Epoch、Tool、Adapter、Approval、TTL、消費状態を保持する。`result_collection_authorities`はTrusted Collection開始時刻、exact Tool Registry Digest、Tool固有Size上限、Retention、Provider Task、Sink、Leaseを保持する。いずれもCaller提示のBearer Tokenとして参照せず、Current ExecutionからRepository解決する。

`result_ingestions`にはResultIngestionStatus、Lease、Receipt / Quarantine Binding、Secure Ingestion Manifest ID / Digest、Deletion Intent Bindingだけを保存し、AdapterRawResult、Raw stdout、Raw stderr、Secret Valueを保存しない。`secure_ingestion_manifests`はRedacted Artifact、Secret Reference、Redaction Metadata、全参照Digestを保持し、Quarantine消去後のExecutionResult再構築に使用する。`raw_result_receipts`はByte Count、Ciphertext Digest、Quarantine Binding等のMetadataだけを保存する。`raw_result_quarantine_metadata`にも暗号化Storage Handle、Binding、Digest、Size、Retention、Stateだけを保存する。`quarantine_deletion_intents`はManifest Commit後にだけ作成し、Cryptographic ErasureとCiphertext削除のReconciliationを行う。

`data_access_grants`はPolicyDecisionまたはContextDataAccessGrantに内包されたEntryを正規化保存するChild Tableであり、`owner_type + owner_id + entry_index`等の内部Composite Keyで所有EnvelopeへBindingする。単独で外部へ提示できるGrant TokenやExecutionRequestのBearer IDを発行してはならない。

`available_tool_snapshots`、`adapter_capability_snapshots`、`sandbox_capability_snapshots`、`session_security_context_snapshots`はDigestだけでなく、Digest生成時に評価した正規化済みSnapshot本体、Schema Version、取得元、生成時刻をImmutableに保持する。`policy_decisions`は参照したSnapshot IDを保持し、後から「なぜToolがAvailableだったか」「なぜALLOW / REQUIRE_APPROVAL / DENYだったか」を再構築できなければならない。

`context_resource_index`はContext Selectorが読取可能なIndex Metadata、原Repository Record ID / Version / Digestだけを保持し、Artifact / Knowledge本文を含めない。`approval_requests`はHumanへ提示したCanonical Content、`approvals`はDecisionだけを保持する。`mcp_transport_identity_snapshots`と`remote_mcp_trust_snapshots`はDiscover Metadataと分離し、`llm_profiles`はCapability Check Resultを参照する。`encryption_key_metadata`にはKey ID / Version / Domain / Algorithm / Key Separation Tag / Rotation Stateだけを保存し、Key Materialを保存しない。

`audit_logs`には`UNIQUE(mission_id, sequence_number)`、`executions`にはExecutable PolicyDecisionのReplayを防ぐ`UNIQUE(policy_decision_id)`を設定する。Grant / Snapshot PersistenceはDeterministic ID、Unique Constraint、同一DigestのIdempotent Upsertを使用し、異なるPayloadのConflictを上書きしない。

通常SQLiteへRaw Secret、Raw stdout、Raw stderr、Raw Artifact Body、Quarantine Ciphertextを保存してはならない。Quarantine Ciphertextは専用のEncrypted Raw Result Quarantine、Secret ValueはSecret Store、Artifact BodyはArtifact Storeで管理する。

---

# 33. Artifact Store

大量出力はDBへ直接格納しない。

Tool出力は以下のSecure Ingestion Pipelineを必ず通す。

```text
Raw Result Chunk Streaming
       |
       v
Encrypted Raw Result Quarantine
       |
       v
RawResultReceipt / AdapterRawResult Metadata
       |
       v
Secure Ingestion
       |
       +-- Classification
       +-- Secret Detection ----> Secret Store
       +-- 必要時のみEncrypted Raw Artifact
       +-- Redacted Artifact
                    |
                    v
           SecureIngestionResult
       |
       v
Ingestion Complete
       |
       v
Quarantine Retention / Secure Delete
```

Planner / Analyzerへ渡してよいのはRedacted Artifactだけとする。Raw Outputを直接Promptへ連結してはならない。

## 33.1 Encrypted Raw Result Quarantine

Encrypted Raw Result Quarantineは通常Artifact Storeと分離した内部耐久領域であり、Raw Result Streaming中およびCommit直後のCrashからResultを保護する。通常Application Database、通常Artifact Store、LLM、Context Builder、通常OperatorからRaw Contentへアクセスできないようにする。

Quarantineは最低限以下を満たす。

* Encryption at RestとKey Separation
* Mission ID / RevisionおよびExecution IDへのBinding
* Toolごと・MissionごとのSize LimitとQuota
* 短いRetention Limit
* CiphertextのIntegrity Digest
* Atomic Commitまたは同等のCrash-safe Durable Write
* Process Restart後のIngestion Resume
* Retention完了後のSecure DeleteまたはCryptographic Erasure
* Raw Contentを含まない作成・読取・再開・削除Audit

通常SQLiteへ保存するのは`quarantine_id`、Mission / Execution Binding、暗号化Storage Handle、Ciphertext Digest、Size、Retention、State等のMetadataだけとし、Raw stdout、Raw stderr、Raw Artifact、Raw Secret自体を保存しない。

Quarantine LifecycleをResult Ingestion Stateと分離して管理する。

```python
RawResultQuarantineStatus = Literal[
    "OPEN",
    "STREAMING",
    "COMMITTED",
    "RECOVERY_REQUIRED",
    "ABORTED",
    "DELETED",
]
```

`OPEN / STREAMING`中は`ResultIngestionStatus=NOT_AVAILABLE`、Durable Commit後にだけ`PENDING`へ進める。ChunkごとにStream種別、単調増加Sequence、Plaintext Length、Ciphertext Offset、Chunk DigestをTransactionally記録し、再送された同一Sequenceは同一Digestの場合だけIdempotentに受理する。同じSequenceに異なるContentが来た場合は`DigestIntegrityError`として隔離する。

Adapter Resultの「取得完了」はQuarantineへのDurable Commit後にだけ記録する。全AdapterはOutputをRawResultSinkへStreamingし、Process Memoryへ全量受信してから保存する実装を禁止する。ProviderがResult再取得を保証する場合も、取得済みResultをIngestion前に失わない同じ境界を使用する。

`ExecutionAdapter.collect_result()`はExecutor管理のResult Collectorから呼び出し、戻り値を受領しただけではResult取得Transactionを完了させない。Providerが同じTask IDからResultを再取得できるAdapterはCrash後にResultだけを再収集できるが、External Actionを再Submitしてはならない。Result再取得を保証しないAdapterは、Quarantine-aware SinkへのStreamingまたはAdapter内のDurable StagingをCapabilityとして必須とし、これを満たさなければ当該ToolをAvailableにしない。

Process Restart時は、`RawResultQuarantineStatus=STREAMING / RECOVERY_REQUIRED`および`ResultIngestionStatus=PENDING / INGESTING`のExecutionとQuarantine Metadataを列挙する。Streaming未完了の場合は既存Provider Task IDと検証済みResume CursorからResult取得だけを再開する。ProviderがCursorを提供しない場合は、同じTask Resultの先頭から再読出し、SinkのSequence / Digestで既存Chunkを照合できるときだけ再開する。いずれもExternal Actionを再Submitしてはならない。Result再取得もできずLocal ProcessのDurable Stagingもない場合は自動回復せずMissionをPAUSED / Human Reviewへ送る。Commit済みの場合は期限切れのIngestion Leaseを回収して`PENDING`へ戻し、同じQuarantine CiphertextからSecure Ingestionを再開する。

Quarantineへの書込み、暗号化、Binding、Integrity検証に失敗した場合は`RawResultQuarantineError`としてFail Closedする。Raw Resultを通常ArtifactやLogへFallback保存してはならず、Provider Execution Stateを変更せずMissionをPAUSED / Human Reviewへ送る。

Secure IngestionはQuarantineからStreaming復号する。Raw Secretを平文の一時Fileへ残さない。Ingestion失敗時は元出力を通常Artifactとして保存せず、Result Ingestion Stateを`FAILED`から`QUARANTINED`へ遷移させてErrorをAuditする。

Quarantineから平文全体を返す`resume()`、`_resume_for_ingestion()`、互換用Full-object Load、Caller生成Publication Objectを権限として扱う経路を実装しない。Secure Ingestionの唯一のApplication入口は`ingestion_id`とし、CoordinatorがResult Ingestion、Receipt、Quarantine、Execution、Current MissionをRepositoryから解決する。Receipt、Quarantine Reference、Retention、Publication、Secret SinkをCaller引数として差し替えさせない。

Encrypted Raw Result QuarantineはIngestion前の短期Crash Recovery領域であり、Section 33の`variant="encrypted_raw"` Artifactとは異なる。後者はMission Policyにより原本保持が必要と判断された場合だけSecure Ingestionが生成する長期管理対象であり、Quarantine Objectをそのまま通常Artifactへ昇格させてはならない。

## 33.2 Durable Secure Ingestion Transaction

Secure IngestionはSQLiteと暗号化File Storeを単一ACID Transactionと仮定せず、決定的Identity、Write-ahead State、read-back verificationによるLogical Transactionとして実装する。

```text
PENDING
  -> INGESTING
  -> output publication prepare
  -> Artifact / Secret create-or-verify
  -> SecureIngestionManifest commit + read-back verify
  -> INGESTED_DURABLE
  -> Quarantine deletion intent commit
  -> DELETE_PENDING
  -> key destruction / ciphertext unlink
  -> QUARANTINE_ERASED
  -> ExecutionResult persist / acknowledgement
  -> SUCCEEDED
```

Artifact ID、Secret Reference ID、Manifest IDはExecution、Receipt、Quarantine Digest、Rule Version、Output Sequenceから決定論的に生成する。Crash後に同じIdentityへ同じPayloadを再適用する場合だけIdempotentに受理し、異なるDigestを上書きしない。Artifact Body / Secret Ciphertextは内部Staging Namespaceへ先にDurable Writeできるが、そのMetadataをCurrent Context Resourceとして公開してはならない。全Staging Payloadのread-back検証後、公開Artifact / Secret Metadata、SecureIngestionManifest、Result Ingestionの`INGESTED_DURABLE`遷移を同じApplication Database TransactionでCommitする。Manifest確定前のStaging IDをContext Selector、Knowledge Reducer、通常Read APIへ返さず、再開時にcreate-or-verifyする。

`SecureIngestionManifest`は少なくとも、`ingestion_id`、`execution_id`、`receipt_id / digest`、`quarantine_id / ciphertext_digest`、Rule Version、Redacted Artifact Reference / Digest、Encrypted Raw Artifact Reference / Digest、Secret Reference / Metadata Digest、Redaction Metadata、作成時刻を含み、自身のCanonical Digestを持つ。全参照をread-back検証したTransactionだけが`INGESTED_DURABLE`へ進める。

Quarantine Deletion IntentはManifest ID / Digest、Receipt、Quarantine Digest、Key MetadataへBindingする。再起動時の規則を次へ固定する。

| Crash境界 | Recovery |
|---|---|
| Manifest Commit前 | 同じQuarantineから決定的Publicationを再開。Provider Actionは再実行しない |
| Manifest Commit後・Deletion Intent前 | Manifestを検証し、Deletion Intent作成から再開 |
| Deletion Intent後・Erasure前 | 同じIntentのKey破棄 / Ciphertext削除だけを再開 |
| Erasure後・ExecutionResult確定前 | ManifestからExecutionResultを再構築。復号しない |

Retention失効、Key unavailable、Manifest不整合、Receipt不整合ではFail Closedし、平文Fallbackまたは通常Artifactへの昇格を行わない。

例:

```text
artifacts/

 mission-001/

   executions/

   logs/

   tool-output/

   reports/
```

DBにはArtifact IDおよび内部Pathだけでなく、以下のMetadataを保存する。

```python
class ArtifactReference(StrictImmutableBoundaryModel):
    artifact_id: str
    mission_id: str
    media_type: str
    size_bytes: int
    sha256: str
    classification: Literal["normal", "sensitive", "secret"]
    variant: Literal["redacted", "encrypted_raw"]
    encrypted: bool
    encryption_metadata_id: str | None
    derived_from_artifact_id: str | None
    created_at: datetime
    retention_until: datetime | None

class SecretDiscoveryReference(StrictImmutableBoundaryModel):
    secret_reference_id: str
    credential_type: str
    associated_principal_ref: str | None
    source_execution_id: str
    verification_state: Literal["detected", "confirmed", "revoked"]

class RedactionMetadata(StrictImmutableBoundaryModel):
    rule_version: str
    redaction_count: int
    secret_detection_count: int

class SecureIngestionResult(StrictImmutableBoundaryModel):
    ingestion_id: str
    ingestion_digest: str
    redacted_artifacts: tuple[ArtifactReference, ...]
    encrypted_raw_artifacts: tuple[ArtifactReference, ...]
    detected_secrets: tuple[SecretDiscoveryReference, ...]
    redaction_metadata: RedactionMetadata
```

Artifact Storeは以下を必須とする。

* Mission単位のアクセス制御
* Path TraversalおよびSymlink Escapeの防止
* 保存時のサイズ上限とDisk Quota
* SHA-256等による整合性検証
* Sensitive / Secret Artifactの暗号化
* ClassificationおよびSecret Detectionを保存・Context生成より前に実施
* Retention Policyと安全な削除
* 読み取りおよびExport操作のAudit

AdapterやLLMが返したPathをそのまま信頼せず、Artifact Storeが内部Pathを割り当てる。

`encrypted=true`では`encryption_metadata_id`を必須、`encrypted=false`では`None`を必須とする。Secret Reference、Quarantine Metadata、Encrypted Artifact Recordはそれぞれ対応するKey DomainのEncryption Metadata IDを保持し、Domain不一致を復号前に拒否する。

原本保持が演習上必要な場合に限り、`classification="secret"`かつ`variant="encrypted_raw"`かつ`encrypted=true`として保存する。Encrypted Raw ArtifactはData Access Policyで明示許可されたOperatorまたは信頼済みServiceだけが参照でき、Context Builderからは取得不可とする。

SecureIngestionResultだけをExecutorへ返し、AdapterRawResultを通常Application DBへ保存しない。Secure Ingestionに成功した場合も、まずResult Ingestion Stateを`INGESTED_DURABLE`としてManifestを確定し、その後`DELETE_PENDING -> QUARANTINE_ERASED -> SUCCEEDED`の順でQuarantineをSecure Deleteする。失敗した場合はExecutionResultを生成してAnalyzerへ進めず、Quarantineを保持してFail Closedする。

---

# 34. Secret Management

パスワード・トークン・秘密鍵等を通常DBやログへ平文保存しない。

```text
Raw Secret
    |
    v
Secure Ingestion
    |
    v
Secret Store
    |
SecretReference
    |
SecretDiscoveryReference
    |
    v
Knowledge Reducer
    |
    v
Knowledge Base
```

Knowledge BaseにはSecret Referenceのみ保存する。

```python
class SecretReferenceMetadata(StrictImmutableBoundaryModel):
    secret_reference_id: str
    mission_id: str
    credential_type: str
    associated_principal_ref: str | None
    encryption_metadata_id: str
    created_at: datetime
    expires_at: datetime | None
    verification_state: Literal["detected", "confirmed", "revoked"]
```

このModelにSecret Value、Ciphertext、復号用Key Handleを含めない。Secret Store内部RecordがEncryption Metadata IDとCiphertext Handleを保持し、通常Application DBの`secret_references`は上記Metadataだけを保持する。

Secret Storeは少なくとも以下を提供する。

* MissionおよびRole単位のアクセス制御
* 保存時暗号化
* 参照、作成、更新、削除のAudit
* 有効期限、失効、Rotation Metadata
* Secret値を含まない安定したReference ID

PlannerおよびAnalyzerへSecret値を渡さない。ExecutionPlanProposalの`arguments`には`credential_reference`等の参照だけを含め、Pre-dispatch成功後に永続化された未消費のDispatch ClaimへBindingされた`SecretInjectionBroker`だけが、実行直前にTrusted Adapter Channelへ値を注入する。解決されたSecretをApplication Callerへ返す汎用API、ExecutionPlan、ExecutionRequest、ExecutionResult、Exception、Prompt、Audit Logへ含めてはならない。

Planner / Analyzer / Knowledge Reducerへ渡してよいのはSecret Reference ID、Credential Type、Associated Principal、Source Execution、Verification State等のMetadataだけとする。Knowledge ReducerはSecretDiscoveryReferenceをProvenance付きFindingへ変換し、Secret ValueをKnowledge Baseへ保存しない。

Secret Valueの注入は、PolicyDecision Envelope内のexact DataAccessGrantに加え、Current Mission、Execution State `DISPATCH_CLAIMED`、Execution State Version、Dispatch Claim、ToolRef、Resolved Adapter、固定Adapter Channel、Operation、期限がすべて一致する場合だけ許可する。`AUTHORIZED`はSecret解決権限ではない。`BLOCKED`、Claim失効 / 消費済み、Mission停止、Epoch変更、Tool / Adapter不一致では拒否し、解決値をEnvironment、Command Line、通常IPC、Caller Callbackへ露出させない。

Raw Tool OutputにSecretが含まれる可能性があるため、Secure Ingestionで分類・Secret Detection・Redactionを行う。Raw SecretをLLM Promptへ渡してはならない。

## 34.1 Encryption Key Management

暗号化Key Domainを次へ分離する。

```text
Secret Store Encryption Key
Quarantine Encryption Key
Artifact Encryption Key
Audit Signing Key（将来拡張）
```

同じStatic Keyまたは同じ`key_id`をSecret Store、Encrypted Raw Result Quarantine、Encrypted Artifactで共用してはならない。DomainごとのKey用途をKey Provider Policyで固定し、別DomainのEncrypt / Decryptへ流用できないようにする。

```python
KeyDomain = Literal[
    "secret_store",
    "raw_result_quarantine",
    "artifact_store",
    "audit_signing"
]

class EncryptionMetadata(StrictImmutableBoundaryModel):
    key_domain: KeyDomain
    key_id: str
    key_version: int = Field(ge=1)
    encryption_algorithm: str
    key_separation_tag: str
    created_at: datetime
    rotation_state: Literal["active", "decrypt_only", "revoked", "destroyed"]

class EncryptionKeyProvider(Protocol):
    async def get_active_key_metadata(
        self,
        domain: KeyDomain,
    ) -> EncryptionMetadata:
        ...

    async def open_key_handle(
        self,
        domain: KeyDomain,
        key_id: str,
        key_version: int,
        operation: Literal["encrypt", "decrypt"],
    ) -> OpaqueKeyHandle:
        ...
```

`key_separation_tag`はKey ProviderがKey Materialを露出せず同一Key再利用を検出するために返す、Provider内で安定した非秘密のEquality Tagとする。異なるDomainで同じTagを使用してはならない。Key Material自体を通常SQLite、Application Config、Audit Log、Environment Dumpへ平文保存しない。MVPはOS Key Store、Vault相当、またはローカル開発専用の明示的Key Provider Interfaceを使用する。開発用ProviderはProductionでDefault Denyし、Key Fileを使用する場合もWorkspace外の権限制限済みStoreと明示的なOperator設定を必須とする。

Rotationでは新規Writeを新しいActive Versionへ切り替え、既存CiphertextのMetadataにKey ID / Version / Algorithmを保持する。旧Versionは移行期間中`decrypt_only`とし、再暗号化完了後に失効・破棄する。Revoked Keyで新規暗号化してはならない。Key BackupはKey Provider固有のWrapped Export / Recovery手順と二者承認を用い、平文Exportを禁止する。

暗号化AlgorithmはVersion付きAllowlistのAuthenticated Encryptionを使用し、Domain / Mission / Execution / Artifact BindingをAdditional Authenticated Dataへ含める。Nonce / IVの再利用を禁止し、Algorithm、Nonce、Authentication Tag等の復号に必要な非秘密MetadataをCiphertext Recordへ保存する。

必要Keyが失われた、失効した、Domainが一致しない、Algorithmが許可されない場合は`EncryptionKeyUnavailableError`としてFail Closedする。暗号化を無効化した保存、別Domain KeyへのFallback、Raw Contentの平文Exportで回復してはならない。起動時に全Key DomainのID分離、Active State、復号可能性を検査する。

## 34.2 Authenticated Generation Commit

Audit Head StateとWrapped Key Stateは同じ`AuthenticatedGenerationCoordinator`を使用し、Generation更新順序を個別実装しない。外部Anchorを単なる整数として扱わず、次の完全なIdentityへCAS Bindingする。

```python
class GenerationAnchor(StrictImmutableBoundaryModel):
    namespace: Literal["audit_head", "wrapped_key_state"]
    generation: int = Field(ge=1)
    immutable_blob_id: str
    state_digest: str
    previous_anchor_digest: str | None
    schema_version: str
```

次世代StateはContent-addressedかつImmutableなTrusted Blob Storeへ先にDurable Writeし、fsync相当とread-back authenticationを完了してからExternal AnchorをCAS更新する。CAS成功後はAnchorが指すBlobを再取得して検証し、Local Cache / Pointerを更新する。外部Anchorが進んでいるが対応Blobを取得できない場合はFail Closedし、別GenerationまたはLocal Alternate PathへFallbackしない。

RecoveryはExternal AnchorをSource of Truthとし、`generation + immutable_blob_id + state_digest`で正確なStateを再取得する。Anchor未更新のPrepared Blobは非権威として回収できる。Anchor更新済みでLocal Commit Markerが欠落している場合は、External BlobからMarkerを自動再構築する。Directory rename / replacement後のProcess Restartでも手動renameを要求してはならない。

Production ProviderはAnchorが指すBlobを、置換可能なApplication作業Directoryとは独立したVault、OS-keystore-backed Store、または同等のTrusted Durable Storeから再取得できなければならない。Generation整数だけを外部保存しBlobをLocal Fileだけに置くProviderはDevelopment-onlyとし、Production起動を拒否する。Wrapped Key Stateは外部Store内でも暗号化された状態を維持し、Secret / Quarantine / Artifact / AuditのKey Domain分離を崩さない。

---

# 35. 推奨ディレクトリ構成

```text
redteam-agent/

├── pyproject.toml
├── README.md
├── .env.example
├── config/
│   ├── agent.yaml
│   ├── tools.yaml
│   ├── policy.yaml
│   ├── adapters.yaml
│   ├── mcp_servers.yaml
│   ├── remote_mcp_trust.yaml
│   ├── llm_profiles.yaml
│   ├── encryption.yaml
│   └── sandbox.yaml
│
├── src/
│   └── redteam_agent/
│
│       ├── main.py
│       │
│       ├── graph/
│       │   ├── graph.py
│       │   ├── state.py
│       │   ├── routing.py
│       │   ├── retry_policy.py
│       │   ├── persistence_retry_policy.py
│       │   ├── run_repository.py
│       │   ├── finalizing.py
│       │   └── indeterminate_handler.py
│       │
│       ├── agents/
│       │   ├── planner.py
│       │   ├── analyzer.py
│       │   └── analysis_repository.py
│       │
│       ├── executor/
│       │   ├── executor.py
│       │   ├── state_machine.py
│       │   ├── result_ingestion_state.py
│       │   ├── normalization.py
│       │   ├── repository.py
│       │   ├── result_repository.py
│       │   ├── ingestion_repository.py
│       │   ├── raw_result_sink.py
│       │   ├── raw_result_receipt_repository.py
│       │   ├── pre_dispatch.py
│       │   └── reconciliation.py
│       │
│       ├── tools/
│       │   ├── registry.py
│       │   ├── availability.py
│       │   ├── target_extractors.py
│       │   ├── repository.py
│       │   ├── snapshot_repository.py
│       │   └── models.py
│       │
│       ├── adapters/
│       │   ├── base.py
│       │   ├── capability_repository.py
│       │   ├── c2/
│       │   ├── mcp/
│       │   │   ├── adapter.py
│       │   │   ├── capabilities.py
│       │   │   ├── discovery.py
│       │   │   ├── discover_repository.py
│       │   │   ├── transport_identity.py
│       │   │   ├── transport_identity_repository.py
│       │   │   ├── remote_trust_policy.py
│       │   │   ├── remote_trust_repository.py
│       │   │   ├── subscriptions.py
│       │   │   └── tasks.py
│       │   └── local/
│       │
│       ├── sessions/
│       │   ├── manager.py
│       │   ├── repository.py
│       │   ├── security_context_repository.py
│       │   └── models.py
│       │
│       ├── knowledge/
│       │   ├── repository.py
│       │   ├── models.py
│       │   ├── reducer.py
│       │   ├── context_index_repository.py
│       │   ├── context_selector.py
│       │   └── context_builder.py
│       │
│       ├── mission/
│       │   ├── models.py
│       │   ├── manager.py
│       │   ├── revision_repository.py
│       │   ├── state_repository.py
│       │   ├── validation.py
│       │   ├── finalizer.py
│       │   ├── goal_evaluator.py
│       │   └── goal_evaluation_repository.py
│       │
│       ├── policy/
│       │   ├── engine.py
│       │   ├── models.py
│       │   ├── scope_models.py
│       │   ├── data_access.py
│       │   ├── context_authorization.py
│       │   ├── context_authorization_repository.py
│       │   ├── grant_repository.py
│       │   ├── target_normalizer.py
│       │   ├── digests.py
│       │   ├── execution_predicate.py
│       │   ├── decision_repository.py
│       │   ├── approval.py
│       │   ├── approval_request_repository.py
│       │   └── approval_record_repository.py
│       │
│       ├── models/
│       │   ├── plan.py
│       │   ├── execution.py
│       │   └── analysis.py
│       │
│       ├── plans/
│       │   ├── proposal_repository.py
│       │   └── plan_repository.py
│       │
│       ├── llm/
│       │   ├── client.py
│       │   ├── config.py
│       │   ├── structured_output.py
│       │   ├── capability_check.py
│       │   ├── profile.py
│       │   └── profile_repository.py
│       │
│       ├── storage/
│       │   ├── database.py
│       │   ├── artifacts.py
│       │   ├── ingestion.py
│       │   ├── quarantine.py
│       │   ├── quarantine_metadata_repository.py
│       │   ├── secrets.py
│       │   ├── encryption_keys.py
│       │   └── encryption_key_metadata_repository.py
│       │
│       ├── sandbox/
│       │   ├── interface.py
│       │   ├── policy.py
│       │   ├── capabilities.py
│       │   └── capability_repository.py
│       │
│       └── logging/
│           ├── audit.py
│           ├── hash_chain.py
│           ├── audit_repository.py
│           └── mission_chain_sequence.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── mocks/
│
└── artifacts/
```

`config/encryption.yaml`にはKey Provider名、Key ID、許可Algorithm、Rotation Policyだけを置き、Key Materialを記載しない。末尾の`artifacts/`は通常Artifact Store用であり、Encrypted Raw Result QuarantineやSecret Storeの物理領域を配下へ置かない。Quarantine / SecretのStorage RootはKey Providerと専用Storage設定から解決する。`context_index_repository.py`はDerived Index専用、`approval_request_repository.py`と`approval_record_repository.py`は提示内容と判断を分離し、MCPのTransport Identity / Remote Trust SnapshotもDiscover Resultと別Repositoryで保持する。

---

# 36. MVP

最初から実C2を使って全機能を実装しない。

以下の順番で実装する。

## Phase 0A: Core Models / Authorization Kernel

```text
Pydantic Models
StrictBoundaryModel / extra=forbid / strict mode
Mission
mission_revision / mission_state_version / authorization_epoch separation
Mission Validation
Basic Typed Execution Scope
Data Access Policy
ToolRef / ExecutionPlanProposal / ExecutionPlan
ContextDataAccessGrant / SessionContextGrant Model
Context Selector / Context Resource Index
Tool Registry
Trusted Target Extractor Registry
Tool Availability Resolver
session_security_context_digest
adapter_capabilities_digest
sandbox_capabilities_digest
Policy Engine
PolicyDecision
Proposal Digest / Authorization Digest
Authorization TTL Invariants
ApprovalRequest / ApprovalRecord Model
Tool Availability / Concrete Target Authorization責務分離
Executor Authorization Gate（Adapter dispatchなし）
Source of Truth定義
SQLite
```

MVPのBasic Typed Execution ScopeはIP / CIDR、Host ID、Session IDを優先する。その他のScope TypeはDefault Denyとする。

Phase 0AのExecutor Authorization GateはPolicyDecision検証だけを行い、AdapterへDispatchしない。外部副作用を扱う完全なExecutorはPhase 0Bで実装する。

受入条件:

* Planner Proposalだけでは実行できない
* PolicyDecisionがなければExecutorが拒否する
* Scope外Actionは必ずDENYされる
* Tool Registry外のToolは実行できない
* ToolRefがRegistry Revisionを含みApplication全体で一意である
* PlannerがAdapterを指定・変更できない
* 利用不能ToolがAvailableToolSnapshotへ含まれない
* SnapshotがMission Revision、Authorization Epoch、Registry、Policy、Scope、Session Security Context、Adapter Capabilities、Sandbox Capabilities、Remote MCP TrustへBindingされる
* Authorization Referenceがない、または有効期間外のMissionは開始・実行できない
* 通常Lifecycle変更ではmission_state_versionが増加し、PAUSED / Emergency Stop等の失効境界ではauthorization_epochも増加する一方、mission_revisionは変化しない
* Authorization設定またはLocal LLM Profile変更では新しいmission_revisionを作成する
* Grant、Snapshot、Decision、Approvalの有効期限がMission Validityを超えない
* Success Condition 0件、Condition ID重複、不正な有効期間やLimitを持つMissionをVALIDATEDへ進めない
* 未登録Target Extractor IDをFail Closedし、設定値から任意ModuleをImportできない
* Planner前のTool Availabilityが具体的TargetのALLOWを決定せず、Policy Engineだけが具体Actionを最終認可する
* Trust Boundary Modelの未知Fieldと意図しない型Coercionを拒否する

---

## Phase 0B: Execution Safety

```text
Execution State Machine
AUTHORIZED -> BLOCKED
AUTHORIZED -> DISPATCH_CLAIMED
Dispatch Claim / Secret Injection Boundary
Result Ingestion State Machine
Idempotency Key
Execution Record
Executor
ExecutionAdapter Protocol / Mock Adapter
RawResultSink / Chunk Streaming / Metadata-only AdapterRawResult
Result Collection Authority / Trusted Tool Output Limit
ExecutionResult Normalization
Raw Result Quarantine Interface
Reconciliation
OUTCOME_UNKNOWN
Crash Recovery
External Side Effect NodeへのLangGraph Automatic Retry禁止
Persistent Mutation Retry Policy
Authorization Epoch Pre-dispatch Check
thread_id Lifecycle
FINALIZING State Skeleton
Approval Execution Predicate
Graph State / Mission State Mapping
```

受入条件:

* Process Crash後、確認不能な副作用Actionを自動再送しない
* Agent側Retryによる重複Dispatchを行わない
* `reconcile()`が`UNSUPPORTED`、`UNKNOWN`、または不確実な`NOT_FOUND`を返す場合は`OUTCOME_UNKNOWN`になる
* Graph Stateだけを根拠にExecutorを再送しない
* Raw ContentをQuarantineへStreamingし、Metadata-only AdapterRawResultがApplication側でExecutionResultへ正規化される
* Provider Execution StateとResult Ingestion Stateを独立して保持できる
* REQUIRE_APPROVAL Decisionは一致する有効なApprovalRequest / ApprovalRecordなしに実行できず、承認後もPolicyDecisionは変更されない
* ExecutionAdapterを交換してもExecutor Coreを変更しない
* Executor Dispatch NodeにLangGraph Automatic Retryが適用されない
* Pre-dispatch不一致は`AUTHORIZED -> BLOCKED`となりProvider APIを呼ばず、ExecutionResultも生成しない
* `AUTHORIZED`だけではSecretを解決できず、Pre-dispatch成功と同一Transactionで作成した未消費Dispatch ClaimだけがTrusted Adapter ChannelへのJIT Secret Injectionを許可する
* Dispatch Claim確定後のCrashではProvider Submitを自動再送せず、Reconciliationへ進む
* Result Collection開始時刻、Tool Registry Digest、Tool固有`max_output_bytes`、Retention、Sink IDをDurable Authorityへ固定し、Execution作成時刻またはCaller設定から再計算しない
* Grant / Snapshot PersistenceのRetryがDeterministic IDとIdempotent Upsertで重複Recordを作らない
* 旧Authorization EpochのDecision / ApprovalをDispatchに使用できない
* Mission Revision変更時にrun_idとthread_idが変わる
* Goal達成時の直接COMPLETED遷移をState Machineが拒否する

---

## Phase 0C: Data Security / Audit

```text
Artifact Store
Secure Ingestion
SecureIngestionResult
Encrypted Raw Result Quarantine
Crash-safe Secure Ingestion Resume
Durable Secure Ingestion Manifest / Quarantine Deletion Intent
Encryption Key Provider Interface
Authenticated Generation Coordinator / Digest-bound External Anchor
Quarantine / Secret / Artifact Key Separation
Secret Store
SecretDiscoveryReference
Redaction
Data Access Enforcement
Sandbox Interface / Sandbox Policy / Sandbox Capability
Application-level Append-only Audit Log
Event Hash Chain
Mission-scoped Audit Sequence
```

受入条件:

* SecretがPromptへ入らない
* Secretが通常Logへ入らない
* Artifact Path TraversalまたはSymlink Escapeができない
* Audit Eventの改ざんをHash Chainで検出できる
* Encrypted Raw Artifactは明示的なDataAccessGrantなしに取得できない
* Raw Contentを含まないReceipt / Metadata以外のAdapter Resultが通常Application DB、通常Audit Log、LLM Contextへ保存されない
* Streaming途中またはReceipt取得直後のCrash後にQuarantineから取得 / Ingestionを再開し、External Actionを再実行しない
* Caller生成Receipt、Quarantine Reference、Publication Object、Full-object compatibility loaderから平文を取得できず、Repository-bound `ingestion_id`だけがSecure Ingestionを開始できる
* Secure Ingestion ManifestをDurable Commitし全参照をread-back検証する前にQuarantineを消去しない
* Manifest Commit、Deletion Intent、Key破棄、Ciphertext削除、ExecutionResult確定の各Crash境界から、Provider再実行または手動File修復なしに再開できる
* Secure Ingestion失敗がExternal Actionの自動再実行を引き起こさない
* Secret ValueではなくSecretDiscoveryReferenceだけがKnowledge Flowへ入る
* 未実装のSandbox Capabilityを利用可能として扱わない
* Secret Store、Quarantine、Artifactで同一Key IDまたはKey Separation Tagを共用しない
* Mission別Audit ChainのSequence重複を拒否し、独立して検証できる
* Audit Head / Wrapped Key StateのExternal AnchorがGeneration、State Digest、Immutable Blob IDへBindingされ、Directory置換後の再起動でもAnchorから正確なCommitted Stateを回復する

---

## Phase 1: Agent Loop

```text
LangGraph
Mock Planner
Mock Analyzer
Knowledge Base
Knowledge Reducer
Session Manager
Context Authorization
Session Context Authorization
Context Selector Integration
Context Builder
Goal Evaluator
Indeterminate Handler / max_indeterminate_retries
ADPrincipalContextCondition
FINALIZING Workflow
Mission FAILED State
Pause / Resume Authorization Invalidation
```

Mock環境で以下を動作させる。

```text
Mission
   ↓
Session Refresh
   ↓
Context Selector
   ↓
Calculate / Persist Context Authorization
   ↓
Context Builder
   ↓
Calculate / Persist Tool Availability
   ↓
AvailableToolSnapshot
   ↓
Planner
   ↓
AvailableToolSnapshot Revalidation
   ↓
Policy Engine
   ↓
Executor
   ↓
Pre-dispatch Enforcement
   |
   +-- BLOCKED --> No Provider Call / No ExecutionResult
   |
   ↓
Mock ExecutionAdapter / Raw Result Streaming
   ↓
Encrypted Raw Result Quarantine
   ↓
Secure Ingestion
   ↓
ExecutionResult
   ↓
Analyzer Context Selector / Calculate & Persist Authorization / Context Builder
   ↓
Analyzer
   ↓
Knowledge Reducer
   ↓
Session Refresh
   ↓
Goal Evaluator
   ↓
Next Iteration / Indeterminate Handler / FINALIZING
```

受入条件:

* Scope内かつ利用可能なMock Actionだけが実行される
* Scope外または利用不能ActionがAdapterへ到達しない
* ContextDataAccessGrantなしでContext BuilderがKnowledge Baseを読めない
* Context Selectorが本文やSecret Valueを読まず、未許可ResourceをContextへ混入させない
* AnalyzerのCandidateSessionObservationだけではSession Runtime Stateが変更されない
* Session、Finding、Execution、Goal StatusがSQLiteへ永続化される
* Goalが`achieved / not_achieved / indeterminate`を区別する
* 同じ原因のIndeterminateが上限を超えて無限Refreshされない
* Domain Admin Principalの発見だけではAD Principal Context Goalを達成しない
* Goal達成後にReconciliationとAudit Verificationを経て終了する
* 最大Iterationで必ず停止する

---

## Phase 2: Local LLM

```text
vLLM
Pydantic AI
Pydantic Strict Boundary Test
Native Structured Output
Fallback Tool Output
Capability Check
Validation Retry
Prompt Injection Test
LocalLLMProfile
wire_api = chat_completions固定
Profile Digest / Capability Binding
```

受入条件:

* Planner / Analyzerに近いCanary SchemaでCapability Checkに合格する
* Nested Model、Enum、Optional、List、Discriminated UnionをValidationできる
* Pydantic AI Output Validation Retryが`max_validation_retries=3`以内で停止し、HTTP RetryおよびLangGraph Retryと独立する
* TimeoutとCancellationが動作する
* Redacted ArtifactだけがLLM Contextへ入る
* LocalLLMProfileとCapability Check結果が一致し、Mission途中のWire API / Profile変更をFail Closedする
* Phase 2以降の実LLM MissionでMockAgentProfileを使用できない

---

## Phase 3: Human Approval / Durable Resume

```text
LangGraph Interrupt
Human Approval
Authorization Digest Binding
Approval Expiration
Authorization Epoch Invalidation
Resume
Execution Reconciliation
```

受入条件:

* 承認後にPlanを変更すると承認が無効になる
* 未承認ActionはAdapterへ到達しない
* Resume時にCheckpoint、Application Database、Adapterの順で照合する
* PAUSED前のPolicyDecision、ApprovalRequest、ApprovalRecord、Grant、SnapshotをResume後に再利用しない
* 状態不明の非冪等Actionを自動再実行しない

---

## Phase 4: C2 Adapter

実C2との統合を1種類だけ実装する。Session取得、Capability取得、Submit、Task照会、Result収集、Cancel、Reconciliationまでを対象とし、コアロジックを特定C2へ依存させない。

C2そのもの、Payload、Implant生成機能は本プロジェクトのMVPで実装しない。

---

## Phase 5: MCP Adapter

管理者承認済みMCP ToolだけをTool Registry Revisionへ登録し、Tool Availability Resolverを経由して利用可能にする。MCPのTool変更通知からRegistryを自動更新しない。

```text
MCP Protocol Discovery / Revision Pinning
MCP Server Stable Internal ID
MCP Logical Identity / Transport Identity Separation
Remote MCP Execution Location / Trust Policy
MCP Capability Negotiation
Tool Subscription Handling
Python SDK Task Extension Capability Check
Task Extension Optional Mode
Task Extension ID / Version検査
MCP Task / OUTCOME_UNKNOWN Integration
Cancellation / Reconciliation Capability検査
```

受入条件:

* 設定したProtocol Revisionと非互換なServerを使用しない
* Unknown Revisionへの自動Upgradeや旧Revisionへの暗黙Fallbackを行わない
* Python SDKのNative Supportまたは検証済みCustom実装がなければ`task_extension=false`となる
* Tool変更通知はCandidate Definitionを作るだけでRegistryを変更しない
* Task CapabilityがないServerへTask APIを呼び出さない
* Timeout後の副作用有無を確認できないCallを`OUTCOME_UNKNOWN`にする
* 同名Toolを公開する複数ServerをToolRefとAdapter IDで一意にRoutingする
* Logical Identityが一致してもTransport Identityが不一致ならFail Closedする
* untrusted_remoteのHigh Risk ToolをDefault Denyし、managed_remoteのRequired Enforcement Capability不足時は利用不可にする

---

## Evaluation

代表的な演習シナリオについて、

```text
成功率
平均Iteration
Tool失敗率
Planner判断精度
無効Action率
LLM Validation Error率
Scope False-Allow件数
Approval Bypass件数
Agent起因の重複副作用Dispatch件数
OUTCOME_UNKNOWN件数
Checkpoint復旧成功率
Prompt Injection耐性
Secret Leakage件数
```

を測定する。

Scope False-Allow、Approval Bypass、Agent起因の重複副作用Dispatch、Secret Leakageの許容件数は0件とする。これは外部Providerを含むExactly Once保証を意味しない。

---

# 37. 最初の完成条件

MVP完成条件を以下とする。

* ローカルLLMのみで動作可能
* LangGraphだけがWorkflow EngineとしてLoop、Checkpoint、Interrupt、Resumeを管理する
* Plannerが型付きExecutionPlanProposalを生成し、ApplicationがSystem IDとBindingを持つExecutionPlanへ確定できる
* LLMがplan_id、execution_id、decision_id、approval_id、run_id、thread_id、grant_id、snapshot_id等のSystem IDを生成しない
* ExecutionPlanProposalにAdapter、Risk、Approval Requirementが含まれない
* Trust Boundary Modelが未知Fieldを`extra="forbid"`で拒否し、Strict型検証で暗黙Coercionを許さない
* Planner / Analyzerに近いSchemaでStructured Output Capability Checkに合格する
* Pydantic AI Output Validation Retryが初期値3回の上限で停止し、HTTP Retry / LangGraph Retryと混同されない
* Tool Availability ResolverがOS、Adapter、Session、Mission、Policyに適合するToolだけを公開する
* Session Refresh、Context Selector、Calculate / Persist Context Authorization、Context Builder、Calculate / Persist Tool AvailabilityがPlannerより前に完了する
* Plannerには有効なPlanner ContextとAvailableToolSnapshotだけが渡される
* Planner後にAvailableToolSnapshotを再検証してからPolicy Engineへ渡す
* ContextDataAccessGrantなしでContext BuilderがKnowledge Base、Artifact、Report、Internal Knowledgeを読めない
* ContextDataAccessGrantで許可されていないSession Runtime StateをPlanner / Analyzer Contextへ含めない
* 型付きExecution Scope、Data Access Policy、SuccessConditionをValidationできる
* Mission RevisionとMission State Versionを分離し、設定変更とLifecycle OCCを独立して管理できる
* Authorization EpochによりPAUSE / Resume境界のGrant、Snapshot、Decision、Approvalを一括失効できる
* MissionのAuthorization Referenceと有効期間を強制できる
* 全短寿命Authorization ArtifactのTTLがMission Validity内に収まり、Approval TTLがPolicyDecision TTLを超えない
* RiskとApproval RequirementをPlannerではなくPolicy Engineが決定する
* AdapterをTool Registryだけから決定する
* ToolRefが複数Adapter / MCP Server間でもToolを一意に識別する
* Trusted Target Extractor Registry外のExtractorをFail Closedし、任意Moduleを動的Importしない
* Executorが共通ExecutionAdapter経由でMock Toolを実行できる
* 有効なPolicyDecisionがないExecutionをExecutorが拒否する
* Tool Registry外またはSnapshot外のToolをExecutorが拒否する
* Raw Resultを全量Memoryへ保持せずEncrypted Raw Result QuarantineへChunk Streamingし、ApplicationだけがExecutionResultを生成する
* Pre-dispatch不一致が`AUTHORIZED -> BLOCKED`となり、Provider CallとExecutionResult生成を行わない
* `AUTHORIZED`がSecret解決またはProvider送信権限として使用されず、Pre-dispatch成功後の単回Dispatch ClaimだけがJIT Secret Injectionを許可する
* Result CollectionのRetentionがTrusted Collection開始時刻から固定され、Tool固有Output上限をCallerまたはGlobal設定で拡大できない
* Provider Execution StateとResult Ingestion Stateを独立して永続化できる
* Ingestion途中CrashからQuarantineを使って再開でき、External Actionを結果取得目的で再実行しない
* Durable Secure Ingestion Manifest確定前にQuarantineを消去せず、消去後CrashではManifestからExecutionResultを再構築できる
* AnalyzerがExecutionResultを構造化できる
* Knowledge ReducerがProvenance付きでKnowledge Baseを更新する
* AnalyzerのCandidateSessionObservationだけではSession Runtime Stateが変化しない
* Session Managerが信頼済みAdapterからSession Runtime Stateを確認する
* Session ManagerはCurrent Runtime Context、Knowledge BaseはDiscovered FactだけのSource of Truthになる
* Goal EvaluatorがOS / ADごとに分離したPrivilege Conditionを決定論的かつ三値で判定する
* Goal INDETERMINATEが専用HandlerへRoutingされ、同一原因のRetry上限を強制する
* ADPrincipalContextConditionが同一Session、Current Principal、Confirmed Group Membershipを結合して評価する
* Goal達成後にFINALIZINGを実行し、未解決のOUTCOME_UNKNOWNがあれば通常COMPLETEDにしない
* 最大Iterationで必ず停止する
* Scope外Targetと未実装Scope TypeへのExecutionがDefault Denyされる
* Basic ScopeのIP / CIDR、Host ID、Session IDを検査できる
* Prohibited Execution ScopeがAllowed Execution Scopeより常に優先される
* DataAccessGrantがないArtifact、Secret、Knowledgeを読み書きできない
* ExecutionRequestがDataAccessGrant Entryを単独Bearer Tokenとして使用せず、PolicyDecision Envelopeから解決する
* Human ApprovalがAuthorization Digestへ紐付けられ、Authorized Execution Intent変更時に失効する
* REQUIRE_APPROVALのPolicyDecisionが一致する有効なApprovalRequest / ApprovalRecordなしに実行されず、承認後もDecisionが変更されない
* Proposal DigestとAuthorization Digestが分離され、順序非依存Collectionの決定論的Sort後に安定して生成される
* Resume時にCheckpoint、Application Database、Adapterの順でReconciliationする
* thread_idがMission ID、Mission Revision、Application発行run_idへBindingされる
* `reconcile()`がProvider Task ID未取得Crashを扱える
* 非冪等Actionの結果不明時に`OUTCOME_UNKNOWN`で停止できる
* External Side Effect NodeにLangGraph Automatic Retryを適用しない
* Persistent MutationはAutomatic Retry禁止またはDeterministic ID / Unique Constraint / Idempotent Upsertを満たす
* Raw Tool OutputからのPrompt Injectionを指示として扱わない
* Secure IngestionがRedacted ArtifactだけをLLMへ渡す
* Secure IngestionがSecretDiscoveryReferenceをKnowledge Flowへ渡し、Secret Valueを渡さない
* SecretがPrompt、通常DB、Audit Log、Exceptionへ平文保存されない
* Sandbox Requirementを満たさないHigh Risk Local / MCP ToolをExecutorが拒否し、Sandbox Capability変更でSnapshotが失効する
* MCP Logical IdentityとTransport Identityを分離し、Remote Execution LocationごとのTrust PolicyをEnforceする
* MCP Protocol Revision、Capability、Task Extension、Tool List Revisionを明示的に検査する
* MCP ProtocolをDiscovery後に完全一致でPinし、利用SDKがTasks非対応ならTask Extensionを無効化する
* Audit LogがApplication-level Append-onlyかつHash ChainでTamper-evidentである
* Mission単位のAudit Sequenceを一意に採番し、Chainを独立検証できる
* Audit HeadとWrapped Key StateがDigest / Blob Identity付きExternal Generation Anchorから手動File操作なしに回復できる
* Secret Store、Quarantine、Artifact Storeが別Key Domainを使用し、Key Materialを通常DBへ保存しない
* LocalLLMProfile、Wire API、Capability Check ResultをMission Revisionへ固定し、途中変更をFail Closedする
* すべてのExecution、PolicyDecision、ApprovalがAudit Logへ残る
* C2 / MCP / Local ExecutionAdapterを交換してもExecutor Core、Planner、Analyzerを変更する必要がない

---

# 38. 非機能要件

## Modularity

各コンポーネントを交換可能とする。

特に、

```text
LLM
C2
MCP
Database
Tool
```

に直接依存しない。

---

## Local First

主要処理をローカル環境で完結可能とする。

```text
LLM inference
Agent orchestration
Knowledge Base
Session management
Logging
```

についてクラウドサービスを必須としない。

---

## Testability

外部C2やLLMを使用せずにUnit Test可能とする。

以下のMockを用意する。

```text
MockLLM
MockC2Adapter
MockMCPAdapter
MockTool
MockSessionManager
MockReconciliationProvider
MockSecureIngestion
MockRawResultSink
MockApprovalService
MockSecretStore
MockEncryptionKeyProvider
MockSandbox
MockContextSelector
MockRemoteMCPTrustVerifier
```

Unit / Integration Testに加えて、最低限以下のSecurity / Recovery Testを実装する。

* IPv4 / IPv6 / CIDR / Hostname / SubdomainのScope境界
* MVP未実装Scope Typeが必ずDefault Denyされること
* AllowedとProhibitedの競合
* DNS解決先変更およびRedirect先の再評価
* Tool引数内に埋め込まれたScope外Target
* Remote Filesystem ScopeでHostまたはPathが欠けた場合の拒否
* Execution ScopeとData Access Policyの分離
* OS、Architecture、Session、Adapter Capability、Mission PolicyごとのTool Availability
* Plannerより前にAvailableToolSnapshotが生成されること
* Planner後のAvailableToolSnapshot Revalidationに失敗したProposalがPolicy Engineへ到達しないこと
* ContextDataAccessGrantなしでContext BuilderがKnowledge Baseを読めないこと
* 期限切れ、Mission Revision不一致、Policy Version不一致のContextDataAccessGrantを拒否すること
* Context BuilderがSecret Resolve、Encrypted Raw Artifact、Raw Tool Outputへ常にアクセスできないこと
* ExecutionPlanProposalへ`adapter`、`risk`、`approval`、`scope`、`plan_id`、`execution_id`またはその他の未知Fieldを追加するとValidation Errorになること
* Trust Boundary Modelで文字列から整数・Boolean等への意図しない型Coercionが発生しないこと
* AvailableToolSnapshotの失効とReplay拒否
* Sessionの`last_seen`、`refreshed_at`、Telemetry Timestampの更新だけではAvailableToolSnapshotが失効しないこと
* Current Principal変更でAvailableToolSnapshotが失効すること
* Adapter Capability変更でAvailableToolSnapshotが失効すること
* 複数MCP Serverの同名ToolがToolRefで衝突せず正しいAdapter IDへRoutingされること
* LLM出力Schemaにplan_id、execution_id、decision_id、approval_id、run_id、thread_id、grant_id、snapshot_id等のSystem IDが含まれないこと
* Canonical JSONと順序非依存CollectionのSortによるProposal Digest / Authorization Digest安定性
* Path TraversalおよびSymlink Escape
* Secure IngestionとEncrypted Raw / Redacted Artifactの分離
* Secure Ingestion失敗時にProvider Execution Stateを推測変更せず、Actionを再実行しないこと
* Full-object Ingestion factory、Caller生成Receipt / Quarantine Reference、Compatibility Loaderを直接呼び出しても平文を取得できないこと
* Receipt永続化 / Ingestion Claim前、Manifest Commit前後、Deletion Intent前後、Key破棄 / Ciphertext削除前後、ExecutionResult確定前後のCrash Recovery
* Quarantine消去後にDurable ManifestだけからExecutionResultを再構築できること
* Audit Eventの削除、並べ替え、内容変更、Previous Hash変更の検出
* AdapterRawResultがAnalyzer、Planner、Knowledge Baseへ直接渡らないこと
* Raw Tool Outputが通常Application DBと通常Audit Logへ保存されないこと
* Tool出力によるPrompt Injection
* Nested Model、Enum、Optional、List、Discriminated UnionのStructured Output Capability
* Approvalの改ざん、期限切れ、Replay
* 同じPolicyDecisionから2件目のExecutionRecordを作成できないこと
* Adapter送信前後のProcess Crashと自動再送防止
* `AUTHORIZED`中、Pre-dispatch失敗後、期限切れ / 消費済みDispatch Claim、Tool / Adapter不一致からのSecret解決拒否
* Dispatch Claim発行後・Secret Injection前後・Provider Submit前後のCrashでSecretまたは外部Actionを自動再送しないこと
* Executor Dispatch、C2 Submit、MCP Side-effect Call、Local Side-effect ExecutionへLangGraph Automatic Retryが適用されないこと
* TaskHandle受信前Crashに対する`reconcile()`
* `reconcile()`の`UNSUPPORTED / UNKNOWN / 不確実なNOT_FOUND`から`OUTCOME_UNKNOWN`への遷移
* Application DatabaseとGraph Stateが矛盾した場合のDB優先
* Graph CheckpointがExecutionPlan / ExecutionResult / AnalysisResult本体ではなくRepository IDだけを保持すること
* Timeout後にProvider側で成功していた場合のReconciliation
* Mission Revision変更でthread_idが変わること
* 旧Mission RevisionのCheckpointが新Revisionへ混入しないこと
* Mission State Repositoryの`expected_mission_state_version`不一致が自動MergeされずFail Closedすること
* CandidateSessionObservationだけではSession Runtime Stateが変化しないこと
* Windows / AD / Linux Goal Conditionの独立判定
* Domain Admin Principalを発見しただけではAD Principal Context Goalを達成しないこと
* 対象Principalとして動作するActive SessionとConfirmed Group Membershipが同時に存在する場合だけAD Principal Context Goalを達成すること
* Session Refresh失敗、Reconciliation不能、Contradicted Evidence、Principal未確認、Artifact検証不能でGoalが`indeterminate`を返すこと
* Goal達成時にRUNNINGまたはDISPATCHED Executionが存在すればFINALIZINGへ進むこと
* 未解決のOUTCOME_UNKNOWNがあるMissionが通常COMPLETEDにならないこと
* Log、Artifact、TracebackへのSecret Leakage
* Secure Ingestionで発見したSecret ValueがPlanner / Analyzerへ渡らないこと
* SecretDiscoveryReferenceだけがKnowledge Reducerへ渡ること
* MCP Tool変更通知だけでRegistryが自動更新されず、Registry Revision更新時にSnapshotとPolicyDecisionが失効すること
* MCP Live Schema / Tool List Revisionが承認済みDefinitionと異なるToolがAvailableToolSnapshotから除外されること
* MCP Protocol Revisionまたは必須Capabilityが設定と一致しないServerを使用しないこと
* MCP Task CapabilityがないServerへTask APIを呼び出さないこと
* MCP Task CapabilityがないServerの不確実なTimeoutがOUTCOME_UNKNOWNになること
* Sandbox Requirementを満たさないHigh Risk Local / MCP Toolを拒否できること
* `RUNNING -> PAUSED`で`mission_revision`が変化せず、`mission_state_version`と`authorization_epoch`が増加すること
* Scope、Goal、Approval Policy、Data Access Policy変更で`mission_revision`が増加すること
* PAUSED前のPolicyDecision、ApprovalRequest、ApprovalRecord、ContextDataAccessGrant、AvailableToolSnapshotがResume後に再利用されないこと
* Authorization Epoch変更でGrant、Snapshot、Decision、Approvalが失効すること
* `ContextDataAccessGrant.session_context.authorized_session_ids`にないSessionがPlanner / Analyzer Contextへ入らないこと
* Session Security Context変更でSessionContextGrantが失効し、Telemetry時刻変更だけでは失効しないこと
* ExecutionRequestが独立DataAccessGrant IDをBearer Tokenとして使用せず、PolicyDecision Envelopeを検証すること
* Goal `INDETERMINATE`がIndeterminate HandlerへRoutingされること
* 同じIndeterminate Retry Keyが`max_indeterminate_retries`を超えて無限Refreshされないこと
* Sandbox有効状態、Egress、Filesystem Allowlist、Isolation、Secret Injection、Resource Limit Capability変更でAvailableToolSnapshotが失効すること
* `ProviderExecutionState=SUCCEEDED`かつ`ResultIngestionStatus=FAILED`を保持できること
* Result Ingestion失敗を`OUTCOME_UNKNOWN`へ誤分類しないこと
* 大容量stdout / stderrを全量Memoryへ保持せずQuarantineへStreamingできること
* Streaming途中またはAdapterRawResult Metadata取得直後のCrash後にQuarantineからResult取得 / Secure Ingestionを再開できること
* Quarantine Recovery時にExternal Action自体を再実行しないこと
* 長時間Provider実行後も新規StreamのRetentionがTrusted Collection開始時刻から始まり、Mission Deadlineを超えず、再起動後も同じ値を維持すること
* 異なるToolの`max_output_bytes`を取り違えず、Caller指定またはGlobal上限でTool固有上限を拡大できないこと
* SuccessConditionが0件またはCondition IDが重複するMissionをValidationで拒否すること
* `valid_from >= valid_until`、非正値Limit、不正なMission Revision / State Versionを拒否すること
* `REQUIRE_APPROVAL`のPolicyDecisionが一致するApprovalRequest / ApprovalRecordなしでは実行できないこと
* Approval後もPolicyDecision自体が変更されず、ApprovalRecordとの組み合わせで実行可能になること
* ExecutionAdapter実装をC2 / MCP / Local間で交換してもExecutor Coreが変化しないこと
* Proposal、Plan、ExecutionResult、Goal Evaluation、Capability Snapshot、Result Ingestionの各Repositoryが存在すること
* Graph StateとMission Stateの全Mappingが仕様表どおりで、Mission Managerを迂回して更新されないこと
* Proposal DigestがLLM Proposalだけを、Authorization Digestが解決済みAuthorized Execution Intentを表すこと
* 未登録Target Extractor IDがFail Closedし、設定文字列から任意Module、Expression、lambdaを解決できないこと
* Python MCP SDKがTask Extension非対応で検証済みCustom実装もない場合に`task_extension=false`となること
* MCP Protocol Revision不一致ServerがFail Closedすること
* 保存済みDiscover ResultのLogical Identity一致時でもTransport Identityが一致しない接続をFail Closedすること
* 未知Revisionへの自動Upgradeおよび旧Revisionへの暗黙Fallbackを行わないこと
* Pydantic AI Output Retry、HTTP Transport Retry、LangGraph Node Retryが独立したBudgetとPolicyを持つこと
* Sandbox Capability不一致で`AUTHORIZED -> BLOCKED`へ遷移し、Provider APIとExecutionResult生成を行わないこと
* ContextDataAccessGrant永続化後のCrash / Retryで重複Grantが作られないこと
* AvailableToolSnapshot永続化後のCrash / Retryで重複Snapshotが作られないこと
* Mission State / Execution State更新とAudit Sequence採番が無条件のLangGraph Automatic Retry対象にならないこと
* 全Authorization Artifactの`expires_at`が`Mission.valid_until`を超えず、ApprovalRecordがPolicyDecision / ApprovalRequestより長く存続しないこと
* 期限切れMissionでExecutorがDispatchせず`MISSION_EXPIRED`のBLOCKEDとFINALIZING要求を記録すること
* Context SelectorがArtifact / Knowledge本文、Secret Value、Encrypted Raw Artifact、Raw Tool Outputを読めないこと
* 未許可ResourceがContext Selector経由でContextへ混入しないこと
* stdio MCPのExecutable SHA-256またはCommand Configuration Digest変更をTransport Identity不一致として拒否すること
* untrusted_remote MCPのHigh Risk、State Change、Destructive、Secret Resolve ToolがDefault Denyされること
* managed_remote MCPがScope / Auth / Audit / Egress / Isolation / Stable Identity Capabilityを満たさなければHigh Risk Toolを利用できないこと
* Immutable ModelのNested Collectionまたは保存内容が改変された場合、使用直前のCanonical Digest検証で拒否されること
* ApprovalRequestで提示したRequest / Authorization DigestとApprovalRecordが一致しない場合に拒否すること
* `UNIQUE(mission_id, sequence_number)`がAudit Sequence重複を拒否し、Mission別Hash Chainを独立検証できること
* Tool Availability Resolverが具体的TargetをALLOW判定せず、Policy Engineだけが具体Target Scopeを最終判定すること
* LocalLLMProfileのWire API、Model、Chat Template、Tokenizer、Structured Output ModeがMission途中で変化するとFail Closedすること
* 実LLMを使用するMissionでMockAgentProfileを選択してCapability Checkを迂回できないこと
* Secret Store Key、Quarantine Key、Artifact KeyのKey IDまたはKey Separation Tagが共用されている構成を起動時に拒否すること
* Audit Head / Wrapped Key StateのPrepare前、Blob Durable Write後、External Anchor CAS前後、Local Marker更新前後のCrashから正確なGenerationを回復すること
* State DirectoryをCAS境界で置換してProcessを再起動しても、External AnchorのDigest / Immutable Blob IDから自動回復し、手動renameを要求しないこと
* External Anchorが進んだ一方で対応Blobが欠落・改ざんされている場合に旧Alternate StateへFallbackせずFail Closedすること

---

## Reproducibility

Plannerに渡したRedacted Context、生成されたPlan、ExecutionResultを保存し、同じ演習を再現・評価できるようにする。

以下をMission単位で記録する。

```text
Model Name / Model Hash
Structured Output Mode / Capability Check Result
LocalLLMProfile Revision / Digest / Wire API / Chat Template Digest
Inference Parameters / Seed
Prompt Version
Application Version / Commit ID
Dependency Lock Digest
Mission Revision
Observed Mission State Version
Authorization Epoch
Policy Version
Tool Registry Snapshot / Digest
AvailableToolSnapshot ID
Execution Scope / Data Access Policy Digest
Adapter Version
Adapter Capability Snapshot ID / Digest / Provider Tool Catalog Digest
Session Security Context Snapshot ID / Digest
MCP Protocol Revision / Tool List Revision / Task Extension Version
MCP Discover Result ID / Digest
MCP Logical Identity / Transport Identity Snapshot
Remote MCP Trust Policy / Capability Snapshot Digest
Sandbox Policy / Capability Snapshot ID / Digest
Context Builder Version
Secure Ingestion / Redaction Rule Version
Encryption Key Domain / Key ID / Key Version / Algorithm Metadata
Audit Chain Scope / Sequence / Chain Head
```

LLMおよび外部環境の非決定性により、完全に同じ出力を保証するものではない。再現性の要件は、同じ入力と構成を復元でき、差分を追跡・評価できることとする。

## Dependency and Schema Versioning

Python、LangGraph、Pydantic、Pydantic AI、vLLM等のVersionをLock Fileで固定する。DB Migration、Mission Schema、Tool Schema、Policy Schema、Promptには明示的なVersionを持たせる。起動時に互換性を検査し、非互換なCheckpointやMissionを暗黙に読み込まない。

---

## Security

* Scopeを必須設定とする
* Execution ScopeとData Access Policyを分離する
* Default Denyとする
* Tool Allowlistを使用する
* Global PolicyでHigh Risk / Destructive操作のHuman Approvalを必須とし、Mission / Tool Policyは要件を追加する方向にだけ変更可能とする
* 承認機能が利用できない場合はFail Closedとする
* Mission Manager、Operator API、C2 API、MCP、Secret Storeへの認証・認可を実装する
* 内部ServiceはLocal Socketまたは相互認証されたChannelを使用する
* Audit Logを残す
* Secretをログへ出力しない
* C2 API資格情報をコードに埋め込まない
* vLLMは原則`127.0.0.1`または管理された閉域InterfaceへBindする
* Remote vLLMはFirewall、Reverse Proxy、mTLS、Network ACL等でAI Agent以外からのアクセスを制限する
* vLLMのAPI KeyだけをSecurity Boundaryとして使用しない
* Tool Output、MCP応答、対象Host上のファイルを非信頼入力として扱う
* Trust Boundary Modelで未知Fieldを拒否し、暗黙型Coercionを禁止する
* Local Toolと外部Process型MCP ServerをDedicated OS User、Process Isolation、Filesystem Allowlist、Resource Limit、Network Egress Control、Environment Allowlist、Secret Injection Controlで隔離可能にする
* MCPのLogical IdentityとTransport Identityを別々に検証し、Remote MCPはExecution Location別Trust Policyを適用する
* Policy EngineをLogical Authorization、OS / Container / Network SandboxをDefense-in-Depth Enforcementとして分離する
* 必須Sandbox Capabilityが未実装または利用不能ならDefault Denyする
* Secret Store、Quarantine、Artifact Storeの暗号化Key Domainを分離し、Key Materialを通常SQLite / Configへ平文保存しない
* Emergency Stopを提供する

---

# 39. 将来拡張

MVP完成後、必要に応じて以下を追加する。

```text
                Main Planner
                     |
       +-------------+-------------+
       |             |             |
       v             v             v
 Discovery      AD Specialist   Linux Specialist
  Agent             Agent           Agent
```

特定フェーズで汎用Plannerの精度が不足した場合のみ専門エージェントへ分割する。

その他:

* Attack Graph
* Graph Database
* BloodHound等の分析結果取り込み
* RAG
* 過去演習Knowledge
* レポート生成
* Purple Team連携
* Multi-agent
* 並列Read-only Recon
* Tool自動選択
* モデルRouter
* 複数ローカルLLM
* 小型専門モデル
* 演習採点

---

# 40. Codexへの実装指示

上記仕様に基づき、まずMVPを実装すること。

実装はSection 36のPhase 0A、0B、0C、1、2、3、4、5の順に、小さな完結した単位で進める。複数Phaseを一度に実装せず、各Phaseの受入条件と関連Testを満たしてから次へ進む。

初回実装では実環境に対する攻撃ロジック、攻撃コマンド、Payload、Implant、配布基盤を追加しない。Phase 0AからPhase 3まではMock Adapterで検証し、安全Kernelと復旧動作が安定した後にだけ実C2 / MCPへ接続する。

Tool Availability Resolver、Policy Engine、Executor、Knowledge Reducer、Session Manager、Goal EvaluatorをLLM Agentとして実装してはならない。

特定C2、特定MCP、特定LLMへの依存をコアロジックへ持ち込まないこと。

## 40.1 不変条件ファミリー単位の実装・Review Loop

Formal Codex Reviewへ進む前に、実装担当はCurrent Phaseで要求される不変条件ファミリーを
`automation/invariant-families.json`から解決し、各Familyについてpublic entry point、caller、
compatibility reader、recovery path、sibling implementationを監査する。指摘行だけを直すのではなく、
同じSemantic Invariantを共有する経路を1つの修正単位とする。

監査結果は`docs/review/<phase>-invariant-audit.json`へ記録し、Implementation Request、入力HEAD、
出力HEAD、Canonical DigestへBindingする。全Familyはpositive、negative、failure-path test evidenceを
持ち、変更されたStateful Familyはproperty-basedまたはstate-machine test evidenceも持つ。CIはこの
監査の構造とBindingを検証してからReview Readyを発行する。

独立Reviewerは監査Reportを正しさの証明として信頼せず、Review順序を決めるRouting Evidenceとして
だけ使用する。各P0/P1はTrusted Policy中のInvariant Family IDを1つ保持する。同じFamilyが同一Phaseの
2回目のFormal Reviewへ再出現した場合、局所Patchを続けずLoopをDesign Reviewで停止する。再開には、
再発した全経路を同時に閉じるCoherent Redesignと、停止Gate、Current Phase / 40桁HEAD、Default
Branchから取り込んだ承認済みDesign commitへBindingした単回`DESIGN_APPROVED` Evidenceを必要とする。
Generic Resume、旧base-refresh Status、Label変更は再開権限ではない。Exact FindingとPhase全体の既存
5回上限はDefense-in-Depthとして残す。

---

# 41. Revision Summary

| 変更箇所 | 現行仕様の問題 | 修正内容 | 修正理由 | 影響コンポーネント | 追加Test |
| --- | --- | --- | --- | --- | --- |
| Section 3 vs Section 4.2のWorkflow | Section 3はResolverがPlanner前、Section 4.2はPlanner後で順序が逆 | Session Refresh、Context Selector、Context Authorization、Context Builder、Resolver、Snapshot、Planner、Revalidation、Policyの順へ統一 | Planner入力のSnapshotを事前に確定し、提案後は再生成ではなくBindingを再検証するため | LangGraph、Context Selector / Builder、Tool Availability Resolver、Planner、Policy Engine | Planner前Snapshot生成、Planner後Revalidation失敗時の拒否 |
| Section 26 vs Section 22のContext Authorization | Knowledge取得とContext生成がData Access Authorizationより先行 | SelectorはIndex Metadataだけを読み、Planner / AnalyzerごとにGrantを発行してからBuilderが本文を取得 | Data Access PolicyのDefault DenyをLLM Contextにも適用するため | Context Selector、Policy Engine、Context Builder、Planner、Analyzer、Knowledge / Artifact Repository | GrantなしのKB読取拒否、Selector本文読取拒否、禁止Resource読取拒否 |
| Section 13 vs Section 33のRaw Result | AdapterがExecutionResultを直接生成し、Secure Ingestionの位置が不明 | Chunk Streaming、Quarantine、Metadata-only AdapterRawResult、SecureIngestionResult、Application生成ExecutionResultを分離 | Raw stdout、stderr、Artifact、SecretがRedactionを迂回せず大容量Outputを全量Memoryへ載せないため | C2 / MCP / Local Adapter、RawResultSink、Executor、Quarantine、Secure Ingestion、Analyzer | Raw Result直渡し拒否、Streaming Crash Recovery、Raw Outputの通常DB非保存 |
| Section 14 vs Section 16のSession / Knowledge | Token、Group、UID等が双方のSource of Truthになり得た | Session ManagerをCurrent Runtime Context、Knowledge BaseをDiscovered Identity / Infrastructure Factへ固定 | 競合更新と誤ったGoal判定を防ぐため | Session Manager、Knowledge Base、Knowledge Reducer、Goal Evaluator | Candidate Sessionだけで状態不変、Principal Context結合評価 |
| Section 24のIndeterminate不足 | 未達と判定不能を区別できなかった | ConditionEvaluationの`achieved / not_achieved / indeterminate`と理由・Evidenceを追加 | Refresh / Reconciliation / Evidence検証不能を安全に表現するため | Goal Evaluator、Mission Manager、LangGraph | 各判定不能理由でindeterminateを返すTest |
| Section 4 vs Section 10 / 13 / 28のRetry | LangGraph Retryが永続化重複やExecutor Dispatchの二重送信を起こし得た | Pure計算、Persistent Mutation、External ExecutionのRetryを分離し、永続化にはDeterministic ID / Unique / Idempotent Upsertを要求 | Commit後例外による重複RecordとCrash / Timeout時の重複副作用を防ぐため | LangGraph、各Repository、Executor、全Adapter | Grant / Snapshot重複防止、Dispatch Node Retry禁止、Submit前後Crash、OUTCOME_UNKNOWN遷移 |
| Section 6 / 20のTool Identity | name + versionおよび暗黙Version解決が複数Serverで衝突 | Application発行ToolRefとRegistry Revision、Adapter Stable IDを導入し、暗黙Version解決を削除 | Registry拡張後も一意かつ再現可能にRoutingするため | Planner、Tool Registry、Resolver、Policy Engine、Executor | 複数MCP Server同名Toolの非衝突Test |
| Section 6のSystem ID | LLMがplan_id等を生成する構造 | LLMはExecutionPlanProposalだけを生成し、ApplicationがExecutionPlanと全System IDを発行 | 非信頼出力にIdentity管理を委ねないため | Planner、Plan Repository、Audit Logger | Planner SchemaにSystem IDが存在しないTest |
| Section 20.1のSnapshot Binding | Telemetry更新でSnapshot / Approvalが過剰失効し得た | session_security_context_digestとadapter_capabilities_digestを導入し、時刻をSession Digestから除外 | Security Context変更だけを失効要因としFreshnessを別検査するため | Session Manager、Resolver、Policy Engine、Executor | last_seen非失効、Principal / Adapter Capability変更失効 |
| Section 17のCheckpoint Isolation | Mission Revisionを跨ぐResumeを防ぐBindingがなかった | `thread_id = mission_id : mission_revision : run_id`を固定し、旧Checkpoint継承を禁止 | 異なるAuthorization RevisionのWorkflow混入を防ぐため | Mission Manager、LangGraph、Workflow Run Repository | Revision変更時thread_id変更、旧Checkpoint混入拒否 |
| Section 21 / 24 / 26の終了処理 | Goal達成から即COMPLETEDとなり未完了Taskを残し得た | FINALIZINGでReconciliation、Cancel、Final Refresh、Audit検証を実施 | 外部副作用とMission終端状態を一致させるため | Mission Manager、Goal Evaluator、Executor、Adapter、Audit Logger | RUNNING時FINALIZING、未解決OUTCOME_UNKNOWN時の通常COMPLETED拒否 |
| Section 33 / 34のSecret Flow | Redaction後にCredential発見事実を安全にKnowledgeへ渡す経路がなかった | Secret Store、SecretDiscoveryReference、Knowledge ReducerのMetadata経路を追加 | Secret ValueをLLMへ渡さず発見事実とProvenanceを保持するため | Secure Ingestion、Secret Store、Knowledge Reducer、Knowledge Base | Secret Value非漏えい、ReferenceのみKnowledgeへ伝播 |
| Section 19のMCP境界 | Protocol Revision、Capability、Task / Timeout意味論が未定義 | Discovery後のRevision Pin、Stable Server ID、Capability検査、Subscription候補化、Task Extension / Reconciliationを追加 | C2と同等のDurable Execution安全性を確保するため | MCP Adapter、Tool Registry、Resolver、Execution State Manager | Task CapabilityなしAPI拒否、通知でRegistry非更新、Timeout時OUTCOME_UNKNOWN |
| Section 19 / 38のSandbox | Tool内部の逸脱にLogical Policyだけでは対処できなかった | Sandbox Interface / Policy / CapabilityとHigh Risk ToolのRequirement検査を追加 | OS、Filesystem、Process、Network層でDefense-in-Depthを行うため | Executor、Local / MCP Adapter、Tool Registry、Sandbox Runtime | Sandbox Requirement不足時のHigh Risk Tool拒否 |
| Section 17.1のSource of Truth | Checkpoint / DB以外を含む全体の正データ所有者が曖昧 | Mission、Execution、Session、Knowledge、Tool、Authorization、Secret、Artifact、Auditの一覧表を追加 | 二重管理と復旧時の優先順位誤りを防ぐため | 全Stateful Component | Graph / DB矛盾時DB優先、Session / Knowledge非重複Test |
| Mission Revision / OCC Version分離 | Authorization設定RevisionとRepository Row Versionが同じ値だった | `mission_revision`と`mission_state_version`を分離し、さらに一時認可失効用`authorization_epoch`を追加 | Lifecycle OCCと設定Revisionを混同せず、PAUSE境界では短寿命Authorizationだけを確実に失効させるため | Mission Manager、Mission Revision / State Repository、Policy、LangGraph | PAUSEでRevision不変・State Version / Epoch増加、Scope変更でMission Revision増加 |
| Session Context Authorization | Context GrantがArtifact系Resourceしか表現できずSession Viewの許可範囲が不明 | SessionContextGrantにSession ID集合とSecurity Context Digestを追加 | Scope外・未許可SessionがLLM Contextへ混入するのを防ぐため | Context Authorization、Context Builder、Session Manager | 未許可Session除外、Security Context変更時Grant失効 |
| DataAccessGrant参照修正 | ExecutionRequestのGrant IDがModelに存在せず単独Bearer化し得た | ExecutionRequestから独立Grant IDを削除しPolicyDecisionのAuthorization Envelopeから解決 | Execution、Tool、Adapter、Mission Revisionに結合したAuthorizationをEnforceするため | Policy Engine、Executor、Adapter、Secret Store | 独立Grant EntryのReplay / Bearer使用拒否 |
| Goal Indeterminate Routing | 三値評価はあっても一部WorkflowがACHIEVED / CONTINUEの二分岐だった | Indeterminate Handler、Bounded Refresh / Reconciliation、Retry Keyと上限を追加 | 判定不能を未達へ丸めず無限Refreshも防ぐため | Goal Evaluator、LangGraph、Mission Manager | 専用Handler Routing、同一Reason上限超過時Pause |
| Sandbox Capability Digest | Resolver入力のSandbox状態がSnapshot Bindingに含まれなかった | `sandbox_capabilities_digest`と失効対象FieldをAvailableToolSnapshotへ追加 | Sandbox弱体化後の古いTool Availability利用を防ぐため | Sandbox Manager、Resolver、Policy、Executor | Egress / Filesystem / Isolation等の変更時Snapshot失効 |
| Result Ingestion State | Provider実行状態だけではExecution成功・Ingestion失敗を表現できなかった | Provider Execution StateとResultIngestionStatusを独立State Machineとして永続化 | 取込失敗を外部結果不明と誤分類しないため | Executor、Secure Ingestion、Execution / Result Ingestion Repository | Provider成功・Ingestion失敗の合法状態、OUTCOME_UNKNOWN非誤分類 |
| Encrypted Raw Result Quarantine | Raw Result取得直後Crashで非再取得Outputを失う可能性があった | 暗号化・Binding・Retention・Crash Resumeを備えた専用Quarantineを追加 | External Actionを再実行せず同じRaw Resultから処理を再開するため | ExecutionAdapter、Executor、Secure Ingestion、Quarantine Store | 取得直後Crash Resume、External Action非再実行、Raw通常DB非保存 |
| Mission Validation | 条件0件や不正期間がMission開始後に即成功・不定動作を起こし得た | Success Condition数、一意ID、期間、Limit、Scope、Revision / Versionを開始前検証 | Authorization Kernelへ不正なMissionを入れないため | Mission Manager、Goal Evaluator、Mission Repository | 空 / 重複Condition、不正期間、非正値Limitの拒否 |
| Approval Execution Predicate | Approval後にPolicyDecisionを書き換えるか、Humanへ何を提示したかが曖昧だった | DecisionをImmutableにし、ApprovalRequestとApprovalRecordの両方をBindingしたExecutable Predicateを定義 | Policy判断、提示内容、Operator判断を独立監査しReplayを防ぐため | Policy Engine、Approval Service、Executor、Audit | Approvalなし拒否、Decision不変、Request / Record Digest不一致拒否 |
| ExecutionAdapter Protocol | C2 Contractだけが詳細でMCP / Localとの共通境界が文章規則だった | Capability、Submit、Status、Raw Result、Cancel、Reconcileの共通Protocolを定義 | Executor CoreをProvider非依存に保つため | Executor、C2 / MCP / Local Adapter | Adapter交換時Executor Core不変、共通Contract Test |
| DB Schema整合 | Proposal、Plan、Result、Goal、Capability、Ingestionの保存要件にTable / Repositoryが不足 | 必須Table、Repository、Snapshot本体保持、通常DBへのRaw禁止を追加 | Audit時にAvailabilityとAuthorization判断を再構築するため | 全Repository、SQLite Migration、Audit | 必須Repository存在、Digest生成元Snapshot復元Test |
| Graph State / Mission State Mapping | GraphとMissionの状態集合・更新主体が対応付いていなかった | 完全なMapping TableとMission Manager経由のOCC更新を定義しMissionにFAILEDを追加 | Graph復元や内部障害時の状態矛盾を防ぐため | LangGraph、Mission Manager、Mission State Repository | 全Mapping、直接更新拒否、FAILED遷移 |
| Authorization Digest | 単一DigestがProposal Hashと解決済みAuthorizationを混在させた | `proposal_digest`と`authorization_digest`を分離しApproval / Executorを後者へBinding | LLM提案とPolicyが許可した実行意図を区別するため | Plan Repository、Policy Engine、Approval、Executor、Audit | Digest役割分離、Canonicalization安定性、Intent変更時失効 |
| Target Extractor Registry | 任意文字列のExtractor解決がScope Enforcement Code差替えを許し得た | 型付きIDとTrusted Target Extractor Registryを導入しDynamic Import等を禁止 | Authorization KernelのCode Injectionと未承認拡張を防ぐため | Tool Registry、Policy Engine、Release / Extension管理 | 未登録ID Fail Closed、任意Module / Expression / lambda拒否 |
| MCP Python SDK Task Extension対応 | Server申告だけではPython RuntimeがTasksを実装できる保証がなかった | Native、検証済みCustom、Disabledの実装Modeと積集合Capability Checkを定義 | 要件上のCapabilityと実装実態を一致させるため | MCP Adapter、Capability Snapshot、Execution State Manager | SDK非対応時`task_extension=false`、Task API呼出拒否 |
| MCP Protocol Discovery / Revision Pinning | 完全Pinと初回Capability Discoveryの接続順が曖昧だった | Discovery / Initialize、完全一致確認、Discover Result保存、以後のPin手順を固定 | 暗黙Fallback / UpgradeとServer取り違えを防ぐため | MCP Adapter、MCP Discover Repository、Configuration | Revision不一致Fail Closed、旧版Fallback / 未知版Upgrade拒否 |
| Pydantic AI Output Retry Mapping | Output Retry、HTTP Retry、LangGraph Retryが同じRetry設定として実装され得た | `max_validation_retries`をOutput Validation専用BudgetへMappingしMetricも分離 | Validation修復がTransport再送やGraph再実行を誘発しないため | Pydantic AI Client、LangGraph Retry Policy、HTTP Client、Observability | 3種類のRetry Budget / Policy独立Test |
| Pydantic Strict Boundary | Pydantic既定動作では未知Field破棄や型Coercionを見逃し得た | StrictBoundaryModelとNested Boundaryの`extra="forbid" / strict=True`を必須化 | LLMや外部入力によるAdapter、Risk、ID等の注入を検知して拒否するため | Planner、Analyzer、Mission、Policy、Approval、Adapter、Ingestion | 未知Field拒否、Adapter / System ID注入拒否、Coercion拒否 |
| Raw Result Streaming | `collect_result()`がRaw Result全体をMemoryへ返しQuarantine要件と不整合だった | RawResultSink、Chunk暗号化、Metadata-only Receipt / AdapterRawResultへ変更 | 大容量・Secret含有Outputと取得途中Crashに耐えるため | ExecutionAdapter、Executor、Quarantine、Secure Ingestion | 大容量Streaming、途中Crash Resume、全量Memory非保持 |
| Pre-dispatch BLOCKED | Authorization後・Provider送信前の拒否状態がResultと混在していた | `AUTHORIZED -> BLOCKED`とVersion付きReason Codeを追加しExecutionResult非生成を固定 | Provider未送信をProvider失敗やOUTCOME_UNKNOWNと区別するため | Executor、Execution State Repository、Audit | Sandbox / Epoch / TTL不一致時BLOCKED、Provider未呼出し |
| Persistent Node Retry Safety | Grant / Snapshot等のDB Commit後例外で重複Recordを作り得た | Calculate / Persist分離とDeterministic ID、Unique Constraint、Idempotent Upsertを必須化 | Graph Retryによる永続状態重複とAudit曖昧化を防ぐため | LangGraph、Grant / Snapshot / Mission / Execution Repository | Commit後Retryの重複防止、異Payload Conflict拒否 |
| Authorization Epoch | Mission Revision不変のPAUSE / Resumeで古い一時認可を再利用できた | Mission Stateへ単調増加`authorization_epoch`を追加しGrant / Snapshot / Decision / ApprovalRequest / ApprovalRecordへBinding | Lifecycle停止境界で短寿命Authorizationを一括失効するため | Mission Manager、Context Authorization、Resolver、Policy、Approval、Executor | PAUSE / Resume後の旧認可Replay拒否、Epoch不一致BLOCKED |
| Authorization TTL | Grant、Snapshot、Decision、ApprovalがMission期限を越え得た | 全Authorization TTLをMission Validity内、ApprovalをRequest / Decision TTL内へ制限 | 期限切れMissionやPolicyでのDispatchを防ぐため | Mission Manager、各Authorization Repository、Executor | TTL Invariant、期限切れMission Dispatch拒否 |
| Context Selector | Grant対象選定のため本文を事前読取する循環が残っていた | Index Metadataだけを読む決定論的SelectorをAuthorization前へ追加 | 未許可Knowledge / Artifact本文やSecretへのGrant前アクセスを防ぐため | Context Index、Selector、Policy、Context Builder | 本文 / Secret読取拒否、未許可Resource混入拒否 |
| MCP Transport Identity | MCP Logical Metadataだけでは同一接続先を暗号学的に確認できなかった | Logical IdentityとTLS / SPKI / mTLS / Executable Hash等のTransport Identityを分離 | Serverなりすまし、Binary差替え、接続先取り違えを防ぐため | MCP Adapter、Discover / Identity Repository、Policy | Logical一致・Transport不一致拒否、stdio Hash変更拒否 |
| Remote MCP Trust Policy | ローカルSandboxではRemote Server内のEgressやProcessを強制できなかった | local_process / managed_remote / untrusted_remote分類とRequired Enforcement Capabilityを導入 | 実行場所に応じたDefense-in-DepthとDefault Denyを実現するため | MCP Config / Adapter、Resolver、Policy、Executor | untrusted High Risk拒否、managed Capability不足拒否 |
| Deep Immutable Model | `frozen=True`でもNested List / Dictは変更可能だった | tuple、frozenset、Canonical Immutable Objectと使用直前Digest再検証を採用 | 保存後・承認後のNested Content改変を検知するため | Snapshot、Grant、Decision、Approval、Executor、Context Builder | Collection改変時Digest拒否、Canonical安定性 |
| ApprovalRequest | ApprovalRecordだけではHumanへ提示したTarget、引数、Riskを再現できなかった | Human提示用ApprovalRequestとOperator判断用ApprovalRecordを分離し相互Digest Binding | Approval UX、判断内容、実行Intentを独立監査するため | Approval Service / Repository、Policy、Executor、Audit | 表示Digest不一致拒否、Request / Record期限とBinding検証 |
| Audit Chain Sequence | Hash ChainのScopeと並列Event順序が未定義だった | Mission単位Chain、単調Sequence、`UNIQUE(mission_id, sequence_number)`、Transaction採番を定義 | 並列Writeでも一意な順序と検証可能なChainを確立するため | Audit Logger / Repository、Finalizer | Sequence重複拒否、Mission別独立検証、改ざん検出 |
| Tool Availability Responsibility | Planner前には具体TargetがなくResolverがScope ALLOWを決められなかった | ResolverをMission Scope Compatibility、Policy Engineを具体Target最終認可へ固定 | 候補提示とAction Authorizationの責務混同を防ぐため | Resolver、Target Extractor / Normalizer、Policy Engine | Resolver具体Target非判定、Policyのみ最終Scope判定 |
| Local LLM Profile | OpenAI互換API、Template、Tokenizer、Structured Output差異が未固定だった | chat_completions固定のLocalLLMProfileとCapability Result / Mission Revision Bindingを追加 | 実行中のWire / Model差替えによるValidation挙動変化を防ぐため | Pydantic AI Client、vLLM、Mission、Profile Repository | Profile途中変更拒否、Capability Digest一致、Retry独立 |
| Encryption Key Management | Secret、Quarantine、ArtifactのKey用途・Rotation・Loss対応が未定義だった | Domain別Key Provider、Key Metadata、Rotation / Revocation / Recovery規則を追加 | Key共用による侵害波及と平文Fallbackを防ぐため | Secret Store、Quarantine、Artifact Store、Key Provider | 同一Key ID共用拒否、Key unavailable Fail Closed、Rotation復号 |
| Durable Execution Authority | `AUTHORIZED`がPre-dispatch前のSecret解決やCaller再構築Sinkの権限として広すぎた | Pre-dispatch成功時の`DISPATCH_CLAIMED`、単回Dispatch Claim、Trusted Adapter ChannelへのJIT Secret Injection、Result Collection Authorityを追加 | Policy認可と今この瞬間のSecret / Side-effect / Collection権限を分離するため | Executor、Secret Store、Adapter、Execution / Tool Repository、RawResultSink | AUTHORIZED / BLOCKEDからのSecret拒否、Claim消費、Cross-tool上限、Collection開始Retention |
| Durable Secure Ingestion | Full-object PublicationとMemory上のResultがQuarantine消去を先行できた | Repository-bound ingestion ID、Durable Manifest、Deletion Intent、`INGESTED_DURABLE -> DELETE_PENDING -> QUARANTINE_ERASED`を追加 | Caller権限mintingと消去後Result喪失を同じState Machineで防ぐため | Secure Ingestion、Quarantine、Artifact / Secret Store、Result Repository | Direct factory拒否、各Crash境界Resume、消去後Manifest復元 |
| Authenticated Generation Commit | 外部AnchorがGeneration整数だけで、Directory置換後にCommitted Stateへ到達不能になり得た | Generation、State Digest、Immutable Blob ID、Previous Anchor DigestをCAS Bindingする共通Coordinatorを追加 | Audit HeadとWrapped Key Stateを手動Path修復なしに回復するため | Audit Head Store、Key Provider、Trusted Blob / Anchor Store | CAS前後Crash、Directory置換Restart、Blob欠落 / 改ざんFail Closed |
