# Phase Acceptance Criteria

## Common Gate

全Phaseで次を満たすこと。

- Unit、Integration、Security TestがすべてPASS
- `ruff`、`mypy`、`compileall`がPASS
- Branch Coverageを取得できる
- 既存Testを削除、skip、xfail化していない
- Protected Filesを変更していない
- 新規Security FindingにRegression Testがある
- BLOCKER/HIGHが0件
- 最新PR head SHAをCodex CloudまたはChatGPTが独立Review済み
- 実C2/MCP/外部TargetへのSide EffectがCIで0件
- Secret Leakageが0件
- 未解決の仕様矛盾、仮実装、Security-critical TODOがない

## AI Loop Control Acceptance

- Local OrchestratorはCurrent default-branch SHAのClean Checkoutでだけ起動する
- `gh`のCurrent Loginが`AI_GATE_APPROVER_LOGIN`と完全一致しなければ停止する
- `github-actions[bot]`以外のImplementation/Ready/Phase Gate Markerを無視する
- Implementation Request、ready/trigger marker、Trusted Phase Gate recordのUnknown Field、Duplicate JSON Keyを拒否する
- Implementation RequestをCurrent Phase、Current HEAD SHA、Trusted Phase Promptへ固定する
- Native Reviewを`AI_REVIEWER_LOGIN`、Current Phase、Current HEAD SHA、Expected Base SHA、ready/trigger permalink、Review中のhead不変性へ固定する
- PASSはCodex標準no-major-issues comment、10文字以上のmatching commit prefix、botの👍、Current HEADのP0/P1/formal finding review不在をすべて要求する
- Native Review判定はtrusted current-HEAD triggerより後のCodex出力だけを候補とし、trigger前の
  stale/malformedな履歴は権限として使わず、trigger後のstale evidenceはFail Closedにする
- CHANGES_REQUESTEDはCurrent HEADへ完全BindingされたCodex formal reviewとP0/P1 inline findingを要求し、root-cause keyを決定論的に導出する
- Required Check成功前にReview Gateを記録しない
- 自動Phase遷移はfreshなPR HEAD/Phase/全Label snapshotから最終Label集合を計算して単一API呼出しで
  完全置換し、置換前後のlabel event差分がGate自身の期待したevent集合・actorと完全一致すること、
  および直後の再取得でHEAD、次Phase、全Label集合が一致することを確認する。並行writeはFail Closedにする
- 同じRequest/Reviewを再処理せず、停止後にGitHub Evidenceから再開できる
- Phase 4/5は`ai-human-gate`中に停止し、承認済みProvider Gate遷移後だけ再開する
- OpenAI API Keyを要求せず、GitHub CredentialをCodex Promptまたは実行環境へ渡さない
- Active PRのCurrent Phaseは、exact phase label、`github-actions[bot]`のCurrent-HEAD
  Implementation Request、隣接するPrior-Phase PASSの完全一致でのみ解決する
- Default BranchをPRへ取り込む前にCurrent Phaseを1つ戻し、旧HEADのPASSを再利用せず、
  取込み後HEADで同Phase Gateを再実行する
- Base-refresh Workflowは旧HEAD、Current default-branch SHA、隣接Prior PASSを固定したStatusのみ
  書込み、PR labelの完全置換はLocal Orchestratorが変更前後の全PR状態を再取得して実行する
- 同じHEAD/Current Phaseにsource側とrollback済み側の複数Base-refresh遷移Identityが成立する
  場合は、label置換とbranch updateのどちらも行わずFail Closedにする
- Local Orchestratorはlabel置換とbranch updateの直前・直後にCurrent PR、Default Branch、
  trusted PASS/Status遷移Snapshotを再取得し、Driftまたは競合をFail Closedにする
- label置換後のSnapshotはrollback後Phaseの視点で旧認可Identityを再確認し、さらに下位Phaseへ
  戻す新しいsource Identityとの競合を拒否する
- Refresh後Phase 0AのReview BaseはReviewed HEADに実際に包含されたtrusted target SHAへ固定し、
  Review中にDefault Branchが進んでもそのGateを記録した後、次Phase実装前に再度rollbackする
- 複数の履歴Base-refreshがReviewed HEADに包含される場合、旧HEADとtarget baseの両方が後続候補へ
  祖先となるPartial Orderで唯一の最大候補だけをReview Baseにし、最大候補が複数ならFail Closedにする
- Base refreshは`expected_head_sha`とCurrent default-branch SHAへ固定し、Final merge APIを
  呼ばない
- Final mergeはLocal Orchestratorだけが実行し、`phase-5`、`ai-project-complete`、
  `ai-review-passed`、全Phase PASS Chain、Current-HEAD Check、Trusted Phase Status、
  Current default-branch ancestryを再検証する
- Final merge APIへCurrent 40桁HEAD SHAを渡し、不一致、競合、不確実なResponseをFail
  Closedにして自動Retryしない
- Final merge dispatch前に同じPR/HEADの既存Attempt Recordがないことを再確認し、Repository
  Git ref claimを原子的に作成して1プロセスだけが所有する
- Claim取得後、PR、HEAD、Default Branch、Phase 5 Gate、Policy Digest、Actor、Claim Ref固定の
  Attempt Recordを永続化してからmerge APIを呼ぶ
- Attempt Record確認後に全Phase PASS Chain、PR全状態、Default Branch SHA/ancestry、
  Current-HEAD Checks、Trusted Phase Statusを再取得し、すべて不変かつPASSの場合だけdispatchする
- Claim/Attempt Recordが存在する、またはClaim作成結果が不明なPR/HEADは、Live GitHub Outcomeを
  明示的にReconcileするまで再送せず、Claim取得後のGate Drift/Unknownも同様に停止し、通常実行で
  Claimを削除しない
- Governance PR、Fork PR、停止Label付きPR、`ai-loop`以外を自動mergeしない

## Phase 0A: Core Models / Authorization Kernel

Phase 0A Gateのbootstrap既定値はNO-GO。Active PRでは、次をすべて満たしたCurrent-HEADの
trusted PASSが存在する場合に限りPhase 0Bへ進める。

### Blockers

- B-01: Port/ProtocolとExecution Sessionを含むConcrete Scope False-Allowが0件
- B-02: Caller生成・改変PolicyDecision、Target omission、Approval bypassを拒否
- B-03: MissionManager以外から不正にVALIDATED/RUNNINGへ遷移できない
- B-04: Stale Policy/Mission State/Authorization Epoch/Session Context Grantを拒否
- B-05: Approval PresentationとExecutable Intentが完全一致
- B-06: Security ArtifactのDigest/ID/Bindingを保存時・読出時に検証

### High-priority hardening

- H-01: Trusted RepositoryからCurrent Authorization Runtime Contextを解決
- H-02: Top-level/Nested duplicate JSON keyを実Trust Boundaryで拒否
- H-03: 全Security Artifact RepositoryでIntegrity検証
- H-04: Sandboxを実Runtime/Adapter/Execution LocationへBinding
- H-05: Mission Revision lookupを`mission_id + mission_revision`へ固定
- H-06: Review Negative Probeを正式Regression Testへ追加
- H-07: Git commit/branch/statusを取得可能にする

### Required zero metrics

```text
Scope False-Allow = 0
Approval Bypass = 0
Policy Engine Bypass = 0
Unknown Field Acceptance = 0
Unauthorized Tool Acceptance = 0
Stale Grant/Snapshot Acceptance = 0
Old Authorization Epoch Acceptance = 0
Digest Mismatch Acceptance = 0
Misleading Approval Presentation Acceptance = 0
Mission Validation Bypass = 0
External Tool Dispatch = 0
```

## Phase 0B: Execution Safety

- Execution StateとResult Ingestion Stateを分離して永続化
- 1 PolicyDecisionから2件目のExecutionを作成不可
- Non-idempotent actionの不確実な結果を自動再送しない
- `reconcile()`の不確実結果を`OUTCOME_UNKNOWN`へ遷移
- Pre-dispatch不一致は`AUTHORIZED -> BLOCKED`、Provider Callなし、ExecutionResultなし
- External Side Effect NodeにLangGraph Automatic Retryなし
- Raw ResultをChunk Streamingし、全量Memory保持なし
- Crash後はResult ingestionだけを再開し、External Actionを再実行しない
- REQUIRE_APPROVALは一致するApprovalRequest/Recordがなければdispatch不可
- Mission Revision変更時にrun_id/thread_idが変化
- Goal達成時の直接COMPLETED遷移を拒否

## Phase 0C: Data Security / Audit

- Secret ValueがPrompt、通常DB/Log、Exception、Traceback、Knowledge Baseへ入らない
- Raw OutputはQuarantine -> Classification -> Secret Detection -> Redactionを通る
- Context BuilderがEncrypted Raw Artifact/Secret Resolveへアクセス不可
- Artifact Path Traversal/Symlink Escapeを拒否
- Artifact size/quota/integrity/classification/retention/auditを強制
- Secret/Quarantine/ArtifactでKey Domain、Key ID、Separation Tagを分離
- Authenticated EncryptionのAADへDomain/Mission/Execution/Artifact Bindingを含める
- Nonce再利用、plaintext export、cross-domain fallbackを禁止
- Key unavailable/revoked/mismatch時は`EncryptionKeyUnavailableError`
- Mission単位Audit SequenceとHash Chainの改ざん検出がPASS

## Phase 1: Agent Loop

- MockだけでMission -> Planner -> Policy -> Executor -> Analyzer -> Goal Evaluationが完走
- Planner前にContext AuthorizationとAvailableToolSnapshotを確定
- Planner後にSnapshotを再検証
- Scope外/Unavailable ActionがMock Adapterへ到達しない
- Context Grantなしで本文を読めない
- CandidateSessionObservationだけでRuntime Stateを変更しない
- Session/Finding/Execution/Goal StatusをSQLiteへ永続化
- Goalを`achieved/not_achieved/indeterminate`で判定
- 同一Indeterminate原因のRetry上限を強制
- FINALIZINGでReconciliationとAudit Verificationを実施
- 最大Iterationで必ず停止

## Phase 2: Local LLM

- `chat_completions`固定LocalLLMProfileをMission RevisionへBinding
- Planner/Analyzer相当Canary SchemaでCapability CheckがPASS
- Nested/Enum/Optional/List/Discriminated UnionをStrict Validation
- Pydantic Output Retryは3回以内で停止し、HTTP/LangGraph Retryと分離
- Timeout/Cancellationが動作
- Redacted ArtifactだけがLLM Contextへ入る
- Profile/Wire API/Model/Template/Tokenizer変更をFail Closed
- 実LLM MissionがMock ProfileでCapability Checkを迂回できない
- Prompt Injection testがPASS

## Phase 3: Human Approval / Durable Resume

- Approval後のPlan/Intent変更でApprovalが無効
- 未承認ActionはAdapterへ到達しない
- PAUSED/Resumeでauthorization_epochが増加
- PAUSED前のGrant/Snapshot/Decision/Approvalを再利用しない
- Resume時にCheckpoint -> Application DB -> Adapterの順に照合
- 不明な非冪等Actionを自動再実行しない
- Approval expiry/replay/wrong bindingを拒否

## Phase 4: Approved C2 Adapter

Human GateでC2製品、Version、隔離環境、認証方式、Egressを確定後に開始する。

- 1種類の承認済みC2 Adapterを`ExecutionAdapter`として実装
- Core/Planner/Analyzerを特定C2へ依存させない
- Session/Capability/Submit/Task status/Result/Cancel/Reconciliationを実装
- Payload/Implant生成・配布機能を実装しない
- 資格情報はSecret Referenceだけで扱う
- Test Doubleまたは隔離LabでContract/Integration TestをPASS
- Timeout/Crash/Unknown outcome/Cancel/Result resumeを検証
- CIから実C2や実Targetへ接続しない

## Phase 5: Approved MCP Adapter

Human GateでMCP Server、Protocol Revision、Transport Identity、Trust Policyを確定後に開始する。

- Protocol Revisionを完全一致でPin
- Unknown upgrade/legacy fallbackを禁止
- Logical IdentityとTransport Identityを分離して検証
- Tool変更通知はCandidateだけを作り、自動Registry更新しない
- Tool/Server/Adapter routingを一意化
- CapabilityがないTask/Cancel/Reconcile APIを呼ばない
- 不確実なtimeoutを`OUTCOME_UNKNOWN`へ遷移
- untrusted remote high-risk toolをDefault Deny
- managed remoteの必須Enforcement不足をUnavailable扱い
- 承認済みTest ServerでContract/Integration/Security TestをPASS
- CIから未承認MCP/外部Targetへ接続しない

## Project Complete

Phase 5 PASS後、次を満たした場合に`ai-project-complete`とし、Local Orchestratorの最終
merge gateへ進む。

- Phase 0A～5の全Gate ResultがGitHub履歴に存在
- 最新HEADで全Common GateがPASS
- 全PhaseのBLOCKER/HIGHが0
- Phase 4/5のHuman Gate Evidenceが存在
- README/SystemDesign/Config/Runbookが実装と一致
- Fresh environment setupとMock end-to-endが再現可能
- Known limitationsと残存MEDIUM/LOWを明文化
- Local Orchestratorが上記AI Loop Control Acceptanceを再検証し、完全HEAD SHA固定の
  GitHub PR mergeを1回だけ実行
- Merge未確認、Default Branch drift、競合または不明な結果は自動再試行せず停止
