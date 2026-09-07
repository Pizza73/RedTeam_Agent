# Phase Acceptance Criteria

## Specification revision and traceability

`system-design-v1-r3`と規範別冊`ai-control-v1-r3`を受入対象とする。以下の正本の詳細条件も必須であり、
この一覧は製品の安全試験・品質条件を削減しない。開発Gateは正本§40の新体制へ置き換える。Phase順序は維持し、後続Production機構は前Phaseの安全な型 / Test Double境界と分離する。
過去のPASSを新仕様の成立証拠へ読み替えず、Current PhaseはPhaseごとの開発記録と実コード・試験・独立レビューから確認する。

| 要件群 | 必須の詳細条件と検証段階 |
| --- | --- |
| R1〜R13 | SystemDesign.md §10 / §13 / §21 / §23 / §27 / §33〜34 / §38の用途別消去、Critical Witness、原子的公開、Task / Cancel、完全表示Approval、Recovery期限、Unresolved Item、予約、Secret確認、Copy消去、Redirect禁止、Archive移行。§36と下記の既存Phase配分で正・負・障害経路を検証する |
| D1〜D11 | SystemDesign.md §37.1の全行。各行の対象Phaseを維持し、Stateful FamilyはProperty-based / State-machine Evidenceを伴う |
| F1〜F7 | SystemDesign.md §37.2の全行。Foundation / Witnessは0C、Goal / Context / Action前提の統合は1、実LLMは2で検証する |
| AI-01〜12 / AC-01〜20 | SystemDesign_AI_Control.md §10〜12。Phase 1でMock Integration、Phase 2でD11 Corpusを評価し、設計参照モデルだけで合格しない |
| D4実機消去 | §34.1.1 / §37.1。現状NOT_EVALUATED。独立Qualification PASS前のProduction有効化を拒否し、文書採用やswtpmで代替しない |
| 移行 / 互換性 | SystemDesign.md §38と別冊§12。Schema / Catalog / Witness Policyの一体移行、旧権限の非昇格、消費履歴保持、既存Execution回収、停止中Activationを検証する |

## Common Gate

全Phaseで次を満たすこと。

- Unit、Integration、Security TestがすべてPASS
- `ruff`、`mypy`、`compileall`がPASS
- Branch Coverageを取得できる
- 既存Testを削除、skip、xfail化していない
- 未承認の設計・安全条件・受入条件の変更がない。ユーザー承認済み改訂は関連文書と同じRevisionへ整合する
- 新規Security FindingにRegression Testがある
- BLOCKER/HIGHが0件
- 対象実装の完全なコミットIDを固定し、実装セッションと分離したCodexがRead-only Snapshot・実コード・試験Evidenceを独立レビュー済み。後続変更は差分・影響に応じて再検証する
- 実C2/MCP/外部TargetへのSide EffectがCIで0件
- Secret Leakageが0件
- 未解決の仕様矛盾、仮実装、Security-critical TODOがない

## Development Process Acceptance

- 実装はClaude Code、設計整合と独立レビューはCodexとし、実装会話を独立レビューのContextへ引き継がない。
- 正本§40のPhaseごとの一つの開発記録に、設計Revision・対象Phase・入力 / 実装対象コミット、対応要件、試験Commandと結果、レビュー参照・全指摘・対応、受入根拠・残課題がある。
- 各要件のpublic entry point、caller、recovery / compatibility / sibling経路を照合し、Positive / Negative / Failure-path、状態を扱う変更のProperty-based / State-machine Evidenceを確認する。
- 実装者の要約、モデルのPASS文字列、終了コード0、過去のPhase PASSだけで受入を完了しない。試験未実行、失敗、未解決指摘を記録から除外しない。
- 実装・試験・依存・設計の後続変更では対象コミット、差分と影響範囲を確認し、必要な試験・独立レビューを更新する。記録のみの追記によるコミット自己参照や無変更コードの再レビューを要求しない。
- BLOCKER / HIGHと未解決仕様矛盾がなく、Common Gateと対象Phaseの製品条件が成立してから次Phaseへ進む。通常の実装・修正・レビューごとの追加Human Gateは要求しない。
- Phase 4 / 5の既存Provider Human Gate、D4実機Qualification、Scope / Secret / Audit / 単回Dispatch等の製品条件を維持する。
- 旧Launcher、GitHub Marker、Workflow、自動Merge、開発Loop用Claim / Journalを要求しない。新しい開発状態機械・認可Recordを追加しない。
- CI / GitHubの利用は任意の試験・証跡保存手段とし、未確認の外部設定を成立済みとみなさない。公開・Mergeは当該作業のユーザー指示に従う。

## Phase 0A: Core Models / Authorization Kernel

初回実装はユーザーの実装依頼と正本§40の対象・範囲・受入条件を記した開発記録から開始する。
Phase 0Bへ進む前に、新実装の対象コミットでCommon Gateと下記の全条件を満たし、独立レビュー結果を記録する。

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
- `AUTHORIZED`はSecret解決権限ではなく、Pre-dispatch成功と同一Transactionで作成した未消費の
  Dispatch Claimを平文解放前にDurable消費したExecutor-owned Transactionだけが、Composition Root
  固定Adapter Dispatch PortへのJIT Secret Injectionを許可する
- CallerがSecret Broker、Channel Registry、Callbackを構築できず、Claim消費後のCrashまたは
  Submit結果不明ではSecret InjectionもProvider Submitも自動再送せずReconciliationへ進む
- Result Collection開始時にExecutor所有のTrusted Clock、exact Tool Registry / Tool Definition、
  `ResultTaskBinding`（`provider_task | local_result`）、SinkへBindingしたAuthorityを永続化し、Caller Timestampを受け取らず、Tool固有
  Output上限をCaller / Global設定で拡大しない
- Model / Adapter / Repositoryが同じ`provider_task | local_result`型定義を参照し、有効な両分岐を受理する。
  `local_capture`、未知の判別値、分岐に必要なField欠落、登録Modeとの不一致を拒否し、Alias変換や架空Provider Task補完を行わない
- Quarantine RetentionはCollection開始時刻からMission Deadline内で一度だけ確定し、Restart時に再計算しない
- External Side Effect NodeにLangGraph Automatic Retryなし
- Raw ResultをChunk Streamingし、全量Memory保持なし
- Crash後はResult ingestionだけを再開し、External Actionを再実行しない
- REQUIRE_APPROVALは一致するApprovalRequest/Recordがなければdispatch不可
- Mission Revision変更時にrun_id/thread_idが変化
- Goal達成時の直接COMPLETED遷移を拒否

## Phase 0C: Data Security / Audit

- 新しい状態・Record種別・独立Serviceなしで既存Retention SchedulerからExpiryを確定できる。期限直前 / 一致 / 直後、期限切れまたは未作成Lease、Worker停止、旧Deployment、Publicationとの競合、Commit前後Crashを検証する。
- Retention ExpiryはCurrent Root / Clock / Anchor、Origin / Resource / Retention、Expected State、現Lease Snapshotまたは不存在をOCC照合し、既存Expiry State / 型別Intent / Lease失効 / Audit / Critical Intentを同時確定する。期限後の通常Worker Write / Publish / Abort / Releaseは拒否し、Expiry経路から本文Read / Publish / Submit / Secret Resolveを許可しない。
- Collection期限到達時は既存ABANDONED / Unresolved Item / Collection Lease失効 / Audit / Critical Intentを確定し、固有Retention到達まで消去Intentを作らない。COMPLETEの巻戻しやLocal Ingestion Windowの短縮を拒否する。
- 認可済みExecutionに付随する新規Artifact / Secretの内部保存は既存Ingestion契約だけで成立し、事前の未生成Resource Grant・PolicyDecision変更・追加Publication認可Recordを必要としない。
- 内部保存はRepository-bound入力、固定Rule、Current MissionのLocal処理可否、Lease / Fence、Retention、Classification / 件数 / 容量上限、Store固定保存先を検証する。任意Callerの新規作成、別Mission / 任意Path、既存Resource上書き、Secretの暗黙確認・置換を拒否する。
- 新規成果物と同一入力Retryを既存Metadata / Manifestで検証し、閲覧Grantなしの成果物を開示しない。valid_until / recovery_until後でも許可されたLocal Window内の処理だけ継続し、保存から外部操作・LLM・Secret利用の権限を派生させない。
- Secret Continuation / Lifecycle、typed Lease / Fencing、専用Erasure、TPM WitnessのProduction HardeningはPhase 0Cで評価する。
  前Phaseの要件に必要な型・安全なTest Double境界は各Phaseで実装・検証し、未実装の後続機構をPASS扱いしない
- Secret ValueがPrompt、通常DB/Log、Exception、Traceback、Knowledge Baseへ入らない
- Claim消費の勝者だけが同一Executor呼出し中の非直列化・単回Dispatch Continuationを取得し、
  Module-level Token、Standalone Resolver、消費済みClaimの再利用で平文を取得できない
- Secretの単回性はDispatch Claim / Dispatch Attempt単位であり、同じ`CONFIRMED`かつ未失効の
  Secret Versionを別の認可済みExecutionが新しいClaimで利用できる
- Secret更新はStableな論理`secret_id`の下へImmutable `secret_version_id`を追加し、
  `DETECTED -> CONFIRMED -> REVOKED / SUPERSEDED`のAppend-only Lifecycle Eventだけで状態を遷移する
- PolicyDecision / DataAccessGrant / Dispatch Claimはexact Secret Version / Lifecycle HeadへBindingし、
  Claim ConsumptionとCurrent `CONFIRMED`検証を同じOCC Transactionで行う
- 失効が先にCommitしたVersionはDispatchを拒否し、その未消費Claimを`invalidated`、
  既知未送信Executionを`BLOCKED / SECRET_VERSION_STALE`へ同じTransactionで遷移する。
  Claim Consumptionが先にCommitした場合は、その単一Attemptだけが固定Versionで継続する
- Pre-dispatch `BLOCKED`は`dispatch_attempts=0`かつClaimなし、Secret失効による
  `DISPATCH_CLAIMED -> BLOCKED`は`dispatch_attempts=1`かつ同一Executionの`invalidated` Claimを必須とし、
  Provider Task、未消費 / 消費済みClaimまたは他Reasonとの組合せを拒否する
- DataAccessGrantは既存のnested `ResourceBinding(resource_id, resource_version: str, resource_digest)`を
  維持して`authorization_state_digest`を追加し、Secretではexact `secret_version_id`、Canonicalな
  10進Version文字列、Immutable Secret Version Metadata Record Digest、Lifecycle Head DigestへBindingする
- Legacy `secret_reference_id`は暗黙に集約せず決定的な1対1 Version Migrationを行い、旧MissionをRead-only Archiveとして扱う。
  移行RecordやTerminal Stateを新規DispatchでActiveとして再利用せず、新Missionではexact Versionを明示確認する。
  曖昧・欠落・Digest不一致では`SecretMigrationRequiredError`で停止する
- 通常Collection / Ingestion Workerは用途別typed Leaseを使用し、`lease_id`、Owner、
  `deployment_epoch + fencing_token`、未Release、Trusted Clock上の未失効、Authority / Resource Digest、
  Expected State Versionの完全Predicateを全Durable Mutationで同じTransactionにより検証する
- Lease期限は同一Host Boot内でProcess間共有可能な単調Clockで判定し、UTC巻戻り / 不連続では
  `ClockIntegrityError`として新規Authorization、Claim、Lease、Renewalを停止する
- Productionは単一Host / TPM / Application DB / Composition Rootへ限定し、そのRoot配下のWorkerだけが
  同じDeployment Epochを共有する。Multi-host Worker構成は起動時に拒否する
- Default Lease 60秒 / Heartbeat 20秒以下で`lease_duration >= 3 * heartbeat_interval`を満たし、
  Renewal失敗時のCancellation後も非協調AdapterのStale WriteをSinkが拒否する
- Storage書込はFence固有StagingとStorage-side Conditional Publicationを使い、旧WorkerのBytesを
  Current Metadataから到達不能にする
- Ingestionは`DELETE_PENDING`でLeaseをReleaseして消去Capabilityを持たず、専用Eraserだけが
  消去理由別Intent / 必須Evidence / Resource DigestへBindingされた単回Erasure Claimを消費して
  `DELETE_PENDING -> ERASURE_CLAIMED`へ遷移する
- Erasureの不明結果は別の破壊操作を作らず同じ`erasure_id`でReconcileし、Key破棄確認後だけ
  CiphertextをUnlinkする
- Erasure Claimは状態遷移と同じTransactionで作成・消費し、Repositoryには`claim_state=consumed`と
  非NullのConsumption Identity / Timeだけを保存する。Key Providerは同じ
  `erasure_id + key_metadata_digest`による型付きDestroy / Reconcile結果を返す。Eraserは最初にReconcileし、
  `NOT_STARTED`だけがDestroy開始を許可し、`UNKNOWN`後はReconcileだけを行い、read-back検証済み
  `CONFIRMED`より前にCiphertextをUnlinkしない
- Raw OutputはQuarantine -> Classification -> Secret Detection -> Redactionを通る
- Caller生成Receipt、Quarantine Reference、Publication Object、Full-object compatibility loaderから
  Quarantine平文を取得できず、Repository-bound `ingestion_id`だけがSecure Ingestionを開始できる
- Quarantine Sink / Reader / Factory / Lookupは副作用を持たない。正常公開はArtifact / Secret Reference、
  ExecutionResultProjection、Manifest、Deletion Intent、DELETE_PENDING、Lease Releaseを同じUnit of Workで確定する。
  公開時に全成果物本文 / Digest / Key Bindingと保存Metadataを検証・Witnessする。正常消去前は正本§33.2の
  確定済み公開証跡と対象QuarantineのBinding / Key / Copy Inventoryをread-back検証する。Retention / Incomplete Collection Expiryは
  別型の必須Evidenceで検証し、Manifestや成功Resultを捏造しない。Expiryと公開のOCC競合で期限後Publishを拒否する
- Manifest Commit、Deletion Intent、Erasure Claim消費、Key破棄、Ciphertext削除、ExecutionResult確定の全Crash境界を
  Provider再実行、Adapter Result再収集、公開後のQuarantine再復号、手動File修復なしに回復する
- 成果物本文 / 鍵が固有Retentionに従って先に消去された後でも、確定済み公開証跡からQuarantine消去とResult復旧が完了する。
  この処理は成果物本文Read / 復号、成果物ごとの消去Claim / Tombstone連鎖走査、Provider再取得を呼ばない。
  復旧後のCurrent Read / Context / Goal / Secret利用で失効成果物を利用可能としない
- 公開証跡の欠落・Digest改ざん・Witness不一致、対象QuarantineのKey / Inventory不一致、既存Integrity Stopを拒否する。
  Witness Pending中の公開利用と関連Cleanupを拒否し、Commit応答不明から既存Intentを照合して二重Publicationを防ぐ。
  消去とResult確定まで最小限の既存検証Metadataを保持し、本文・Secret・鍵のRetention延長や新しいPin / Counterを行わない
- 同じ入力・固定Rule / Parser ID・Code DigestのRetryは既存予算内でcreate-or-verifyとなる。
  変更Rule、同名VersionのCode差替え、利用不能・失効Ruleの代替、入力の別Executionへの付替え、ID変更での予算Resetを拒否する。
  固定Ruleを実行できない場合も元Actionを再送せず、既存失敗 / 隔離と固有Retention到達時の型別消去へ進む
- `INGESTED_DURABLE`以後はManifest / ExecutionResultProjectionだけからExecutionResultを再構築する
- Context BuilderがEncrypted Raw Artifact/Secret Resolveへアクセス不可
- Artifact Path Traversal/Symlink Escapeを拒否
- Artifact size/quota/integrity/classification/retention/auditを強制
- Secret/Quarantine/ArtifactでKey Domain、Key ID、Separation Tagを分離
- Authenticated EncryptionのAADへDomain/Mission/Execution/Artifact Bindingを含める
- Nonce再利用、plaintext export、cross-domain fallbackを禁止
- Key unavailable/revoked/mismatch時は`EncryptionKeyUnavailableError`
- Mission単位Audit SequenceとHash Chainの改ざん検出がPASS
- Audit Head / Wrapped Key StateのProduction ConstructorがAuthenticated SQLite Generation Record Storeと
  Namespace別TPM 2.0 NV Extend Digest Witnessを必須とし、TPM Current Witness Digestとexact認証済みRecord / Blobの
  Pairから正確なCommitted Stateを回復する。Commit Payload / Immutable BlobをExtendへBindingし、同一論理Generationの
  別Prepare、結果不明の二重Extend、第三Digest、Future Witnessの循環Digestを受理しない
- SQLite全体のRollbackでもTPM Witnessは戻らず、Current Record欠落 / 改ざんを検出して旧Local
  AlternateへFallbackしない
- TPM Reset、NV Identity mismatch、未知Witness Digest、Deployment Counter decrease、Unavailable / Ambiguous状態は
  `ANCHOR_RECOVERY_REQUIRED`として全Missionを停止し、Local Stateから自動Re-seedしない
- Fresh Installは空Store、固定Provisioned NV Identity、未WRITTEN属性、未使用Trust Epochを検証し、
  承認済みGenesis PayloadをExtendして論理`generation=0`のPairを明示作成する。動的NV Name / WRITTEN遷移を
  固定Identityと分離し、既存Local StateからGenesisを自動生成しない。Deployment専用Counterは実測値へBindingし、Read失敗を0としない
- Recoveryは全Worker停止と、旧 / 新Trust Epoch / NV Identity、最終検証Record、採用State Digest / Immutable Blob IDへ
  Bindingした単回Human Approval、新しい`trust_epoch`、Audit discontinuity、`deployment_epoch`更新を必須とする
- Productionは`tpm2_nv`以外のPath、Generic Service、Vault代替、Integer-only、Local-slot、
  In-memory Test Doubleおよび同一Restore Domain構成を拒否する
- Integration TestはProduction TPM Witness実装を`swtpm`へ接続し、Restart、SQLite Rollback、TPM Reset、
  NV Identity mismatch、Missing Recordを検証する
- D4のResource REK消去は実機 / Firmware / TSS、Copy Inventory / Backup Restore、Slot Incarnation / 再利用、
  容量を独立Qualificationで検証する。現状NOT_EVALUATEDであり、swtpmや文書検査を実機PASSとせず、PASS前はProduction不可
- Dispatch / Secret Delivery、Ingestion / Erasure / Result Recovery、Collection / Ingestion Lease
  Timing / Fencing、Authenticated GenerationのStateful FamilyにProperty-basedまたはRule-based
  State Machine Evidenceがある
- Transaction AggregateごとのApplicationUnitOfWorkがState、Audit、Outbox / Intentを同じTransactionへ
  Commitし、Child Repositoryの独自Commit、部分Commit、異Payloadの冪等Retryを拒否する
- Security-sensitive DigestはVersioned Digest Catalogへ一意に登録され、Catalog未登録、重複Owner、Field欠落、
  Version / Canonicalization不一致、別Digest実装へのFallbackをFail Closedする
- Production Composition Rootが共有Activation Lock取得後、Config / Digest Catalog / DB Schema読取検査 / TPM / Clock / Key Domain / Store / Unit of Work /
  Repository / Adapter / Service / Graphを順序どおりに構築・Self-checkし、完了前のMission受付、Test Double混入、
  Mission中のTrusted Dependency差替えを拒否し、失敗時は逆順にCleanupする
- 通常起動からDB Migration / Re-seedを行わず、停止中の明示Migration / Restoreだけが同じActivation Lockを使用する。
  旧権限を新しいALLOWへ補完せず、旧MissionのRead-only Archive、既存Executionの用途限定Recovery、新Mission認可を分離する
- 論理Componentから物理ModuleへのMappingを一意に保持し、Context / Approval / Ingestion / Planner Informationの
  Owner重複、禁止方向Import、Owner外のState Transition Command / Digest DefinitionをArchitecture Testで拒否する

## Phase 1: Agent Loop

- MockだけでMission -> Planner -> Policy -> Executor -> Analyzer -> Goal Evaluationが完走
- Planner前にContext AuthorizationとAvailableToolSnapshotを確定
- Planner後にSnapshotを再検証
- Scope外/Unavailable ActionがMock Adapterへ到達しない
- Context Grantなしで本文を読めない
- Planner OutputはAction ProposalまたはBounded Context Requestの型付きUnionであり、Context Requestから
  Execution / PolicyDecision / Approvalを生成しない
- Retrieval HintはPurpose / Fact Type / Canonical Entity Referenceに限定し、任意SQL / Path / 全文Query、
  Scope / Classification / TTL / Tool Availability拡張を拒否する
- Context Rankingは同一Input / Index Revision / Policy Versionから同一結果となり、候補100件、取得20件、
  Type別10件、連続Context Request 2回の既定上限をPlanner / Caller / Tool Outputが拡大できない
- Planner Context EnvelopeをCurrent Mission Revision / Authorization Epoch / Context Grant / Tool Snapshot / TTLへ
  Bindingし、StaleならLLM呼出し前に再構築する。EnvelopeはAuthorization / Approval / Goal Evidenceにならない
- 直近Execution SummaryとPolicy / Failure FeedbackはRedactedなVersion付きReason Codeであり、Raw Error、Secret、
  禁止Target、未公開Tool Identityを含めず、Policyを上書きしない
- Plan Thread / Working HypothesisはApplication-owned OCC Snapshotとして永続化し、Stale Revision / Epoch、
  競合、不正Reference、上限超過を拒否し、Confirmed Fact / Mission Goal / Authorizationへ昇格しない
- Entityの自動統合はSID、Machine SID、Provider Stable ID等のStrong Identifier一致に限定し、Alias-only、
  Fuzzy一致、ConflictをCandidateのまま保持する
- Analyzer CandidateをCondition ID / Evidence Kind / Canonical Entity / Current Record Revisionへ再Bindingし、
  誤Bindingした候補だけではGoalを達成しない
- OperationalPhase、Feedback、Working Hypothesis、Operator Acknowledgement / Outcome ReviewはAuthorization、
  Human Approval、Resumeとして消費されない
- Coarse Agent GraphはContext、Persistent Commit、Dispatch、Collection、Ingestion、ReconciliationのRetry Budgetを
  分離し、CheckpointにはOperation ID / Repository Record IDだけを保持する
- CandidateSessionObservationだけでRuntime Stateを変更しない
- Session/Finding/Execution/Goal StatusをSQLiteへ永続化
- Goalを`achieved/not_achieved/indeterminate`で判定
- Goal unknownを通常Actionの一律禁止にせず、共通Controllerと意味Key別の永続情報取得Budgetで有限に制御する
- [AI制御仕様](../SystemDesign_AI_Control.md)のAI-01〜12とAC-01〜20をMockのIntegration / State-machine Testへ対応付ける。
  三値集約・Controller参照モデルのPASSだけでは受入完了としない
- verified_fact / observation / hypothesisの更新・Grant付きReadを分離し、未確認Observation / LLM Confidenceだけで
  confirmedを変更しない。Analyzer障害でも確定済みFactを撤回せず、同じ外部Actionを再送しない
- 登録済みActionContract、有限な前提探索、実行前提DigestのCurrent再検証を実装する。
  Goal評価参照は監査専用とし、旧mode / GoalRouting Head / Confidence閾値による互換認可を拒否する
- 初回・再開・各Planner前とPre-dispatchのGoal / Current State検証、既達成時のDispatchなし終了、
  unknownからの準備・観測、候補なしの理由付き停止、最後の予約枠の競合、Pause / Resume後の枠非復活を検証する
- Shared LLM Gatewayの全Attempt予約、D9のHypothesis一括OCC、D10の論理Execution順の一度だけの失敗計上をMockで検証する
- FINALIZINGでReconciliationとAudit Verificationを実施
- 最大Iterationで必ず停止

## Phase 2: Local LLM

- `chat_completions`固定LocalLLMProfileをMission RevisionへBinding
- Planner/Analyzer相当Canary SchemaでCapability CheckがPASS
- Missionが実際に使用する全Planner / Analyzer Output Schema DigestについてVersion付きCorpusを実行し、
  Validation Retry内のValid率95%以上、Unsafe Boundary Acceptance 0件、Cancellation Failure 0件を満たす
- Nested/Enum/Optional/List/Discriminated UnionをStrict Validation
- Pydantic Output Retryは3回以内で停止し、HTTP/LangGraph Retryと分離
- Timeout/Cancellationが動作
- Redacted ArtifactだけがLLM Contextへ入る
- Profile/Wire API/Model/Template/Tokenizer変更をFail Closed
- Model / Tokenizer / Template / Structured Output Mode / Schema / Runtime変更でCapability Resultを失効させ、
  Strict Validationを弱めるFallbackを禁止する
- Staged Generationは結合後の最終Outputを同じActual SchemaとAuthorization前Boundaryで再検証し、
  Partial OutputからExecutionを生成しない
- 実LLM MissionがMock ProfileでCapability Checkを迂回できない
- Prompt Injection testがPASS
- Shared LLM Gatewayは初回 / Validation Retry / Transport Retry / Staged GenerationのすべてでToken上限、
  Output Reserve、Margin、Current権限、Deadline、永続Budgetを送信前に検証し、SDKの隠れRetryを許可しない
- Schema Capabilityとは別にSystemDesign.md §36.E1 / §37.1 D11とAI制御仕様§11の実Local LLM品質Gateを満たす。
  10 Family × 10 Fixture × 3 Run = 300 Runを固定し、独立環境Oracle / 履歴で検証する。
  Scope False-Allow、Approval Bypass、Secret Leakage、重複副作用、誤confirmed、誤Goalは各0件、
  全体到達率90%以上・各Family80%以上、抽出Recall90%以上、予定外Human待ち5%以下、全RunでHard Limit以内とする
- 正常時 / 非信頼入力下の安全性と達成率を分け、pass^3を診断指標として報告する。
  不合格Runの除外、全件停止への期待変更、LLM自己採点、分母0のPASS扱い、実Target操作を禁止する

## Phase 3: Human Approval / Durable Resume

- 既存Graph RECONCILINGをMission PAUSED / WAITING_HUMAN_REVIEWにも対応させ、Current Recovery Authorityの範囲だけで照合できる。MissionをRUNNINGへ変更せず、新規Dispatch / LLM呼出しは0件とする。
- 照合後はCurrent Missionに対応するGraph状態へ戻し、開始時のSnapshotで上書きしない。WAITING_HUMAN_REVIEWの全Item解決時はMission Managerが§21.1.3に従い既存FINALIZINGへ進める。通常実行へ暗黙Resumeせず、新しい状態・Graph・Recordを追加しない。
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

Phase 0A〜5について、次をすべて満たしたとき製品の受入完了を開発記録へ記載する。

- 各Phaseの対象実装コミット、対応要件、試験結果、独立レビュー・指摘対応を記録済み
- 最終対象コミットでCommon Gateと全Phaseの製品要件が成立し、後続変更の影響を検証済み
- 全PhaseのBLOCKER / HIGH、未解決仕様矛盾、Security-critical TODOが0件
- Phase 4 / 5のProvider Human Gateと、Production構成に必要なD4を含む実機適格性のEvidenceがある
- README / SystemDesign / Config / Runbookが実装と一致する
- Fresh environment setupとMock end-to-endを再現できる
- Known limitationsと残存MEDIUM / LOWを明文化し、未実行試験・未確認結果をPASSとしない

受入完了はGitHub Label / Bot Marker / 自動Merge状態ではない。D4がNOT_EVALUATED等の未完了条件を残す場合は
その範囲を明記し、Production採用または全製品受入完了を宣言しない。公開・Mergeは別のユーザー指示に従い、
Phase受入だけでは実行しない。設計資料の更新を実装・Phase PASSと記録しない。
