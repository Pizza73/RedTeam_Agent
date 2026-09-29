# Safety Invariants

以下はPhase・実装方式・Adapterに関係なく破ってはならない。

設計改訂は`system-design-v1-r3`。AI固有の規約は[規範別冊](../SystemDesign_AI_Control.md)のAI-01〜12と
併せて適用する。実装が旧方式であることを理由に製品の安全条件を弱めない。開発のPhase受入は正本§40、既存データを扱う場合の移行は正本§38に従う。

## Authorization

- Plannerは提案だけを生成し、System ID、Adapter、Risk、Approvalを決定しない。
- Policy Engineだけが具体Actionを認可する。
- CallerはPolicyDecisionを発行・差替え・再Digestできない。
- Target set、port、protocol、session、scope、risk、side effect、approval、adapterの欠落はDefault Deny。
- Gateは最新のTrusted Source of TruthとDecisionの完全一致を確認する。
- 1 Decisionは1 ExecutionへだけBindingする。
- `AUTHORIZED`はPolicyDecisionをExecutionへBindingした候補状態であり、Secret解決、Provider送信、Raw Result Sink発行の権限ではない。
- Pre-dispatch成功と`DISPATCH_CLAIMED`へのOCC遷移を同じTransactionで確定し、外部送信は目的限定・単回・短寿命のCurrent Dispatch ClaimへBindingする。
- Dispatch Claim確定後のCrashまたは送信結果不明ではProvider Submitを自動再送せず、Reconciliationへ進む。

## Mission and context

- Mission lifecycleの唯一の正規入口はMission Manager。
- Mission Revision、State Version、Authorization Epochを相互に代用しない。
- PAUSE/Emergency Stop/Resume境界で短寿命Authorizationを一括失効する。
- 非RUNNING Missionの通常Planner/Analyzer Grantを拒否する。
- Context SelectorはIndex Metadataだけを読み、本文/Secretへ触れない。
- Context Builderは有効なGrantに含まれるResourceだけを読む。
- Retrieval HintはVersion付き型とCurrent MissionのCanonical Entity Referenceに限定し、任意Query、Scope、
  Classification、TTL、Tool AvailabilityまたはGrantを拡張しない。
- Planner Context EnvelopeはCurrent Mission Revision、Authorization Epoch、Grant、Tool Snapshot、TTLへBindingし、
  PolicyDecision、Approval、Goal EvidenceまたはSecret解決権限として扱わない。
- Plan Thread / Working HypothesisはApplication-ownedな未確認作業状態であり、Confirmed Fact、Mission Goal、
  Policy Authorityへ昇格させない。OCC競合、Stale Revision / Epoch、不正ReferenceはFail Closedにする。
- Planner Feedback / Recent Result SummaryはVersion付きSafe Projectionだけを含み、Raw Output / Error、Secret、
  禁止Target、未公開Tool Identityを開示せず、Policy Denialを上書きしない。
- Entityの自動統合はStrong Identifier一致だけに限定し、Alias-only、Fuzzy一致、Conflictを自動Mergeしない。
- Analyzer CandidateはCondition、Evidence Kind、Canonical Entity、Current Record Revisionを証明せず、Reducerと
  Goal Evaluatorの再検証を経るまでGoal Evidenceとして扱わない。
- OperationalPhaseはPlanning / Rankingの弱いSignalに限定し、Tool、Risk、Approval、Scope、Data Access、Adapter、
  Goal ConditionまたはMission Lifecycle Authorityを変更しない。

## Approval

- Human-visible structured presentationはExecutable Intentへ完全Bindingする。
- Actual targetと表示target、risk、side effect、adapter、argumentsが異なるApprovalを拒否する。
- ApprovalRecordはRequest/Digest/Presentation/Decision/Execution/TTLへBindingする。
- Free-text summaryはAuthorization Evidenceではない。
- Operator Acknowledgement、Attention解除、Outcome ReviewをHuman ApprovalまたはResumeとして消費しない。

## Data and secrets

- Secret ValueはPlanner、Analyzer、Knowledge Reducer、Knowledge Base、Promptへ渡さない。
- Planには`credential_reference`等の参照だけを含める。
- Secret配送はExecutor-owned Dispatch Transactionだけが行う。Application CallerがBroker、Channel Registry、Callbackを構築または注入できず、Composition Root固定のAdapter Dispatch Portだけを使用する。
- Current Dispatch Claimを平文復号前にOCCでDurable消費してread-back検証する。Claim消費後のCrashまたは不明な結果ではSecret配送とProvider Submitを再実行しない。
- Claim消費の勝者だけが、そのExecutor呼出し中に1回だけ使える非直列化・非公開のDispatch Continuationを得る。Module-level Token、再利用可能なResolver、別Entry Pointから消費済みClaimを使う平文解放を禁止する。
- Secretの単回性はDispatch Claim / 外部送信試行に対して保証し、Secret Versionの生涯使用回数として数えない。同じ`CONFIRMED`かつ未失効のSecret Versionは、別の認可済みExecutionと新しいClaimから利用できる。
- SecretはStableな論理`secret_id`とImmutable `secret_version_id`を分離する。Value変更は新Versionを追加し、状態は`DETECTED -> CONFIRMED -> REVOKED / SUPERSEDED`のAppend-only Lifecycle Eventだけで遷移する。EventとAuditを同じTransactionでCommitし、Sequence gap / duplicate、Digest Chain置換、Head Rollbackを拒否する。
- PolicyDecision、DataAccessGrant、Dispatch Claimはexact Secret VersionとCurrent Lifecycle HeadへBindingする。Current `CONFIRMED`検証とClaim Consumptionを同じOCC Transactionで行い、これを失効とのLinearization Pointとする。先に失効したVersionは未消費Claimの`invalidated`化と既知未送信Executionの`BLOCKED / SECRET_VERSION_STALE`を同じTransactionで確定し、先にConsumeした単一Attemptだけが固定Versionで継続する。
- Pre-dispatch `BLOCKED`は`dispatch_attempts=0`かつClaimなし、Secret失効後の`BLOCKED / SECRET_VERSION_STALE`は`dispatch_attempts=1`かつ同一ExecutionへBindingされた`invalidated` Claimを必須とする。それ以外の`BLOCKED` / Claim組合せを拒否する。
- DataAccessGrantは既存のnested `ResourceBinding`と文字列Versionを維持してAuthorization State Digestを追加する。Secret Bindingはexact Version ID、Canonical decimal Version、Immutable Version Metadata Record Digest、Lifecycle Head Digestを保持する。Legacy Secret IDを暗黙に集約または「最新Version」へ変換せず、曖昧なMigrationはFail Closedにする。
- `AUTHORIZED`、`BLOCKED`、失効 / 消費済みClaim、Mission / Epoch / Tool / Adapter不一致からSecretを解決しない。
- Secret StoreはApplication Callerへ平文bytesを返す汎用Resolve、公開Broker / Channel Constructor、任意Callback、任意Environment / Command Line注入Interfaceを提供しない。
- 解決SecretをPlan、Result、Exception、Traceback、Audit Log、通常DBへ含めない。
- Raw Tool Outputは非信頼入力であり、直接Promptへ連結しない。
- Quarantine、Classification、Secret Detection、Redactionを経たArtifactだけをLLM可視にする。
- Caller生成Receipt、Quarantine Reference、Publication Object、Full-object compatibility loaderをSecure Ingestion権限として扱わない。
- Secure IngestionはRepository-bound `ingestion_id`から完全なCurrent Bindingを解決する。正常公開後の消去は正本§33.2の確定済み公開証跡（Manifest / Projection / 全参照Resourceの公開時Immutable Metadata・Proof / Audit・Witness）と対象QuarantineのBinding / Key / Inventoryのread-back検証を必須とする。成果物本文の現存や消去Claim連鎖を要求しない。公開に至らないRetention Expiry / Incomplete Collection Expiryは別型のIntent / Claimと必須Evidenceで消去し、架空ManifestやExecutionResultを生成しない。

- 新規成果物の生成・内部保存は認可済みExecutionに付随する既存Secure Ingestionだけが行う。Repository-bound入力、固定Rule、Current MissionのLocal処理可否、Lease / Fence、Retention、Classification / Quotaを検証し、Storeが内部保存先を決める。未生成ResourceのGrantや追加Publication認可Recordを作らず、元PolicyDecisionを変更しない。
- 内部保存の例外を任意のCaller / Toolの新規作成、保存先指定、既存Resource上書き、Secret確認・置換に使わない。exact成果物Metadata / Manifestを確定しても閲覧・変更・Export・Secret Resolve権限を与えず、Current Data Access認可を別途要求する。

- Quarantine消去とExecutionResult確定まで必要な既存Immutable検証MetadataとAudit / Witness経路を保持し、本文・Secret値・鍵のRetentionを延長しない。証跡欠落・Witness不一致・既存Integrity Stopでは消去を拒否する。過去の公開証跡はCurrent Read / Context / Goal / Secret利用の認可・有効性を代替しない。
- Ingestion Retryは同じ入力・固定Rule / Parser ID・Code Digestだけを既存予算内で使う。MVPは変更Ruleでの既存Quarantine再処理を扱わず、ID変更による予算回避や元Action再送を許可しない。Rule利用不能・失効時は既存の失敗 / 隔離 / Human Review、期限到達時は型別消去へ進む。

## Integrity and encryption

- Security Artifactはwrite/read両方でDigest/ID/Bindingを検証する。
- Security-sensitive Digestは単一のVersioned Digest CatalogとCanonical Digest Serviceだけが定義・計算し、
  未登録、重複Owner、Field欠落、Version / Canonicalization不一致、別実装Fallbackを拒否する。
- State Transition、Audit、Outbox / IntentはTransaction Aggregate OwnerのApplicationUnitOfWorkで同時Commitし、
  Child Repositoryの独自Commitまたは部分Commitを許さない。
- Duplicate JSON key、unknown field、暗黙型変換を実Boundaryで拒否する。
- Missionで使用するActual Planner / Analyzer Schema DigestはVersion付きCapability CorpusへBindingし、Model、
  Tokenizer、Template、Structured Output Mode、Schema、Runtime変更時に失効させる。Capability不足をStrict
  Validationの弱体化やPartial Outputの直接実行で回避しない。
- Secret Store、Quarantine、Artifact StoreのKey Domainを分離する。
- Authenticated Encryptionを使用し、Domain/Mission/Execution/ArtifactをAADへBindingする。
- Nonce再利用、平文export、cross-domain fallback、暗号化無効化fallbackを禁止する。
- Key unavailable/revoked/mismatch/unsupported algorithmはFail Closed。
- ProductionのAudit Head / Wrapped Key Constructorは、Authenticated SQLite Generation Record StoreとNamespace別TPM 2.0 NV Extend Digest Witnessを必須とする。AuthorityはTPMのCurrent Witness Digestと、exact認証済みRecord / Immutable BlobのPairである。Extend前にCommit Payloadを確定し、`SHA256(previous_witness_digestのraw bytes || commit_payload_digestのraw bytes)`へBindingする。論理Generation番号だけでCurrentを選ばず、Future Witness / Record DigestをPayloadへ循環参照させない。
- TPM WitnessはGeneration DatabaseのStorage / Snapshot / Backup / Restore単位から独立させる。SQLite全体をRollbackして相互整合する旧GenerationをCurrentとして受理せず、TPMが示すCurrent Record / Blobを回復できなければLocal Alternate StateへFallbackしない。
- Productionは`tpm2_nv`以外のPath、Generic Service、Vault代替、Integer-only、Local-slot、同一Restore DomainまたはIn-memory Providerを受理しない。Mission / Caller入力でProviderを選択させない。
- TPM unavailable、Reset、NV Identity mismatch、未知Witness Digest、Deployment Counter decrease、Provisioning ambiguity、Current Record欠落は`ANCHOR_RECOVERY_REQUIRED`として全Missionを停止し、自動Re-seedしない。Recoveryは全Worker停止、Human Approval、新Trust Epoch、Audit discontinuity、Deployment Epoch更新を必須とする。
- Fresh Installだけが空Store、未使用Trust Epoch、固定Provisioned NV Identityと許可された未WRITTEN状態を検証し、承認済みGenesis PayloadをExtendして論理`generation=0`のPairを作成する。動的NV Name / WRITTEN属性と固定Identityを混同せず、Read失敗をCounter 0としない。`deployment_epoch`だけは別のNV Monotonic Counterの実測値へBindingする。Recovery Approvalは旧 / 新Trust Epoch / NV Identity、最終検証Record、採用State Digest / Immutable Blob IDへBindingし、検証不能なLocal Stateを正本化しない。
- `generation-witness-policy-v5`で指定したMission / Epoch、Claim / Budget、Knowledge等の重要状態は同期Critical Witness Barrierを満たすまで権限・Current Factとして公開しない。DB内だけのOCC、古い有効署名、論理Generation一致をRollback耐性と取り違えない。Goal評価履歴は実行許可Headではない。
- Resource単位消去は全Copy / Backup / 復元経路を含めて保証する。D4のTPM-backed Resource REK候補は実機 / Firmware / TSS、Slot Incarnation、容量、Restore・消去のQualificationがNOT_EVALUATEDであり、PASS前はProductionへ採用しない。Domain KEK一括破壊やWrapped Key Row削除だけで個別Resource消去を完了としない。
- Production Trusted Dependencyは単一Composition Rootが起動時に順序どおり生成・Self-check・固定し、Mission受付後の
  Provider / Clock / Key / Repository / Adapter差替え、Test Double混入、複数Rootを拒否する。
- 通常Startupは共有Activation Lock取得後にSchema / Catalogを読取検査するだけとし、Migrationを自動実行しない。明示Migration / Restoreは全Worker停止中に同じLockと承認済みOperationを使い、旧権限を新SchemaのALLOWへ補完しない。旧MissionはRead-only Archiveとし、新Missionの認可と既存Executionの用途限定Recoveryを分離する。

## Result collection and durable ingestion

- Result Collection開始時にExecutorがComposition Rootから注入されたTrusted Clockを1回読み、exact Tool Definition、`ResultTaskBinding`（`provider_task | local_result`）、Sink、Missionの用途別期限へBindingしたDurable Authorityを作成する。`local_capture`のAlias受理・自動変換を禁止する。同期Local Captureに架空Provider Task IDを発行せず、元の単回Submit内で取得する。Security-sensitive Collection APIはCaller supplied `now`を受け取らない。
- RetentionはTrusted Collection開始時刻から一度だけ計算して保存し、Execution作成時刻、Caller / Provider TimestampまたはRestart時刻から再計算しない。
- Tool固有`max_output_bytes`はTrusted Registryから解決し、CallerまたはGlobal設定で拡大しない。
- Result CollectionとSecure Ingestionは用途別typed Leaseを使用し、Collection / Execution / Authority / exact ResultTaskBinding / Sink / State VersionまたはIngestion / Execution / Receipt / Quarantine / State Versionを必須Bindingとする。汎用Optional FieldでBindingを省略させない。
- Production起動または全Worker停止中の認可済みRestoreごとにTPM-backed `deployment_epoch`を進め、Fenceを`(deployment_epoch, fencing_token)`とする。Database Rollback後も旧ProcessをCurrentにせず、Release済みFenceを削除 / 再利用しない。
- Productionは単一Host / TPM / Application DB / Composition Rootへ限定し、そのRoot配下のWorkerだけが同じDeployment Epochを共有する。Multi-host Workerを起動時に拒否する。
- 通常Collection / Ingestion WorkerのRenewal、Chunk / Cursor / Receipt / Manifest / State / Deletion Intent、Abort、Releaseを含む全Durable Mutationは、`lease_id`、Owner、Current Deployment Epoch / Fencing Token、未Release、Host Boot内共有の単調Clock上の未失効、Authority / Resource Digest、Expected State Versionの完全Predicateを同一Transactionで検証する。UTC巻戻り / 不連続は`ClockIntegrityError`で停止し、TTLを延長しない。
- 期限切れ確定は既存Retention Schedulerから既存Collection / Ingestion Ownerを呼ぶ経路だけが行う。Current Root / Clock / Anchor、対象処理の保存済み期限到達、Origin / Resource Binding、Expected State Version、現Lease ID / Fence / Snapshotまたは不存在をOCC照合し、既存Expiry State・型別Deletion Intent・旧Lease失効・Audit / Critical Intentを同時確定する。未失効Leaseは要求せず、Workerへ期限後更新権限を返さない。Collection期限ではABANDONED / Unresolved Item / Lease失効を確定し、固有Retention到達まで消去Intentを作らない。公開済みなら既存post_ingestion消去へ進める。新しい状態・Record種別・Serviceは追加しない。
- Default Leaseは60秒、Heartbeatは20秒以下とし、`lease_duration >= 3 * heartbeat_interval`を強制する。Renewal失敗はCancellationを通知し、非協調Adapterが継続してもSinkが全Stale Mutationを拒否する。
- Lease更新とRecovery Authority更新は別々にCurrent Predicateを再検証する。継続Stream / Sinkも短命Authorityの失効を検査し、Heartbeatから認可TTLやMission期限を延長しない。`valid_until`、`recovery_until`、`evidence_retention_until`を分離し、期限後の新規Action / LLM利用をRecovery名義で認可しない。
- Filesystem / Blob Writeは`work_id/deployment_epoch/fencing_token`へStageし、Storage-side Conditional PublicationだけがCurrent Metadataへ到達可能にする。旧FenceのBytesは到達不能なGarbageであり正本にならない。
- Quarantine Sink / Reader / Factory / Lookupは副作用を持たない。正常公開はRedacted Artifact / Secret Reference、ExecutionResultProjection、Manifest、Deletion Intent、DELETE_PENDING、Lease Releaseを同じUnit of Workで確定する。公開時は全成果物本文 / Digest / Key Bindingと保存Metadataを検証・Witnessし、消去時は確定済み公開証跡と対象Quarantineをread-back検証する。ExpiryとManifest Commitは同じExpected StateでOCC競合し、期限後Publishを許さない。
- Secure Ingestionは`DELETE_PENDING`でLeaseをReleaseして消去Capabilityを持たない。Composition Root固定の専用Eraserだけが消去理由別のIntent / 必須Evidence / Resource Digest / Key Metadata / deterministic `erasure_id`へBindingされた単回Erasure Claimを状態遷移と同じTransactionで作成・消費して`ERASURE_CLAIMED`へ遷移する。RepositoryにはConsumed Claimだけを保存する。EraserはKey Providerへ同じ`erasure_id + key_metadata_digest`でまずReconcileし、`NOT_STARTED`だけでDestroyを開始し、`UNKNOWN`後はReconcileだけを行い、read-back検証済み`CONFIRMED`後にだけCiphertextをUnlinkする。未公開Orphan Resource Cleanupは別の限定AuthorityとCopy Inventoryを検証し、通常消去を迂回しない。
- `INGESTED_DURABLE`以後はManifest / ExecutionResultProjectionだけからExecutionResultを再構築し、Adapter Collection、Provider照会、Quarantine復号を再実行しない。
- Manifest Commit、Deletion Intent、Erasure Claim消費、Key破棄、Ciphertext削除、ExecutionResult確定の各Crash境界を、Provider再実行、平文Fallback、追加の未検証消去、手動File修復なしに回復する。

## External effects and retry

- Provider Outcome、Collection、Ingestion、Erasureの未解決を別々に永続化し、未解決の受容終了を正常完了と偽らない。Cancelは元Dispatchとは別の単回AttemptとCurrent目的限定認可を要し、Task未取得照合をKnown Task操作へ読み替えない。
- MVPのRedirect自動追従は禁止し、得られた候補は別の新規Executionとして全Target / Scope / Approvalを再認可する。
- Phase 0Aでは外部dispatchを行わない。
- CIでは全Phaseを通じて実C2/MCP/Targetへ接続しない。
- Non-idempotent/unknown-outcome actionを自動再送しない。
- External side-effect nodeにLangGraph/HTTPの無条件retryを適用しない。
- Coarse Agent GraphのContext、Persistent Commit、Dispatch、Collection、Ingestion、ReconciliationはRetry Budgetを
  共有せず、Composite Nodeの再実行から外部副作用を再送しない。
- ReconciliationなしにOutcomeを推測しない。
- Payload/Implant生成・配布・永続化機能はMVP対象外。

- PAUSED / WAITING_HUMAN_REVIEWでも既存GraphのRECONCILINGからCurrent Recovery Authorityの範囲で既存Executionを照合できる。MissionをRUNNINGへ変えず、終了後はCurrent Missionに対応する状態へ戻す。通常ResumeやLLM / 新規Dispatch権限に代用しない。

## AI control

- 証拠評価、登録済みActionContractによる前提検証、Policy / Approvalによる認可を分離する。Goal unknownは全ActionのDENYではないが、当該Actionの安全上の前提unknown / conflictは拒否する。
- verified_fact / observation / hypothesisを分離し、全区分にGrant・内容整合性・秘密情報非混入を要求する。未確認Observation、LLM Confidence、予測効果、人の自由文だけではFact / Session / Goalを確定・失効・矛盾化しない。
- GoalはCurrentな適格Evidenceの三値で評価し、all(false, unknown)はnot_achieved、any(true, unknown)はachievedとする。Security Errorは三値の外側で停止する。
- 共通Controllerが初回・再開・各Planner前のGoalとCurrent状態を評価する。準備・調査も同じPolicy / Approval / Pre-dispatch / Claim経路を使い、旧normal / investigate、GoalRoutingHeadによる互換認可を作らない。
- Action契約と実行前提DigestをPlan / 認可へBindingし、Goal評価参照は監査専用とする。安全上必要な前提の失効をPre-dispatchで拒否し、旧全量Goal Headの削除をCurrent Mission / Epoch / Knowledge保護の削除へ拡張しない。
- 前提探索と全LLM Attemptは登録済み契約、探索上限、永続Budget / Deadlineで有限にする。意味Key別情報取得枠、Claim Reservation、消費履歴を言い換え・再構築・Restart・Pause / ResumeでResetしない。最後の予約枠は勝者だけが継続できる。
- 検証済みFact保存後のAnalyzer失敗はFactを撤回せず、既存Local処理だけを有限に回復する。新しい提案 / Keyから結果不明の外部Actionを自動再送しない。
- 安全性と正常時 / 攻撃下の達成能力を独立Oracleで検査する。Schema PASS、全件停止、同じLLMの自己採点をAgent品質の合格根拠にしない。

## Development process

- 設計整合と独立レビューはCodex、実装はClaude Codeが担当する。製品のPlanner / Analyzerとは別の役割である。
- 正本§40に従いPhaseごとの一つの開発記録へ対象コミット、対応要件、試験結果、独立レビュー、受入根拠・残課題を残す。Phase順序を飛ばさず、旧PASSを新実装に流用しない。
- Codexは実装会話を引き継がない別セッションで対象コミットのRead-only Snapshotと試験Evidenceを独立に確認する。実装者の説明、モデルのPASS、終了コード0だけを受入根拠にしない。
- 実装後の変更は対象コミット・差分・影響範囲に応じて試験と独立レビューを更新する。記録だけの追記は製品変更と区別し、コミットIDの自己参照を要求しない。
- 未実施の試験・レビューを実施済みと記録しない。安全条件を満たす試験を失敗回避のために削除・skip・xfail化しない。
- 設計・受入条件を合格目的で無断に緩和しない。承認済みの設計改訂は関連文書へ一貫して反映し、旧自動Design Approvalを追加要求しない。
- BLOCKER / HIGH、未解決仕様矛盾、Security-critical TODOを残して次Phaseを受入済みとしない。同じ問題で進展しない場合は設計と関連経路を見直す。
- 製品のScope・Policy・Approval・Secret・単回実行・Audit・移行・Production適格性は開発規約の簡素化で変更しない。Phase 4 / 5の外部選択は既存Human Gateを通す。
- 開発・CIには実演習Secretや不要なCredentialを渡さず、実C2 / MCP / Targetへの操作を行わない。
- 旧Launcher / Bot Marker / Workflow / 自動Merge / 開発用Claimは現行Gateではない。新しい開発状態機械や認可Tokenを追加しない。公開・Mergeは当該作業のユーザー指示に従い、Phase受入だけで自動実行しない。
