# Safety Invariants

以下はPhase・実装方式・Adapterに関係なく破ってはならない。

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

## Approval

- Human-visible structured presentationはExecutable Intentへ完全Bindingする。
- Actual targetと表示target、risk、side effect、adapter、argumentsが異なるApprovalを拒否する。
- ApprovalRecordはRequest/Digest/Presentation/Decision/Execution/TTLへBindingする。
- Free-text summaryはAuthorization Evidenceではない。

## Data and secrets

- Secret ValueはPlanner、Analyzer、Knowledge Reducer、Knowledge Base、Promptへ渡さない。
- Planには`credential_reference`等の参照だけを含める。
- SecretはPre-dispatch成功後の未消費Dispatch Claimを検証したBrokerだけが、固定されたTrusted Adapter Channelへ実行直前に注入する。
- `AUTHORIZED`、`BLOCKED`、失効 / 消費済みClaim、Mission / Epoch / Tool / Adapter不一致からSecretを解決しない。
- Secret StoreはApplication Callerへ平文bytesを返す汎用Resolve、任意Callback、任意Environment / Command Line注入Interfaceを提供しない。
- 解決SecretをPlan、Result、Exception、Traceback、Audit Log、通常DBへ含めない。
- Raw Tool Outputは非信頼入力であり、直接Promptへ連結しない。
- Quarantine、Classification、Secret Detection、Redactionを経たArtifactだけをLLM可視にする。
- Caller生成Receipt、Quarantine Reference、Publication Object、Full-object compatibility loaderをSecure Ingestion権限として扱わない。
- Secure IngestionはRepository-bound `ingestion_id`から完全なCurrent Bindingを解決し、Durable Manifestをread-back検証する前にQuarantineを消去しない。

## Integrity and encryption

- Security Artifactはwrite/read両方でDigest/ID/Bindingを検証する。
- Duplicate JSON key、unknown field、暗黙型変換を実Boundaryで拒否する。
- Secret Store、Quarantine、Artifact StoreのKey Domainを分離する。
- Authenticated Encryptionを使用し、Domain/Mission/Execution/ArtifactをAADへBindingする。
- Nonce再利用、平文export、cross-domain fallback、暗号化無効化fallbackを禁止する。
- Key unavailable/revoked/mismatch/unsupported algorithmはFail Closed。
- Audit HeadとWrapped Key StateのExternal Generation AnchorはGenerationだけでなくState DigestとImmutable Blob IDへBindingする。
- Anchorが指すCommitted BlobをTrusted Storeから回復できなければ、Local Alternate StateへFallbackせずFail Closedにする。ProductionはGeneration整数だけを外部保存するFile-only Providerを使用しない。

## Result collection and durable ingestion

- Result Collection開始時にTrusted Clock、exact Tool Definition、Provider Task、Sink、Mission DeadlineへBindingしたDurable Authorityを作成する。
- RetentionはCollection開始時刻から一度だけ計算して保存し、Execution作成時刻またはRestart時刻から再計算しない。
- Tool固有`max_output_bytes`はTrusted Registryから解決し、CallerまたはGlobal設定で拡大しない。
- Redacted Artifact、Secret Reference、Secure Ingestion ManifestをDurableに確定してからQuarantine Deletion Intentを作成する。
- Manifest Commit、Deletion Intent、Key破棄、Ciphertext削除、ExecutionResult確定の各Crash境界を、Provider再実行、平文Fallback、手動File修復なしに回復する。

## External effects and retry

- Phase 0Aでは外部dispatchを行わない。
- CIでは全Phaseを通じて実C2/MCP/Targetへ接続しない。
- Non-idempotent/unknown-outcome actionを自動再送しない。
- External side-effect nodeにLangGraph/HTTPの無条件retryを適用しない。
- ReconciliationなしにOutcomeを推測しない。
- Payload/Implant生成・配布・永続化機能はMVP対象外。

## Development loop

- Codexは自分を評価する仕様、Gate、Workflowを変更しない。
- 独立AI Reviewは最新HEAD SHAへBindingする。
- Stale Reviewは無効。
- Loop回数を制限し、同じ失敗を無限反復しない。
- 同じInvariant Familyの2回目のFormal Reviewは`DESIGN_CHANGE_REQUIRED`として通常Resume不能にする。過去のbase-refresh / Resume Evidenceは新しいDesign Stopを越えて再利用しない。
- Design Stop後の再開は、停止Gate、Current 40桁HEAD、Phase、承認済みDesign revisionへBindingした単回`DESIGN_APPROVED` Evidenceだけを使用する。LabelやFree-text commentを権限にしない。
- Phase 4/5の外部選択はHuman Gateを通す。
- 最終mergeは、承認済みDefault Branch上のLocal OrchestratorだけがPhase 0A～5の
  SHA-bound PASS Chain、Current-HEAD CI/Status、Stop Label不在、Current Default Branch
  ancestryを再検証し、Expected HEAD SHA固定で1回だけ実行する。Dispatch前に同じPR/HEAD
  固定のRepository Git ref claimを原子的に取得し、ClaimへBindingした永続Attempt Recordを
  保存する。その後、同じGateを再取得して不変性を確認する。Claim/Recordの既存・作成結果不明
  または取得後Gate Drift/Unknownは明示的Reconciliationまで再送を禁止し、通常実行ではClaimを
  削除しない。Codex、GitHub Actions、Governance PR、Fork PRはこの経路を使用できない。
