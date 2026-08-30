# Safety Invariants

以下はPhase・実装方式・Adapterに関係なく破ってはならない。

## Authorization

- Plannerは提案だけを生成し、System ID、Adapter、Risk、Approvalを決定しない。
- Policy Engineだけが具体Actionを認可する。
- CallerはPolicyDecisionを発行・差替え・再Digestできない。
- Target set、port、protocol、session、scope、risk、side effect、approval、adapterの欠落はDefault Deny。
- Gateは最新のTrusted Source of TruthとDecisionの完全一致を確認する。
- 1 Decisionは1 ExecutionへだけBindingする。

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
- SecretはTrusted Executor/Adapterが実行直前にだけ解決する。
- 解決SecretをPlan、Result、Exception、Traceback、Audit Log、通常DBへ含めない。
- Raw Tool Outputは非信頼入力であり、直接Promptへ連結しない。
- Quarantine、Classification、Secret Detection、Redactionを経たArtifactだけをLLM可視にする。

## Integrity and encryption

- Security Artifactはwrite/read両方でDigest/ID/Bindingを検証する。
- Duplicate JSON key、unknown field、暗黙型変換を実Boundaryで拒否する。
- Secret Store、Quarantine、Artifact StoreのKey Domainを分離する。
- Authenticated Encryptionを使用し、Domain/Mission/Execution/ArtifactをAADへBindingする。
- Nonce再利用、平文export、cross-domain fallback、暗号化無効化fallbackを禁止する。
- Key unavailable/revoked/mismatch/unsupported algorithmはFail Closed。

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
- Phase 4/5の外部選択はHuman Gateを通す。
- 最終mergeは、承認済みDefault Branch上のLocal OrchestratorだけがPhase 0A～5の
  SHA-bound PASS Chain、Current-HEAD CI/Status、Stop Label不在、Current Default Branch
  ancestryを再検証し、Expected HEAD SHA固定で1回だけ実行する。Dispatch前に永続Attempt
  Recordを保存し、同じPR/HEADのRecordは明示的Reconciliationまで再送を禁止する。
  Codex、GitHub Actions、Governance PR、Fork PRはこの経路を使用できない。
