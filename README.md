# RedTeam Agent — 設計資料と段階実装

許可された隔離演習向け支援AIエージェントの設計資料と、Phase 0A〜3の段階実装を保持するリポジトリ。
Phase 3までの実ネットワークは閉域Local LLM資格に限定し、実C2/MCP/Target接続・Payload生成・汎用Shell実行は含まない。Phase 3はHuman ApprovalとDurable Resumeを追加するが、実Adapterは持たない。

## 担当方針

| 工程 | 担当 |
| --- | --- |
| 設計・仕様の整合 | Codex |
| コーディング・実装 | Claude Code |
| 独立レビュー | 実装セッションと分離したCodex |

製品のPlanner / Analyzer用LLM仕様と、開発担当の分担は別の事項として扱う。

## 設計資料

| ファイル | 内容 |
| --- | --- |
| [SystemDesign.md](SystemDesign.md) | 設計正本。構成、安全基盤、接続Schema、Phase要件、開発規約 |
| [SystemDesign_AI_Control.md](SystemDesign_AI_Control.md) | 必須別冊。証拠・計画・認可の分離と共通制御ループ |
| [docs/acceptance-criteria.md](docs/acceptance-criteria.md) | Phase別の製品受入条件と開発記録の条件 |
| [docs/safety-invariants.md](docs/safety-invariants.md) | 製品の安全不変条件と開発時の遵守事項 |
| [docs/threat-model.md](docs/threat-model.md) | 製品と現行開発体制の脅威・対策・限界 |
| [docs/development/phase-0a.md](docs/development/phase-0a.md) | Phase 0A の開発記録（対象・要件・試験・残課題・独立レビュー） |
| [docs/development/phase-2.md](docs/development/phase-2.md) | Phase 2 Local LLM の開発・実モデル資格・独立レビュー記録 |
| [docs/development/phase-3.md](docs/development/phase-3.md) | Phase 3 Human Approval / Durable Resume の開発記録（対象・要件・試験・残課題） |

設計改訂は`system-design-v1-r3` / `ai-control-v1-r3`。
AIの意味・判断は別冊を先に読み、安全基盤と接続Schemaは正本で確認する。
Phase順序・製品要件は正本§36〜38、開発開始・記録・独立レビューは§40と受入条件に従う。

## Phase 0A 実装

`src/redteam_agent/` に、正本§36 Phase 0Aの認可カーネルを実装する。決定論的で外部送信を行わない。

- `canonical/` — Trust Boundary JSON（重複キー拒否）、Canonical JSON、Versioned Digest Catalog / Digest Service、Deep-immutable Canonical JSON Object。
- `models/` `plan/` `mission/` — Strict Boundary Model、Mission Revision / State / Authorization Epoch の分離、Mission Manager（唯一のLifecycle入口、OCC、原子的audit）。
- `policy/` — Typed Execution Scope（IP/CIDR・Host・Session, Port/Protocol）、Data Access Policy（`resource-pattern-v1`）、Versioned Effective Risk / Approval Policy、PolicyDecision、Proposal/Authorization Digest、TargetDispatchBinding、TTL不変条件、Execution Authorization Service。
- `tools/` — Tool Registry（Revision/Digest/Validation）、Trusted Target Extractor（閉じた引数契約, 隠しdestination拒否）、Secret Argument Path（RFC 6901）、Tool Availability Resolver / AvailableToolSnapshot / Revalidation。
- `context/` — Context Resource Index、Context Selector（Index Metadataのみ）、ContextDataAccessGrant発行/検証。
- `approval/` — ApprovalPresentation（完全一致Binding）、ApprovalRequest/Record、認証済みactor + RBAC。
- `executor/` — Executor Authorization Gate（PolicyDecision検証のみ、Dispatchなし）。
- `runtime/` `auth/` `resources/` `sandbox/` `adapters/` `contracts/` `semantics/` `llm/` `storage/` `composition/` `devtools/` — Trusted Clock、Principal/RBAC境界、Secret Metadata読取境界、Sandbox Capability Binding、Adapter Capability、Action Contract Catalog、Semantic Catalog、Mock LLM Profile、SQLite Repository（write/read Integrity・Owner限定書込）、Composition Root、Git状態取得。

後続Phaseの機構（Dispatch/Secret Injection、TPM/暗号、実Adapter、実LLM）は前倒しせず、必要な境界は明示Test Double / Protocolで分離する。

### 再現手順

Python 3.14.6 で検証（`.python-version`へ固定）。プロジェクト仮想環境内へ固定依存を導入し、システムPython/グローバル設定は変更しない。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-build-isolation   # lock済みbuild backendを使用
.venv/bin/ruff check src tests scripts
.venv/bin/mypy
.venv/bin/python -m compileall -q src
.venv/bin/python -m coverage run --branch -m pytest
.venv/bin/python -m coverage report
```

依存は`requirements.lock`へ固定する（worktree絶対パスのeditable entryは含めない）。build backendは`setuptools.build_meta`で、
`requirements.lock`と`pyproject.toml`の`build-system.requires`に`setuptools==80.9.0` / `wheel==0.45.1`を固定する。
編集不要なら`PYTHONPATH=src`でも実行できる。

### 状態

Phase 0Aの製品コードと Unit/Integration/Security/Property-State-machine 試験を実装済み。ruff/mypy/compileall/branch coverageと独立レビューを完了済み。
受入結果と残課題は [docs/development/phase-0a.md](docs/development/phase-0a.md) を参照。

## Phase 3 Human Approval / Durable Resume

Phase 3 は Human Approval の完全表示・厳密Bindingと、停止 / レビュー中Missionの Durable Resume を追加する。
新しいWorkflow状態・Graph・永続Record・認可経路・重複Serviceは追加せず、実C2 / MCP / 外部Target / Credential /
Payload / Implant 操作も持たない。開発記録は [docs/development/phase-3.md](docs/development/phase-3.md)。

- `REQUIRE_APPROVAL` は一致する有効な `APPROVED` Record がなければ Dispatch できず、`DENY` は Record があっても
  実行不可、Plan / Intent 変更・期限切れ・Replay・誤Digest・誤Epoch / Revision・誤Bindingはすべて Fail Closed する
  （`ExecutorAuthorizationGate` / `evaluate_executable`、`tests/security/test_phase3_approval.py`）。
- `PAUSE` / `Resume` は `authorization_epoch` を単調増加させ `mission_revision` は不変とし、Pause前の Grant /
  Snapshot / Decision / Approval を再利用しない（`MissionManager`、`tests/integration/test_phase3_durable_resume.py`）。
- Durable Resume は Compiled Planning Graph と LangGraph Checkpoint が Workflow Resume を所有する。認証済み
  Operator が Canonical `thread_id` で Resume を Trigger すると実 Checkpoint を復元し、既存 RECONCILING node が
  LangGraph Checkpoint → Application DB → Adapter の順（DBがExecution Stateの正）で Current Recovery Authority
  だけを用いて照合する。新規 Dispatch / LLM 呼出しは 0 件、不明な非冪等 Outcome は `OUTCOME_UNKNOWN` のまま
  自動再送しない。Mission を RUNNING へ戻さず現在 Mission に対応する Graph 状態へ写像し（並行の正当な変化も拒否せず写像）、
  WAITING_HUMAN_REVIEW は全Item解決時にだけ Mission Manager が §21.1.3 の既存 FINALIZING へ進める
  （`Phase1AgentWorkflow.durable_resume` / `FinalizationService.advance_from_human_review`）。

## Phase 2 Local LLM（Capability / 300-Run Qualification）

Phase 2 は Local LLM（vLLM、`chat_completions` 固定）向けの Profile・Capability・Gateway 予算・Adapter・
評価入口・品質 Gate を追加する。Pydantic AI は固定依存に含まれないため、同契約を満たす明示的な OpenAI 互換
HTTP Client（`httpx`）を用いる。開発記録は [docs/development/phase-2.md](docs/development/phase-2.md)。

Phase 2の最終実装`66f55bad667261a5cd8ec5e54bb375d7ea0a2644`に対する自動試験、実`gemma-4-31B-it`
Capability Check、固定300-Run Qualification、独立Common Gateレビューは完了し、Phase 3移行判定は`PERMITTED`。
詳細は [Phase 2開発記録](docs/development/phase-2.md) と
[Phase 2独立レビュー](docs/reviews/phase-2-common-gate-66f55ba.md) を参照する。D4実機消去は`NOT_EVALUATED`であり、Production採用は別条件のままである。

- Schema Capability（§6.2）: `schema-capability-corpus-v2`（`src/redteam_agent/llm/capability_corpus.py`）を
  Planner/Analyzer の全 Actual Schema Digest に対して実行し、Valid 率 95%以上・Unsafe Boundary Acceptance 0 件・
  Cancellation Failure 0 件を満たすと合格。結果は Profile Digest / Model Hash / Runtime / Tokenizer / Template /
  Output Mode / Schema / Corpus へ Binding し、いずれかの変更で失効する。
- Agent Quality（§36.E1 / §37.1 D11）: `agent-quality-policy-v2`（`src/redteam_agent/quality/corpus.py`）の
  10 Family × 10 Fixture × 3 Run = 300 Run を独立 Oracle で採点する。

エンドポイント設定例（`LocalLLMEndpointConfig`。`base_url=None` は未設定＝Gate `NOT_RUN`）:

```yaml
llm:
  provider: vllm
  wire_api: chat_completions
  base_url: http://10.0.6.181:8100/v1
  model: gemma-4-31B-it
  api_key_file: /absolute/path/to/vllm-api.key
  temperature: 0.1
```

実 vLLM に対する Capability / 300-Run Qualification は Local Evaluation Entry Point 経由で実行する（擬似コード）:

```python
from redteam_agent.composition.phase2 import build_phase2_kernel
from redteam_agent.llm.attestation import HttpServerMetadataProvider, SignedManifestArtifactSource
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.secrets import FileAPIKeySource

config = LocalLLMEndpointConfig(
    model="gemma-4-31B-it",
    base_url="http://10.0.6.181:8100/v1",
    api_key_file="/absolute/path/to/vllm-api.key",
)
kernel = build_phase2_kernel(
    endpoint=config,
    qualification_commit_id=commit_id,             # 評価対象の完全な commit ID
    dependency_lock_digest=requirements_lock_sha256,
)
profile = ...       # 実モデルの model_hash / tokenizer_revision / runtime_version に一致する LocalLLMProfile
token_counter = ... # 実モデルの Tokenizer（profile.tokenizer_revision に一致、TokenCounter.count_request 実装）

# §6.2 Capability: real_local_llm Evidence の Provenance は「具体 Probe」から導出する（Caller の
# フラグではない）。real は LiveCapabilityProbe + retry 無効の直接 HTTP Transport のみが生む。
# MockTransport を注入した同じ Probe は test_double のままである。LiveCapabilityProbe は
# 隔離 EvaluationGateway（Attempt 予約 → Token Preflight → 有限 Run Budget/期限 → Network）を経由し、
# Endpoint/Profile と実 Tokenizer の束縛を必須化する。test_double は永続化されず Mission も認可しない。
key_source = FileAPIKeySource(config.api_key_file)
client = VLLMChatClient(base_url=config.base_url, api_key_source=key_source)
policy = kernel.request_budget_policy(profile)
attestation = kernel.attest_server(
    profile=profile,
    provider=HttpServerMetadataProvider(api_key_source=key_source),
    artifact_source=SignedManifestArtifactSource(...),
)
probe = kernel.build_live_capability_probe(
    profile=profile, policy=policy, client=client, token_counter=token_counter,
    run_id="startup-capability", cancellation=..., attestation=attestation,
)
capability_results = kernel.run_capability_evaluation(profile=profile, probe=probe)

# §36.E1 300-Run Qualification。Binding は Kernel が信頼済み構成値から生成し、品質 Driver は
# 全 model call を隔離 EvaluationGateway 経由で発行する。任意 Driver の evidence_kind 自己申告は拒否される。
binding = kernel.build_evaluation_binding(
    profile=profile, capability_results=capability_results, attestation=attestation,
)
quality_driver = kernel.build_isolated_workflow_quality_driver(
    profile=profile, policy=policy, client=client, token_counter=token_counter,
    evaluation_binding=binding, attestation=attestation,
    capability_results=capability_results, max_parallel_runs=4,
)
report = kernel.qualify_real_local_llm(
    profile=profile, driver=quality_driver,
    evaluation_binding=binding, capability_results=capability_results,
    attestation=attestation,
)
# report.gate_status は PASS / FAIL / BLOCKED / NOT_RUN。real_local_llm Evidence・妥当な EvaluationBinding
# （commit/profile/model/tokenizer/chat template/runtime/output mode/prompt/schema/contract/catalog/
# gateway-budget-policy/dependency-lock/両 corpus digest/合格 Capability Result digest/全 300 Run の一意 Seed）
# ・全閾値達成のすべてを満たしたときのみ PASS になる。
```

Unit / Integration Test は決定論的な Fake OpenAI 互換 Server（`httpx` mock transport）で経路を検証する。Fakeだけで
Gate `PASS` を主張しない。構成所有の `IsolatedPhase1ScenarioRunner`
は期待値を含まない `QualityWorkflowInput.environment_spec` から隔離Missionと安全Adapterを構成し、
`WorkflowRunTrace` を返す構成所有の実行関数である。MockTransport は具体 Probe／Driver
を使っても `test_double` と判定され、製品 API は文字列ラベルで real へ付け替えられない。
送信前Budgetのトークン計測は実モデルの Tokenizer を `count_request` で用い、近似 Counter は Test 専用で本番
Fallback はない。品質Evidenceの実消費量はvLLM応答の`usage.prompt_tokens` / `usage.completion_tokens`を全完了Attemptで保存し、
欠落・不正値・LLM Callがあるのに全量0の場合は実GateをFail Closedする。現在の実モデル資格状態と実行結果はPhase 2開発記録に保存する。

## 今回の整合方針（設計）

- 期限切れ確定は既存Retention Schedulerが行い、通常Workerの未失効Lease条件と分ける。
- 新規成果物の内部保存は既存Secure Ingestionへ限定し、追加の作成認可Recordを設けない。保存後のアクセス認可は維持する。
- 停止中のRecoveryは既存Graph状態とMission状態の対応表で表し、暗黙Resumeを行わない。
- 開発はPhaseごとの一つの記録に対象コミット・要件・試験・独立レビュー・残課題をまとめる。旧Launcher・Bot Marker・自動Mergeを必須としない。
- 公開時に全成果物を検証し、後日のQuarantine消去は確定済み公開証跡と消去対象自身から判断する。成果物本文の先行期限切れで消去を妨げず、本文・鍵の保持期限を延長しない。
- Ingestion Retryは同じ入力・固定Rule / Parserと既存予算内に限定し、変更Ruleでの既存Quarantine再処理はMVP対象外とする。
- 結果経路の正規値は`provider_task | local_result`へ統一し、表記揺れの互換Aliasを設けない。

新しい製品状態・Record種別・独立Service・開発状態機械は追加しない。根拠と適用限界は正本§41.11に記録する。
Scope・Policy・Human Approval・Secret保護・監査・Phase順序・実AdapterのHuman Gateは保持する。
D4の実機消去Qualificationは`NOT_EVALUATED`であり、Production採用は未承認である。

## 履歴と整合性

設計文書の旧原文は整理前コミット`9f45af326207606c0107c585bed01428055cbf9d`の履歴で参照できる。
現在の文書は承認済み整合を反映しており、旧原文のままではない。
正本§41の旧仕様・旧PR状態・旧開発Loopは履歴に限定し、新実装のGateや権限へ読み替えない。

`SHA256SUMS`は正本・別冊・受入/安全/脅威モデル文書・LICENSE・このREADMEの整合性を対象とする。
リポジトリ直下で`sha256sum --check SHA256SUMS`により確認できる。実装コード（`src/`, `tests/`）はGitで追跡し、
上記の静的検査・試験で検証する。

[LICENSE](LICENSE)
