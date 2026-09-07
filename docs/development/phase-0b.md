# Phase 0B 開発記録 — Execution Safety

本記録は正本 `SystemDesign.md` §40.1 が要求するPhaseごとの一つの開発記録である。
主要実装と一次修正はClaude Code、Claude Codeの利用上限到達後に残った局所修正と試験追加はCodex、
独立レビューはClaude Codeの実装プロセスから分離したCodexが担当した。本記録の結果は実コード、固定コミット、
再実行した試験結果と合わせて判定する。**固定コミットに対する独立レビューを完了し、Phase 0Bの受入条件は成立した。**

## 1. 対象

| 項目 | 内容 |
| --- | --- |
| 設計Revision | `system-design-v1-r3` / `ai-control-v1-r3` |
| Phase | 0B: Execution Safety |
| 入力コミット（完全ID） | `d2e52ca1b844fcba471e828e0e51b75d85c0c90c`（Phase 0A受入記録済みbaseline） |
| 実装先 | 現checkout（ブランチ `codex/phase-0b`） |
| 実装対象コミット | `1a7178862fb8aece6ef29788798181bccc0eca4c` |
| 独立レビュー | Codex、対象 `1a7178862fb8aece6ef29788798181bccc0eca4c`、2026-09-07完了 |

成果物はブランチ `codex/phase-0b` に置く。リモートへのpush・mainへのmergeは別途指示があるまで行わない。

### 実装範囲（正本§36 Phase 0B / §9 / §10〜10.5 / §17.2〜17.3 / §21.1.1〜21.1.3）

Provider Execution State と Result Ingestion State を分離した専用の永続Record（`ExecutionRecord`、
`DispatchClaim`、`ResultCollectionAuthority`、`ResultCollectionStateRecord`、`ResultIngestionStateRecord`、
`RawControlMetadataRecord`、`ExecutionResultProjection`、`ExecutionResult`、`ResultTaskBinding`、
`ExecutionRecoveryAuthority`、`CancelAttempt`、`MissionExecutionBudget`）と、DB強制の一意性 / OCC遷移を持つ
Repository群。Executorのpre-dispatch再検証と`AUTHORIZED -> BLOCKED`のfail-closed、`AUTHORIZED -> DISPATCH_CLAIMED`
＋Claim作成の原子的遷移、Claim消費とComposition Root固定Adapter Dispatch PortだけによるJIT Secret Injection、
単回Dispatch（`dispatch_attempts` ∈ {0,1}）と自動再送禁止、`reconcile()`不確実結果の`OUTCOME_UNKNOWN`遷移、
Executor所有Trusted Clockによる固定Collection Authority（Deadline / Retention / Output上限）、
全量Memory保持なしのChunk Streaming Sink、独立したIngestion状態とCrash Resume、Recovery Authority / 単回Cancel、
run_id / thread_id Lifecycle、Durable Mission Execution Budget、FINALIZING Skeleton（Goal達成直接COMPLETED拒否）、
Mock Execution Adapter と`ExecutionAdapter` Protocol。

### 範囲外（前倒ししない。Phase 0Cで評価）

Production暗号 / TPM Witness / 実Key Provider、実C2 / MCP / 外部Target接続、Encrypted Quarantineの実暗号化と
Verified Erasure（`DELETE_PENDING`以降のErasure実行）、typed Lease / Fencing / 単調Clock（`ClockIntegrityError`）と
§10.3.1 F6継続再認可のProduction Hardening、Secret Lifecycleの完全なProduction実装、Audit Hash Chain / Manifest公開証跡の
実装。これらは正本が要求する型・安全なTest Double境界だけをPhase 0Bで用意し、未実装の後続機構をPASS扱いしない。
Phase 0Bは**実外部Dispatchゼロ**（Mock Adapterのみ）。Phase 0Aの認可カーネル挙動と安全不変条件を保持する。

## 2. 実装したファイル

新規（製品）:

- `execution/models.py` — 状態Literal、`ExecutionRecord`（BLOCKED理由整合、`dispatch_attempts` 0/1）、
  `DispatchClaim`（`unconsumed/consumed/invalidated`のField整合）、`ResultTaskBinding`（`provider_task | local_result`
  Discriminated Union）、Collection / Ingestion / Recovery / Cancel / Budget Record、Lease型（0C境界）。
- `execution/state_machine.py` — Provider / Collection / Ingestion の合法遷移表。
- `execution/records.py` — 各Object Integrity Digestの確定、Consumption ID / Progress / Cancel Intent Digest。
- `execution/adapter.py` — `ExecutionAdapter` Protocol、`ExecutionRequest`（Secret参照のみ）、`TaskHandle`、
  `ReconciliationResult`、`AdapterCollectionControl`、`MockExecutionAdapter`（Call Countと非秘密Metadataのみ記録）。
- `execution/secret_binding.py` — 直列化 / Copy / Pickle不可・redactする`_EphemeralSecretBinding`とzeroize。
- `execution/secret_source.py` — Composition所有の`open_version`のみ持つ`TrustedSecretSource`（汎用resolveなし）。
- `execution/dispatch_port.py` — 固定`TrustedAdapterDispatchPort`と`DispatchResultCapture`（非直列化TCB Capability）。
- `execution/secret_injection.py` — Durable Claim消費勝者だけに開くmodule-private・単回・非直列化Continuation。
- `execution/executor.py` — create（PLANNED→AUTHORIZED）、dispatch（pre-dispatch再検証、BLOCKED、Claim、消費、JIT注入）。
- `execution/collection.py` — Trusted Clock固定Authority、Streaming、状態機械、Ingestion開始、metadata-only recovery。
- `execution/ingestion.py` — 独立Ingestion状態、INGESTED_DURABLE Milestone、固定Rule create-or-verify、Retry予算。
- `execution/reconcile.py` — RECONCILINGへの遷移と不確実→OUTCOME_UNKNOWN、再送なし。
- `execution/recovery.py` — §21.1.1 Recovery Authority Matrixと§21.1.2単回Cancel。
- `execution/thread.py` — thread_id Lifecycle（Revisionごとの新run_id / thread_id、照合Fail Closed）。
- `execution/budget.py` — Durable Mission Execution Budget（OCC予約）。
- `storage/execution_db.py` — Phase 0B専用テーブルのLiteral SQL（UNIQUE / 部分UNIQUE Index / OCC UPDATE / Row Digest）。
- `storage/execution_repositories.py` — Write/Read Integrity＋Owner Guard＋Row-key Bindingを持つ12 Repository。
- `composition/execution_testing.py` — Phase 0B Test Composition（`build_phase0b_kernel`）。

変更（製品）:

- `canonical/digest_catalog.py` — Phase 0B Object / 明示Digestを一意登録。
- `storage/database.py` — Phase 0B専用テーブルの作成と公開`row_digest`。
- `storage/integrity.py` — Phase 0B familyのObject Integrity / Id-bound登録（未知typeはFail Closed維持）。
- `errors.py` — Phase 0B typed error群。

新規（試験）: `tests/support_phase0b.py`、`tests/unit/test_execution_models.py`、`test_streaming_sink.py`、
`test_thread_lifecycle.py`、`test_secret_binding.py`、`test_dispatch_port.py`、
`tests/integration/test_executor_dispatch.py`、`test_secret_injection.py`、`test_result_collection.py`、
`test_result_ingestion.py`、`test_reconciliation.py`、`test_recovery_cancel.py`、`test_budget.py`、
`test_finalizing_mission.py`、`test_crash_boundary.py`、`tests/security/test_execution_negative.py`、
`tests/property/test_execution_state_machine.py`。

## 3. 試験結果

実行環境: 現checkout、`.venv`（Python 3.14.6）。`redteam_agent`は未pip installのため`PYTHONPATH=src:tests`で実行。

| コマンド | 結果 |
| --- | --- |
| `.venv/bin/ruff check src tests scripts` | All checks passed |
| `PYTHONPATH=src .venv/bin/mypy`（package=redteam_agent, strict） | Success: no issues found in 98 source files |
| `.venv/bin/python -m compileall -q src tests` | exit 0 |
| `PYTHONPATH=src:tests .venv/bin/python -m pytest -q` | 384 passed（Phase 0A 269 + Phase 0B 115、warningなし） |
| `coverage run --branch -m pytest -q` + `coverage json` | line 5641/6175、branch 1223/1658、combined 87.6% |
| `scripts/verify_pydantic_contract.py` / `scripts/verify_wire_and_immutable.py` | いずれも exit 0 |
| `sha256sum -c SHA256SUMS` | 承認済みr3正本・別冊・受入 / 安全 / 脅威モデル文書・LICENSE・README すべて OK（無変更） |

既存Phase 0A試験は削除・skip・xfail化していない（269件が引き続きPASS）。

## 4. 受入条件（正本§36 Phase 0B / docs/acceptance-criteria.md）とTraceability

各条件の主な検証Test。すべてPASS。

| 受入条件 | 主なOwner / Test |
| --- | --- |
| Execution StateとResult Ingestion Stateを分離して永続化 | `execution/models.py`、`test_result_collection.py::test_collection_and_ingestion_states_are_separate_records`、`test_result_ingestion.py::test_ingestion_state_is_independent_of_provider_state` |
| 1 PolicyDecisionから2件目のExecution作成不可（DB強制） | `storage/database.py`（`executions.policy_decision_id UNIQUE`）、`test_executor_dispatch.py::test_one_decision_yields_one_execution`、`test_execution_negative.py::test_one_decision_one_execution_enforced_by_database` |
| Non-idempotentの不確実結果を自動再送しない | `test_reconciliation.py::test_uncertain_submit_goes_to_reconciliation_without_resubmit`、`test_crash_boundary.py::test_uncertain_submit_crash_reconciles_without_resubmit` |
| `reconcile()`不確実結果を`OUTCOME_UNKNOWN`へ | `execution/reconcile.py`、`test_reconciliation.py::test_uncertain_reconcile_maps_to_outcome_unknown`（UNKNOWN/UNSUPPORTED/NOT_FOUND_*） |
| Pre-dispatch不一致は`AUTHORIZED -> BLOCKED`・Provider Callなし・ExecutionResultなし | `execution/executor.py`、`test_executor_dispatch.py::test_pre_dispatch_mismatch_blocks_without_provider_call`、`::test_stale_authorization_epoch_blocks_dispatch` |
| `AUTHORIZED`はSecret権限でなく、未消費Claimを平文解放前にDurable消費したExecutor所有Txnだけが固定Port経由JIT注入 | `execution/executor.py` + `secret_injection.py` + `dispatch_port.py`、`test_secret_injection.py::test_secret_injected_just_in_time_via_fixed_port`、`::test_authorized_does_not_resolve_secret_until_claim_consumed` |
| Caller がBroker / Channel / Callbackを構築できず、Claim消費後Crash / 結果不明はReconciliationへ | `test_secret_injection.py::test_no_public_standalone_secret_resolver_or_broker`、`test_crash_boundary.py::test_uncertain_submit_crash_reconciles_without_resubmit` |
| Collection開始でTrusted Clock / exact Registry / ResultTaskBinding / Sink Authority固定、Caller Timestamp不受領、Tool上限を拡大しない | `execution/collection.py`、`test_result_collection.py::test_authority_fixes_deadline_retention_and_output_cap` |
| Model / Adapter / Repositoryが同じ`provider_task | local_result`を参照し両分岐受理・`local_capture` / 未知 / 欠落 / Mode不一致拒否 | `execution/models.py`、`storage/execution_repositories.py`、`test_execution_models.py`（binding系）、`test_dispatch_port.py::test_capture_mode_mismatch_rejected` |
| Quarantine RetentionはCollection開始時刻から一度だけ確定、Restartで再計算しない | `test_result_collection.py::test_retention_not_recomputed_on_resume` |
| External Side Effect NodeにLangGraph Automatic Retryなし（Executor単回Dispatch） | Executorは自動再送しない（`dispatch_attempts`≤1）。`test_reconciliation.py::test_uncertain_submit_goes_to_reconciliation_without_resubmit`。LangGraph Node設定自体はPhase 1（本Phaseにグラフなし） |
| Raw ResultをChunk Streaming、全量Memory保持なし | `execution/sink.py`、`test_streaming_sink.py::test_streams_without_buffering_whole_result` |
| Crash後はResult ingestionだけ再開、External Action再実行しない | `test_crash_boundary.py::test_restart_after_dispatch_does_not_resubmit`、`::test_collection_resume_after_commit_is_metadata_only` |
| REQUIRE_APPROVALは一致するApprovalなしdispatch不可、承認後もDecision不変 | `test_executor_dispatch.py::test_require_approval_without_record_is_not_authorized`、`::test_require_approval_with_record_dispatches` |
| Mission Revision変更でrun_id / thread_idが変化 | `execution/thread.py`、`test_thread_lifecycle.py` |
| Goal達成時の直接COMPLETED遷移を拒否（FINALIZING Skeleton） | `test_finalizing_mission.py::test_goal_achieved_cannot_go_directly_to_completed`、`::test_finalizing_skeleton_...` |
| 旧Authorization EpochのDecision / ApprovalをDispatchに使えない | `test_executor_dispatch.py::test_stale_authorization_epoch_blocks_dispatch` |
| Grant / Snapshot Persistence RetryがDeterministic ID / Idempotent Upsertで重複を作らない | 決定論的Idempotency Key（`test_executor_dispatch.py::test_idempotency_key_is_deterministic_and_bound`）、ExecutionResult upsert冪等（`test_result_ingestion.py::test_reingest_is_create_or_verify_idempotent`） |
| valid_until後もrecovery_untilまで継続、新Action Dispatch不可 | `test_recovery_cancel.py::test_recovery_window_allows_continuation_but_not_new_dispatch` |
| Finalization Cancelはexact Execution / Task / OperationへBindingしたRecovery AuthorityなしにAdapter到達不可、単回消費 | `execution/recovery.py`、`test_recovery_cancel.py::test_cancel_requires_bound_recovery_authority`、`::test_single_consume_cancel_attempt` |
| Sink Commit後・Metadata確定前はCOMMITTED_METADATA_PENDINGでmetadata-only recoveryのみ | `test_crash_boundary.py::test_collection_resume_after_commit_is_metadata_only` |
| ABANDONEDからProvider Result再取得せず終端 | `test_result_collection.py::test_abandon_from_streaming_is_terminal` |
| Durable Mission Execution Budget（OCC） | `execution/budget.py`、`test_budget.py` |

## 5. 独立レビュー

Codexは固定コミット`1a7178862fb8aece6ef29788798181bccc0eca4c`を対象に、正本§36 / §40.1、
受入条件、実コード、Repository制約、Positive / Negative / Failure-path / Property試験を照合した。
最初の指摘で打ち切らず、Claude Codeの初期実装に対して次の全指摘を記録し、固定前に修正と回帰試験を行った。

| 重要度 | 指摘 | 対応結果 |
| --- | --- | --- |
| BLOCKER | Callerが構築可能なClaim tokenと公開Secret source / dispatch surfaceからContinuationを偽造できた | 公開token / transactionを廃止し、Repository上のconsumed Claim、exact Consumption ID、Execution Version、Secret集合を再検証するprivate単回Continuationへ変更。CompositionはSecret source / portを公開しない |
| BLOCKER | `local_result`がCaptureを永続Bindingへ結合せず、Inline結果をCollectionへ渡せなかった | Dispatch前にLocal Binding / Authority / Sinkを固定し、同じ`capture_id`でStreaming・Control metadata commit・Ingestion開始まで通す。Crash後は保存済みmetadataだけで再開する試験を追加 |
| HIGH | Durable Mission BudgetがDispatch Claim transactionへ接続されず、未設定時に無制限実行できた | Budget予約をClaim作成と同一Unit of Workへ移し、未設定・枯渇時はいずれもExecutionを`AUTHORIZED`に保ったままClaim / Provider callなしで停止 |
| HIGH | valid / recovery windowとRecovery Authorityのexact binding検証が不足していた | Mission / Revision / Epoch / Origin authorization / Adapter / Idempotency key / Expected Execution Version / Task / Operation / TTLを再取得して完全照合し、境界時刻とcross-binding試験を追加 |
| HIGH | Result resume / cancellation bindingがExecution・Sink・Modeを横断して再利用できた | Resume cursor / cancellationをexact Execution、Collection、Task digest、Sink、Delivery modeへBindingし、cross-sink / cross-execution拒否試験を追加 |
| HIGH | Adapter submit / reconcile結果のIdentity・Mode・Task・Normalization rule検証が不足していた | 固定Adapter identity、Provider identity、Task ID、Delivery mode、Provider task、Execution ID、Task digest、登録Normalization ruleを状態変更前に検証 |
| HIGH | Model組合せ不変条件とDB参照整合が不足していた | Pydanticの相互Field validatorとExecution配下テーブルのForeign Keyを追加し、無効な状態組合せ・不正Union・Row tamperのNegative試験を追加 |

修正後の再レビューではBLOCKER / HIGH 0、未解決仕様矛盾 0、Security-critical TODO 0を確認した。
実C2 / MCP / Targetへの外部操作はなく、全試験はMock Adapterだけで実施した。

### Common Gate / 安全不変条件

Unit / Integration / Security / Property-State-machine PASS、ruff / mypy / compileall PASS、Branch Coverage取得、
既存Test非削除、独立レビュー後BLOCKER / HIGH 0、実C2 / MCP / 外部Target Side Effect 0（Mock Adapterのみ）、
Secret Leakage 0（`test_execution_negative.py::test_secret_plaintext_absent_from_all_durable_rows`、
`test_secret_injection.py::test_no_plaintext_in_adapter_records_or_repository`）。
Owner限定書込（`test_execution_negative.py::test_forged_execution_write_without_owner_guard_rejected`）、
Row Integrity（`::test_row_tamper_detected_on_read`）、非直列化Capability（`::test_capabilities_are_not_serializable`）。

## 6. 設計との整合メモ（矛盾ではない、適用限界の明示）

- **Sinkは同期実装**: 正本§10のRawResultSink / Adapter Protocolは`async def`で示されるが、Phase 0A〜0Bの
  カーネルは同期で、Event Loopを持たない。Phase 0BはChunk Streaming・全量非Buffer・Idempotent Commitという
  不変条件を同期で満たす。実AdapterのAsync境界はPhase 4 / 5で扱う。
- **Quarantineは暗号化せずhash-and-discard**: Phase 0Bは暗号化Quarantine Store / 実Erasureを持たない（Phase 0C）。
  Sinkは走行Digestとサイズだけを保持し平文を破棄する。ExecutionResultはProjection Metadataから構成する。
- **Ingestion成功はDELETE_PENDING（INGESTED_DURABLE Milestone）まで**: 実Erasure（`DELETE_PENDING`以降の
  QUARANTINE_ERASED / SUCCEEDED）とManifest公開証跡はPhase 0C。状態機械の合法辺は登録済みだがEraserは未実装。
- **Lease / Fencing / 単調Clock / F6継続再認可はPhase 0C**: 型（`ResultCollectionLease` / `SecureIngestionLease` /
  `LeaseFence`）は安全境界として置くが、`ClockIntegrityError`・Deployment Epoch・Fencing・Heartbeat再認可は
  前倒ししない。Phase 0BのCollection所有はTrusted Clock固定Authority＋Collection State OCCで表現する。
- **pre-dispatchのSecret失効はGateが先に捕捉し得る**: Secret Revocation時はGateの認可再導出が失敗し
  `DIGEST_INTEGRITY_FAILURE`でBLOCKEDになる（Provider Call・Claim・ExecutionResultなし）。Executor固有の
  `SECRET_VERSION_STALE`は主にClaim消費時のRevocation Race（`dispatch_attempts=1`＋`invalidated` Claim）で用いる
  （`test_secret_injection.py::test_secret_head_change_at_consumption_blocks_with_invalidated_claim`）。
- **thread_id Lifecycleはヘルパとして提供**: Revisionごとのrun_id / thread_id生成と照合Fail Closedを実装。
  実際のGraph / Checkpoint統合はPhase 1。

## 7. 受入と残課題

- Phase 0Bの製品コードとUnit / Integration / Security / Property-State-machine試験を実装し、ruff / mypy /
  compileall / branch coverage / verify scripts / sha256sumを実行済み。
- 実装コミットを固定し、Claude Code実装プロセスから分離したCodexがRead-only Snapshot・実コード・試験Evidenceを
  正本と照合した。全指摘を修正し、Phase 0Bの必須受入条件は成立した。
- 未実行 / 未達（対象外）: Production暗号 / TPM / `swtpm`統合、実Erasure、Lease / Fencing Production Hardening、
  実Adapter Contract / Integration（Phase 4 / 5）、実LLM品質Gate（Phase 2）、D4実機Qualification（`NOT_EVALUATED`）。
- 未解決の仕様矛盾・仮実装・Security-critical TODO: なし（0C以降の機構は明示的に範囲外とし、PASS扱いしていない）。
- 次Phase範囲: Phase 0C（Data Security / Audit）。
