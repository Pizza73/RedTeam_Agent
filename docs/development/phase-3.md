# Phase 3 Human Approval / Durable Resume 開発記録

## 対象

- 設計正本: `SystemDesign.md` §17.3 / §18 / §21 / §21.1〜§21.1.3 / §22 / §22.1〜§22.2 / §23、`docs/acceptance-criteria.md` Phase 3（294〜303行）、`docs/safety-invariants.md`、`docs/threat-model.md`
- 設計改訂: `system-design-v1-r3` / `ai-control-v1-r3`
- 基点: Phase 2 受入コミット `d89739a`（`docs/development/phase-2.md` / `docs/reviews/phase-2-common-gate-66f55ba.md`、Phase 3移行 `PERMITTED`）
- 実装ブランチ: `codex/phase-3-human-approval-durable-resume`
- 実装対象コミット: `897f553badfcf5debcc1eab9d3c7d803cc083090`（初版 実装 + 試験）、`99437ef294a9a40dda5861f1a87f80aa10e3c747`（第1次レビュー対応: LangGraph Checkpoint駆動のDurable Resumeへ改修）、`a8820705619ec8475299e0df5e85476e7a7f5299`（第2次レビュー対応: 全未完了Execution照合・実Checkpoint内容検証・graph内FINALIZING引継ぎ）、`dfe3d11a8fc11122545760c7d0e2f6ce22bdfe51`（受入後再レビュー対応: Approval単一割当・同一pass finalization・local-result非Adapter照合）、`a612cecefe8fd7db0a21842212ed245c113fe38d`（独立レビュー対応: Approval一意Indexの本番起動検査）
- 最終独立レビュー: `docs/reviews/phase-3-common-gate-a612cec.md`、Common Gate `PASS`、Phase 3 `ACCEPTED`
- 実装範囲: Phase 0A〜2 の型・Test Double境界を保存したまま、Human Approval の完全表示・厳密Binding強制と、停止 / レビュー中Mission の Durable Resume 照合・引継ぎを実装する。新しいWorkflow状態・Graph・永続Record・認可経路・重複Serviceは追加しない。実 C2 / MCP / 外部Target / Credential / Payload / Implant / Detection Evasion 機構は実装しない。Phase 4 / 5 は実装しない。

## 実装方針

Phase 3 の Approval / Recovery / Mission Lifecycle の型と大半の強制は Phase 0A〜1 で「安全な型 / Test Double境界」として既に存在する。本Phaseは以下の狭い差分だけを追加し、既存の不変条件・単一Service / 単一Graph構成を保存する。

1. `Phase1AgentWorkflow.durable_resume` — Compiled Planning Graph と LangGraph SqliteSaver が Workflow Resume を所有する。Canonical `thread_id = mission_id:mission_revision:run_id` でGraphを再Invokeし実Checkpointを復元、`AgentController` が PAUSED / WAITING_HUMAN_REVIEW + 未完了ExecutionをRECOVERへ経路付け、既存 `reconciliation` node が Application DB（Execution State の正）→ Adapter の順で照合する（§17.1）。新規 Dispatch / Planner / Analyzer 呼出しを 0 件とし、MissionをRUNNINGへ遷移させない。認証済みOperator権限（R18）とCanonical Binding・実Checkpoint存在を必須とし、誤Mission / Revision / ThreadはFail Closed。
2. `FinalizationService.advance_from_human_review` — 全Unresolved Item が RESOLVED のときだけ `WAITING_HUMAN_REVIEW -> FINALIZING`（§21.1.3）を取り、元の終了理由を保持する。
3. `AgentController.step` が PAUSED / WAITING_HUMAN_REVIEW の未完了Executionを既存RECOVER経路（`ACTIVE_EXECUTION_STATES`）へ経路付け（Plan / Dispatch / RUNNING遷移なし）。`MissionManager.authorize_operator` を追加。`Phase1AgentWorkflow` へ `context_resolver` / `clock` / `mission_manager` を注入（構成 `composition/phase1.py`）。

既存の `ExecutorAuthorizationGate` / `evaluate_executable` / `MissionManager`（Epoch回転）/ `ReconciliationService`（不明 -> `OUTCOME_UNKNOWN`）/ `ExecutionRecoveryService`（PAUSED / WAITING_HUMAN_REVIEW対応）は変更せず、Phase 3 受入境界を明示Testで確認する。

## 実装と受入要件

| 受入要件（Phase 3） | 実装 / Evidence |
| --- | --- |
| 不変な ApprovalRequest / ApprovalRecord と request / policy / authorization / execution / presentation / epoch / revision / TTL の厳密Binding | `approval/models.py`、`approval/service.py`（`build_approval_request` / `build_approval_record` / `evaluate_executable`）。`tests/security/test_phase3_approval.py` |
| `REQUIRE_APPROVAL` は一致する有効 `APPROVED` Record なしでは Dispatch 不可 | `executor/authorization_gate.py`、`execution/executor.py`。`tests/security/test_phase3_approval.py::test_unapproved_action_never_reaches_the_adapter` / `::test_revoked_approval_blocks_dispatch_before_the_adapter` |
| `DENY` は Record があっても実行不可 | `evaluate_executable`。`tests/security/test_phase3_approval.py::test_deny_decision_is_never_executable_even_with_an_approved_record` |
| Plan / Intent 変更で Approval 無効 | Gate の proposal / authorization digest 再導出と presentation 一致。`tests/security/test_phase3_approval.py::test_plan_intent_change_invalidates_prior_approval_at_the_gate` |
| Expiry / Replay / 誤Digest / 誤Epoch / 誤Revision / 誤Binding を Fail Closed | `evaluate_executable`。`tests/security/test_phase3_approval.py`（rejected / expired / replayed / wrong_authorization_digest / wrong_epoch_and_revision / ttl_exceeding） |
| 未承認ActionはAdapterへ到達しない | `test_unapproved_action_never_reaches_the_adapter`、`test_revoked_approval_blocks_dispatch_before_the_adapter`（`mock_adapter.submit_calls == 0`） |
| PAUSED / Resume で `authorization_epoch` 増加・`mission_revision` 不変 | `mission/manager.py`、`mission/models.py`（`EPOCH_ROTATING_EDGES`）。`tests/integration/test_phase3_durable_resume.py::test_pre_pause_decision_and_approval_are_not_reused_after_resume` |
| PAUSED前の Grant / Snapshot / Decision / Approval を再利用しない | Gate の Epoch / Revision 照合。同上（resume後の stale decision は `AUTHORIZATION_EPOCH_STALE` / `PLAN_EPOCH_STALE`） |
| Resume時に LangGraph Checkpoint -> Application DB -> Adapter の順に照合し、実Checkpoint内容（mission_id / mission_revision / run_id）を現在Repository・Canonical threadへ検証 | `durable_resume` が `self._checkpointer.get` の実Checkpoint `channel_values` を検証（§17.2、不一致で `MissionRevisionConflictError`）→Graph再Invoke→`_graph_reconciliation`（DBから未完了Execution列挙）→`execution/reconcile.py`（Adapter）。graph state に `mission_revision` / `run_id` を追加し通常Planningが書込む。`test_durable_resume_reads_checkpoint_then_appdb_then_adapter`、`test_durable_resume_rejects_a_checkpoint_bound_to_another_mission`（foreign mission / wrong revision / wrong run、DB変更・Adapter Read前にFail Closed）、`test_durable_resume_restores_a_persisted_checkpoint_in_a_new_kernel`（file-backed SQLite + 新Kernelで実Checkpoint復元） |
| 既存 RECONCILING を PAUSED / WAITING_HUMAN_REVIEW に対応、全未完了Executionを決定論順でTask Binding別に各1回照合、Current Recovery Authority のみ、RUNNINGへ変更せず新規 Dispatch / Planner / Analyzer 0件 | `AgentController.step`（PAUSED/WAITING_HUMAN_REVIEW→RECOVER）+ 既存 `reconciliation` node（DBから全未完了Execution列挙・各1回`_reconcile`）。`test_durable_resume_reconciles_paused_via_langgraph_checkpoint`、`test_durable_resume_reconciles_every_incomplete_execution_exactly_once`（2 Execution各1回・binding一致・`submit_calls`不変）、`test_durable_resume_makes_zero_planner_and_analyzer_calls`（LLM Gateway spyでPlanner/Analyzer 0件） |
| 不明な非冪等Actionを自動再実行しない | `ReconciliationService` の不明 -> `OUTCOME_UNKNOWN`。`test_durable_resume_reconciles_paused_mission_without_dispatch_or_llm` |
| 照合後は Current Mission に対応する Graph状態へ戻し開始Snapshotで上書きしない。並行の正当な変化は拒否せず写像 | `durable_resume` は照合後に Repository から再読込し `_GRAPH_STATE_BY_MISSION_STATE`（§17.3）で写像。状態変化を拒否せず、自身はRUNNING遷移を行わない。`test_durable_resume_maps_a_concurrent_resume_without_rejecting_it`（並行Operator Resumeの決定論的Interleaving） |
| Workflow Resume は LangGraph Checkpoint が所有・Canonical thread_id / Mission・Revision Binding検証・誤Thread Replay拒否 | `durable_resume` が `self._checkpointer.get` で実Checkpoint必須化、`verify_run_thread_binding`、Revision不一致で `MissionRevisionConflictError`。`test_durable_resume_requires_an_actual_langgraph_checkpoint` / `test_durable_resume_rejects_a_malformed_or_foreign_thread` |
| 明示Operator Resume Triggerの認証・認可 | `MissionManager.authorize_operator`（Operator Role必須）。`test_durable_resume_requires_an_authenticated_operator` |
| WAITING_HUMAN_REVIEW 全Item解決時にだけ既存 FINALIZING へ進め、通常Resumeへ暗黙遷移しない。引継ぎは graph finalization node が所有（LangGraph単一所有） | `_graph_finalization`（WAITING_HUMAN_REVIEW + 未Active + 全RESOLVEDで `advance_from_human_review` + 既存FINALIZING drive、元の終了理由保持）/ `FinalizationService.advance_from_human_review`。`test_durable_resume_advances_to_finalizing_once_all_items_resolved`（graph内でABORTED終端まで）/ `test_durable_resume_holds_waiting_review_while_items_are_open` / `test_advance_from_human_review_fails_closed_while_items_unresolved` |
| Recovery期限後は Provider Read を行わない（§21.3） | `durable_resume` の `recovery_until` 判定。`test_durable_resume_after_recovery_window_makes_no_provider_read`（`reconcile_calls` 不変） |
| Crash境界（RECONCILING commit後 / Adapter前）を再送なしで回復 | `test_durable_resume_recovers_from_a_crash_between_reconciling_and_adapter`（RECONCILING durable → 再開で `SUCCEEDED`、`submit_calls == 1`） |
| WAITING_HUMAN_REVIEW -> FINALIZING の OCC | `MissionManager._transition`（`expected_version` / `expected_epoch`）。`test_review_exit_edge_is_occ_guarded` |

## 試験 Command と結果

すべて `PYTHONPATH=src` / 固定 `.venv` で実行。

```text
.venv/bin/ruff check .                                  PASS
PYTHONPATH=src .venv/bin/mypy                            PASS: 194 source files（固定snapshot）
PYTHONPATH=src .venv/bin/mypy --strict src              PASS: 193 source files
.venv/bin/python -m compileall -q -f src tests scripts  PASS
PYTHONPATH=src scripts/verify_pydantic_contract.py      PASS
PYTHONPATH=src scripts/verify_wire_and_immutable.py     PASS
PATH=<isolated-swtpm>/usr/bin:$PATH ... pytest -o addopts= -q -ra  PASS: 816 passed / 0 skipped
  （新規 Phase 3: tests/integration/test_phase3_durable_resume.py 20 + tests/security/test_phase3_approval.py 10 = 30 passed）
同一swtpm環境で coverage run --branch / coverage report  PASS: 17,013 statements / 4,458 branches / 86.516696940059%
```

- 隔離済み`swtpm` / `tpm2-tools`を用いてWitness 7件も実行し、skip 0を確認した。既存Testの削除・skip・xfail化は行っていない（追加のみ）。
- 実 C2 / MCP / 外部Target への Side Effect は 0 件。Durable Resume / Approval Test はすべて決定論的 Test Double（`MockExecutionAdapter`）で完結し、Secret 平文の露出はない。

## 独立レビュー

- 独立 Codex レビューが初版 `897f553` に対して BLOCKER 2件を報告した。
  - BLOCKER 1: Durable Resume が Application OCC Checkpoint（`AgentController.checkpoint`）を読み、`_reconcile` を命令的Loopで直接呼んでおり、LangGraph Checkpoint / 既存 RECONCILING node による Workflow Resume を実装・証明していなかった。
  - BLOCKER 2: 照合後に現在Mission状態が entry_state と異なると例外を送出しており、並行の正当な Resume / Finalization による状態変化を拒否していた。
- 対応コミット `99437ef294a9a40dda5861f1a87f80aa10e3c747`:
  - Compiled Planning Graph + LangGraph SqliteSaver を Workflow Resume の所有者とし、Canonical `thread_id` で再Invoke・実Checkpoint必須化・Mission/Revision/Thread検証・誤Thread Replay拒否を実装。既存 `reconciliation` node が DB→Adapter順で照合。認証済みOperator権限を必須化。file-backed SQLite + 新Kernelでの復元Testを追加。
  - 照合後は現在Repository状態を写像し、変化を拒否しない。durable_resume自身はRUNNING遷移を行わない。並行Resumeの決定論的Interleaving Testを追加。
- 独立 Codex 第2次レビューが `99437ef` に対して HIGH 2件を報告した。
  - HIGH 1: `_graph_reconciliation` が全未完了ExecutionをDB列挙しながら `active[0]` だけを照合しており、複数未完了時に1件のみ照合して完了報告し得た（§17.1）。
  - HIGH 2: Canonical thread_id を caller run_id + 現在Missionから計算し、その計算値を `verify_run_thread_binding` で検証していたためTautologicalで、実際に永続化されたCheckpoint内容（channel_values の mission_id / revision / run）を検証していなかった（§17.2）。
- 対応コミット `a8820705619ec8475299e0df5e85476e7a7f5299`:
  - `_graph_reconciliation` を全未完了Execution（execution_id昇順・決定論）を各1回Task Binding別に照合するよう改修。AUTHORIZED破棄 / PLANNED Fail-closed / OUTCOME_UNKNOWN読取照合 / Retry予算枯渇 / RUNNING時のみのHuman Review Escalationを保持。
  - graph state に `mission_revision` / `run_id` を追加し通常Planningが書込む。`durable_resume` は `SqliteSaver` の実Checkpoint `channel_values` を現在Repository・Canonical threadへ照合し、foreign mission / wrong revision / wrong run / corrupt を DB変更・Adapter Read前に `MissionRevisionConflictError` でFail Closed。
  - WAITING_HUMAN_REVIEW -> FINALIZING 引継ぎを graph finalization node（Mission Manager + 元の durable intent）内へ移し、LangGraph を単一Workflow所有者として維持。認証済みOperator Triggerは維持。
  - 決定論的Regression（複数Execution各1回照合・binding一致、実Checkpoint内容拒否、zero Planner / zero Analyzer）を追加。file-backed restart Testは引き続きPASS。
- 上記対応後、Codexが実装`a882070`を再レビューし、swtpm 7件を含む全816件、branch coverage、ruff、configured / direct strict mypy、compileall、boundary検証、SHA256SUMS、依存整合性を独立に再実行した。指摘残数はBLOCKER / HIGH / MEDIUM / LOWすべて0、Common Gate `PASS`、Phase 3 `ACCEPTED`。詳細は`docs/reviews/phase-3-common-gate-a882070.md`。

## 受入後再レビュー対応（2026-09-09）

`a882070`受入後の再レビューでBLOCKER 1件・HIGH 2件を検出し、`dfe3d11a8fc11122545760c7d0e2f6ce22bdfe51`で修正した。

- ApprovalRequestごとのHuman DecisionをSQLiteの部分Unique IndexとRepository検査で単一割当にし、矛盾するAPPROVED / REJECTED Recordを順序・caller指定IDに関係なく拒否する。DB一意制約を競合時の線形化点とする。
- planning graphの`reconciliation`から既存`finalization` nodeへ接続し、最後のExecutionが同じ照合passでterminalになった場合も、全Item RESOLVEDなら追加Triggerなしで`WAITING_HUMAN_REVIEW -> FINALIZING`へ進める。
- `LocalResultBinding`は`ExecutionAdapter.reconcile()`へ渡さず、durable capture / receipt / control metadataだけで照合する。確定済みmetadataはterminalへ収束し、不完全captureはAdapter非接触で`OUTCOME_UNKNOWN`とする。
- 回帰試験を6件追加し、Phase 3専用36件をPASS。全体は815 passed / 7 skipped（ローカル環境にswtpm / tpm2-toolsがないためWitness 7件をskip）、ruff、configured mypy 196 files、direct strict mypy 193 files、compileall、boundary検証、SHA256SUMS、依存整合性をPASSした。
- 独立レビューで、本番read-only起動検査がApproval一意Indexの欠落を検出しないHIGH 1件を追加検出。`a612cec`でIndex定義全体の検査と回帰試験を追加した。
- 隔離swtpm 7件を含む全823件をskip 0でPASSし、branch coverage 86.549272870882%、ruff、configured / direct strict mypy、compileall、boundary検証、SHA256SUMS、依存整合性をPASSした。未解決指摘は0、Common Gate `PASS`、Phase 3 `ACCEPTED`。詳細は`docs/reviews/phase-3-common-gate-a612cec.md`。

## 受入根拠・残課題

- 再レビュー修正版`a612cec`に対するCommon Gateは`PASS`し、Phase 3を再受入した。Phase 4は承認済みC2 ProviderのProvider Human Gate完了まで保留する。
- 残課題 / 未検証:
  - D4 実機消去は引き続き `NOT_EVALUATED`。Production採用は別条件。
  - Phase 4（承認済み C2 Adapter）/ Phase 5（承認済み MCP Adapter）は本Phase対象外で未実装。実Adapter / Provider Human Gate は保持する。
