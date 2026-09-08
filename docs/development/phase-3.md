# Phase 3 Human Approval / Durable Resume 開発記録

## 対象

- 設計正本: `SystemDesign.md` §17.3 / §18 / §21 / §21.1〜§21.1.3 / §22 / §22.1〜§22.2 / §23、`docs/acceptance-criteria.md` Phase 3（294〜303行）、`docs/safety-invariants.md`、`docs/threat-model.md`
- 設計改訂: `system-design-v1-r3` / `ai-control-v1-r3`
- 基点: Phase 2 受入コミット `d89739a`（`docs/development/phase-2.md` / `docs/reviews/phase-2-common-gate-66f55ba.md`、Phase 3移行 `PERMITTED`）
- 実装ブランチ: `codex/phase-3-human-approval-durable-resume`
- 実装対象コミット: `897f553badfcf5debcc1eab9d3c7d803cc083090`（実装 + 試験）
- 実装範囲: Phase 0A〜2 の型・Test Double境界を保存したまま、Human Approval の完全表示・厳密Binding強制と、停止 / レビュー中Mission の Durable Resume 照合・引継ぎを実装する。新しいWorkflow状態・Graph・永続Record・認可経路・重複Serviceは追加しない。実 C2 / MCP / 外部Target / Credential / Payload / Implant / Detection Evasion 機構は実装しない。Phase 4 / 5 は実装しない。

## 実装方針

Phase 3 の Approval / Recovery / Mission Lifecycle の型と大半の強制は Phase 0A〜1 で「安全な型 / Test Double境界」として既に存在する。本Phaseは以下の狭い差分だけを追加し、既存の不変条件・単一Service / 単一Graph構成を保存する。

1. `Phase1AgentWorkflow.durable_resume` — PAUSED / WAITING_HUMAN_REVIEW Mission を既存 RECONCILING 経路と Current Recovery Authority だけで照合する Durable Resume。新規 Dispatch / Planner / Analyzer 呼出しを 0 件とする。
2. `FinalizationService.advance_from_human_review` — 全Unresolved Item が RESOLVED のときだけ `WAITING_HUMAN_REVIEW -> FINALIZING`（§21.1.3）を取り、元の終了理由を保持する。
3. `Phase1AgentWorkflow` へ `context_resolver` / `clock` を注入（構成 `composition/phase1.py`）。

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
| Resume時に Checkpoint -> Application DB -> Adapter の順に照合 | `Phase1AgentWorkflow.durable_resume` / `_durable_resume_targets` / `execution/reconcile.py`。`tests/integration/test_phase3_durable_resume.py::test_durable_resume_consults_checkpoint_then_appdb_then_adapter` |
| 既存 RECONCILING を PAUSED / WAITING_HUMAN_REVIEW に対応、Current Recovery Authority のみ、RUNNINGへ変更せず新規 Dispatch / LLM 0件 | `durable_resume` は `_reconcile`（Recovery Authority発行）だけを使い Planner / Executor.dispatch を呼ばない。`test_durable_resume_reconciles_paused_mission_without_dispatch_or_llm`（`submit_calls == 1`固定） |
| 不明な非冪等Actionを自動再実行しない | `ReconciliationService` の不明 -> `OUTCOME_UNKNOWN`。`test_durable_resume_reconciles_paused_mission_without_dispatch_or_llm` |
| 照合後は Current Mission に対応する Graph状態へ戻し開始Snapshotで上書きしない | `durable_resume` は照合後に Repository から再読込し `_GRAPH_STATE_BY_MISSION_STATE`（§17.3）で写像。Mission状態変化を Fail Closed で拒否 |
| WAITING_HUMAN_REVIEW 全Item解決時にだけ既存 FINALIZING へ進め、通常Resumeへ暗黙遷移しない | `FinalizationService.advance_from_human_review`。`test_durable_resume_advances_to_finalizing_once_all_items_resolved` / `test_durable_resume_holds_waiting_review_while_items_are_open` / `test_durable_resume_handoff_preserves_the_original_terminal_reason` / `test_advance_from_human_review_fails_closed_while_items_unresolved` |
| Recovery期限後は Provider Read を行わない（§21.3） | `durable_resume` の `recovery_until` 判定。`test_durable_resume_after_recovery_window_makes_no_provider_read`（`reconcile_calls` 不変） |
| Crash境界（RECONCILING commit後 / Adapter前）を再送なしで回復 | `test_durable_resume_recovers_from_a_crash_between_reconciling_and_adapter`（RECONCILING durable → 再開で `SUCCEEDED`、`submit_calls == 1`） |
| WAITING_HUMAN_REVIEW -> FINALIZING の OCC | `MissionManager._transition`（`expected_version` / `expected_epoch`）。`test_review_exit_edge_is_occ_guarded` |

## 試験 Command と結果

すべて `PYTHONPATH=src` / 固定 `.venv` で実行。

```text
.venv/bin/ruff check .                                  PASS
PYTHONPATH=src .venv/bin/mypy                            PASS: 196 source files
PYTHONPATH=src .venv/bin/mypy --strict src              PASS: 193 source files
.venv/bin/python -m compileall -q -f src tests scripts  PASS
PYTHONPATH=src scripts/verify_pydantic_contract.py      PASS
PYTHONPATH=src scripts/verify_wire_and_immutable.py     PASS
PYTHONPATH=src .venv/bin/python -m pytest tests         PASS: 800 passed / 7 skipped
  （新規 Phase 3: tests/integration/test_phase3_durable_resume.py 11 + tests/security/test_phase3_approval.py 10 = 21 passed）
PYTHONPATH=src .venv/bin/coverage run --branch -m pytest / coverage report   PASS: 17,004 statements / 4,460 branches / 86%
```

- `7 skipped` は `tests/integration/test_swtpm_witness.py` の swtpm / tpm2-tools 未導入による環境Skipで、Phase 3 実装とは無関係。既存Testの削除・skip・xfail化は行っていない（追加のみ）。
- 実 C2 / MCP / 外部Target への Side Effect は 0 件。Durable Resume / Approval Test はすべて決定論的 Test Double（`MockExecutionAdapter`）で完結し、Secret 平文の露出はない。

## 独立レビュー

- 独立 Codex レビュー（Read-only Snapshot・実コード・試験Evidence）は本実装会話と分離した別Sessionで実施する Common Gate の必須条件であり、本記録時点では未実施（PENDING）。実装対象コミットは `897f553badfcf5debcc1eab9d3c7d803cc083090` に固定する。
- したがって本記録は技術Gate（Unit / Integration / Security / Recovery Test・ruff・mypy・compileall・branch coverage）の成立だけを主張し、Common Gate PASS / Phase 3 受入完了は独立レビュー完了まで主張しない。

## 受入根拠・残課題

- Phase 3 の全受入条件（承認境界・Epoch単調増加・非再利用・Checkpoint->App DB->Adapter照合・不明Outcome非再送・停止 / レビュー状態保存・§21.1.3 引継ぎ）を実コードと決定論Testで確認済み。
- 残課題 / 未検証:
  - 独立 Codex レビューが未実施（上記）。
  - D4 実機消去は引き続き `NOT_EVALUATED`。Production採用は別条件。
  - Phase 4（承認済み C2 Adapter）/ Phase 5（承認済み MCP Adapter）は本Phase対象外で未実装。実Adapter / Provider Human Gate は保持する。
  - `swtpm` / tpm2-tools 未導入環境では Witness 統合 Test が Skip される（本Phaseの範囲外）。
