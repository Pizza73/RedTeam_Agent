# Phase 1 Agent Loop 開発記録

## 対象

- 設計正本: `SystemDesign.md` Phase 1、`SystemDesign_AI_Control.md`、`docs/acceptance-criteria.md`
- 基点: `0a12cf9a702303f1b9ca87c702141addb996ae87`（Phase 0C受入記録）
- 実装範囲: 基点の次から最終実装コミットまで
- 最終実装コミット: `28896ae5a4ab8ded665941cb5e0abd4b878f327f`

## 実装と受入要件

| 要件 | 実装 / Evidence |
| --- | --- |
| Mission→Planner→Policy→Executor→Analyzer→Goal | `Phase1AgentWorkflow`のcompiled LangGraph、`tests/integration/test_phase1_mock_loop.py::test_mock_agent_loop_reaches_goal_through_real_policy_and_executor` |
| Coarse Agent Graph / retry境界 | `tests/integration/test_phase1_mock_loop.py::test_phase1_uses_compiled_coarse_graphs_without_automatic_retry`。Planning 12 node、Analysis 8 nodeを実経路に接続し、LangGraph automatic retryは全nodeで未設定 |
| Analyzer Context / Source Binding | Analyzer用Selector→Grant→Builderと、callback前のexact Execution/Result Digest検証、callback後のsource Execution一致を強制。正常loop内のforged digest / planner grant negative oracle |
| Context Grant / Tool Snapshot前後検証 | `PlannerContextService`、`test_phase1_planner_context.py`、`test_phase1_context_builder.py` |
| Scope外・UnavailableのProvider到達拒否 | `PlannerActionApplicationService`、Phase 0A/0B Policy・Executor negative suite |
| Bounded Context Request / typed Retrieval Hint | Envelope lineage、durable context retry budget、Pydantic closed union tests |
| Stale Context再構築 | Planning Graphの`context_rebuild`でCurrent Goal / Tool Snapshot / Context Selection / Grant / Bodyを所有Serviceから再構築。Context Requestと同じ系譜別の永続2回上限を共有し、再構築後EnvelopeをPlanner callbackへ直接渡す |
| Durable Graph checkpoint | `langgraph-checkpoint-sqlite==3.1.1`を固定し、Planning / Analysis Graphを同一Application SQLiteの専用接続へ保存。checkpoint stateはOperation / Repository Record IDとrouting文字列だけに限定し、業務RecordやContext本文を保存しない。checkpoint schemaは明示provisioning対象とし、通常起動時の暗黙migrationを拒否 |
| Canonical run / thread binding | Planning / Analysisのcheckpoint load前とAction適用前に、Current Mission Revision、Application `run_id`、`thread_id = mission_id:mission_revision:run_id`を照合。Malformed、別Revision、別runからの再利用を副作用前に拒否 |
| Plan Thread / Working Hypothesis OCC | `PlannerStateManager`、`test_phase1_state_controls.py` |
| Strong-key Entity解決 / Alias candidate | `EntityResolver`、`test_phase1_state_controls.py` |
| Analyzer再Binding / Observation分離 | `KnowledgeReducer`、`test_phase1_mock_loop.py`、`test_phase1_knowledge.py` |
| Verified Fact / Finding | `VerifiedFindingProjector`は成功・取込・消去完了済みExecutionだけを確認済みFindingへ投影し、Knowledge headをCritical mutationとして更新 |
| Versioned Semantic Catalog | `SemanticCatalog`、unknown predicate rejection test |
| ActionContract / finite prerequisite search | `FinitePrerequisiteSearch`、実行直前Predicate Snapshot再検証 |
| Shared LLM Gateway / attempt reservation | `SharedLLMGateway`、同一InputのOperation ID差替えとstale Contextをcallback前に拒否 |
| D10 failure accounting | `ExecutionOutcomeAccountingService`、Execution作成順・取込完了後・一度だけ適用 |
| retry境界分離 | context / persistent commit / dispatch / collection / ingestion / reconciliationの永続Budgetを別Keyで管理 |
| AD Principal Context Goal | Current Active Session、exact principal、Session Managerが確認した登録済みAD Group SIDを同時要求。Group証明なしを拒否 |
| Finalization | 終了理由を固定し、期限到達は`ABORTED`、Goal達成は`COMPLETED`へ収束。`tests/integration/test_phase1_mock_loop.py::test_finalizing_cancelled_execution_collects_ingests_and_completes`と`::test_finalizing_resume_uses_bounded_reconciliation_and_cancel` |
| 有限Recovery停止 | RUNNING/FINALIZINGの予算枯渇をexact Execution固定のUnresolved Itemと`WAITING_HUMAN_REVIEW`へ収束。`tests/integration/test_phase1_mock_loop.py::test_running_recovery_budget_exhaustion_converges_to_human_review` |
| 最大Iteration | Planner iterationをdurable dispatch budgetへ一致させ、ControllerがMission上限で停止 |

## AI-01〜12 対応

| ID | 製品経路 / 主な試験 Evidence |
| --- | --- |
| AI-01 | Analyzer候補を`KnowledgeObservation`へ隔離。`test_unconfirmed_observation_does_not_change_goal_or_witnessed_fact_head`、Mock loop |
| AI-02 | Goal、前提探索、Policy/Executorを別Serviceで評価。Controller、prerequisite search、Mock loop |
| AI-03 | Current candidate/target/scope/epochを再検証。`test_planner_action_cannot_select_another_target`、`test_scope_false_action_never_reaches_mock_adapter` |
| AI-04 | Verified Findingはowner resultだけから生成しKnowledge headを更新。Phase 1 knowledge security tests、再投影idempotency assertion |
| AI-05 | Context Grantと本文Digestを分離。`test_context_builder_reads_only_the_body_bound_by_verified_grant`、grantなしnegative |
| AI-06 | 全ActionをPolicy→Executor→Claimへ接続。Mock loop、Phase 0A/0B gate negative suite |
| AI-07 | 実Executionの取込・消去完了後だけFact投影。Mock loopのpre-ingestion/pre-erasure rejection |
| AI-08 | RECOVERを既存Executionの予算付きReconciliationへ接続。Mock loop recovery/finalizing retry assertion、crash/reconciliation suite |
| AI-09 | Planner Context/Action/epoch/OCC binding。Planner context tests、atomic invalid→valid retry probe |
| AI-10 | 種類別durable retry budgetとMission dispatch budget。state controls、budget suite |
| AI-11 | Mission Manager、Goal Evaluator、Source owner、exact Execution固定のunresolved eventへ所有権を固定。Mock loop、mission lifecycle suite |
| AI-12 | 正常Mock loopとscope/stale/replay/tamper negativeを別試験として実行。zero-metrics suite |

## AC-01〜20 対応

| ID | 主な試験 Evidence |
| --- | --- |
| AC-01 | `test_goal_controller_plans_then_finalizes_from_current_session_source`、Mock loopのPlannerなしFINALIZE |
| AC-02 | `test_finite_prerequisite_search_uses_observer_for_unknown_predicate`、Mock loopの通常認可・結果確認 |
| AC-03 | `test_scope_false_action_never_reaches_mock_adapter` |
| AC-04 | prerequisite searchのunknown observer選択、Planner ContextのCurrent source再検証 |
| AC-05 | `test_unconfirmed_observation_does_not_change_goal_or_witnessed_fact_head` |
| AC-06 | Source owner以外からのFact更新拒否、exact Execution固定のappend-only unresolved owner event |
| AC-07 | Analyzer confidenceをObservation以外のGoal/Policy入力にしない型・Reducer経路 |
| AC-08 | Phase 1 context builder positive/negative、context authorization suite |
| AC-09 | Mock Analyzer候補分離、semantic catalog unknown rejection、publication-rule negative suite |
| AC-10 | Goal Evaluatorの三値集約とControllerの`not_achieved`経路、success-condition validation suite |
| AC-11 | finite prerequisite searchの固定上限・循環key、`PLANNING_SEARCH_LIMIT`分岐 |
| AC-12 | bounded Context Request、種類別retry budget、FINALIZING reconciliation 3回上限、同一operation replay tests |
| AC-13 | target差替え、epoch変更、snapshot/approval staleのnegative suite |
| AC-14 | Mock loop RECOVER、`test_uncertain_submit_goes_to_reconciliation_without_resubmit`、crash suite |
| AC-15 | Verified Finding再投影idempotency、Analyzer候補失敗がowner Factを変更しない境界 |
| AC-16 | pause/resume epoch rotation、paused Context/Dispatch rejection |
| AC-17 | budget claim transaction、exhaustion、OCC conflict tests |
| AC-18 | Knowledge head tamper、selective DB rollback、swtpm rollback tests |
| AC-19 | closed Planner schema/unknown field rejection、legacy compatibility recordsを認可入力にしないarchitecture checks |
| AC-20 | 正常Mock loopがPlan→Dispatch→Ingestion→Goal→COMPLETEDへ到達。安全停止だけを成功扱いしない |

Phase 1固有の状態遷移Evidenceは、Mock loop内の`PLAN → RECOVER → FINALIZE → FINALIZING再開 → COMPLETED`、
`test_lifecycle_matches_reference_model`、`test_provider_edges_match_independent_oracle`を組み合わせる。参照モデルの
PASSだけでは受入とせず、同じ公開Serviceに対するscope、stale、replay、未取込、未消去、任意unresolved解消の
negative pathも実行する。

## 検査結果

最終実装コミットの作業ツリーで次を実施した。

```text
PATH=/tmp/phase0c-tpm/usr/bin:$PATH \
LD_LIBRARY_PATH=/tmp/phase0c-tpm/usr/lib/x86_64-linux-gnu:/tmp/phase0c-tpm/usr/lib/x86_64-linux-gnu/swtpm \
PYTHONPATH=src .venv/bin/python -m pytest -q -ra
  PASS: 567 tests（swtpm 7件を含む）

.venv/bin/python -m ruff check src tests
  PASS
.venv/bin/python -m mypy
  PASS: 164 source files
.venv/bin/python -m compileall -q src tests
  PASS
PYTHONPATH=src .venv/bin/python scripts/verify_pydantic_contract.py
  PASS
PYTHONPATH=src .venv/bin/python scripts/verify_wire_and_immutable.py
  PASS
sha256sum -c SHA256SUMS
  PASS
coverage run --branch -m pytest / coverage report
  PASS: branch coverage取得、総合86%
```

既存testの削除、skip、xfail化はない。実C2 / MCP / 外部Targetへの通信は行わず、Mock/local adapterだけを使用した。

## レビュー

独立レビューは実装と別ContextのCodexが固定コミットのfresh snapshotで実施する。`a808f11`対象の初回判定は
BLOCKER 0 / HIGH 2 / MEDIUM 3でFAILだった。任意Unresolved解消・cross-mission付替え、Workflow未接続、
Verified Finding再投影、古いコミット参照、要件対応表を`a22302824ff6a918d421b2c31347b6448033e6ca`で修正した。
再レビューで残ったexact Execution未固定、監査Event不足、期限/FINALIZING回復未収束を
`6eb667966620139eb027874408d59d50935fed82`で修正した。terminal cancelの収集・取込・消去、RUNNING/
FINALIZING recovery予算枯渇のHuman Review収束、実LangGraph接続、Phase 1生成的状態遷移Evidenceを
`0b95281e5dc4d8780c4a74ebf28b1e05818a580e`で追加した。独立プローブで検出したAnalyzer Context/
Result Source未固定を`f28dd0206b39063becef6bb9c9549b5ae48501e8`で修正した。
Analyzer LLM入力をexact Grant DigestとGrant-bound Context本文へ固定する追補を
`6b7287c003b08e96269bf27f90c6a9f1e9a1d846`で追加した。
LangGraph型境界のdirect `mypy --strict src`も`5332515e69b7e1e4fdc095d342188de43c7a0253`で
警告なしに固定した。
残ったMedium指摘のStale Envelope再構築とGraph checkpoint未永続化は
`c9a52ce301942e939414b4181067acac1e652d3f`で修正した。再構築は既存Context retry budgetを共有し、
SQLite checkpointにはIDとrouting文字列だけを保存する。最終独立判定はこの固定コミットを対象に実施する。
その再レビューで検出したcheckpoint / ExecutionPlanの非canonical thread受入は
`6bb647642b7e351835383ff4a812fa25c9f1fc68`で修正した。Planning / Analysis / Action適用の三境界で
Current Mission Revisionとrun / threadを照合し、別Revision・別runのcheckpoint reuseを拒否する。
公開Context再構築を直接呼んだ場合の旧Revision retry budget先行消費は
`28896ae5a4ab8ded665941cb5e0abd4b878f327f`で修正し、Current Revision照合を予算予約より前へ固定した。
固定コミット`1b658a132669d4e0b6e5bf51ea3b0b14dc9823ad`（最終実装
`28896ae5a4ab8ded665941cb5e0abd4b878f327f`）に対する最終独立再レビューは、
BLOCKER 0 / HIGH 0 / MEDIUM 0 / LOW 0、Common Gate PASS、Phase 2移行可と判定した。
固定証跡は`docs/reviews/phase-1-common-gate-1b658a1.md`、SHA256は
`624d0b1518a11dc2bda5c131c72d85df2397970652550d99c0cdc85a3b34dac8`。
D4実機REK消去はPhase 1 Gateの対象外で未評価のため、Production有効化は別途その物理適格性確認を要する。

## Phase 1生成的状態遷移Evidence

`tests/property/test_phase1_agent_state_machine.py::TestPhase1AgentStateMachine::runTest`は、公開Workflowを
`plan_once`、`reconcile_uncertain_execution`、`reach_hard_limit`、`resume_finalization`、
`stale_working_state_update_is_atomic`の規則で生成的に駆動する。独立Oracleは、Provider submitが最大1回、
reconciliation消費が最大3回、予算枯渇時のexact source Unresolved eventが1件、Missionが
`WAITING_HUMAN_REVIEW`へ収束、stale Working State失敗時にrow不変、Graph checkpointerが永続Objectを
保持せず、IDとrouting文字列だけを保持することを検査する。これを次の固定node IDと組み合わせてAI/ACの状態変更Evidenceとする。

| Oracle | 固定pytest node ID |
| --- | --- |
| compiled Graph、node接続、side-effect自動retryなし | `tests/integration/test_phase1_mock_loop.py::test_phase1_uses_compiled_coarse_graphs_without_automatic_retry` |
| Stale Contextの上限付き再構築、再構築後EnvelopeのPlanner入力、checkpointのprimitive state | `tests/integration/test_phase1_mock_loop.py::test_stale_planner_context_is_rebuilt_before_the_model_call`、`tests/integration/test_phase1_planner_context.py::test_automatic_stale_rebuild_shares_the_lineage_retry_budget` |
| 同一Application SQLiteへのcheckpoint永続化、通常起動時の未知schema拒否 | `tests/integration/test_phase1_mock_loop.py::test_graph_checkpoints_are_written_to_the_application_sqlite_file`、`tests/integration/test_production_composition.py::test_unknown_graph_checkpoint_schema_fails_closed_no_migration` |
| Malformed / 別Revision / 別run threadのcheckpoint load前拒否、Action前の再検証 | `tests/integration/test_phase1_mock_loop.py::test_workflow_rejects_malformed_wrong_revision_and_reused_run_threads`、`tests/integration/test_phase1_planner_context.py::test_action_rejects_noncanonical_thread_before_consuming_context`、`tests/unit/test_thread_lifecycle.py::test_verify_run_thread_binding_rejects_reused_thread_for_another_run` |
| 旧Mission Revisionの直接Context再構築をretry budget予約前に無変更拒否 | `tests/integration/test_phase1_planner_context.py::test_old_revision_rebuild_is_rejected_before_retry_budget_reservation` |
| 正常 Plan→Dispatch→Ingest→Analyze→Goal→COMPLETED | `tests/integration/test_phase1_mock_loop.py::test_mock_agent_loop_reaches_goal_through_real_policy_and_executor` |
| terminal cancel→Collection→Ingestion→Erasure→COMPLETED | `tests/integration/test_phase1_mock_loop.py::test_finalizing_cancelled_execution_collects_ingests_and_completes` |
| FINALIZING recovery上限→Unresolved→Human Review | `tests/integration/test_phase1_mock_loop.py::test_finalizing_resume_uses_bounded_reconciliation_and_cancel` |
| RUNNING recovery上限→Finalization Intent→Human Review | `tests/integration/test_phase1_mock_loop.py::test_running_recovery_budget_exhaustion_converges_to_human_review` |
| Controller/Finalization/Unresolved/Working State生成系列 | `tests/property/test_phase1_agent_state_machine.py::TestPhase1AgentStateMachine::runTest` |
| Context grant/body/current snapshot negative | `tests/security/test_phase1_context_builder.py::test_context_builder_cannot_read_body_without_stored_grant`、`tests/integration/test_phase1_planner_context.py::test_epoch_change_invalidates_planner_context_before_model_use` |
| Analyzer forged Result Digest / wrong service Grantのcallback前拒否 | `tests/integration/test_phase1_mock_loop.py::test_mock_agent_loop_reaches_goal_through_real_policy_and_executor` |
| uncertain submit/reconcileで再送なし | `tests/integration/test_reconciliation.py::test_uncertain_submit_goes_to_reconciliation_without_resubmit` |
