# Phase 1 Agent Loop 開発記録

## 対象

- 設計正本: `SystemDesign.md` Phase 1、`SystemDesign_AI_Control.md`、`docs/acceptance-criteria.md`
- 基点: `0a12cf9a702303f1b9ca87c702141addb996ae87`（Phase 0C受入記録）
- 実装範囲: 基点の次から最終実装コミットまで
- 最終実装コミット: `a22302824ff6a918d421b2c31347b6448033e6ca`

## 実装と受入要件

| 要件 | 実装 / Evidence |
| --- | --- |
| Mission→Planner→Policy→Executor→Analyzer→Goal | `Phase1AgentWorkflow`、`test_phase1_mock_loop.py` |
| Context Grant / Tool Snapshot前後検証 | `PlannerContextService`、`test_phase1_planner_context.py`、`test_phase1_context_builder.py` |
| Scope外・UnavailableのProvider到達拒否 | `PlannerActionApplicationService`、Phase 0A/0B Policy・Executor negative suite |
| Bounded Context Request / typed Retrieval Hint | Envelope lineage、durable context retry budget、Pydantic closed union tests |
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
| Finalization | Result collection、ingestion、verified erasure、unresolved item、Goal、Audit、Witnessを再検証し、`FINALIZING`から再開可能 |
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
| AI-08 | RECOVERを既存ExecutionのReconciliationへ接続。Mock loop recovery assertion、crash/reconciliation suite |
| AI-09 | Planner Context/Action/epoch/OCC binding。Planner context tests、atomic invalid→valid retry probe |
| AI-10 | 種類別durable retry budgetとMission dispatch budget。state controls、budget suite |
| AI-11 | Mission Manager、Goal Evaluator、Source owner、typed unresolved resolutionへ所有権を固定。Mock loop、mission lifecycle suite |
| AI-12 | 正常Mock loopとscope/stale/replay/tamper negativeを別試験として実行。zero-metrics suite |

## AC-01〜20 対応

| ID | 主な試験 Evidence |
| --- | --- |
| AC-01 | `test_goal_controller_plans_then_finalizes_from_current_session_source`、Mock loopのPlannerなしFINALIZE |
| AC-02 | `test_finite_prerequisite_search_uses_observer_for_unknown_predicate`、Mock loopの通常認可・結果確認 |
| AC-03 | `test_scope_false_action_never_reaches_mock_adapter` |
| AC-04 | prerequisite searchのunknown observer選択、Planner ContextのCurrent source再検証 |
| AC-05 | `test_unconfirmed_observation_does_not_change_goal_or_witnessed_fact_head` |
| AC-06 | Source owner以外からのFact更新拒否、typed unresolved owner-source resolution |
| AC-07 | Analyzer confidenceをObservation以外のGoal/Policy入力にしない型・Reducer経路 |
| AC-08 | Phase 1 context builder positive/negative、context authorization suite |
| AC-09 | Mock Analyzer候補分離、semantic catalog unknown rejection、publication-rule negative suite |
| AC-10 | Goal Evaluatorの三値集約とControllerの`not_achieved`経路、success-condition validation suite |
| AC-11 | finite prerequisite searchの固定上限・循環key、`PLANNING_SEARCH_LIMIT`分岐 |
| AC-12 | bounded Context Request、種類別retry budget、同一operation replay tests |
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
  PASS: 553 tests（swtpm 7件を含む）

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
最終判定と固定review artifactは再レビュー完了後に`docs/reviews/`へ記録する。
