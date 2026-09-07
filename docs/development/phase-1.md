# Phase 1 Agent Loop 開発記録

## 対象

- 設計正本: `SystemDesign.md` Phase 1、`SystemDesign_AI_Control.md`、`docs/acceptance-criteria.md`
- 基点: `0a12cf9d790d7c81ea676fc39ba9ba337793194c`（Phase 0C受入記録）
- 実装対象: `5884942`、`753b2fe`、`7865b2a`、`98a3bd2`、`43699ff`、`3a59791`
- 最終実装コミット: `3a59791b7e351bd463fab3913ce07ed6ba23db5a`

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

## AI-01〜12 / AC-01〜20対応

閉じたPlanner Output、Application生成ID、Context非権限化、Current Snapshot再検証、Policy/Executorの独立認可、
Observation/Hypothesis/Verified Finding分離、三値Goal、有限ActionContract探索、永続Budget、単回Dispatch、
stale Epoch拒否、FINALIZING収束を、`test_phase1_planner_context.py`、`test_phase1_mock_loop.py`、
`test_phase1_state_controls.py`、既存security/property/regression suiteで検証した。参照モデルの結果だけを
受入根拠にせず、公開callerに対するreplay、stale、scope false、未取込、未消去、unknown semanticのnegative pathを含む。

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
  PASS: 163 source files
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

独立レビューは実装と別ContextのCodexが固定コミットのfresh snapshotで実施する。初回指摘のstale Gateway、
Action replay、未取込/未消去Finalization、Finalization再開、Verified Finding / AD Goal、Workflow caller、
Working State消費順序を修正し、各negative pathを追加した。最終判定と固定review artifactは独立レビュー完了後に
`docs/reviews/`へ記録する。
