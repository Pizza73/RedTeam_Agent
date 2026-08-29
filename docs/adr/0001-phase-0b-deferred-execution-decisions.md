# ADR 0001: Phase 0B以降へ保留するExecution境界

- Status: Proposed / Deferred
- Date: 2026-08-29
- Scope: Phase 0B以降

## Context

Phase 0AはAuthorization Kernelまでであり、外部副作用、Provider Task、Raw Result、
Quarantine、C2/MCP/vLLM統合を実装しない。次の事項をPhase 0Aの都合で確定すると、
後続AdapterやRecovery要件を誤って拘束する。

## Deferred decisions

| ID | 未決事項 | Phase 0Aでの扱い | 確定Phase |
| --- | --- | --- | --- |
| D-01 | `ExecutionRequest.request_digest`のDigest対象 | Model自体を未実装 | 0B |
| D-02 | Effective TimeoutとTool / Adapter / Mission上限の優先順位 | ToolDefinitionのdefault/max検証だけ実装 | 0B |
| D-03 | Effective Output Limitの計算 | ToolDefinitionの正値上限だけ実装 | 0B |
| D-04 | `ExecutionLifecycleState`の最終命名 | Execution State Modelを未実装 | 0B |
| D-05 | `DISPATCHED -> CANCEL_REQUESTED` | Cancel API/遷移を未実装 | 0B |
| D-06 | Synchronous Providerの直接Terminal遷移 | Provider実行を未実装 | 0B |
| D-07 | `RawResultSink.commit()`の責任主体 | Interface/Quarantineを未実装 | 0B/0C |
| D-08 | Quarantine物理Storage Backend | Metadata Tableも本体も未実装 | 0C |
| D-09 | 実C2製品選定 | Adapterを未実装 | 4 |
| D-10 | MCP Python SDKとTasks Extension実Version | Dependencyへ未追加 | 5 |
| D-11 | vLLM / Pydantic AI実Version | Runtime Dependencyへ未追加 | 2 |

## Decision

上記事項はPhase 0Aで仮実装しない。Phase 0AのExecutorは
`authorize_execution()`だけを提供し、常に`dispatch_performed=False`を返す。
後続Phaseでは本ADRを置換する個別ADRとFailure/Recovery Testを先に追加する。

