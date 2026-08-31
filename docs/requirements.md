# AI Development Loop Requirements

## Purpose

Codex CloudまたはChatGPTによる独立ReviewとCodexによる実装を、Phase 0AからPhase 5まで有限・監査可能・Fail Closedに反復する。OpenAI APIは使用せず、OperatorがChatGPT連携済みGitHub AccountでLocal Orchestratorを1回起動し、Provider Human Gateまたは完全検証済みの最終mergeまでPhase Loopを自動継続する。

## Functional Requirements

| ID | Requirement |
|---|---|
| LOOP-001 | 実装担当とReview担当のContext、権限、出力を分離する |
| LOOP-002 | 全ReviewをCI ready marker、Operator trigger、Current PR HEAD、Review中のhead不変性を検証してPRの最新40桁commit SHAへBindingする。Codex表示上の短縮SHAだけをBinding根拠にしない |
| LOOP-003 | Codexの完了報告ではなく、Git差分、CI、受入条件で判定する |
| LOOP-004 | Codex native reviewを検証後、Trusted Phase Gateが`PASS`、`CHANGES_REQUESTED`、`BLOCKED`を機械可読JSONとして記録する |
| LOOP-005 | Review Verdictのうち`CHANGES_REQUESTED`だけがCodex修正Requestを生成する。CI failureは同じPhaseの実装Requestを再発行できるが、Review PASSやPhase遷移として扱わない |
| LOOP-006 | CI成功時だけ独立AI Reviewを要求する |
| LOOP-007 | 同じSHAを重複Review・重複修正しない |
| LOOP-008 | Phaseごとに最大5回、同じRoot Causeは最大3回で停止する |
| LOOP-009 | Phase GateをPASSするまで次Phaseを開始しない。自動遷移は`ai-review-passed` marker中だけnext Phaseを先に追加してからcurrent Phaseを個別削除し、marker中の1件または隣接2件のPhaseをRunnerが遷移中として待機する。完全Label置換を使用せず、無関係な並行Label writeを上書きしない。競合によりmarker、HEAD、open state、Phase隣接性が崩れた場合はFail Closedにする |
| LOOP-010 | Phase 0A、0B、0C、1、2、3、4、5の順序を固定する |
| LOOP-011 | Phase 4/5の未設定外部依存はHuman Gateで停止する |
| LOOP-012 | 最終mergeはLocal Orchestratorだけが、Phase 5のCurrent-HEAD PASS、Phase 0A～5の完全なSHA Chain、必須Check、Trusted Status、Current Default Branch包含を検証し、PR/完全HEAD固定のGit ref claimとBinding Recordを作成後に同じGateを再取得・再検証してから、Expected HEAD SHA固定で1回だけ実行する |
| LOOP-013 | Loop停止・再開操作をGitHub Label/Workflowで提供する |
| LOOP-014 | PR、Review、Test、Finding、Phase遷移の履歴をGitHubへ保持する |
| LOOP-015 | Codexが仕様・Gate・Workflowを変更して自己合格できないよう保護する |
| LOOP-016 | Local Orchestratorは`github-actions[bot]`が作成したCurrent Phase/HEAD SHA固定Requestだけを受理し、ChatGPT連携済みGitHub UserとしてCodex実装・Reviewを要求する |
| LOOP-017 | Local Orchestratorはnative reviewer identity、P0/P1またはno-finding形式、ready/trigger、Phase、HEAD SHA、Base SHA、Review中のhead不変性を検証してから、承認者制限付きPhase Gate Workflowを起動する |
| LOOP-018 | Phase 4/5はProvider Human Gate承認前に開始せず、承認後は同じLoopを再起動して当該Phaseを自動実行できる |
| LOOP-019 | Active PRのCurrent Phaseはexact phase label、`github-actions[bot]`のCurrent-HEAD実装Request、Current HEADへ包含された隣接Prior-Phase PASSから解決する。複数PASSはGit祖先関係で唯一の最大候補だけをPhase Baseとし、コメント順やDefault Branch上のStatus Snapshotを遷移権限として使用しない |
| LOOP-020 | 次Phase実装前にDefault Branchが進んだ場合、Approver限定WorkflowがPrior PASSと同じExpected HEADへ固定したStatusを記録し、Local Orchestratorだけが競合しない単一の遷移Identityと全PR状態を前後検証してPhaseを1つ戻し、Expected HEAD固定でBase Refreshした後の新HEADでGateを再実行する。Refresh履歴が複数ある場合は旧HEADとtarget baseの両方の祖先関係で唯一の最大遷移だけをReview Baseに採用し、並行または曖昧な履歴を拒否する |
| LOOP-021 | Base RefreshはPR BranchへDefault Branchを取り込む操作に限定し、Final PR Merge APIを呼び出さない |
| LOOP-022 | Governance PR、Fork PR、Phase未完了、Stop Label、Stale/Unknown/Ambiguous Evidence、Default Branch未包含時は自動mergeしない。CodexとGitHub ActionsにはFinal Merge APIを与えない |
| LOOP-023 | Final Merge API呼出し前に、PR番号と完全HEAD固定のRepository Git ref claimを原子的に作成し、PR番号、完全HEAD、Default Branch SHA、Phase 5 Gate、Policy Digest、Actor、Claim RefへBindingした永続Attempt RecordをPRへ保存する。同じPR/HEADのClaim/Recordが存在・作成結果不明、または取得後GateにDrift/Unknownがあれば、明示的Reconciliationなしに再送しない |

## Non-Functional Requirements

- Private Repositoryを前提とする。
- Fork PRでは実装Workflowを起動しない。
- GitHub TokenをCodex実行環境へ渡さない。
- Local OrchestratorのGitHub認証は`gh`のCredential Storeだけを使用し、Token Valueを引数、Prompt、Logへ出さない。
- API Key、C2/MCP資格情報、Secret ValueをPrompt、PR、Artifact、Logへ含めない。
- Repository/PR contentをPrompt Injection可能な非信頼入力として扱う。
- 全自動処理は取消可能で、最大回数とTimeoutを持つ。
- Local Orchestrator停止中もGitHub上のMarker/Label/Reviewを正本とし、同じCommandで再開できる。
- Deterministic CheckはCI、意味的・Security ReviewはCodex CloudまたはChatGPTが担当する。
- Web Event Taskはローカル実行を行わず、GitHub上の差分とCI Evidenceを確認する。

## Project Phase Requirements

実装仕様のSource of Truthは`SystemDesign.md`と`docs/acceptance-criteria.md`である。Phase Promptは当該Phaseの範囲を狭める実行指示であり、仕様を緩和しない。
