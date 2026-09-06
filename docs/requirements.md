# AI Development Loop Requirements

## Purpose

実装と独立Reviewを別々のローカルCodex CLI Workerで行い、Phase 0AからPhase 5まで有限・監査可能・Fail Closedに反復する。OperatorはTrusted Local Orchestratorを1回起動し、通常の実装・Reviewには人間の都度承認を要求しない。Codex Cloud Task / GitHubの`@codex` Trigger / Cloud ReviewへのFallbackは使用しない。RepositoryによるOpenAI API呼出しやAPI Key連携は追加しないが、ローカル実行は推論のOffline化を意味せず、Codex CLIのChatGPT Account認証とModel通信は必要である。Provider / Design Human GateとGovernance Reviewは維持する。

## Functional Requirements

| ID | Requirement |
|---|---|
| LOOP-001 | 実装担当とReview担当のContext、権限、出力を分離する |
| LOOP-002 | 全ReviewをCI ready marker、Launcherが記録する単一RunのStart / Result Evidence、Current PR HEAD、Review中のhead不変性を検証してPRの最新40桁commit SHAへBindingする。Base SHA、Source / Policy / Audit Digest、異なるWorker SessionもBindingし、短縮SHAやModelの自己申告だけを根拠にしない |
| LOOP-003 | Codexの完了報告ではなく、Git差分、CI、受入条件で判定する |
| LOOP-004 | LauncherのOperator GitHub Accountで認証された`local-review-v1`のStart / Result Evidenceを独立再検証後、Trusted Phase Gateが`PASS`、`CHANGES_REQUESTED`、`BLOCKED`を機械可読JSONとして記録する。`codex-native-v1`は移行前の既存Gate Chainを検証する履歴形式だけとし、新規Cloud Reviewを要求しない |
| LOOP-005 | Review Verdictのうち`CHANGES_REQUESTED`だけがCodex修正Requestを生成する。修正Requestは単一Formal Review内の全P0/P1の件数、Reference、不変条件ファミリーを列挙し、Codexは全件と同じSemantic Invariantを共有する全public entry point・caller・sibling pathを修正する。`finding_key`はRetry判定専用で修正範囲を縮小しない。CI failureは同じPhaseの実装Requestを再発行できるが、Review PASSやPhase遷移として扱わない |
| LOOP-006 | CI成功時だけ独立AI Reviewを要求する。`ai-loop-blocked`中のHEADではCIは検証結果だけを確定し、Review Ready markerやレビュー待ちLabelを生成しない |
| LOOP-007 | 同じSHAを重複Review・重複修正しない |
| LOOP-008 | Phaseごとに最大5回、同じexact Root Causeも最大5回で停止する。これとは別に、同じSemantic Invariant Familyが2回目のFormal Reviewへ再出現した時点で局所修正を停止し、通常Resume不能な`DESIGN_CHANGE_REQUIRED` Human Gateへ送る |
| LOOP-009 | Phase GateをPASSするまで次Phaseを開始しない。自動遷移は`ai-review-passed` marker中だけnext Phaseを先に追加してからcurrent Phaseを個別削除し、marker中の1件または隣接2件のPhaseをRunnerが遷移中として待機する。完全Label置換を使用せず、無関係な並行Label writeを上書きしない。競合によりmarker、HEAD、open state、Phase隣接性が崩れた場合はFail Closedにする |
| LOOP-010 | Phase 0A、0B、0C、1、2、3、4、5の順序を固定する |
| LOOP-011 | Phase 4/5の未設定外部依存はHuman Gateで停止する |
| LOOP-012 | 最終mergeはLocal Orchestratorだけが、Phase 5のCurrent-HEAD PASS、Phase 0A～5の完全なSHA Chain、必須Check、Trusted Status、Current Default Branch包含を検証し、PR/完全HEAD固定のGit ref claimとBinding Recordを作成後に同じGateを再取得・再検証してから、Expected HEAD SHA固定で1回だけ実行する |
| LOOP-013 | Loop停止・再開操作をTrusted Workflowで提供する。Lifecycle Labelは状態の表示・操作導線だけに使用し、Current-HEAD Request / Gate / Approvalを代替する認可証拠にしない |
| LOOP-014 | PR、Review、Test、Finding、Phase遷移の履歴をGitHubへ保持する |
| LOOP-015 | Codexが仕様・Gate・Workflowを変更して自己合格できないよう保護する |
| LOOP-016 | Local OrchestratorはClean Current Mainから実行し、`github-actions[bot]`が作成したCurrent Phase/HEAD SHA固定Requestだけを受理してローカルWorkerを起動する。Implementationは別CheckoutのWorkspace Write、ReviewはFresh Context / Read-only Snapshotとし、ModelへGitHub Credential、Runner状態やRemote Write権限を渡さない。Phase Gate成功後の通常Commit / PR PushとWorkflow DispatchはRunnerだけが行う |
| LOOP-017 | Local Orchestratorは全Phaseで1回の網羅Reviewを要求し、Reviewerは最初の指摘で停止せず単一Resultへ全P0/P1を保持する。Launcherが実際のWorker終了、Fresh Session、Read-only実行、Source不変性を確認し、Operator-authenticated Evidenceを公開する。Orchestratorと承認者制限付きPhase Gate Workflowは単一Run、全Finding、ready/start/result、Phase、HEAD / Base、Digest、Review中のhead不変性を独立に検証し、人間の都度承認なしでGateを記録する。これはOperator Host / Sandbox / LauncherをRoot of TrustとするProcess / Context分離であり、Operatorから独立したReviewer Accountの証明ではない |
| LOOP-018 | Phase 4/5はProvider Human Gate承認前に開始せず、承認後は同じLoopを再起動して当該Phaseを自動実行できる |
| LOOP-019 | Active PRのCurrent Phaseはexact phase label、`github-actions[bot]`のCurrent-HEAD実装Request、Current HEADへ包含された隣接Prior-Phase PASSから解決する。複数PASSはGit祖先関係で唯一の最大候補だけをPhase Baseとし、コメント順、Lifecycle Label、Default Branch上のStatus Snapshotを遷移権限として使用しない |
| LOOP-020 | 次Phase実装前にDefault Branchが進んだ場合、Approver限定WorkflowがPrior PASSと同じExpected HEADへ固定したStatusを記録し、Local Orchestratorだけが競合しない単一の遷移Identityと全PR状態を前後検証してPhaseを1つ戻し、Expected HEAD固定でBase Refreshした後の新HEADでGateを再実行する。Refresh履歴が複数ある場合は旧HEADとtarget baseの両方の祖先関係で唯一の最大遷移だけをReview Baseに採用し、並行または曖昧な履歴を拒否する |
| LOOP-021 | Base RefreshはPR BranchへDefault Branchを取り込む操作に限定し、Final PR Merge APIを呼び出さない |
| LOOP-022 | Governance PR、Fork PR、Phase未完了、Stop Label、Stale/Unknown/Ambiguous Evidence、Default Branch未包含時は自動mergeしない。CodexとGitHub ActionsにはFinal Merge APIを与えない |
| LOOP-023 | Final Merge API呼出し前に、PR番号と完全HEAD固定のRepository Git ref claimを原子的に作成し、PR番号、完全HEAD、Default Branch SHA、Phase 5 Gate、Policy Digest、Actor、Claim RefへBindingした永続Attempt RecordをPRへ保存する。同じPR/HEADのClaim/Recordが存在・作成結果不明、または取得後GateにDrift/Unknownがあれば、明示的Reconciliationなしに再送しない |
| LOOP-024 | Phase 0B～3のblocked cumulative HEADがCurrent default branch上の必須Governanceを含まない場合、Approver限定WorkflowはCurrent-Phase `BLOCKED_LIMIT` Gate、そのGateの唯一の隣接Base PASS、旧HEAD、Current default-branch SHAを検証したStatusだけを発行する。Local OrchestratorはPhase Labelを戻さずExpected HEAD固定でBaseを取り込み、両祖先関係とCurrent-HEAD Checkを検証する。非Design Stopだけが同Gate permalinkへBindingしたbounded Resumeへ進める。Invariant Family再発のDesign Stopは停止を維持し、LOOP-027～029の専用Design Approvalを要求する |
| LOOP-025 | 新しい実装・修正RequestはCurrent Phaseの不変条件ファミリー監査を必須化する。CodexはFormal Review前に各Required Familyのentry point、sibling path、invariant evidence、positive/negative/failure testを閉じたJSONへ記録し、Stateful Family変更時はproperty-basedまたはstate-machine testを追加する。CIはRequest、出力HEAD、監査DigestをBindingしてからready markerを発行する |
| LOOP-026 | Formal ReviewはSHA-bound不変条件監査をrouting evidenceとしてのみ使用し、各Familyを独立に再検証する。各P0/P1はTrusted Policy中のFamily IDを1件だけ保持し、Trusted GateはPhase内のFamily再発を機械的に集計する |
| LOOP-027 | Invariant Family再発による`BLOCKED_LIMIT`は`DESIGN_CHANGE_REQUIRED`終端状態とし、通常の`Resume AI Loop`、過去のbase-refresh Status、旧bounded Resumeを認可に使用しない。最新のTrusted Current-Phase Gateが常に過去Evidenceへ優先する |
| LOOP-028 | Design Stop後の再開はApprover限定の専用操作で、停止Gate permalink、Current Phase、Current 40桁HEAD、承認済みDesign commit / permalink、Policy DigestへBindingした単回`DESIGN_APPROVED` recordを発行する。RecordのUnknown Field、Duplicate Key、Stale Head、未包含Design、再利用を拒否する |
| LOOP-029 | Base Refresh Authorizationは1回のExpected-HEAD Branch Updateだけを認可し、ResumeまたはImplementation Requestを認可しない。更新後はApprover限定WorkflowがCurrent HEADの直前1 Edgeについて、2親Mergeの第1親がPrevious HEAD、第2親が認可済みDefault SHAであり、第1親に対応するTrusted Authorizationがあることを検証し、Current HEAD、Previous HEAD、Default SHA、Phase pair、Blocking GateをDigest Bindingした`BASE_REFRESH_APPLIED` StatusをCurrent HEADへ発行する。Design Stop中の後続Governance取込はCurrent HEAD上の単一Checkpointからだけ同じGateを継承し、Checkpoint未発行中は`REFRESH_AWAITING_CONFIRMATION`として実装・Resume・次Refreshを禁止する。単回Design Approvalを消費したImplementation Requestの出力は通常の子CommitとしてCurrent-HEAD CIとReviewへ進み、新たな2親Checkpointを要求しないが、Resumeまたは次Refreshの権限は継承しない。RunnerはTransition消費、最新Gate、Stop latch、Current HEADを各Remote Write後とLocal Worker起動直前に再取得し、Design StopまたはAuthority Driftがあれば`ai-loop-blocked`を維持して停止する。Lifecycle Projectionだけの遅延・残存はTrusted Transitionが正規化する |
| LOOP-030 | Runnerの次ActionはCurrent Phase / HEADへBindingされたTrusted Implementation Request、Review Ready、Phase Gate、Design Approvalの決定論的優先順位から一度だけ解決する。Transient Labelの到着順やProcess MemoryをAction認可に使用せず、同一Evidenceの再処理は冪等No-opとする |
| LOOP-031 | SystemDesign.md §38の再利用・置換・新規実装方針を、新規Requestの`invariant_audit.implementation_strategy_version=1.0`と既存監査JSONの同Versionの`implementation_strategy`へ引き渡す。各単位の入力HEAD上のFile、現行Output / Entry Point / 兄弟経路、Owner、分類理由、現行規範参照、Family、移行影響、保持する試験、追加試験、変更前後を記録する。CIは閉じたSchema、Input File存在、全変更Source / Test Path・Affected Familyの網羅、試験種別を検証し、Request / Output HEAD / Audit DigestへBindingする。分類記録だけを適合証明にはしない |
| LOOP-032 | 新Policyの実装Requestは旧PolicyへDowngradeしない。旧Request / Auditは祖先・停止・Refreshの履歴確認用に読めるが、新規実装・Review Readyの必須分類を省略する権限にはしない。規範別冊SystemDesign_AI_Control.mdも保護対象にし、Human Governance Reviewなしに実装AIが書き換えられないようにする。Phase順序、停止上限、Design Approval、既存データ保護は変更しない |
| LOOP-033 | ローカルWorkerの起動・終了・結果公開はUnique Run / SessionとCurrent RequestまたはReadyへBindingする。既存Run、重複・再利用・曖昧なResult、Process Crash / Timeout / Cancellation、Commit / Push結果不明は自動再送せずReconciliationで停止する。終了コード0やModelのPASSだけをGateへ昇格しない |
| LOOP-034 | Local移行前に送信済みCloud Requestとその出力を正確な入力HEADへBindingしてReconcileし、旧Workerの継続や結果が不明な間は同じ入力のLocal Workerを起動しない。移行用GovernanceをReview / MergeするまでProduct実装は再開しない。移行後も履歴Gate・Finding・Retry消費・Design Stopを消去しない |
| LOOP-035 | WorkerのRead-only入力に、親が設定から独立検証した`configured_authorities.approver_login`とTrusted Workflow IDを渡す。Approval本文の`approved_by`、環境変数や自由文から設定上の承認者を推定しない。Credential StoreへのWorkerアクセスは引き続き禁止する |
| LOOP-036 | 親がWorker終了を確認した既知BLOCKEDは、Commit / Push前に`BLOCKED_NO_OUTPUT`終端記録へBindingする。旧版の終了済み実行は、明示Operator停止確認とJournal / Claim / Start / Request / HEAD照合によってのみ同記録を公開する。結果不明・公開ACK不明は再送せず照合だけを行う。未解決実行をBase Refreshや新HEADによって迂回せず、終端記録も同HEADの再実行・Resume・Phase PASSを認可しない |

## Non-Functional Requirements

- Private Repositoryを前提とする。
- Fork PRでは実装Workflowを起動しない。
- GitHub TokenをCodex実行環境へ渡さない。
- Local OrchestratorのGitHub認証は`gh`のCredential Storeだけを使用し、Token Valueを引数、Prompt、Logへ出さない。
- API Key、C2/MCP資格情報、Secret ValueをPrompt、PR、Artifact、Logへ含めない。
- Repository/PR contentをPrompt Injection可能な非信頼入力として扱う。
- 全自動処理は取消可能で、最大回数とTimeoutを持つ。
- Local Orchestrator停止中もGitHub上のTrusted Marker / Review / Checkを正本とし、同じCommandで再開できる。Lifecycle Labelは再構築可能なProjectionとして扱う。
- Deterministic Checkは隔離されたローカルValidationとCI、意味的・Security Reviewは別のローカルRead-only Codex CLI Workerが担当する。
- Local WorkerにはDefaultのUser設定、MCP / Plugin、会話履歴を継承せず、Trusted Launcherの固定構成だけを適用する。ModelはRunnerのStart / Result Recordを自作・公開できない。
- Reviewの認証主体はLauncherのOperator Accountである。同じHostやAccountの侵害に対して独立した第三者認証を保証せず、Host隔離・Credential非公開・Read-only境界の成立を起動前に検証する。成立しない環境では人間承認やCloudへの暗黙Fallbackをせず停止する。

## Project Phase Requirements

実装仕様のSource of Truthは`SystemDesign.md`、同書が必須参照する規範別冊`SystemDesign_AI_Control.md`、
`docs/safety-invariants.md`、`docs/acceptance-criteria.md`である。AI規約の適用範囲は別冊§12に限定する。
Phase Promptは当該Phaseの範囲を狭める実行指示であり、仕様を緩和しない。`SystemDesign_update.md`と
`docs/review/`配下の履歴・検証報告は現行規範を上書きしない。残る規範間の矛盾はBLOCKEDとして解決する。
`system-design-v1-r1`の文書反映は、既存実装の受入完了・DB移行・Current-HEAD実装権限を意味しない。
