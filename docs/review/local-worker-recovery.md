# ローカルWorker停止の修正記録

2026-09-06。Governance修正。製品Phase 0Cの実装やPhase PASSではない。

## 対象と結果

- 修正Branch: `codex/local-worker-recovery`
- Governance差分基準: `1befa35ece8b4f0875c002433d4effe9f01b1cd6`
- 停止した製品Phase: `phase-0c`
- 入力HEAD: `208233a2bade9d510356583ea3a3f14cf59c32bf`
- 入力Request: https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5560829089
- Design Approval: https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5560828855
- Worker Session: `01a077b7-6a80-77f0-96ff-4427b00aa568`
- 今回のFormal Review SHA: なし。上記HEADは停止実行の入力であり、本修正のレビュー合格ではない。
- 終了済みAttempt: `/tmp/redteam-local-implementation-7bqyvp3j`
- この修正中にWorker再起動、Claim削除、既存PR HEAD変更、承認再利用をしていない。

## 原因と変更前後

| 対象 | 変更前 / 原因 | 変更後 |
| --- | --- | --- |
| 入力Bundle | Approvalの`approved_by`はあるが、独立設定された承認者IDがない。Workerは正しくBLOCKED | 親の検証済み`approver_login`とWorkflow IDをRead-only `configured_authorities`へ追加。自己申告から推定しない |
| Governance Test | `LocalExecution`やCommand生成Testが実HostのCodex設定に依存。CIでは設定なし、Workerでは意図的にアクセス拒否 | Synthetic Account / Model設定へ固定。Sandbox / Credential保護は不変 |
| BLOCKED終了 | 03-worker Journalのみ残り、GitHub Startが未解決 | 親がwait済みBLOCKEDを確認した場合、永続Intentと`BLOCKED_NO_OUTPUT`終端記録を作る。自由文を公開しない |
| 旧版の停止 | 同HEAD再起動は永久Claimで拒否されるが、終了を確定する操作なし | 明示Operator停止確認と厳格な旧Journal / Claim / Start / Request / HEAD照合だけを行うCLIを追加 |
| 新HEADへの移動 | 古いHEADの未解決StartがSame-HEAD検査から外れる | Base Refresh要求・実Branch更新・新Worker起動で未解決Startを拒否 |
| CI待機 | `check_state()`は`waiting`だが再開側が`pending`と比較し途中停止 | `waiting`へ整合。CI成功でもDesign Approvalは自動発行しない |
| Process停止Test | `/proc/<pid>/stat`読取中の終了競合でESRCHになる場合がある | ENOENTと同様、ProcessLookupErrorも既に終了した状態として扱う。生存Processは従来通り失敗 |

## 再現根拠

元入力HEADのコピーを、同じbubblewrapとCodex sandboxで固定pytest実行した結果:
`21 failed, 524 passed, 43 errors`。Worker報告と一致した。

- 43 errors + 18 failures: 実Host設定読取の`LOCAL_HOST_MODEL_CONFIG_INVALID`
- 残る3 failures: Command生成Testの禁止AccountパスへのstatでPermissionError
- 製品Sourceや依存Versionの差が原因ではなかった。隔離を緩めずFixtureを修正した。
- 診断に実LLM、GitHub書込、外部Target/C2/MCPを使用していない。
- 元Workspaceには診断で作られた未追跡のpytest / sandbox一時Fileが残る。Source・Journal・既存Reportを
  改変せず、以後の検証は別コピーで実施した。未追跡Fileの存在をCommit / Push済みと解釈しない。

## 回帰・検証

通常環境とNative二重隔離環境で以下の7Suiteを実行し、各589件PASS、Skip / Failure / Errorなし。
その後追加したRefresh要求の実接続Regressionを含む通常環境の最終7Suiteは590件PASS。
最終Phase-loop Suiteも178件PASS。Native測定は追加1件の前であることを区別する。

```bash
PATH=/usr/lib/chatgpt/resources/cua_node/bin:$PATH .venv/bin/python -m pytest -q \
  tests/unit/test_local_execution.py tests/unit/test_local_worker.py \
  tests/unit/test_phase_loop.py tests/unit/test_local_attempt_reconciliation.py \
  tests/unit/test_local_review_evidence.py tests/unit/test_automation_validation.py \
  tests/unit/test_governance_check.py --strict-markers --tb=short
```

Native検証コピー: `/tmp/redteam-environment-integrated.lRxdmV`。モデル起動ではなく、
`automation.local_worker._outer_command(..., native_auth=False)`と同じ`_permission_options`で
`codex sandbox -P redteam-local-worker -- <workspace>/.venv/bin/python -m pytest ...`を実行した。
PROFILEの実値は`automation/local_worker.py`を参照する。固定Node PATHとWorker専用TMPDIRだけを指定し、
Credential / Network / Protected Path制限を変更していない。

新Reconciliation Suiteは32件PASS。Hypothesis RuleBasedStateMachineで正常公開、送信前の不明結果、
ACK喪失、再照合、Refresh停止を反復した。個別Regressionは以下を含む:

- 設定承認者欠落・不正・Account不一致を起動前に拒否、Approval自己申告からの推定を拒否
- BLOCKED後にGate / Commit / Pushへ進まず、自由文なしの終端だけを公開
- 終端化後も同HEADを再実行しない
- Journal / Remote Claim / Start / Request / HEADの不一致、Unknown Field、破損を拒否
- READY、進行済み検証/Push記録、実行中Launcher、Remote DriftをNO_OUTPUT扱いしない
- 永続公開Intent後の結果不明は再投稿せず、正確な既存終端だけを冪等に照合
- 未解決StartをRefresh要求や新HEADから迂回しない
- CI待機中はResume / Design Approvalを発行しない

その他の実行結果:

- `.venv/bin/python -m ruff check`（変更したAutomation / Test 7File）: PASS
- `.venv/bin/python -m compileall -q automation tests/unit/test_local_attempt_reconciliation.py`: PASS
- `.venv/bin/python scripts/ci/validate_automation.py`: PASS
- `.venv/bin/python -m pip check`: PASS
- `git diff --check`: PASS
- `.venv/bin/python -m coverage run --data-file=/tmp/redteam-local-recovery.coverage --branch
  --source=automation.local_execution,automation.local_attempt_reconciliation,automation.run_phase_loop
  -m pytest -q tests/unit/test_local_execution.py tests/unit/test_local_attempt_reconciliation.py
  tests/unit/test_phase_loop.py --strict-markers --tb=short`: 281件PASS（追加Refresh Test前）
- `coverage report`（同data-file）: Reconciliation 87%、LocalExecution 85%、Runner 64%、合計69%。
  これは対象Governanceの分岐込み測定であり、製品Coverageではない。

最初の通常7Suite実行はNodeをPATHに入れ忘れて145件失敗したため、規定Node PATHで再実行した。
試験をSkipせず、依存不足とコード不具合を区別した。

## 製品Phase Gateの制約

```bash
PATH=/home/kali/RedTeam_Agent/.venv/bin:/usr/lib/chatgpt/resources/cua_node/bin:$PATH \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

このGovernance BranchではCompile / Automation検証が成功、AuditはNOT_REQUIRED。
未変更のmain製品コード・TestにあるRuff 88件でExit 1となり、後続製品Test/Coverageには進んでいない。
別途`.venv/bin/python -m mypy src/redteam_agent`は未変更の60 Source File中16Fileで40 Errors。
今回`src/`、製品Security / Integration Test、依存LockやGate要求は変更していない。
これは既存累積実装PR #3のCI失敗を意味しない。製品Phase PASSをこの修正の合格と称さない。

## 変更Fileと採用手順

- Runtime: `automation/local_execution.py`、`automation/local_attempt_reconciliation.py`、
  `automation/run_phase_loop.py`
- Prompt / CI: `.github/prompts/implement.md`、`.github/workflows/ci.yml`
- Test: `tests/unit/test_local_execution.py`、`tests/unit/test_local_worker.py`、
  `tests/unit/test_phase_loop.py`、`tests/unit/test_local_attempt_reconciliation.py`
- 規範・運用: `SystemDesign.md`、`docs/requirements.md`、`docs/acceptance-criteria.md`、
  `docs/ai-loop-runbook.md`、`docs/implementation-status.md`、本書

対応要件: LOOP-007 / 015 / 016 / 028 / 029 / 033と追加LOOP-035 / 036。
保護対象のGovernance修正としてHuman Review / Mergeが必要。

1. 本修正をレビュー・マージする。Codexはマージしない。
2. Clean current mainから、運用書の限定Reconciliationコマンドで旧実行の終了を明示確定する。
3. 既存のExact-HEAD Refresh / Checkpointで修正を実装PRへ取り込む。
4. 新HEADのCI成功後、必要な新しいDesign Approvalを取得する。古い承認を再利用しない。
5. Local Runnerを一度起動し、実装→検証→Push→CI→別Local Reviewへ進む。

`BLOCKED_NO_OUTPUT`は未Commit変更の削除や実装再開の許可ではない。旧JournalにPIDがないため、
旧版ReconciliationはOperator停止確認と現在のProcess確認を信頼する。Host侵害に対する証明ではない。
不明な実行、Push済み/結果不明、公開結果不明の自動再送、Claim削除による復旧は対象外で停止する。
