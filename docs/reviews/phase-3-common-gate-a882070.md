# Phase 3 Common Gate 最終独立レビュー

## 最終判定

- 対象実装: `a8820705619ec8475299e0df5e85476e7a7f5299`
- Git tree: `1acb0c3c41b10ac34bc9f9a7afc5b6ea30d2f66c`
- 指摘残数: **BLOCKER 0 / HIGH 0 / MEDIUM 0 / LOW 0**
- 未解決仕様矛盾: **0**
- Security-critical TODO / stub: **0**
- Common Gate: **PASS**
- Phase 3: **ACCEPTED**
- Phase 4: Provider Human GateでC2製品・Version・隔離環境・認証方式・Egressを確定するまで未着手
- 実C2 / MCP / 外部Target side effect: **0**。全Action試験はMock Adapterのみ
- Secret leakage: **0 observed**
- D4実機Resource REK消去: **NOT_EVALUATED**。Production採用は引き続き不可

本レビュー後の開発記録・README・本ファイルだけの追記は記録更新であり、対象製品実装treeを変更しない。

## 固定snapshot

対象commitをshared clone `/tmp/phase3-independent-review-a882070-3wccaL/implementation`へdetached HEADで固定した。
`HEAD=a8820705619ec8475299e0df5e85476e7a7f5299`、tree hashは上記対象と一致し、tracked worktreeはclean。
実装会話の未追跡状態やレビュー文書追記から分離したこのsnapshotで、swtpmを含む全816件と静的検査を再実行した。

## 修正済み指摘

| ID / 重大度 | 初回所見 | 最終対応 |
| --- | --- | --- |
| B-01 / BLOCKER | 初版はApplication OCC Checkpointを読み、LangGraphの既存RECONCILING nodeを通さず命令的に照合していた | Compiled Planning Graphと実SqliteSaver checkpointをResume所有者に変更。既存RECONCILING nodeがDB→Adapter順で照合し、認証済みOperatorとCanonical thread bindingを必須化。`99437ef` |
| B-02 / BLOCKER | 照合中の正当な並行Mission遷移をentry snapshotとの差として拒否していた | 照合後にCurrent Mission Repositoryを再読込して対応Graph状態へ写像し、開始時snapshotで上書き・拒否しない。`99437ef` |
| H-01 / HIGH | 未完了Executionを列挙しても先頭1件だけを照合し、複数件を残したまま完了報告できた | Application DBの全未完了Executionを`execution_id`順に各1回、Task Binding別に既存node内で照合。`a882070` |
| H-02 / HIGH | caller値から再計算したthread_idを自己検証するだけで、永続checkpoint本体のMission / Revision / Run bindingを検証していなかった | Graph stateへ`mission_revision` / `run_id`を保存し、SqliteSaverから読んだ実`channel_values`をCurrent Repositoryと照合。不一致はDB変更・Adapter read前にFail Closed。`a882070` |

修正はClaude Codeへ依頼し、各commit後にCodexが差分・設計・回帰経路を再レビューした。

## Phase 3受入確認

- ApprovalRequest / ApprovalRecordはRequest、Presentation、PolicyDecision、Authorization Digest、Execution Intent、Mission Revision、Authorization Epoch、TTLへBindingされる。
- `REQUIRE_APPROVAL`は一致する有効な`APPROVED` RecordなしではDispatch不可、`DENY`は承認Recordがあっても実行不可。
- Plan / Intent変更、期限切れ、Replay、誤Digest、誤Epoch / Revision / Binding、Approver権限失効はFail Closed。
- PAUSE / Resumeは`mission_revision`を維持して`authorization_epoch`を単調増加させ、旧Grant / Snapshot / Decision / Approvalを再利用しない。
- Durable Resumeは実LangGraph checkpointを復元・検証後、Application DBを正として全未完了Executionを列挙し、Adapterを最後に照合する。
- PAUSED / WAITING_HUMAN_REVIEW中の新規Dispatch、Planner、Analyzer呼出しは0。Missionを暗黙にRUNNINGへ戻さない。
- 不明な非冪等Outcomeは`OUTCOME_UNKNOWN`として保持し、自動再送しない。
- WAITING_HUMAN_REVIEWの全Item解決時だけ、既存Graph finalization nodeとMission Managerが元の終了理由を保持してFINALIZINGへ進める。
- file-backed SQLite上の実checkpointを新Kernelから復元する再起動試験、checkpoint改ざん、複数Execution、crash境界、OCC、並行Resumeを確認した。

## Common Gate Evidence

| 条件 | 結果 |
| --- | ---: |
| Unit / Integration / Security / Property / Regression | PASS — **816 passed / 0 skipped** |
| Phase 3専用試験 | PASS — Durable Resume 20件 + Approval 10件 = 30件 |
| swtpm | PASS — 7件を全体試験へ含めた |
| Branch Coverage | PASS — 17,013 statements、4,458 branches、**86.516696940059% combined** |
| Ruff | PASS |
| configured mypy | PASS — 194 source files |
| direct `mypy --strict src` | PASS — 193 source files |
| compileall | PASS |
| Pydantic boundary / wire・deep-immutable検証 | PASS |
| SHA256SUMS / `pip check` / `git diff --check` | PASS |
| 既存test削除・skip・xfail追加 | PASS — 削除0、skip / xfail追加0 |
| BLOCKER / HIGH / 仕様矛盾 / critical TODO | PASS — 全て0 |
| 実C2 / MCP / 外部Target / Secret leakage | PASS — 全て0 observed |

主なCommand:

```sh
PATH=/tmp/phase2-tpm-packages-9YjSxf/root/usr/bin:$PATH \
LD_LIBRARY_PATH=/tmp/phase2-tpm-packages-9YjSxf/root/usr/lib/x86_64-linux-gnu:/tmp/phase2-tpm-packages-9YjSxf/root/usr/lib/x86_64-linux-gnu/swtpm \
PYTHONPATH=src:tests .venv/bin/python -m pytest -o addopts= -q -ra
# 816 passed, 0 skipped

PATH=/tmp/phase2-tpm-packages-9YjSxf/root/usr/bin:$PATH \
LD_LIBRARY_PATH=/tmp/phase2-tpm-packages-9YjSxf/root/usr/lib/x86_64-linux-gnu:/tmp/phase2-tpm-packages-9YjSxf/root/usr/lib/x86_64-linux-gnu/swtpm \
PYTHONPATH=src:tests COVERAGE_FILE=/tmp/phase3-common-gate.coverage \
  .venv/bin/python -m coverage run --branch -m pytest -o addopts= -q
COVERAGE_FILE=/tmp/phase3-common-gate.coverage \
  .venv/bin/coverage report --precision=12
# TOTAL 17013 1606 4458 1107 86.516696940059%

.venv/bin/ruff check .
PYTHONPATH=src .venv/bin/mypy
PYTHONPATH=src .venv/bin/mypy --strict src
.venv/bin/python -m compileall -q -f src tests scripts
PYTHONPATH=src .venv/bin/python scripts/verify_pydantic_contract.py
PYTHONPATH=src .venv/bin/python scripts/verify_wire_and_immutable.py
sha256sum -c SHA256SUMS
.venv/bin/pip check
git diff --check
# all PASS
```

## 結論と限界

Phase 3の製品条件とCommon Gateは成立し、未解決BLOCKER / HIGHは0。Phase 3を受入済みとする。
Phase 4は承認済みC2 ProviderのHuman Gateが別途必要であり、本判定から自動着手・実接続しない。
D4実機REK消去は`NOT_EVALUATED`のままで、Production採用または全製品受入完了は宣言しない。
