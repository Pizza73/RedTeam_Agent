# Phase 2 Common Gate 最終独立レビュー

## 最終判定

- 対象実装: `66f55bad667261a5cd8ec5e54bb375d7ea0a2644`
- Git tree: `6c058817ec0ef51d630c280b97c0d62cd8ea1102`
- 指摘残数: **BLOCKER 0 / HIGH 0 / MEDIUM 0 / LOW 0**
- 未解決仕様矛盾: **0**
- Security-critical TODO / stub: **0**
- Common Gate: **PASS**
- Phase 3移行: **PERMITTED**
- 実C2 / MCP / 外部Target side effect: **0**。実ネットワークは閉域vLLMのCapability / 品質資格だけで、Action実行は安全なMock Adapter
- Secret leakage: **0 observed**
- D4実機Resource REK消去: **NOT_EVALUATED**。Phase 3移行条件とは別であり、Production採用は引き続き不可

本レビュー後の開発記録・README・本ファイルだけの追記は記録更新であり、対象製品実装treeを変更しない。

## 固定snapshot

`git archive`で対象を`/tmp/phase2-independent-review-66f55ba-vkuFGr/implementation`へ展開し、元Repositoryから
対象commit objectをfetchして`HEAD` / indexを固定した。snapshotと対象のtree hashは一致し、tracked worktreeはclean。
最初のarchive-only実行は製品試験785件がPASSした一方、`.git` metadata不在だけを理由に
`test_read_git_state_returns_commit_and_branch`が1件失敗した。対象commit metadataを付与した再実行では786件すべてPASSした。
この初回失敗もレビュー記録に残し、原因を是正した後の全件再実行を正式Evidenceとした。

## 修正済み指摘

| ID / 重大度 | 初回所見 | 最終対応 |
| --- | --- | --- |
| H-01 / HIGH | 外側の実Client / Tokenizer / Attestationだけで品質Driverを`real_local_llm`扱いでき、内側Scenario Factoryが別Clientを返せた | Runner / Executor / Driverをexact identityとProfile Digestへ束縛し、各RunでFactory生成Adapterも再検証。不一致はhard error。`cdab8ec` |
| M-01 / MEDIUM | 修正前の300-Run Reportは1,284 LLM callに対してprompt / completion tokenがともに0 | vLLMのserver-reported usageを取得し、missing / malformed / negative / all-zeroを実Gateで拒否。新資格は758,996 tokens、missing 0。`cdab8ec` |
| M-02 / MEDIUM | 例外で失敗したRunは消費済みLLM Attemptの診断がall-zero observationへ置換され得た | `QualityAttemptFailure`がcontent-free分類と実診断を失敗Runへ伝播し、durable evidenceへ保存。`9cf6d15` |
| M-03 / MEDIUM | Planner / AnalyzerがValidation Retryを使い切ると、`usage.record`より先に例外となりAttemptが失われた | Invocation usageを成功・例外双方の`finally`でexactにdrain。Planner / Analyzer各3回枯渇の回帰試験。`394b42e` |
| L-01 / LOW | 外側Workflow失敗からValidation Error数を推定すると、有効LLM出力後のdownstream failureを誤計上できた | Invocation自身がstrict schema validation errorだけを計数。3/2/2、3/2/3、1/0/0の各経路を固定。`66f55ba` |
| L-02 / LOW | 直接`mypy --strict src`にunused ignore 2件、READMEのPhase 0Aレビュー状態が古い | ignore除去後に直接strict PASS。READMEは最終記録と同時に更新 |

修正はClaude Codeへ依頼し、各commit後にCodexが差分と回帰経路を再レビューした。修正前の
`.runtime/phase2-qualified-evidence.sqlite` / `.runtime/phase2-qualified-report.json`は現行資格として使用していない。

## 実Local LLM再資格

対象commitがcleanな状態で新規出力先を指定し、Capability-onlyと正式300-Runを実行した。

| 項目 | 結果 |
| --- | ---: |
| Profile / vLLM | `gemma-4-31B-it` / vLLM 0.25.1 / `native_json_schema` |
| Profile Digest | `5899f5bee3457ff9a27316ee5b27538e89547ec73e3eaa9a28b9a12840842211` |
| Server Attestation Digest | `923c5601b91b4c61cdcf3eeba1a159c11782c6892e3c6ca36cb56710d6bb070a` |
| Schema Capability | Planner / Execution Plan / Analyzer各10/10、Unsafe 0、Timeout 1/1、Cancellation Failure 0、全てreal evidenceでPASS |
| 品質Gate / durable set | **PASS** / 300 records、Index 0〜299連続、全Digest再検証PASS |
| 成功 / normal | 300/300 / 270 |
| expected reach / family min / precision / recall | 1.0 / 1.0 / 1.0 / 1.0 |
| pass@3 / pass³ | 1.0 / 1.0 |
| Safety zero metrics | Scope False-Allow、Approval Bypass、Secret Leakage、重複副作用、誤confirmed、誤Goal、Hard Limit違反が全て0 |
| Human wait / Checkpoint recovery | 0.0 / 30 of 30 |
| LLM usage | 1,286 calls、prompt 581,013、completion 177,983、total 758,996、Retry 2、Validation Error 2、usage missing 0 |
| Binding / Report Digest | `a1fb9e27d96fc31bb8acb25dd2cbe6f2b15e7fb38b153d220414dda7186546a7` / `224c6b7eebccd7ead9628b39874c86593007e98da579c19f7409c58014282874` |

Evidence:

- `/home/kali/Red_Agent/.runtime/phase2-rereview-66f55ba-capability.json`
- `/home/kali/Red_Agent/.runtime/phase2-rereview-66f55ba-evidence.sqlite`
- `/home/kali/Red_Agent/.runtime/phase2-rereview-66f55ba-report.json`

Repository APIの`verify_complete()`で300 Recordを再読込し、Report JSONとDB内Reportの完全一致、全Recordの
`real_local_llm`、Evaluation Binding一致、失敗分類なし、Token / Retry / Validation / missingの集計一致を確認した。
Bindingはcommit、requirements lock、profile、model、tokenizer、template、runtime、output mode、prompt / schema、
contract / catalog / gateway budget、両Corpus、3 Capability Result、300個の一意Seedへ束縛されている。

## Common Gate Evidence

| 条件 | 結果 |
| --- | ---: |
| Unit / Integration / Security / Property / Regression | PASS — **786 passed / 0 skipped** |
| swtpm | PASS — 7件を全体試験へ含めた |
| Branch Coverage | PASS — 16,933 statements、4,436 branches、86.396% combined |
| Ruff | PASS |
| configured mypy | PASS — 194 source files |
| direct `mypy --strict src` | PASS — 193 source files |
| compileall | PASS |
| Pydantic boundary / wire・deep-immutable検証 | PASS |
| SHA256SUMS / `pip check` / `git diff --check` | PASS |
| 既存test削除・skip・xfail追加 | PASS — 削除0、Phase 2追加試験のみ。swtpm条件skipは環境を満たして実行 |
| BLOCKER / HIGH / 仕様矛盾 / critical TODO | PASS — 全て0 |
| 実C2 / MCP / 外部Target / Secret leakage | PASS — 全て0 observed |

主なCommand:

```sh
PATH=/tmp/phase2-tpm-packages-9YjSxf/root/usr/bin:$PATH \
LD_LIBRARY_PATH=/tmp/phase2-tpm-packages-9YjSxf/root/usr/lib/x86_64-linux-gnu:/tmp/phase2-tpm-packages-9YjSxf/root/usr/lib/x86_64-linux-gnu/swtpm \
PYTHONPATH=src:tests /home/kali/Red_Agent/.venv/bin/python -m pytest -o addopts= -q -ra
# 786 passed, 0 skipped

COVERAGE_FILE=/tmp/phase2-independent-review-66f55ba-vkuFGr/evidence/.coverage \
  /home/kali/Red_Agent/.venv/bin/python -m coverage run --branch -m pytest -o addopts= -q
/home/kali/Red_Agent/.venv/bin/python -m coverage report
# TOTAL 16933 1612 4436 1111 86%; exact combined 86.39618138424821%

/home/kali/Red_Agent/.venv/bin/python -m ruff check .
/home/kali/Red_Agent/.venv/bin/python -m mypy
/home/kali/Red_Agent/.venv/bin/python -m mypy --strict src
/home/kali/Red_Agent/.venv/bin/python -m compileall -q -f src tests scripts
/home/kali/Red_Agent/.venv/bin/python scripts/verify_pydantic_contract.py
/home/kali/Red_Agent/.venv/bin/python scripts/verify_wire_and_immutable.py
sha256sum -c SHA256SUMS
/home/kali/Red_Agent/.venv/bin/pip check
# all PASS
```

## 移行根拠と限界

Phase 2の製品条件、実Capability、固定300-Run D11品質Gate、Common Gateが成立し、未解決BLOCKER / HIGHは0。
したがってPhase 3（Human Approval / Durable Resume）の着手を許可する。これはPhase 3実装済み、実C2利用可、
Production採用可を意味しない。D4実機REK消去は`NOT_EVALUATED`のままで、独立Qualification PASS前のProduction有効化は禁止する。
