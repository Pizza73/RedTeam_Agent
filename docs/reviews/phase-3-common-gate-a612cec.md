# Phase 3 修正版 Common Gate 独立レビュー

- レビュー日: 2026-09-09
- 対象コミット: `a612cecefe8fd7db0a21842212ed245c113fe38d`
- 主要修正コミット: `dfe3d11a8fc11122545760c7d0e2f6ce22bdfe51`
- Common Gate: **PASS**
- Phase 3: **ACCEPTED**

## 結論

受入後再レビューで検出したBLOCKER 1件・HIGH 2件は`dfe3d11`で修正された。独立レビュー中に、Approval単一割当を保証するSQLite Indexが欠落した旧スキーマを本番read-only起動検査が受理するHIGH 1件を追加検出し、`a612cec`で修正した。再レビュー後の未解決BLOCKER / HIGH / MEDIUM / LOWは0。

Phase 3のHuman Approval境界、Durable Resume、同一pass finalization、LocalResultBindingのAdapter非接触照合、およびApproval一意制約の本番起動時検査は、実装・回帰試験・全体Gateで確認した。Phase 3を再受入する。

## 独立レビュー指摘と解消

| 重大度 | 指摘 | 対応 | 状態 |
| --- | --- | --- | --- |
| BLOCKER | 同一ApprovalRequestに矛盾するDecision Recordを保存でき、検索順で認可結果が変わる | Repository検査とSQLite部分Unique Indexでrequest単位の単一割当を強制 | 解消 |
| HIGH | 最後のExecutionが照合pass内でterminalになってもWAITING_HUMAN_REVIEWから進まない | reconciliationを既存finalization nodeへ接続し、同一graph invocationで再評価 | 解消 |
| HIGH | LocalResultBindingが外部Adapterのreconcileへ渡される | durable local captureだけで照合し、不完全captureはAdapter非接触でOUTCOME_UNKNOWN | 解消 |
| HIGH | 新しいApproval一意Indexが欠落・改変した旧スキーマを本番起動検査が受理する | IndexのUnique式・部分条件を含む定義全体をread-only検証し、相違時は明示migration要求でFail Closed | 解消 |

## Common Gate Evidence

| 条件 | 結果 |
| --- | ---: |
| Unit / Integration / Security / Property / Regression | PASS — **823 passed / 0 skipped** |
| Phase 3専用試験 | PASS — Durable Resume 26件 + Approval 10件 = 36件 |
| Approval schema起動回帰 | PASS — 1件 |
| swtpm | PASS — 7件を全体試験へ含めた |
| Branch Coverage | PASS — 17,049 statements、4,474 branches、**86.549272870882% combined** |
| Ruff | PASS |
| configured mypy | PASS — 196 source files |
| direct `mypy --strict src` | PASS — 193 source files |
| compileall | PASS |
| Pydantic boundary / wire・deep-immutable検証 | PASS |
| SHA256SUMS / `pip check` / `git diff --check` | PASS |
| 未解決BLOCKER / HIGH / MEDIUM / LOW | **0 / 0 / 0 / 0** |

隔離swtpmツールチェーンを`/tmp`へ展開し、システムパッケージを変更せず全体試験へ含めた。

主なCommand:

```sh
PATH=<isolated-swtpm>/usr/bin:$PATH \
LD_LIBRARY_PATH=<isolated-swtpm>/usr/lib/x86_64-linux-gnu:<isolated-swtpm>/usr/lib/x86_64-linux-gnu/swtpm \
PYTHONPATH=src:tests COVERAGE_FILE=/tmp/phase3-common-gate-final.coverage \
  .venv/bin/python -m coverage run --branch -m pytest -o addopts= -q -ra
# 823 passed / 0 skipped

COVERAGE_FILE=/tmp/phase3-common-gate-final.coverage \
  .venv/bin/coverage report --precision=12
# TOTAL 17049 1606 4474 1107 86.549272870882%

.venv/bin/ruff check .
PYTHONPATH=src .venv/bin/mypy
PYTHONPATH=src .venv/bin/mypy --strict src
.venv/bin/python -m compileall -q -f src tests scripts
PYTHONPATH=src .venv/bin/python scripts/verify_pydantic_contract.py
PYTHONPATH=src .venv/bin/python scripts/verify_wire_and_immutable.py
sha256sum -c SHA256SUMS
.venv/bin/pip check
git diff --check
```

## Phase 4移行条件

Phase 3のCommon Gateは成立した。ただしPhase 4は承認済みC2 ProviderのProvider Human Gateが別途必要であり、このレビューだけでは実C2接続・外部Target操作を許可しない。D4実機REK消去も`NOT_EVALUATED`のままとする。
