# SystemDesign 正本反映レポート

日付: 2026-09-06。対象: ローカル作業ツリーの文書改訂。正式PR Review / Phase PASSではない。

## 反映結果と境界

ユーザー承認に基づき[SystemDesign.md](../../SystemDesign.md)へ整合済み更新案を反映し、
[AI制御仕様](../../SystemDesign_AI_Control.md)を必須の規範別冊として採用した。
改訂は`system-design-v1-r1` / `ai-control-v1-r1`。
[旧Draft](../../SystemDesign_update.md)は本文を保存した比較用スナップショットとし、
[旧v3レビュー](phase-0c-coherent-redesign.md)は現行実装要件ではなく歴史的な理由説明とした。

- R1〜R13、D1〜D11、F1〜F7とAI-01〜12 / AC-01〜20を正本へ反映した。
- 受入条件・安全条件・要件参照・Threat Model・Phase 0C / 1 / 2 Promptを整合させた。
- 共通Controller / ActionContract、検証済みFactと観測・仮説の分離、有限Budget、独立品質Gateを採用した。
- NV Extend Digest / Genesis、型別Result / Recovery / 消去、Critical Witness、共有Activation Lockと明示Migrationを反映した。
- Secretの生涯利用回数を数えないこと、別認可Executionからの再利用、単回Dispatch、Lease更新 / Fencing、結果不明の非自動再送は維持した。
- 製品コード、製品Test、DB、Workflow / CI / 自動化、PR / GitHub権限は変更していない。
  初回反映ではAGENTS.mdを変更せず、後続の明示承認で消去規則だけを整合させた（下記参照）。

## 規範不一致 — 後続の明示承認で解消（2026-09-06）

初回反映時の`AGENTS.md`はQuarantine消去前のDurable Manifest / Result Projection / Resource / Intent検証を
一律に要求していた。一方、SystemDesign.md §10 / §33.2 / §38のR1は、Manifest未作成のRetention Expiryと
Receiptも未確定のIncomplete Collection Expiryを、各型の必須Evidence・単回Claim・専用Eraserで消去する。
両方の規則を同時には満たせないため、初回はこの不一致をBLOCKEDとして報告した。

ユーザーが後続でAGENTS.md変更を明示承認したため、正常公開後消去の完全検証を維持し、期限切れ消去の2型を
それぞれの必須Evidenceへ限定して明記した。Manifestなしを任意消去の許可にせず、型の流用・状態不一致・
失効した権限・Raw再収集を禁止する。文書上の当該不一致は解消したが、正式なDesign Stop、Phase Gate、
Current-HEAD Design Approval要件は維持し、Design Approval / Resumeを発行・消費していない。

## 初回正本反映時の検証（AGENTS.md更新前の履歴）

設計の有限参照モデル・文書Drift検査であり、暗号 / 認可 / Dispatch / Recovery実装の成立証拠ではない。
ローカルBranchは`codex/phase-0c-coherent-redesign-v3`、参照HEADは
`e51d9bd81a216d81ea8c14f7d6bd0c2f4f648caa`。今回の変更は未コミットであり、このSHAに含まれるとは主張しない。

| 実行コマンド | 結果 |
| --- | --- |
| `.venv/bin/python docs/review/validate_ai_control_design.py` | exit 0。14文書のLink / Fence、AI不変条件12 / 12とScenario20件、三値240組合せ、Controller384組合せ / 9分岐、unknown共通経路128組合せ、不正入力34件、廃止Runtime12パターン、接続Model5種、Python例AI1 / 正本50 Blockを検査。別途AUTHORITY_ALIGNMENT=BLOCKEDを明示 |
| `.venv/bin/python -m ruff check docs/review/validate_ai_control_design.py` | exit 0。検査ScriptのLint PASS |
| `.venv/bin/python scripts/ci/validate_automation.py` | exit 0。AUTOMATION_VALIDATION=PASS。現在PRの認可や正式Phase Gateではない |
| `git diff --check` | exit 0。Tracked差分のWhitespace問題なし |
| `git diff --exit-code -- AGENTS.md src tests .github automation scripts/ci pyproject.toml requirements.lock` | exit 0。対象はHEADから未変更 |
| `.venv/bin/python -m ruff check .` および `--statistics`付き再確認 | exit 1。既存コード / Testの88件を検出。仕様を通すための実装修正は行わない |
| `.venv/bin/python -m ruff check src tests --statistics` | exit 1。同じ88件が未変更のsrc / testsに存在することを確認 |

Untracked文書と検査Scriptは次のコマンドでWhitespaceを確認した。全対象で診断出力なし。
各no-index比較のexit 1は新規内容の差分があるためであり、製品Testの失敗やPhase結果ではない。

```sh
for design_doc in SystemDesign_AI_Control.md SystemDesign_update.md docs/review/ai-control-research-review.md docs/review/validate_ai_control_design.py docs/review/systemdesign-canonical-adoption.md; do
  git diff --no-index --check /dev/null "$design_doc"
done
```

検査Scriptは当初のMarkdownからの`exec`を廃止した。固定したローカル参照関数と文書のASTを完全照合してから
参照関数を評価し、文書から任意コードを実行しない。初回LintのS102 / B905 / 長行を検査Script内だけで修正し、
Rule除外、CI設定変更、製品Testの削除・skipは行っていない。

作業前Backup `/tmp/redteam-spec-adopt-YUmCyP`と読取比較し、旧Draftは追加した保存状態Header以外の全本文一致、
正本§1〜§40は承認済みDraftと採用状態の1文を除き一致することを確認した。
Backupは一時保全用であり、常設検査Scriptの動作には不要である。

## 初回正本反映時の変更ファイル

既に未コミット変更があったため、HEAD全体のDiffを今回だけの差分と偽らない。作業前Backupとの比較で
SystemDesign.mdは+3065 / -531行。以下15ファイルのうち14既存ファイルを更新し、反映レポート1件を新規作成した。

- `SystemDesign.md`、`SystemDesign_AI_Control.md`、`SystemDesign_update.md`
- `docs/requirements.md`、`docs/acceptance-criteria.md`、`docs/safety-invariants.md`、`docs/threat-model.md`、`docs/implementation-status.md`
- `prompts/phases/phase-0c.md`、`prompts/phases/phase-1.md`、`prompts/phases/phase-2.md`
- `docs/review/phase-0c-coherent-redesign.md`、`docs/review/ai-control-research-review.md`、`docs/review/validate_ai_control_design.py`
- `docs/review/systemdesign-canonical-adoption.md`（新規）

Phase 0A / 0B / 3〜5のPrompt、既存の独立AI-agent設計レビュー、製品コード・Test・Governance実行機構は変更していない。
回帰検査は正本 / 別冊 / 旧Draftの適用境界、NV Extend / local_capture / D4 / Activation Lockの文書Drift、
旧Controller / Goal Head契約の再混入、参照モデルの予期しないコードに対して追加した。製品の回帰Testは未追加。

## AGENTS.md整合の追補（2026-09-06、後続依頼「修正して」）

明示承認された消去規則の修正だけをAGENTS.mdへ反映した（+32 / -3行）。正常公開済み結果は期限後も
`post_ingestion`のManifest / Projection / 全Resource検証を維持する。`retention_expiry`はCollection COMPLETE・
Manifest未確定・Trusted Clockによる固有Retention到達・Receiptと最終Ingestion Evidenceを必須とする。
`incomplete_collection_expiry`はCollection ABANDONED / Quarantine RETENTION_EXPIRED・Task / Partial Ciphertext /
Chunk Progressを必須とし、存在しないReceipt / Manifestを捏造しない。

全経路のTrusted Repository read-back、型一致、Copy Inventory、OCC / Lease競合、専用Eraserによる単回Claimと
Critical Witness、同じKey破棄Identityの照合、破棄確認後Unlink、Raw再収集 / 再送禁止を維持した。
当該不一致のBLOCKED表示を解消済みに更新したが、正式なPR Design StopやPhase権限は変更していない。

この追補の変更ファイルはAGENTS.md、SystemDesign_AI_Control.md、docs/implementation-status.md、
docs/review/ai-control-research-review.md、docs/review/validate_ai_control_design.py、本Reportの6件。
SystemDesign.md本文や製品実装を追加変更せず、既存の未コミット変更を維持した。

| 実行コマンド | 結果 |
| --- | --- |
| `.venv/bin/python docs/review/validate_ai_control_design.py` | exit 0。従来の14文書・AI参照モデル・接続Schema検査に加えERASURE_RULE_DOCUMENT_ALIGNMENT=PASS。正常文言 / 空白変更3件、必須条件欠落・型取り違え・期限 / 状態 / Witness / 再破棄等の改変18件を拒否 |
| `.venv/bin/python -m ruff check docs/review/validate_ai_control_design.py` | exit 0。All checks passed |
| `.venv/bin/python scripts/ci/validate_automation.py` | exit 0。AUTOMATION_VALIDATION=PASS |
| `git diff --check` | exit 0。Tracked差分のWhitespace問題なし |
| `git diff --exit-code -- src tests .github automation scripts/ci pyproject.toml requirements.lock` | exit 0。製品実装・Test・Governance実行機構はHEADから未変更 |

追加検査は承認された消去規則の文言Fingerprintを正規化して照合する文書Drift検査である。
古い一律要件が消えただけでは合格にせず、必要な文言の欠落や変更を検出した場合は再レビューを要求する。
Fingerprintは実行認可・正式Design Approval・消去実装の正しさを証明しない。製品の回帰 / State-machine Testは未追加。
現在Phase / 正式Review SHAはこの文書修正では取得・認証しておらず、完全Phase Gate、型検査、Coverage、実LLM / TPMは未実行。
初回に確認した未変更のsrc / testsのLint88件は本追補でも修正していない。文書修正からPhase PASSを派生させない。

## 未実行・次工程

1. 正本・AGENTS.md・関連文書の人間レビューとマージ。既存のExact-HEAD取込 / Checkpoint / 単回Design Approval手順は維持する。
2. 正式Current Phase権限確認後、そのPhaseの完全な不変条件ファミリー実装・回帰 / State-machine Test・Phase Gate。
3. Phase 1でAI ACのMock Integration、Phase 2で実Local LLMの固定300 Run / 独立Oracle評価。
4. D4実機消去QualificationはNOT_EVALUATED。実機・Firmware / TSS・Copy / Restore・容量検証PASS前のProduction採用は禁止。

Current Phase / Input review SHAはこの文書作業ではGitHubから取得・認証していない。
Implementation Status中の過去SHAをCurrent Phase権限や今回の正式Review SHAとして使用しない。
製品Test、型検査、Coverage、完全Phase Gate、実LLM、実Adapter、実TPM検証は未実行である。
