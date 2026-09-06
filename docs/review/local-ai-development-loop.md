# ローカルAI開発ループ 修正結果

## 結論と対象

2026-09-06。Codex Cloudへ実装・レビューを依頼する経路を、ローカルCodex CLIの
実装Workerと別セッションのRead-only Review Workerへ置き換えた。
通常のReview結果登録・修正依頼・Phase遷移に人間の都度承認は不要。
既存のGovernance Review、Design Stop、Provider Human Gateは維持する。

- 作業区分: Governance変更。製品Phaseを進める作業ではない。
- 入力Review SHA: 本変更には正式Phase Reviewなし。
  差分の基準HEADは`83fcdf9605338506f31fa6bdb329b2af17816908`。
- 作業Branch: `codex/local-ai-development-loop`。
- 結果: ローカル修正と対象範囲の検証は完了。本書はCommit / Push前の検証記録であり、
  PR作成後もGovernance Mergeと配備が完了するまでは稼働開始を意味しない。
- 製品実装、PR #3の再開、Phase PASS、Merge、Branch Protection変更は実施していない。
- 製品全体Gateは既存の未変更コードに起因するエラーで不合格。下記に区別して記録する。

## 何を変更したか

1. `run_phase_loop.py`から新規Cloud trigger投稿を取り除き、`LocalExecution`へ接続した。
   文書にあるスクリプト起動形式でもモジュールをロードできるようにした。
2. 親Runnerは承認済みCurrent Mainから動き、完全HEAD固定のSnapshotと入力Bundleを作る。
   GitHub資格情報、元Checkout、JournalをWorkerへ公開しない。
3. Worker起動前にGitHub Git refの永久Claimを原子的に作る。開始・検証・Push試行等は
   親専用Journalへ排他的に追記する。既存Claim、結果不明、途中公開後のRestartでは自動再送しない。
4. 実装Workerは`src/`、`tests/`、`docs/review/`の変更を未Commitで返す。
   親が変更範囲、Symlink、HEAD、検証前後の内容Digest、完全Gate、必要なStrict Auditを確認し、
   通常の単一子Commitと既存PR Branchへの通常Pushを行う。Force Push経路は追加していない。
5. レビューは新規CLI Process / Context / Read-only Snapshotで実施する。
   元の閉じたReview Schemaで検証し、全指摘を実在するCommentへ公開してからResultへBindingする。
   親とGitHub Workflowの両方でHEAD、Base、Ready、Audit / Policy Digest、Actor、時系列、
   全Finding、必須CIを再検証する。
6. 新規Gate登録は`local-review-v1`だけを受理する。過去の`codex-native-v1` PASSは
   Phase Chain・Design Approval・Base Refreshの履歴検証用として残す。
7. 隔離はLinux bubblewrapとCodex権限設定を組み合わせる。GitHub Credential、Tool Network、
   Git Metadata、保護File、他Sessionを隔離する。必要なNative Code ModeはRoot-ownedの
   Standalone Hostだけを使い、In-process / Cloud / Unisolated Fallbackはしない。
8. CLIへ送るJSON Schemaは対応するTransport形へ投影するが、出力は必ず元Schemaでも検証する。
   条件付きSchema制約や不正Resultの拒否を緩和していない。
9. Hostから継承する設定は`model`と`model_reasoning_effort`の2 Scalarだけ。
   Provider、Plugin、MCP、Hook、既存会話は継承しない。API Key連携は追加していない。
10. 設計・要件・受入条件・運用文書をLocal-onlyへ整合した。
    `same_finding_limit`の表示値は、既存Workflowと規範の5へ合わせた。
    実際の停止閾値は変更せず、Invariant Familyの2回目再発Stopも維持する。

対応要件: LOOP-001〜007、015〜017、030〜034、およびCommon Development-loop Gate。

## 接続レビューで修正した指摘と回帰

- Reviewにも実装用`request.json`を必須にしていた不備を修正。
  Reviewは`evidence.json`、Implementationは追加の`request.json`を必要とする。
- `FIX_REVIEW_FINDINGS`の全指摘本文を、認証済みGate / Review / Referenceへ照合してBundleへ格納。
  Bodyは非信頼データとして扱う。欠落・改ざん・別Actor・Reference不一致を拒否する。
- 指摘付き`BLOCKED`で誤ってRetry Keyを設定する不備を修正。
  `finding_key`は`CHANGES_REQUESTED`の時だけ登録する。
- Review中のHEAD変更はResult公開前の最新Timelineでも検証する。
- Validationが同じFile名の内容を変更した場合もDigest比較で拒否する。
- Lifecycleの表示Labelだけの遅延は停止理由にしない。Phase、HEAD、Main、Stop latchは再検証する。
- 全Findingを公開する途中の応答喪失、Claim / Startの応答喪失、重複起動、再起動時の再送を拒否する。
- 実CLIのUUIDv7 Session IDに対応し、親のRun IDはUUIDv4に固定した。
- Native Cloud形式の新規Gate発行を拒否し、過去PASSの混在Chainは引き続き受理する。

## 変更File

新規:

- `automation/local_execution.py`
- `automation/local_worker.py`
- `automation/local_review_evidence.js`
- `automation/local-execution-policy.json`
- `automation/schemas/local-execution-policy.schema.json`
- `tests/unit/test_local_execution.py`
- `tests/unit/test_local_worker.py`
- `tests/unit/test_local_review_evidence.py`
- `docs/review/local-ai-development-loop.md`

更新:

- `automation/run_phase_loop.py`、`automation/approve_design_resume.js`
- `automation/project-settings.yml`、`automation/chatgpt-event-task-prompt.md`
- `.github/prompts/implement.md`
- `.github/workflows/ai-loop-control.yml`、`.github/workflows/ci.yml`
- `.github/workflows/refresh-ai-loop-base.yml`、`.github/workflows/revalidate-blocked-phase.yml`
- `scripts/ci/validate_automation.py`、`tests/unit/test_phase_loop.py`
- `AGENTS.md`、`SystemDesign.md`（§40.1のみ）
- `docs/requirements.md`、`docs/acceptance-criteria.md`、`docs/safety-invariants.md`
- `docs/ai-development-loop.md`、`docs/ai-loop-runbook.md`
- `docs/implementation-status.md`、`docs/threat-model.md`

`src/`、製品Security / Integration Test、製品Phase Promptは変更していない。

## 検証結果

### 今回のGovernance範囲

549件PASS、Skipped 0、Errors 0、Failures 0。
新規の正例・負例・障害経路・再起動/状態機械テストと既存Governance回帰を含む。

実行Command:

```bash
PATH='/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin':"$PATH" \
COVERAGE_FILE=/tmp/redteam-local-loop-governance-coverage \
.venv/bin/python -m coverage run --branch --source=automation -m pytest -q \
  tests/unit/test_local_execution.py tests/unit/test_local_review_evidence.py \
  tests/unit/test_local_worker.py tests/unit/test_phase_loop.py \
  tests/unit/test_automation_validation.py tests/unit/test_governance_check.py \
  --strict-markers --junitxml=/tmp/redteam-local-loop-governance-tests.xml --tb=short

COVERAGE_FILE=/tmp/redteam-local-loop-governance-coverage \
.venv/bin/python -m coverage report --show-missing

.venv/bin/python -m ruff check automation scripts/ci \
  tests/unit/test_automation_validation.py tests/unit/test_governance_check.py \
  tests/unit/test_phase_loop.py tests/unit/test_local_execution.py \
  tests/unit/test_local_worker.py tests/unit/test_local_review_evidence.py

.venv/bin/python scripts/ci/validate_automation.py
.venv/bin/python -m compileall -q automation scripts/ci src/redteam_agent
git diff --check
```

全て成功。Coverage（Branchを含む）: `local_execution.py` 84%、`local_worker.py` 86%。
既存`run_phase_loop.py`等を含む`automation`全体は66%。これは製品全体Coverageではない。
JavaScriptのWorkflow模擬試験は上記pytestで実行しているがPython Coverage対象ではない。

追加の構文確認も成功:

```bash
/usr/lib/chatgpt/resources/cua_node/bin/node --check automation/local_review_evidence.js
/usr/lib/chatgpt/resources/cua_node/bin/node --check automation/approve_design_resume.js
/usr/bin/python3 -c 'from pathlib import Path; import yaml; paths=[Path("automation/project-settings.yml"),*Path(".github/workflows").glob("*.yml")]; [yaml.safe_load(p.read_text()) for p in paths]; print("YAML_PARSE=PASS", len(paths))'
```

YAML 10 Fileを解析。環境の`.venv`にはPyYAMLがないため、この構文確認だけSystem Pythonを使用。

### 製品を含む完全Gate — 既存Baselineの問題で不合格

```bash
PATH='/home/kali/RedTeam_Agent/.venv/bin:/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin':"$PATH" \
bash scripts/ci/run_phase_gate.sh phase-0c
```

Compile・Automation SchemaはPASS、Invariant Auditは`NOT_REQUIRED`。
その後、未変更の製品コード/製品TestのRuff 88件で停止（Exit 1）。
Gateを弱めず、後続Commandも別途確認した:

```bash
.venv/bin/python -m mypy src/redteam_agent
PATH='/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin':"$PATH" \
.venv/bin/python -m pytest -q tests/unit --strict-markers --tb=short
.venv/bin/python -m pytest -q tests/integration tests/security --strict-markers --tb=short
PATH='/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin':"$PATH" \
COVERAGE_FILE=/tmp/redteam-local-loop-full-coverage \
.venv/bin/python -m coverage run --branch -m pytest -q tests --strict-markers \
  --junitxml=/tmp/redteam-local-loop-full-tests.xml --tb=no
.venv/bin/python -m pip check
```

- Mypy: 16 Fileで40 Error（Exit 1）。
- Unit: 製品ModuleのCollection Error 3件（Exit 2）。
- Integration + Security: Collection Error 11件（Exit 2）。
- 全Test/Coverage: Collection Error 14件。完全な製品Coverageは取得不能。
- 共通のCollection Errorは未変更の`src/redteam_agent/canonical/models.py:13`。
  RuntimeでUnion型と文字列を`|`演算して`TypeError`になる。
- `pip check`: PASS。依存関係破損なし。

これらは今回の変更範囲外であり、修正・Skip・Xfail化していない。
今回の549件PASSを、製品Phase 0C PASSまたは製品受入完了へ読み替えない。

### 実ローカルCLIの合成Qualification

Runtime: `codex-cli 0.153.0-alpha.5`、Host設定の`gpt-6-astra / medium`、Node `v24.19.0`。
Fixtureは`/tmp/redteam-worker-smoke.YYIMHu/`。Modelによる製品レビューではない。

- Reviewの実Schema: `run_local_worker`へ既存`review-result.schema.json`を渡し、
  固定した架空HEAD / Base / PASS JSONと戻り値が一致することを確認。
  Session `01a07790-1d5d-7723-84a5-85ffa0350de0`。
  Transcript SHA-256 `f95b79297c79d332fd9a95ada91b0f4fe46b450d84fffb22a57f02f208a9c023`。
- Implementation: 実`IMPLEMENTATION_SCHEMA`でNative編集Toolを使い、
  `src/probe.txt`だけに固定文字列を生成。親が全Fileの前後Hashを比較し、
  `.git`不変・Commitなしを確認。
  Session `01a07792-8902-7212-ad9a-2ad94820052d`。
  Transcript SHA-256 `30e125b658d82f1540d8388a85cc5dec7673787fb0b48eabee55c681047c7522`。
- 両Roleで`preflight_local_worker`を実行してPASS。
  合成Auth領域と`/proc/1/root`経由の読取拒否、Tool Network拒否、
  Schema / Input / Git保護とRole別書込権限を確認。実資格情報の読取試験はしていない。
- 隔離Namespace内の`.venv`でjsonschema / pytest / mypy / ruff / coverageをImportし、
  同Namespace内でNodeを起動してPASS。

実CLI確認はNative Account認証によるModel通信を伴う。
Codex Cloud Task、GitHub Cloud Review、RepositoryによるAPI Key連携は使用していない。
OpenAI Docsの[非対話実行仕様](https://learn.chatgpt.com/docs/non-interactive-mode)を参照し、
CLI実行・JSONL・構造化出力を採用した上で、実Runtimeと元Schemaの検証を追加した。

## 残る運用上の条件

- 本変更をHuman Governance Review / MergeしてCurrent Mainへ配備すること。
- 旧Cloud依頼・未公開結果をReconcileし、必要なCurrent-HEAD Authorityを用意してからRunnerを起動すること。
  既存の単回Design Approvalを勝手に再利用しない。
- GitHubの実Workflow Dispatch / Pushを伴う本番Loopは、この変更の配備前には実行していない。
  API動作は模擬GitHub、実Processは合成ローカルFixtureで検証した。
- Host / Native CLI / Sandbox / Operator Accountを信頼する。独立第三者署名や
  Host侵害耐性のRemote Attestationを保証するものではない。
- 認証失効、Runtime更新、隔離失敗、未解決Claimでは停止する。CloudへのFallbackはない。
