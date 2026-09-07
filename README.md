# RedTeam Agent — 設計資料 と Phase 0A 実装

許可された隔離演習向け支援AIエージェントの設計資料と、その認可・データ保護基盤（Phase 0A）の実装を保持するリポジトリ。
Phase 0Aは**実外部Dispatchゼロ**の認可カーネルであり、実C2/MCP/Target接続・Payload生成・汎用Shell実行は含まない。

## 担当方針

| 工程 | 担当 |
| --- | --- |
| 設計・仕様の整合 | Codex |
| コーディング・実装 | Claude Code |
| 独立レビュー | 実装セッションと分離したCodex |

製品のPlanner / Analyzer用LLM仕様と、開発担当の分担は別の事項として扱う。

## 設計資料

| ファイル | 内容 |
| --- | --- |
| [SystemDesign.md](SystemDesign.md) | 設計正本。構成、安全基盤、接続Schema、Phase要件、開発規約 |
| [SystemDesign_AI_Control.md](SystemDesign_AI_Control.md) | 必須別冊。証拠・計画・認可の分離と共通制御ループ |
| [docs/acceptance-criteria.md](docs/acceptance-criteria.md) | Phase別の製品受入条件と開発記録の条件 |
| [docs/safety-invariants.md](docs/safety-invariants.md) | 製品の安全不変条件と開発時の遵守事項 |
| [docs/threat-model.md](docs/threat-model.md) | 製品と現行開発体制の脅威・対策・限界 |
| [docs/development/phase-0a.md](docs/development/phase-0a.md) | Phase 0A の開発記録（対象・要件・試験・残課題・独立レビュー未実施） |

設計改訂は`system-design-v1-r3` / `ai-control-v1-r3`。
AIの意味・判断は別冊を先に読み、安全基盤と接続Schemaは正本で確認する。
Phase順序・製品要件は正本§36〜38、開発開始・記録・独立レビューは§40と受入条件に従う。

## Phase 0A 実装

`src/redteam_agent/` に、正本§36 Phase 0Aの認可カーネルを実装する。決定論的で外部送信を行わない。

- `canonical/` — Trust Boundary JSON（重複キー拒否）、Canonical JSON、Versioned Digest Catalog / Digest Service、Deep-immutable Canonical JSON Object。
- `models/` `plan/` `mission/` — Strict Boundary Model、Mission Revision / State / Authorization Epoch の分離、Mission Manager（唯一のLifecycle入口、OCC、原子的audit）。
- `policy/` — Typed Execution Scope（IP/CIDR・Host・Session, Port/Protocol）、Data Access Policy（`resource-pattern-v1`）、Versioned Effective Risk / Approval Policy、PolicyDecision、Proposal/Authorization Digest、TargetDispatchBinding、TTL不変条件、Execution Authorization Service。
- `tools/` — Tool Registry（Revision/Digest/Validation）、Trusted Target Extractor（閉じた引数契約, 隠しdestination拒否）、Secret Argument Path（RFC 6901）、Tool Availability Resolver / AvailableToolSnapshot / Revalidation。
- `context/` — Context Resource Index、Context Selector（Index Metadataのみ）、ContextDataAccessGrant発行/検証。
- `approval/` — ApprovalPresentation（完全一致Binding）、ApprovalRequest/Record、認証済みactor + RBAC。
- `executor/` — Executor Authorization Gate（PolicyDecision検証のみ、Dispatchなし）。
- `runtime/` `auth/` `resources/` `sandbox/` `adapters/` `contracts/` `semantics/` `llm/` `storage/` `composition/` `devtools/` — Trusted Clock、Principal/RBAC境界、Secret Metadata読取境界、Sandbox Capability Binding、Adapter Capability、Action Contract Catalog、Semantic Catalog、Mock LLM Profile、SQLite Repository（write/read Integrity・Owner限定書込）、Composition Root、Git状態取得。

後続Phaseの機構（Dispatch/Secret Injection、TPM/暗号、実Adapter、実LLM）は前倒しせず、必要な境界は明示Test Double / Protocolで分離する。

### 再現手順

Python 3.14.6 で検証（`.python-version`へ固定）。プロジェクト仮想環境内へ固定依存を導入し、システムPython/グローバル設定は変更しない。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-build-isolation   # lock済みbuild backendを使用
.venv/bin/ruff check src tests scripts
.venv/bin/mypy
.venv/bin/python -m compileall -q src
.venv/bin/python -m coverage run --branch -m pytest
.venv/bin/python -m coverage report
```

依存は`requirements.lock`へ固定する（worktree絶対パスのeditable entryは含めない）。build backendは`setuptools.build_meta`で、
`requirements.lock`と`pyproject.toml`の`build-system.requires`に`setuptools==80.9.0` / `wheel==0.45.1`を固定する。
編集不要なら`PYTHONPATH=src`でも実行できる。

### 状態

Phase 0Aの製品コードと Unit/Integration/Security/Property-State-machine 試験を実装済み。ruff/mypy/compileall/branch coverageを実行済み。
**独立レビューは未実施であり、実装コミットの固定と正式なPhase受入は未完了。** 詳細と残課題は [docs/development/phase-0a.md](docs/development/phase-0a.md) を参照。

## 今回の整合方針（設計）

- 期限切れ確定は既存Retention Schedulerが行い、通常Workerの未失効Lease条件と分ける。
- 新規成果物の内部保存は既存Secure Ingestionへ限定し、追加の作成認可Recordを設けない。保存後のアクセス認可は維持する。
- 停止中のRecoveryは既存Graph状態とMission状態の対応表で表し、暗黙Resumeを行わない。
- 開発はPhaseごとの一つの記録に対象コミット・要件・試験・独立レビュー・残課題をまとめる。旧Launcher・Bot Marker・自動Mergeを必須としない。
- 公開時に全成果物を検証し、後日のQuarantine消去は確定済み公開証跡と消去対象自身から判断する。成果物本文の先行期限切れで消去を妨げず、本文・鍵の保持期限を延長しない。
- Ingestion Retryは同じ入力・固定Rule / Parserと既存予算内に限定し、変更Ruleでの既存Quarantine再処理はMVP対象外とする。
- 結果経路の正規値は`provider_task | local_result`へ統一し、表記揺れの互換Aliasを設けない。

新しい製品状態・Record種別・独立Service・開発状態機械は追加しない。根拠と適用限界は正本§41.11に記録する。
Scope・Policy・Human Approval・Secret保護・監査・Phase順序・実AdapterのHuman Gateは保持する。
D4の実機消去Qualificationは`NOT_EVALUATED`であり、Production採用は未承認である。

## 履歴と整合性

設計文書の旧原文は整理前コミット`9f45af326207606c0107c585bed01428055cbf9d`の履歴で参照できる。
現在の文書は承認済み整合を反映しており、旧原文のままではない。
正本§41の旧仕様・旧PR状態・旧開発Loopは履歴に限定し、新実装のGateや権限へ読み替えない。

`SHA256SUMS`は正本・別冊・受入/安全/脅威モデル文書・LICENSE・このREADMEの整合性を対象とする。
リポジトリ直下で`sha256sum --check SHA256SUMS`により確認できる。実装コード（`src/`, `tests/`）はGitで追跡し、
上記の静的検査・試験で検証する。

[LICENSE](LICENSE)
