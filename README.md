# RedTeam Agent — 設計資料

再実装のための設計資料を保持するリポジトリ。
既存の製品コード、テスト、依存環境、CI/CD・自動開発ループは含まない。

## 担当方針

| 工程 | 担当 |
| --- | --- |
| 設計・仕様の整合 | Codex |
| コーディング・実装 | Claude Code |
| 独立レビュー | Codex |

製品のPlanner / Analyzer用LLM仕様と、開発担当のCodex / Claude Codeの分担は別の事項として扱う。

## 設計資料

| ファイル | 内容 |
| --- | --- |
| [SystemDesign.md](SystemDesign.md) | 設計正本。システム目的、構成、認可・状態・データ保護、Phase別の製品要件 |
| [SystemDesign_AI_Control.md](SystemDesign_AI_Control.md) | 必須別冊。AI判断、証拠、計画、ActionContract、制御ループと受入シナリオ |
| [docs/acceptance-criteria.md](docs/acceptance-criteria.md) | Phase別の製品受入条件と品質条件 |
| [docs/safety-invariants.md](docs/safety-invariants.md) | 認可、Secret、暗号、実行・回収、AI制御の安全不変条件 |
| [docs/threat-model.md](docs/threat-model.md) | 製品と旧開発ループの脅威分析 |

[LICENSE](LICENSE)、このREADME、[SHA256SUMS](SHA256SUMS)を含め、管理するファイルは8件。
設計文書5件とLICENSEは、整理前のコミット`9f45af326207606c0107c585bed01428055cbf9d`の原文を保持する。
設計改訂は`system-design-v1-r1` / `ai-control-v1-r1`。

AIの意味・判断は別冊を先に読み、安全基盤と接続Schemaは設計正本で確認する。
Phase順序・詳細要件は正本§36〜38と受入条件に記載されている。

## 新体制への整合事項

原文には旧実装・旧CI/CD運用の記述が残る。次の箇所は、新規実装の開始前に新しい担当方針と整合させる。

| 文書・箇所 | 見直す事項 |
| --- | --- |
| `SystemDesign.md` 冒頭、§38 Implementation Strategy、§41.9 | 既存コードの再利用・置換方針、旧Phase権限への参照 |
| `SystemDesign.md` §40〜40.1 | Codex実装、Trusted Runner、GitHub証拠、旧自動Review Loopを前提とする開発規約 |
| `SystemDesign_AI_Control.md` §0・§12・§14 | 旧PR状態・設計採用履歴・移行前提と製品要件の整理 |
| `docs/acceptance-criteria.md` Common Gate / AI Loop Control Acceptance / Project Complete | 旧GitHub Marker・Launcher・自動Mergeへの依存 |
| `docs/safety-invariants.md` Development loop | 旧開発ループの規約と新しい担当分担の整合 |
| `docs/threat-model.md` | 製品の脅威分析の保持と旧CI/CD・Launcherの脅威分析の再設計 |

製品のScope・Policy・Human Approval・Secret保護・監査等は保持する。
D4の実機消去Qualificationは原文どおり`NOT_EVALUATED`。設計の保存やリポジトリ整理は実装検証・Phase PASSを意味しない。

設計文書間のリンクは保持している。旧`docs/review/`、`automation/`、`prompts/`等への参照先は削除済み。
具体的には、次の資料へのMarkdownリンクが原文に残っている。

- `docs/review/ai-control-implementation-ready.md`
- `docs/review/ai-control-research-review.md`
- `docs/review/current-design-research-assessment.md`
- `docs/review/systemdesign-canonical-adoption.md`
- `docs/review/validate_ai_control_design.py`

ファイルの整合性は、リポジトリ直下で`sha256sum --check SHA256SUMS`を実行して確認できる。
