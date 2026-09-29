# AD MCP サーバ実装計画

改訂: `ad-mcp-plan-v1` / 2026-09-29。
対応仕様: `system-design-v1-r4` / `ai-control-v1-r4` / [ad-mcp-v1](../ad-mcp-spec.md)。
状態: 工程2と工程3の共通基盤、本体Adapter、工程4の閉じたCatalogを実装済み。
Mock / SDK stdio試験は実施済み。実ツール別argv互換、実AD結合、Windows Remote Transport、HTTP、
未確定Riskの有効化は未実施であり、該当操作をProduction利用可能とは扱わない。

## 1. 決定事項

- 同じリポジトリ内の独立`ad-mcp/`パッケージとして作成する。
- 本プロジェクトのPolicy・Approval・Executor経由に限定する。
- 公式Python SDK v2の`MCPServer`を使用する。
- 添付の全ツールを操作単位で登録し、長時間ジョブと登録済みWindowsペイロードの実行を含める。
- 専用Sandbox構築・検証を必須から外す。実行時間等の個別制限とScope検査は残す。
- 生出力の暗号化必須を外し、非公開の生ログ保管と公開用JSON生成へ簡素化する。
- 実環境での専用資格判定を、ツールごとの結合テストと確認記録へ置き換える。

これらは会話でユーザーが承認した変更である。追加の方針変更は、具体的な変更案を示してユーザーの許可を得る。
未確定事項は推測せず、仕様§10の質問を該当工程の前に解決する。今回の文書更新は実装着手の指示へ読み替えない。

## 2. 現状と再利用候補

| 現在の資産 | 扱い |
| --- | --- |
| `adapters/mcp*.py` | Identity、Protocol固定、承認Schema照合を再利用候補とし、SDK v2との実Wire互換を検証 |
| `mcp_servers/impacket_*.py` | 4操作の既存サーバ。新サーバの全ツール対応と混同せず、移行時の比較・回帰に使用 |
| `adapters/mcp_stdio_transport.py` | one-shot・全応答収集を、新サーバの寿命・大容量出力・Job契約と照合して改修 |
| `tools/`, `policy/`, `approval/`, `execution/` | 本体の認可・単回実行・結果不明処理を継続利用 |
| `quarantine/`, `ingestion/`, `erasure/` | 新経路の平文保存・公開・通常削除と、既存暗号化経路の保存・復旧を明示的に区別 |
| `ad_assessment/` | 検出項目・Coverage・既存Certipy処理の再利用可否を確認。現行の設定評価機能を侵襲的操作と混同しない |
| `composition/`, `ui/kali_provider_status.py` | Sandbox必須・資格判定の旧Blockerを、新経路の結合テスト結果と設定確認へ置換 |

コードの存在、過去のPASS、サンプルの`production_eligible`を、新仕様の受入証拠とは扱わない。
本体のTPM・Secret・Runtime依存は別途棚卸しし、MCP専用Gateの簡素化だけで全体が起動可能とは扱わない。

## 3. 作成予定の構成

以下の構成で共通基盤を作成した。Parserは現時点で`parsers.py`に集約し、実ツールFixtureの追加時に
操作別Moduleへ分割する。Payload manifestは空であり、未承認Payloadを同梱していない。

```text
ad-mcp/
  pyproject.toml
  README.md
  config/
    scope.example.yaml
    settings.example.yaml
  src/ad_mcp/
    server.py
    registry.py
    models.py
    executor.py
    jobs.py
    scope.py
    risk.py
    audit.py
    remote_exec.py
    parsers/
    tools/
      recon.py
      enumeration.py
      kerberos.py
      adcs.py
      coercion_relay.py
      secrets.py
      cracking.py
      analysis.py
      privesc.py
  payloads/
    manifest.json
  tests/
    unit/
    contract/
    integration/
    security/
```

カタログSchemaは仕様§3を正本とする。実行別の生ログRootは設定で与え、Git管理するソース・Payload置場から分ける。
依存はpyprojectで管理し、uvまたはpipで導入できるようにする。exact依存の固定方式を工程1で決める。

## 4. 工程

工程番号は今回の追加開発の順序であり、プロジェクトPhase 0A〜5の再編ではない。
実装は現行の担当方針に従いClaude Code、独立レビューは別セッションのCodexが行う。

### 工程1: 未確定事項と接続契約の確定

- 仕様§10のうち依存・Protocol・Transport・Risk・Jobに関わる回答を得る。
- SDK版、対応Protocol、Stable ID、入力Schema、Secret注入、出力・エラー形式を固定する。
- `local_result`と`provider_task`を操作ごとに選び、独自Job APIと標準Tasksを混同しない。
- 新AD MCPだけを識別する構成と、本体のSandbox・保存・有効化条件の適用範囲を確定する。
- 添付全ツールを版・操作・リスク・Parser・受入試験へ対応付ける。

成果物: 契約表、カタログ定義案、質問への回答、既存コードとの差分表。
完了条件: 実装対象に未解決の仕様矛盾がない。後段機能の未確定事項はその有効化を保留する。

### 工程2: MCP接続と共通基盤

- MCPServer、カタログ登録、入力検証、Scope、risk gate、dry-runを実装する。
- subprocess、時間・出力制限、監査、生ログの保存を接続する。
- 本体Registryと承認済みSchemaを照合し、本体以外からの実行を防ぐ。
- 実バイナリを使わないTest Serverで一覧取得と呼出を検証する。

成果物: モックで実行できるサーバ、設定例、共通基盤の単体・契約試験。
完了条件: Scope外、未知操作、不正入力、intrusive既定無効、dry-run非実行を確認できる。

### 工程3: 結果保存・ジョブ・本体統合

- 暗号化Quarantine必須を新AD MCPの生ログ保存・公開用JSON生成へ置換する。
- 生ログの部分・完了、容量・期限、公開Resultの確定、Parser失敗、通常削除を実装する。
- Job IDとExecution / Actor / Missionを対応付け、照会・停止・回収へ既存認可を適用する。
- 再起動、接続切断、応答消失、孤児プロセス、重複起動を検証する。
- 既存データは旧Readerで扱い、保存形式を途中で暗黙変更しない。必要な移行は明示手順にする。
- Sandbox能力を偽装せず、新AD MCPのRegistry / Availability / Pre-dispatch / Compositionの要求を改訂する。

成果物: 本体へ戻る構造化Result、Job管理、保存・復旧・削除契約と試験。
完了条件: 他Missionの結果アクセス拒否、Raw非公開、Secret非混入、部分結果保持、重複副作用なし。

### 工程4: ツール・Parserの段階追加

仕様§6の全行を対応表で追跡する。各操作は定義・Parser・検出Rule・Fixture・拒否試験を一組で追加する。
passive → active → intrusiveの順に進める。各区分内では次をまとまりとして扱う。

1. オフライン変換・解析、SMB/RPC/LDAP列挙、nmap、NetExec探索、Certipy find。
2. BloodHound収集・取込・分析、hashcat/john、Kerberosと認証試験。
3. Certipyの侵襲的操作、ImpacketのSecret取得・実行・AD変更、coercion/relay、Windows操作。

この順序は個々のリスク分類を先取りしない。分類未確定の操作は有効化しない。
汎用ラッパは具体的な操作の検証を再利用し、追加引数で制約を迂回できないことを確認する。
Windows操作は配布・実行・回収・後処理を含めて試験し、ローカル停止をリモート停止成功にしない。

成果物: 添付全ツールの対応表、定義、Parser、説明文、検出観点、試験。
完了条件: 未対応・部分対応を明記し、登録名だけのStubを実装済みと数えない。

### 工程5: 品質確認とREADME

- `pytest`、`ruff`、`mypy`を新パッケージと変更した本体部分に適用する。
- 実バイナリのsubprocessは単体試験でモックし、出力Fixtureに実Secretを含めない。
- 本体の認可・Secret・既存MCP・保存・復旧の影響範囲を回帰試験する。
- セットアップ、Scope例、本プロジェクトの接続設定、intrusive有効化、Job管理、生ログ閲覧・削除を記載する。
- READMEに認可済み環境のみで使用する旨と、OS Sandbox・暗号化保存の保証範囲を明記する。
  一般MCPクライアントの直接実行設定は、承認された利用範囲に合わせて提供しない。

成果物: 再現手順、README、試験結果、独立レビュー記録。
完了条件: 未解決指摘・未実施項目を含めて記録し、合格した範囲を特定できる。

### 工程6: 実環境結合テストと有効化

- 許可済みKali・AD上で、操作と版を限定して接続・出力・制限・停止を確認する。
- 仕様§9の項目を既存のPhase 5開発記録へ追記し、別の資格認定サービスを追加しない。
- 実際に確認した操作だけを有効化対象とし、後続ツール追加時は該当分を確認する。
- 本体の残る依存条件を確認し、ツール単体の合格と本体End-to-Endの成立を区別する。

成果物: ツール別結合テスト記録、設定手順、未完了項目。
完了条件: 受入項目が確認済みで、利用する本体経路にも未解決の必須依存がない。

## 5. 変更対象と移行

新パッケージに加え、本体のMCP契約・Transport・Composition、RegistryのSandbox要求、Availability、
結果保存・公開・削除、JobのCollection / Recovery、Provider状態表示、受入試験が変更対象になる。
§19.4対象外のAdapterへ、暗号化やSandbox条件の撤廃を波及させない回帰試験を置く。

既存Mission・Execution・暗号化Quarantine・Secretの意味を変更しない。新しいRegistry / 保存形式のRevisionは
停止中の明示的な構成変更・必要なMigrationを通じて導入する。既存未完了Executionを新経路で再送しない。
RawのDigest・保存形式・保持期限をMetadataへ固定し、暗号化領域を平文ファイルとして読み替えない。

## 6. 実装時点の記録

- `ad-mcp/`に独立pyproject、公式SDKサーバ、Catalog、実行・保存・Job・監査・設定例・試験を追加した。
- 本体にAD MCP Catalog Bridge、永続stdio Composition、provider-task Adapter、専用Target Extractorを追加した。
- 78操作は登録済みだが、Risk未確定操作はdry-run以外を拒否する。全操作は設定の明示Allowlistが空のまま開始する。
- Windows manifestは空、Remote Transportは`disabled`固定である。Payloadや転送方式を推測して追加していない。
- SDK実プロセス試験10件と、既存を含む全1101件（1094 PASS / 7 skip）を実行した。実AD・実ツールへの接続は0件である。
- `ruff`と`mypy`は新パッケージおよび本体全SourceでPASSした。
- 仕様§10の未確定事項に依存する機能は有効化せず、回答後にCatalog引数・Risk・Transportを確定する。
