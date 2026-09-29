# AD MCP サーバ仕様

改訂: `ad-mcp-v1` / 2026-09-29。`system-design-v1-r4` / `ai-control-v1-r4`の規範別冊。
状態: 共通サーバ、本体Adapter、78操作の閉じたCatalog、Mock / SDK stdio試験まで実装済み。
実ツール別の結合試験と有効化、Windows Remote Transport、HTTP、未確定Riskは未完了である。

## 1. 目的と適用範囲

自社所有・テスト許可済みのAD環境を対象に、Kali Linux上の登録済みツールをMCPから実行する。
同じリポジトリの`ad-mcp/`を独立Pythonパッケージとし、本プロジェクトのExecutor / MCP Adapterからだけ利用する。
一般MCPクライアントからの直接実行は今回の提供範囲に含めない。

本書は[設計正本](../SystemDesign.md)§19.4で指定するAD MCP経路だけに適用する。
既存Impacketサーバは4操作のone-shot実装のままであり、本書の機能を既に備えるとは扱わない。
既存C2、他のMCP、Secret Store、監査の鍵・Witnessへ今回の緩和を広げない。

### 1.1 承認済みの決定

| 項目 | 決定 |
| --- | --- |
| 配置 | 同じリポジトリ内の独立した`ad-mcp/`パッケージ |
| 利用経路 | 本プロジェクトのPolicy・Approval・Executor・Secret管理を通す |
| SDK | 公式Python SDK `mcp` v2の`MCPServer`。添付のFastMCP指定を置換 |
| 対応範囲 | §6の全ツールを段階的に実装。登録済みWindowsペイロードの配布・実行・回収を含む |
| 実行方式 | `asyncio`と`asyncio.create_subprocess_exec`。引数配列を使用し、`shell=True`は禁止 |
| ジョブ | 長時間処理のID返却、照会、停止、部分出力、復旧を本体Adapterまで設計する |
| Sandbox | 専用Sandboxの構築・検証証跡を、この経路の実行開始の必須条件から外す |
| 生出力 | 暗号化を必須にせず、アクセス制限付きの実行別ディレクトリへ保存する |
| Quarantine | 暗号化Quarantineへの保存必須を、生ログ保管と公開用JSON生成の分離へ置き換える |
| 導入確認 | MCP専用の資格判定・証跡管理を、ツールごとの実環境結合テストと確認記録へ置き換える |

### 1.2 適用の識別と維持する境界

対象はComposition Rootが固定するAD MCPのAdapter ID、Server ID、承認済みRegistry Revisionに結び付ける。
具体IDは実装前に確定する。LLM引数、Mission自由文、ツール結果から緩和対象を選べる設定にしない。
暗号化やSandboxの故障を契機にこの経路へ切り替えるFallbackを設けない。

Scope、入力検証、Human Approval、単回Dispatch、Secretの参照・注入、監査、結果不明時の再送禁止は維持する。
`intrusive`の有効化はHuman Approvalの代替ではない。登録・有効化・各Actionの認可を区別する。
Source、Rule、Coverageを検証するKnowledge ReducerとGoal Evaluatorの責務も維持する。

本書による生出力暗号化の撤廃は、Secret StoreやApplication全体のTPM要件の撤廃を意味しない。
暗号化Quarantine固有の鍵・消去資格は新しい平文生ログに要求しないが、残る本体依存条件を満たさずに
全製品が稼働可能と宣言しない。既存Production構成の残条件は計画の依存確認で区別する。

## 2. 構成と責務

```text
Plannerの提案
  → 本体のRegistry / Policy / Approval / Executor
  → MCP Adapter
  → ad-mcp: Schema / Scope / risk gate / 登録済み操作
  → subprocess または登録済みWindows操作
  → 非公開の生ログ保存
  → 固定Parser / Secret分離 / 公開項目の検証
  → 本体の公開用Result / Artifact
  → Analyzer / Knowledge Reducer
```

本体がMissionの認可とExecution状態を所有する。サーバはプロセス、Provider Job、生ログの保存を所有する。
サーバのカタログ申告を本体Registryへ自動採用しない。Schemaと安全属性をレビューしRevisionへ固定する。
サーバが返す構造化JSONも非信頼入力として、本体の公開Rule・Evidence Ruleへ照合する。
本体のSecret注入経路と、サーバ側の一時的なSecret保持・破棄を接続契約に含める。

stdioを既定とする。HTTPの候補はStreamable HTTPであり、旧SSEの必要性は§10の確認事項とする。
本体のProtocol Baseline `2026-07-28`を維持し、公式SDKの固定版とのWire互換を確認する。
HTTPを追加するときも呼出主体を本プロジェクトへ限定し、認証・Transport Identityを定義する。
別ホストへ配置する場合は既存Remote MCP Trust Policyの検討が必要であり、local_process向けの緩和を流用しない。

## 3. ツールカタログ

1定義は「バイナリ＋サブコマンド＋操作」に対応する。読取と変更、認証とSecret取得を区別する。
Pythonの型付き定義を基礎とし、任意Import Pathや実行式を設定から読み込む方式にしない。

| Field群 | 必須内容 |
| --- | --- |
| Identity | 安定した操作ID、MCP tool名、カテゴリ、定義Revision、本体ToolRefへの対応 |
| Description | 目的、前提、検出観点、観測できない事項、出力の限界 |
| Binary / arguments | 絶対パス、対応Version、SHA256、固定argvテンプレート、許可オプション |
| Input schema | 型、必須項目、列挙値、長さ・範囲、文字列パターン、未知項目拒否 |
| Targets / paths | 全通信先の抽出規則、ポート、対象モード、入力Artifactと出力先の規則 |
| Risk | `passive / active / intrusive`、本体の最低Risk、副作用、冪等性、承認条件 |
| Secret | Secret参照の項目、注入方式、機密成果物・公開禁止項目 |
| Output | 出力Schema、Parser ID / Revision、公開Rule、Evidence Rule、検出項目ID |
| Execution | timeout、最大出力量、対象数、並列数、ジョブ対応、必要権限 |
| Application contract | ActionContract、Schema Digest、Adapter Capability、結果取得方式 |

添付の3区分と本体の`read / low / medium / high`は別の属性として対応表を管理する。
未分類操作は有効化しない。MCP annotationsの自己申告でRiskやApprovalを引き下げない。
`run_allowlisted_tool`とImpacket汎用ラッパは登録済み操作IDを選ぶ共通入口とし、通常のSchema・Scope・Risk検査を通す。
任意argv、自由形式Shell、任意のNSE・NetExecモジュールを追加する抜け道にしない。

## 4. 入力・Scope・実行制限

- `scope.yaml`に許可CIDR、ドメイン、ホスト名を定義する。空・不正・判定不能は拒否する。
- 本体Mission ScopeとサーバScopeの両方を満たす対象だけ実行する。
- DC、DNS、CA、列挙先、Referral、relay先、待受Interfaceなど、操作が使用する対象を抽出する。
  ネットワーク越しの追加対象を検査できない操作は、有効化前に契約を解決する。
- ドメイン名の一致だけで任意IPへの通信を許可しない。名前解決結果と実際の接続先のBindingを定義する。
- 出力は実行別ワークスペース配下へ限定する。パストラバーサル、Symlink、他Executionの上書きを拒否する。
  入力リスト、辞書、ハッシュファイル、証明書等も許可済みResourceとして扱う。
- argvはツール定義から組み立てる。シェル展開に加え、オプション注入、入力ファイル内の対象、ツール固有の
  コマンド・スクリプト実行機能を検証する。正規表現だけで全ての意味検証を済ませない。
- 時間・出力量・対象数を制限し、stdout/stderrを上限付きで回収する。停止時は子プロセスも扱う。
- 専用Sandboxなしの構成では、ツール内部の想定外通信やFilesystem操作をOSで全面阻止できるとは主張しない。
  アプリケーションのScope検査とOS強制の保証を区別する。

`intrusive`は設定で明示有効化するまで拒否する。全操作にdry-runを用意し、入力検証結果、対象、Risk、
Secretを伏せたコマンド表示を返す。dry-runではツール起動、Secret解決、対象通信を行わない。
ネットワーク照会が必要なScope確認は「未確認」と返し、dry-runから実行認可を発行しない。

## 5. 生ログ、公開結果、監査

### 5.1 暗号化Quarantineの置換

この経路では、生ログをExecutionごとの非公開ディレクトリへ段階的に保存する。
保存先はサーバが生成し、呼出側の任意パスを採用しない。OSアクセス権、総容量、保持期限を設定する。
実装時にファイル権限・保存Root・容量・保持期間を確定する。設定欠落を無制限保存へ変換しない。

生ログにはパスワード、ハッシュ、秘密鍵が含まれる場合がある。保存ファイルを読めるOS主体はその内容を読める。
Raw RootをLLMのファイル参照、通常UIの静的配信、公開MCP Resourceに登録しない。
監査やMCP結果にパスを含めても、それ自体を読取権限としない。

保存MetadataはExecution / Job ID、stream種別、サイズ、Digest、部分・完了の区別、保持期限を持つ。
書込み完了と完了Metadataの確定を分け、Crash後に不完全なファイルを完全な結果と誤認しない。
同じ実行の保存済み出力から解析を再開し、出力不足を元ツールの再実行で埋めない。

### 5.2 公開用JSON

固定Parser、機密項目の分離、公開Field Allowlistを通したJSONだけをLLMへ渡す。
Parserが読めない出力は原本を非公開で保持し、型付きエラー・Coverage不足として返す。
生stdoutや例外文字列を、そのまま代替結果として公開しない。

検出結果は検出ID、対象、観測値、証拠参照、時刻、Tool / Parser / Ruleの版、Coverageと不足情報を持つ。
正常終了を脆弱性検出と同一視せず、「未検出」と「調査不能」を区別する。
SPNの存在から弱いパスワードを断定せず、認証強制への露出と成立確認を区別する。
秘密値はLLMへ返さず、利用可能な認証材料として扱うときは本体Secret Storeの既存認可・登録を通す。

本体の保存・公開担当はこの平文保管契約を明示的に扱う。サーバが生成したJSONをそのまま信頼したり、
本体の暗号化Quarantine必須処理を黙って通過させたりしない。Result Modeは既存の
`local_result | provider_task`を維持し、保存形式と結果取得方式を混同しない。

### 5.3 保持・削除

保持期限後は生ログの閲覧・解析を終了し、対象ディレクトリを削除する。削除失敗は記録して再処理する。
既存の期限管理・公開用Result復旧へ接続し、完了済みResultを復元するためにツールを再送しない。
暗号化していない原本に鍵破棄、暗号学的消去、D4のResource Key資格を要求・捏造しない。
通常ファイル削除はバックアップや記憶媒体を含む復元不能性の保証とは扱わない。
既存の暗号化Quarantineは従来のReader / Retention / Eraserで完了させ、今回の変更で平文化しない。

### 5.4 JSONL監査

開始、拒否、dry-run、完了、timeout、cancel、解析失敗、削除の各Eventを追記する。
ISO8601時刻、Tool / Operation ID、マスク済み引数、対象、Execution / Job ID、終了コード、結果パスを記録する。
未起動・実行中等で終了コードが存在しない場合は未確定とし、0を補わない。
Secretや生出力を監査本文へ複製しない。本体のMission / Policy / Approval / Execution監査とIDで関連付ける。
サーバJSONLは本体の認可監査を置き換えない。

## 6. ツールの対応範囲

以下は添付要件の対応表であり、公開済み一覧ではない。各行を操作単位へ分け、対応Versionとリスクを確定する。
記載のRiskは添付で明示されたもの。未指定操作の最終分類は§10に残す。

| カテゴリ | 必須対象 | 分割・検証事項 |
| --- | --- | --- |
| recon | nmap（`smb-*`, `ldap-*`, `krb5-enum-users`, `smb2-security-mode`）、nxcのsmb/ldap/winrm探索 | NSEは具体名で登録。ワイルドカードによる未登録Script追加を拒否 |
| enumeration | enum4linux-ng、rpcclient、smbclient、smbmap、ldapsearch、windapsearch、ldapdomaindump、bloodhound-python、adidnsdump | 読取操作と内部コマンドを固定。CE collector名・形式は確認待ち |
| kerberos | kerbrute userenum/passwordspray、Impacket GetNPUsers / GetUserSPNs / getTGT / getST / ticketer / ticketConverter / describeTicket / raiseChild / goldenPac | 重複掲載のGetNPUsers/GetUserSPNsは単一定義。ticketer/raiseChild/goldenPacはintrusive |
| adcs | Certipy find / cert / req / auth / shadow / template / ca / account / relay / forge | find=active、cert=passive、残り=intrusive。版固定後に「全サブコマンド」との差分も確認 |
| secrets | Impacket secretsdump / psexec / smbexec / wmiexec / atexec / dcomexec / mssqlclient | 添付どおりintrusive。実行・SQL等の公開操作を事前に列挙 |
| enumeration / AD変更 | Impacket findDelegation / GetADUsers / samrdump / lookupsid / netview / rpcdump / reg / services、addcomputer / rbcd / dacledit / owneredit / changepasswd | findDelegation=active、AD変更群=intrusive。reg/services等は参照と変更を分離 |
| coercion-relay | impacket-ntlmrelayx、responder、Coercer、PetitPotam | intrusive。待受範囲、接続先、停止、成果物を操作契約へ含める |
| cracking | hashcat、john | 許可済みハッシュ・辞書を入力とする。資源上限と回収した秘密値を管理 |
| enumeration / 認証試験 | NetExec各プロトコルのpassword spray | 対象・試行上限・停止条件を確定。低速だけでロックアウト回避を保証しない |
| analysis | BloodHound CEへのbloodhound-python / SharpHound収集データ取込、Cypherによる権限・委任・ACL・経路分析 | 取込と照会を分離。CE版・DB・API方式・許可クエリ・collector形式を確認 |
| privesc | Rubeus（asktgt / kerberoast / asreproast / s4u / tgtdeleg / ptt等）、PowerUp.ps1 Invoke-AllChecks、GodPotato | 全てintrusive。§8の登録済みWindows操作として公開 |
| 共通入口 | 許可リスト式Impacket exampleラッパ、run_allowlisted_tool | 上記と同じ操作Schema・Scope・Risk・承認を適用 |

検出項目はSMB signing、LDAP signing/channel binding、匿名SMB/LDAP、AS-REP roasting露出、
Kerberoasting関連設定、ADCS ESC1〜8、認証強制への露出、MachineAccountQuota、各種委任、LAPS、
パスワードポリシー、過剰ACL・特権グループへ対応付ける。必要Evidenceがない項目は未確認として返す。

## 7. 長時間ジョブと本体Adapter

ツールはジョブIDを返せ、`get_job_status(job_id)`で進捗・状態・部分結果を取得できる。
停止用操作も用意し、timeout時の子プロセス終了と部分出力保存へ接続する。
Job IDは実際に保存されたProvider Jobを識別し、本体Execution / Actor / MissionへBindingする。
IDを知っているだけで他のMissionの出力を読めたり停止できたりしない。

本体側の照会・結果取得・停止は既存ExecutionのRecovery / Collection認可を通す。
LLMへ新しい自由な管理操作として公開して認可を迂回しない。標準Tasksを選ぶ場合はServer / Client双方の
CapabilityとExtension版を検証する。独自`get_job_status`の存在だけで`task_extension=true`にしない。
標準Tasksと独自Provider Job契約のどちらを採用するかは、公式SDKの固定版で確認して決める。

サーバを1要求で終了させる現行Transportはジョブ所有にそのまま使わない。プロセス寿命、ジョブ永続化、
クライアント切断時の動作を決め、再起動時に孤児プロセスと未完了Jobを照合する。
不確実な起動結果を成功・失敗へ決め打ちせず、同じ副作用操作を別Jobとして自動再送しない。
ローカルプロセスを終了できてもWindows側の停止確認とは扱わない。

## 8. Windows側の実行

`remote_exec.py`は登録済みペイロードの検証、配布、実行、回収、後処理を担当する。
`payloads/`のManifestに名称、版、SHA256、許可操作を登録し、配布前に照合する。
最初のTransport、配布元、対応OS、利用権限、保存先、停止・後処理を実装前に確認する。

netexec / impacket系 / evil-winrm / 既存C2は候補であり、全て採用済みとはしない。
C2へ委譲する場合は既存Adapterの認可経路へ接続し、MCP内部から別の無認可C2経路を作らない。
配布・実行・回収・後処理で必要な対象と副作用をActionContractへ表し、失敗・残存物を記録する。
LLM生成Payload、Implant生成、自由形式のリモートShellはこの追加範囲に含めない。

## 9. 実環境確認と受入

AD MCP専用のSandbox attestationやProduction資格レコードを必須にせず、ツールごとの実環境結合テストを記録する。
記録項目は対象コミット、設定・カタログRevision、SDK / ツール版、Kali / 対象OS、対象範囲、試験内容、
実施日時、結果、ログ参照、残課題とする。秘密値は含めない。

実環境では起動・一覧取得、登録操作の引数互換性、接続・認証、Parser、Scope拒否、停止・timeout・部分出力を確認する。
実際に行う操作は本体の認可を通す。CIはモック・Test Serverを用い、実ADへ接続しない。
特定の版・操作の合格を他のツールへ転用せず、未実施は未実施と記録する。
新しい資格判定サービスを追加せず、既存開発記録へまとめる。

添付の受入条件に加え、暗号化なしの保存・公開分離、ジョブの認可と復旧、汎用ラッパの迂回拒否を検証する。
詳細は[受入条件](acceptance-criteria.md)の「AD MCP追加開発」を参照する。

## 10. 未確定事項

以下は未承認の推奨案を確定仕様へ読み替えず、該当工程の実装前にユーザーへ確認する。

| ID | 確認内容 | 影響する工程 |
| --- | --- | --- |
| Q-01 | Python 3.11自体の動作保証、公式SDK v2のexact版、各実バイナリの版 | 依存・接続契約 |
| Q-02 | HTTPを今回含めるか、旧SSEが必要か、配置先・認証方式 | Transport |
| Q-03 | ping sweepのpassive表記の扱い、未指定操作のリスク、本体Riskへの対応 | カタログ |
| Q-04 | 標準Tasksの検証済み実装か独自Job契約か、切断・再起動時の継続／停止 | Job・Adapter |
| Q-05 | Windowsの最初のTransport、Payload版・配布元・後処理条件 | remote_exec |
| Q-06 | BloodHound CE版、Neo4j必須性、API利用可否、CE collector、クエリ範囲 | analysis |
| Q-07 | Scope、保存Root・権限、保持期間、容量・時間・並列・対象数の上限 | 実行・保存 |
| Q-08 | Password spray対象・認証試行上限・ロックアウト条件、自由形式を持つツールの公開操作 | 認証試験・intrusive |

SDK後継名とTasks対応は[公式移行ガイド](https://py.sdk.modelcontextprotocol.io/migration/)を参照する。
BloodHound CE collectorとLegacy collectorの区別は[開発元の説明](https://github.com/dirkjanm/BloodHound.py#bloodhound-ce)を参照する。
これらは2026-09-29の調査に基づく。実装時に固定する版の契約を再確認する。

### 10.1 実装で閉じたままにした項目

- Q-02: stdioだけを実装した。HTTP / SSEのListenerは作成していない。
- Q-03: 明示分類のない操作を`unclassified`とし、dry-run以外を拒否する。
- Q-04: 独自Provider Jobを実装した。再起動時の未完了Jobは`outcome_unknown`へ遷移し、自動再送しない。
- Q-05: Windows操作名だけをCatalogへ登録した。Manifestは空、Remote Transportは`disabled`である。
- Q-06: BloodHound照会はQuery IDのAllowlistだけを定義し、CE接続は有効化していない。
- Q-07: 設定項目とFail-closed検証を実装した。実運用値は結合試験前に確定する。
- Q-08: 認証試験操作を`unclassified`とし、試行上限等が確定するまで実行しない。
