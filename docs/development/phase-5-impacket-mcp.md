# Phase 5 Impacket MCP Server 開発記録

## 判定

Fortra Impacket `0.13.1`を使用するローカルMCP Serverの、実環境接続を必要としない実装は完了した。
Ubuntu 24.04 LTS / x86_64のControl VMで専用`stdio`プロセスとして起動できる。実Targetへの接続試験、Control VM上の
Sandbox / OS Egress強制、実Credential登録はProduction Activation条件として残る。

実装は汎用Impacket CLI、Python式、任意Module名、任意Commandを受け取らない。次の4 Toolだけを固定Schemaで公開する。

| Tool | 動作 | Credential | Target Port |
| --- | --- | --- | --- |
| `impacket.smb.negotiate` | SMB 2/3のNegotiation情報取得 | 不要 | TCP/445 |
| `impacket.smb.authenticate` | Password / NTLM Hash認証の成否確認 | 必須 | TCP/445 |
| `impacket.smb.list_shares` | Share名・種別・Remarkの上限制限付き取得 | 必須 | TCP/445 |
| `impacket.rpc.endpoint_map` | RPC Endpoint Mapperの上限制限付き列挙 | 不要 | TCP/135 |

`psexec`、`wmiexec`、`smbexec`、`secretsdump`、`ntlmrelayx`、Service / Task / Registry変更、File read/writeは実装していない。
未知Tool名はBackend importやNetwork接続より前に拒否する。

## 実装境界

- Serverは1 JSON-RPC Requestにつき1 Processだけ起動し、Request完了後に終了する。
- Server起動はShellを使用せず、Absolute Executable Path、Executable SHA-256、Command Configuration Digest、
  Package VersionへBindingする。各Requestの直前とProcess起動直後に実行Identityを再測定する。
- ProcessはCPU時間、経過時間、Address Space、File Size、FD数、Request / Response Sizeを制限し、stderrを信頼結果へ
  取り込まない。
- Server Command Lineに固定`--allow-target` CIDRを持たせ、空Allowlist、Hostname、非Canonical IP、重複IP、最大16件超、
  Allowlist外IPをNetwork接続前に拒否する。
- one-shot ProcessへPython Audit Hookを導入し、Backendが引数検証を迂回しても固定CIDRのTCP/445・135以外への
  `socket.connect`を拒否する。これはOS / vCenter Egress資格の代替ではなく、追加のApplication層防御である。
- PolicyDecisionで作成した`exact_ip_enforced` TargetDispatchBindingをExecutionRequestへ渡し、Adapterが引数の全IP / Port /
  Protocolと完全一致することを再検証する。Redirectは使用しない。
- Credentialは固定Secret Reference Schemaで認可する。PlaintextはExecutionRequest、Plan、Tool Registry、監査Record、Result、
  Command Line、Environmentへ保存しない。認可済みJIT Secret Bindingをローカルstdio Requestの専用`_meta` Extensionへ一度だけ
  格納し、Server側でVersion一致を確認する。Secretを扱うProcessはone-shotで終了し、Decode Bufferは終了前にzeroizeする。
- Password Secret MaterialはUTF-8 JSONの`{"domain":"...","password":"...","username":"..."}`、NTLM Hashは
  `{"domain":"...","lmhash":"32 hex","nthash":"32 hex","username":"..."}`という閉じた形だけを受理する。
- Tool Call直前にMCP DiscoveryとLive Tool Schemaを再検証し、固定Catalog Digestと異なるToolを実行しない。
- Tool結果は既存のQuarantine-owned `RawResultSink`へ`local_result`として保存する。

## Control VMへの導入

依存は`requirements.lock`へ固定済みであり、Impacket MCP用extraも使用できる。

```bash
python3.12 -m venv /opt/redteam-agent/venv
/opt/redteam-agent/venv/bin/python -m pip install -r requirements.lock
/opt/redteam-agent/venv/bin/python -m pip install . --no-deps --no-build-isolation
/opt/redteam-agent/venv/bin/redteam-impacket-mcp --version
```

Adapterは`build_impacket_mcp_adapter()`で構成する。`executable_path`には上記Entry Pointの実体Absolute Path、
`allowed_targets`にはvCenter隔離Lab内のCanonical IP / CIDRだけを設定する。値はCommand Configuration DigestへBindingされる。

```python
adapter = build_impacket_mcp_adapter(
    executable_path="/opt/redteam-agent/venv/bin/redteam-impacket-mcp",
    allowed_targets=("10.20.30.0/24",),
    evidence_kind="live",
    production_eligible=True,
    sandbox_verified=True,
    clock=clock,
    digest_service=digest_service,
)
```

この`live`設定は例示であり、`sandbox_verified=True`を自己申告して本番化してはならない。Control VM上でProcess隔離と
OS / vCenter EgressがAllowlistどおり強制されることを別資格試験で確認し、その証跡からComposition Rootが設定する。

## 実環境なしで完了した試験

- 4 Toolの固定Catalog / Schema DigestとTool Registry安全契約
- Password / NTLM Hash Secret ReferenceとVersion Binding
- Secret欠落・不正形・応答への平文混入防止
- Exact IP Target Binding、Hostname / Allowlist外 / 空Allowlistの拒否
- 未承認・高リスクImpacket Tool名の拒否
- 実one-shot stdio ProcessによるDiscovery / Tool List Qualification
- Executable変更、Logical Identity / Schema / Revision Driftの拒否
- Impacket `0.13.1` Runtimeと使用APIの存在確認

試験はFake BackendまたはCredential-free Control Operationだけを使用し、TargetへのNetwork接続は行わない。

## Production Activationに残る項目

1. Control VMへ固定依存と専用Entry Pointを導入し、Absolute Path / SHA-256を本番Profileへ確定する。
2. vCenter隔離セグメントのTarget CIDRを`allowed_targets`へ確定する。
3. OSレベルProcess SandboxとEgress強制を構成し、`sandbox_verified`の外部証跡を作成する。
4. Secret Storeへ専用低権限Credentialを登録し、PasswordまたはNTLM Hash方式を確定する。
5. Windows Server / Windows 11検証Targetで4 ToolのLive Discovery / Integration試験を実施する。

この5項目が完了するまでは、オフライン実装済みであってもProduction Activation済みとは判定しない。
