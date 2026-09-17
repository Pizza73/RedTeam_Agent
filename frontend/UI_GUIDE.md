# RedTeam Agent UI Guide

このUIは、`nathanhoma/RedTeam_Agent`のOperator Consoleを本リポジトリのローカルControl Planeへ統合したものです。
本番ビルドではMockを使わず、同一Originの`/api/v1`からRedTeam AgentのSQLite状態を読み取ります。

## 1. 起動

Python環境とフロントエンドを準備します。

```sh
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-build-isolation
cd frontend
npm ci
npm run build
cd ..
```

既にRedTeam Agentが作成したSQLiteデータベースを指定し、loopbackで起動します。

```sh
.venv/bin/redteam-ui \
  --database /absolute/path/to/redteam-agent.db \
  --operator-token-file /absolute/private/path/ui-operator.token
```

VLLM Settingsから実Capability Checkを行う場合は、初期接続先、許可CIDR、署名済みモデルIdentityをサーバ側で固定して起動します。Kali製品構成ではUIから許可CIDR内の候補接続先とAPI keyを登録し、非公開の候補試験後に有効化できます。モデルIdentity自体は変更できません。

```sh
.venv/bin/redteam-ui \
  --database /absolute/path/to/redteam-agent.db \
  --operator-token-file /absolute/private/path/ui-operator.token \
  --vllm-base-url http://10.0.6.181:8100/v1 \
  --vllm-model gemma-4-31B-it \
  --vllm-api-key-file /absolute/path/to/vllm-api.key \
  --vllm-manifest /absolute/path/to/gemma-4-31b.manifest.json \
  --vllm-public-key /absolute/path/to/attestation-signing-public.pem \
  --vllm-tokenizer-directory /absolute/path/to/gemma-4-31b-tokenizer
```

APIキーの値はCLI引数やブラウザへ渡しません。ブラウザには固定Endpoint、Model、Wire API、Structured Output Modeだけが公開され、別のURLへ変更できません。

ブラウザで`http://127.0.0.1:18000/dashboard`を開きます。隔離LANへ直接公開する場合は
`--host 0.0.0.0 --allow-rfc1918-same-origin`を指定します。ブラウザで実際に使用した実行環境IPを動的に採用するため、
IPの固定設定は不要です。外部OriginはRFC1918のliteral IPv4とbind portへ限定され、Host/Origin完全一致が必要です。

開発時はAPIとViteを別プロセスで起動できます。

```sh
.venv/bin/redteam-ui --database /absolute/path/to/redteam-agent.db \
  --operator-token-file /absolute/private/path/ui-operator.token --api-only
cd frontend
npm run dev
```

Viteは`/api`を`http://127.0.0.1:18000`へProxyします。`npm run test`だけが決定論的なMock Gatewayを使用します。

## 2. 管理できる内容

| 画面 | 実データ / 操作 |
| --- | --- |
| `Dashboard` | Mission、Revision、Authorization Epoch、Scope、Lifecycle、集計を表示 |
| `New Mission` | Draftを保存し、owner service構成時は正式Missionの作成・検証・状態遷移 |
| `Interventions` | 永続Approval Requestを表示。信頼済みApproval Service注入時だけ承認 / 拒否 |
| `Knowledge` | Entity、Relationship、Verified Finding、Redacted Artifact参照を表示 |
| `C2 & Tools` | Tuoni / SliverとImpacket MCPの非権威Policy Draftを保存 |
| `VLLM Settings` | 信頼済みPhase 2 Capability Port注入時だけ実Capability Check |

Draft保存だけではMission Activation、Policy Decision、Tool Dispatchを行いません。Kali製品構成では既存Mission Managerが作成・検証を所有し、実行runtimeが未認証の間はStart/Resumeを拒否します。

`New Mission`の先頭には、DBへ保存済みのControl Plane状態を基準にした`Execution readiness`を表示します。上部の`Execution blocked · N`から同じ一覧へ移動でき、各項目には「不足しているもの」「進められない理由」「次に行うこと」「安定したエラーコード」が表示されます。Mission draft、Session reference、Provider policy、LLM Capability、Sliver credential / identity / Beacon、Impacket sandbox、TPM key provider、Execution runtimeを別々に判定します。未保存のフォーム編集は一覧へ反映されず、Draft保存、Mission作成、状態遷移の成功後に自動再読込します。

Readiness API自体を取得できない場合も実行可能とは扱わず、`Readiness unavailable` / `ERROR`としてFail Closedで表示します。Mission作成・状態遷移が拒否された場合は、汎用エラーだけでなく安全な解消手順とエラーコードを画面に表示します。

単体の`redteam-ui`コマンドではApproval writeとruntime LLM設定変更を無効化し、VLLM network checkも`--vllm-*`構成を省略した場合は無効です。Kaliの`redteam-product`では、API keyを画面へ返さずservice-owned `0600`ファイルに保存し、候補登録→完全試験→有効化をsingle-flightで実行します。署名済みManifest、固定Tokenizer、Phase 2 Server Attestationと全Schema Capability Corpusは変更しません。

## 3. C2 / MCP

`C2 & Tools`は次の固定範囲だけを扱います。

- C2: `none`、既存の`Tuoni Commercial`、または`Sliver 1.7.7`。
- Tuoni Version: `latest`表示。実接続前にRelease / Image / OpenAPI Digestの固定が必要。
- Sliver: Operator `joe`、HTTP Beacon、Session / Beacon Inventoryと既存Beacon Task Read / Cancelだけを表示する。現在は
  Operator設定はsystemd credentialの固定pathを使用し、実Server identityと実BeaconがないためActivation不可。
- Control VM access: 未設定のままDraft保存可能。Production Activationは不可。
- MCP Server: `impacket_mcp`のみ。
- Operations: `impacket.smb.negotiate`、`impacket.smb.authenticate`、`impacket.smb.list_shares`、`impacket.rpc.endpoint_map`の4件のみ。
- 任意Command、任意Argument、Upload、Delete、Payload生成、Credential dumpは登録されません。

画面上のPolicy StateはDraftです。保存しただけではExecution Authorizationにならず、Mission Scope、Policy Decision、Human Approval、Current Revision / Epochの検査を省略できません。

### AD Assessment

同じ画面の`AD Assessment`タブは、特権アクセス、Kerberos SPNアカウント、Kerberos事前認証、AD CS ESC1〜ESC8、Delegationの5つの設定監査を表示します。

- `Run verifier simulator`はSynthetic Evidenceだけを決定論的Ruleへ渡し、実Targetには接続しません。
- `Ask local LLM for next check`は、実Local LLMの`planner_output` Capabilityが合格済みの場合だけ、5つの登録済み候補から次の監査を選びます。
- LLMが作成した説明文は表示せず、信頼済みCatalogのID・名称・説明だけを返します。
- LLM推薦はFindingでもExecution Authorizationでもありません。
- 実LDAP Collectorはサーバ固定のLDAPS設定として接続済みです。現在の`10.0.10.212`はWS01でTCP 636へ到達できないため、UIはDC IP・TCP 636・発行CAの設定を要求します。未収集項目は`indeterminate`であり、安全判定にはなりません。
- Ticket取得、Crack、証明書Enrollment/認証、Delegation悪用、Directory変更、任意Commandは提供しません。

## 4. Interventions

Approval RequestにはMission ID、Revision、Epoch、期限、Tool、Adapter、正規化Target、Redacted Argument、Risk、Side Effect、Presentation Digestを表示します。

承認 / 拒否は、表示した`presentationDigest`をリクエストへ再送し、サーバ側で現在の永続Requestと完全一致する場合に限り、既存Approval Serviceへ渡されます。期限切れ、Stale、Digest不一致、サービス未注入はFail Closedです。一括承認はありません。

Planning ChoiceはApprovalではありません。現在のランタイムでは読み取り専用で、選択APIは`409 UNAVAILABLE`を返します。

## 5. Knowledge / Activity

Knowledge画面は検証済みの永続Recordだけを投影します。ArtifactはRedacted VariantのMetadataとDigest検証済みReferenceだけを表示し、Raw Artifact、Credential、Secret、Raw Tool Outputは返しません。

Mission FlowとAgent Activityも、型付きOperation、状態、Reference ID、Redacted Summaryに限定します。任意Shell CommandやProvider Native Commandは表示契約に含まれません。

## 6. セキュリティ境界

- APIとSPAは同一Origin。CORSは提供しません。
- UI tokenはHttpOnlyの再起動時失効sessionへ交換し、ブラウザstorageやDBへ保存しません。
- Mutationは`Origin` / `Host`完全一致と`X-RedTeam-UI: 1`を要求します。
- JSON Bodyは1 MiB以下、Strict Schema、未知Field拒否です。
- CSP、Frame拒否、MIME sniffing拒否、no-referrerを返します。
- UIは既存DBを自動Provisionせず、存在するSchemaへFail Closedで接続します。
- Browser表示はExecution Authorityではありません。

直接外部bindは隔離networkでのHTTP利用だけを対象とします。現在のsystemdサンプルは`0.0.0.0/0`からのIPv4接続を許可するため、
internetへ直接公開しないでください。Reverse Proxy、TLS、SSO / RBAC統合はこのオフライン実装の対象外です。
Production利用には認証を含む別のHuman Gateと設計レビューが必要です。

## 7. 検証

```sh
cd frontend
npm run typecheck
npm run lint
npm run test
npm run build
npm run test:e2e
```

Backend境界は`tests/unit/test_ui_models.py`と`tests/integration/test_ui_control_plane.py`で検証します。
PlaywrightのChromiumを別途導入していない環境では、`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`に既存Chromiumの絶対パスを指定できます。
