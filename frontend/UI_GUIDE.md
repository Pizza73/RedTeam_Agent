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
.venv/bin/redteam-ui --database /absolute/path/to/redteam-agent.db
```

ブラウザで`http://127.0.0.1:18000/dashboard`を開きます。サーバは`127.0.0.1`または`localhost`以外へBindできません。

開発時はAPIとViteを別プロセスで起動できます。

```sh
.venv/bin/redteam-ui --database /absolute/path/to/redteam-agent.db --api-only
cd frontend
npm run dev
```

Viteは`/api`を`http://127.0.0.1:18000`へProxyします。`npm run test`だけが決定論的なMock Gatewayを使用します。

## 2. 管理できる内容

| 画面 | 実データ / 操作 |
| --- | --- |
| `Dashboard` | Mission、Revision、Authorization Epoch、Scope、Lifecycle、集計を表示 |
| `New Mission` | 非権威のMission Draftを保存 |
| `Interventions` | 永続Approval Requestを表示。信頼済みApproval Service注入時だけ承認 / 拒否 |
| `Knowledge` | Entity、Relationship、Verified Finding、Redacted Artifact参照を表示 |
| `C2 & Tools` | Tuoni / SliverとImpacket MCPの非権威Policy Draftを保存 |
| `VLLM Settings` | 信頼済みPhase 2 Capability Port注入時だけ実Capability Check |

Draft保存はMission Activation、Policy Decision、Tool Dispatchを行いません。Missionの作成・検証・開始は既存の信頼済みMission Workflowが所有します。

単体の`redteam-ui`コマンドではApproval writeとVLLM network checkを無効化しています。これらは、認証済みActorやSecret境界を迂回しないよう、実行中の信頼済みCompositionから対応Portを注入した場合だけ有効になります。

## 3. C2 / MCP

`C2 & Tools`は次の固定範囲だけを扱います。

- C2: `none`、既存の`Tuoni Commercial`、または`Sliver 1.7.3`。
- Tuoni Version: `latest`表示。実接続前にRelease / Image / OpenAPI Digestの固定が必要。
- Sliver: Operator `joe`、HTTP Beacon、Session / Beacon Inventoryと既存Beacon Task Read / Cancelだけを表示する。現在は
  Operator設定の正確な絶対パスと実BeaconがないためActivation不可。
- Control VM access: 未設定のままDraft保存可能。Production Activationは不可。
- MCP Server: `impacket_mcp`のみ。
- Operations: `impacket.smb.negotiate`、`impacket.smb.authenticate`、`impacket.smb.list_shares`、`impacket.rpc.endpoint_map`の4件のみ。
- 任意Command、任意Argument、Upload、Delete、Payload生成、Credential dumpは登録されません。

画面上のPolicy StateはDraftです。保存しただけではExecution Authorizationにならず、Mission Scope、Policy Decision、Human Approval、Current Revision / Epochの検査を省略できません。

## 4. Interventions

Approval RequestにはMission ID、Revision、Epoch、期限、Tool、Adapter、正規化Target、Redacted Argument、Risk、Side Effect、Presentation Digestを表示します。

承認 / 拒否は、表示した`presentationDigest`をリクエストへ再送し、サーバ側で現在の永続Requestと完全一致する場合に限り、既存Approval Serviceへ渡されます。期限切れ、Stale、Digest不一致、サービス未注入はFail Closedです。一括承認はありません。

Planning ChoiceはApprovalではありません。現在のランタイムでは読み取り専用で、選択APIは`409 UNAVAILABLE`を返します。

## 5. Knowledge / Activity

Knowledge画面は検証済みの永続Recordだけを投影します。ArtifactはRedacted VariantのMetadataとDigest検証済みReferenceだけを表示し、Raw Artifact、Credential、Secret、Raw Tool Outputは返しません。

Mission FlowとAgent Activityも、型付きOperation、状態、Reference ID、Redacted Summaryに限定します。任意Shell CommandやProvider Native Commandは表示契約に含まれません。

## 6. セキュリティ境界

- APIとSPAは同一Origin。CORSは提供しません。
- Mutationは`Origin` / `Host`完全一致と`X-RedTeam-UI: 1`を要求します。
- JSON Bodyは1 MiB以下、Strict Schema、未知Field拒否です。
- CSP、Frame拒否、MIME sniffing拒否、no-referrerを返します。
- UIは既存DBを自動Provisionせず、存在するSchemaへFail Closedで接続します。
- Browser表示はExecution Authorityではありません。

UIを別ホストへ公開する構成、Reverse Proxy、TLS、SSO / RBAC統合はこのオフライン実装の対象外です。Productionでloopback外から利用する場合は、認証を含む別のHuman Gateと設計レビューが必要です。

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
