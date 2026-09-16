# Phase 4 Sliver C2 Adapter 開発記録

## 現在の判定

SliverをTuoniと置き換えず、第2 C2 Providerとして追加した。実環境に依存しないProvider Profile、閉じたRPC契約、
Session / Beacon / Beacon Task応答の正規化、Adapter、one-shot gRPC/mTLS Worker、固定Production Composition、UI、
Test Doubleによる統合試験は実装済みである。

現在はOperator設定の正確なファイルとServer接続先を取得できず、HTTP Beaconも存在しないため、Production Activationは
Fail Closedのままである。これはオフライン実装の未完了ではなく、実環境証跡の保留である。

## 確定した構成

| 項目 | 値 |
| --- | --- |
| Provider | Sliver |
| Release | `v1.7.3` |
| Source Commit | `3bbaf805104dcc4a75414ee0084e8de50702cad4` |
| Operator | `joe` |
| Operator設定の場所 | `downloads`という情報のみ。絶対パスとファイル名は未解決 |
| Operator接続 | Sliver Multiplayer gRPC / mTLS（Bearer Token併用） |
| Implant通信 | HTTP |
| Target | Windows / x86_64 |
| Beacon | 現在なし |
| Tuoni | 維持。Sliverは追加Provider |

`HTTP`はImplant / BeaconとSliver Server間の通信方式である。RedTeam AgentのOperator接続はHTTPではなく、Sliverの
Operator `.cfg`に含まれる接続先、CA、Client Certificate / Private Key、Tokenを使うgRPC/mTLSである。

## 実装した範囲

- `SliverProviderPin`でv1.7.3と公式Source Commitを固定。
- Operator `joe`、direct gRPC/mTLS、HTTP Implant、Windows x86_64をProfile Digestへ束縛。
- 次の7 RPCだけを固定Allowlistとして実装。
  - `GetVersion`
  - `GetSessions`
  - `GetBeacons`
  - `GetBeacon`
  - `GetBeaconTasks`
  - `GetBeaconTaskContent`
  - `CancelBeaconTask`
- Session IDとBeacon IDを`session:<id>` / `beacon:<id>`としてProvider中立境界へ投影。
- HTTP以外、Windows x86_64以外、dead / stale Beaconを区別し、対象条件不一致ではCapabilityを空にする。
- Beacon Taskの`pending / sent / completed / canceled`を厳密に正規化し、既存Taskの照会・Reconcile・Cancelだけを提供。
- `Generate`、Listener作成、Shell / Execute、Upload / Download、Process Injection、Pivot / Port Forward、Credential
  収集、任意RPCは契約に存在せず呼び出せない。
- `submit`とRaw Result収集は明示的に拒否。Sliverによる新規攻撃操作は現在の契約では生成できない。
- Operator `.cfg`を長期Secretとして扱い、Repository、Pydantic Model、IPC、stdout / stderr、例外、DBへ内容を返さない。
- systemd `LoadCredentialEncrypted=`で固定runtime path
  `/run/credentials/redteam-agent.service/sliver-operator.cfg`へだけ復号するDeployment Assetを追加。
- one-shot Workerがowner-privateなregular fileだけを`O_NOFOLLOW`で開き、公式`.cfg`の完全な7 fieldだけを受理。
- `.cfg`全体、CA、Operator CertificateのSHA-256、Operator名、Server Address / Port、TLS NameをLive Attestationと照合。
- Workerだけが`grpcio`を遅延importし、mTLSとBearer metadataで1 RPCを実行して終了。
- 公式v1.7.3の必要なprotobuf fieldだけをbounded decoderで正規化し、Request / Response payload bytesは親へ返さない。
- Test Double証跡は`production_eligible=false`から昇格できず、固定Production Compositionはliveかつ全Identity検証済みの
  Attestation以外を拒否。
- UIのC2選択へSliverを追加し、v1.7.3、Operator `joe`、HTTP、Beacon未接続を表示。保存は非権威Draftのみ。

Sliver用runtimeは次で追加できる。

```sh
.venv/bin/python -m pip install -e '.[sliver-c2]' --no-build-isolation
```

オフラインReadinessは次で生成する。この処理はOperator設定を読まず、Networkへ接続しない。

```sh
PYTHONPATH=src .venv/bin/python scripts/phase4_sliver_offline_readiness.py
```

## Production Activationに必要な実環境情報

| 必要情報 / 証跡 | 目的 | 現在のBlocker |
| --- | --- | --- |
| `joe`のOperator `.cfg`絶対パスとファイル名 | 指定された`downloads`から正しい1ファイルを特定する | `operator_config_secret_reference_unresolved` |
| `.cfg` SHA-256 | 差替えや別Operator設定の利用を拒否する | `operator_config_digest_unresolved` |
| `.cfg`内のServer Address / Port | RedTeam Agentが接続するMultiplayer endpointを固定する | `operator_server_endpoint_unresolved` |
| Server Certificateの検証用TLS Name | CA検証に加えて接続先名を検証する | `operator_server_endpoint_unresolved` |
| CA / Operator Certificate SHA-256 | ServerとOperatorの暗号Identityを固定する | `operator_ca_certificate_unresolved` / `operator_certificate_unresolved` |
| v1.7.3 clean buildの`GetVersion`結果 | 実Serverが固定Releaseと一致することを確認する | `live_provider_attestation_unverified` |
| Windows x86_64 HTTP Beacon | 実TargetのInventory / Task Controlを検証する | `http_beacon_unavailable` |
| Sliver binaryの実パス | 「導入済み」の実体とVersion / Digestを確認する | 現KaliのPATH・標準場所から未発見 |

Operator `.cfg`は内容をチャットやGitへ貼らず、絶対パスだけを指定する。Activation時はそのファイルを
`systemd-creds encrypt`で暗号Credential Storeへ移し、元のDownloads上の平文は運用手順に従って保護・廃棄する。

## 現在実施できない試験

- 実Sliver ServerへのmTLS接続と`GetVersion`。
- 実Session / Beacon一覧。
- HTTP BeaconのTransport、Windows、x86_64、Check-in状態の確認。
- 実Beacon Taskの照会・Cancel・Reconcile。

Beacon生成、Payload配布、HTTP Listener作成は本実装の受入試験に含めない。既存の承認済みBeaconが用意された後に、
読み取りと既存Task取消だけをLive Human Gateで検証する。
