# Phase 4 Sliver C2 Adapter 開発記録

## 現在の判定

SliverをTuoniと置き換えず、第2 C2 Providerとして追加した。実環境に依存しないProvider Profile、閉じたRPC契約、
Session / Beacon / Beacon Task応答の正規化、Adapter、one-shot gRPC/mTLS Worker、固定Production Composition、UI、
Test Doubleによる統合試験は実装済みである。2026-09-16にKali上のSliver v1.7.7へloopback接続し、RedAgentの
one-shot Workerを通した実`GetVersion`、Session一覧、Beacon一覧に加え、Windows 11 HTTP BeaconのInventory、
個別取得、Task一覧も成功した。

Operator設定、Server接続先、Server/Operator Identity、HTTP Beaconは時限試験で検証済みである。試験後にBeaconと
HTTP Listenerを撤去したため、現在のProduction ActivationはFail Closedへ戻している。

## 確定した構成

| 項目 | 値 |
| --- | --- |
| Provider | Sliver |
| Release | `v1.7.7` |
| Source Commit | `0aa7e5bf962414823f12c3a8ea1f667f61b19ce2` |
| Operator | `joe` |
| Operator設定の場所 | `/home/kali/Downloads/joe.cfg`（mode `0600`、Git管理外） |
| Operator接続 | Sliver Multiplayer gRPC / mTLS（Bearer Token併用） |
| Server endpoint | `127.0.0.1:31337` |
| Server TLS name | `multiplayer` |
| Implant通信 | HTTP |
| Target | Windows / x86_64 |
| Beacon | 現在なし |
| Tuoni | 維持。Sliverは追加Provider |

`HTTP`はImplant / BeaconとSliver Server間の通信方式である。RedTeam AgentのOperator接続はHTTPではなく、Sliverの
Operator `.cfg`に含まれる接続先、CA、Client Certificate / Private Key、Tokenを使うgRPC/mTLSである。

## 実装した範囲

- `SliverProviderPin`でv1.7.7と公式Source Commitを固定。
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
- 公式v1.7.7の必要なprotobuf fieldだけをbounded decoderで正規化し、Request / Response payload bytesは親へ返さない。
- v1.7.7のWindows `amd64`を方針上の`x86_64`へ、`http(s)`と`https://` Active C2をHTTP Transportへ正規化する。
- Test Double証跡は`production_eligible=false`から昇格できず、固定Production Compositionはliveかつ全Identity検証済みの
  Attestation以外を拒否。
- UIのC2選択へSliverを追加し、v1.7.7、Operator `joe`、HTTP、Beacon未接続を表示。保存は非権威Draftのみ。

Sliver用runtimeは次で追加できる。

```sh
.venv/bin/python -m pip install -e '.[sliver-c2]' --no-build-isolation
```

オフラインReadinessは次で生成する。この処理はOperator設定を読まず、Networkへ接続しない。

```sh
PYTHONPATH=src .venv/bin/python scripts/phase4_sliver_offline_readiness.py
```

## Production Activationに必要な実環境情報

| 必要情報 / 証跡 | 目的 | 現在の状態 |
| --- | --- | --- |
| `joe`のOperator `.cfg`絶対パスとファイル名 | 正しい1ファイルを特定する | 解決済み |
| `.cfg` SHA-256 | 差替えや別Operator設定の利用を拒否する | 検証済み |
| `.cfg`内のServer Address / Port | Multiplayer endpointを固定する | `127.0.0.1:31337`で検証済み |
| Server Certificateの検証用TLS Name | CA検証に加えて接続先名を検証する | `multiplayer`で検証済み |
| CA / Operator Certificate SHA-256 | ServerとOperatorの暗号Identityを固定する | 検証済み |
| v1.7.7 clean buildの`GetVersion`結果 | 実Serverが固定Releaseと一致することを確認する | Version/Commit一致を検証済み |
| Windows x86_64 HTTP Beacon | 実TargetのInventory / Task Controlを検証する | 時限試験済み。試験後撤去のため現在は`http_beacon_unavailable` |
| Sliver binaryの実パス | 導入済み実体とVersion / Digestを確認する | `/home/kali/.local/bin/sliver`で検証済み |

Operator `.cfg`は内容をチャットやGitへ貼らず、絶対パスだけを指定する。Activation時はそのファイルを
`systemd-creds encrypt`で暗号Credential Storeへ移し、元のDownloads上の平文は運用手順に従って保護・廃棄する。

## 2026-09-16 実接続試験

- Sliver Server v1.7.7を`127.0.0.1:31337`で起動。
- Server証明書のTLS名`multiplayer`、mTLS、HTTP/2、Operator `joe`、Bearer認証を検証。
- RedAgentの固定Credential pathを一時mount namespace内に再現し、実one-shot Workerを使用。
- `GetVersion`はv1.7.7 / Commit `0aa7e5bf962414823f12c3a8ea1f667f61b19ce2`と一致。
- `GetSessions` / `GetBeacons`は正常応答。Windows 11 `WS01`のHTTP Beaconを`active`、`windows/x86_64`として取得。
- Production Compositionを`production_eligible=true`で構築し、Provider capability 6件、Beacon capability 5件、
  `GetBeacon`、`GetBeaconTasks`（0件）を検証。Attestation Digestは
  `e72caa5ac9a509879feb3b07b4dbb74b952dcb331e010bdbd6963401e8191033`。
- RedAgentが公開するread/control capabilityは6件。任意実行、Payload生成、Listener操作は引き続き不許可。
- Target上ではBeaconの固定パスだけをDefenderの一時除外へ追加。試験後にBeaconプロセス、実行ファイル、一時サービス、
  Defender除外を削除し、`process_count=0` / `exclusion_present=False`を確認。HTTP Listener Job、ローカル出力、
  Sliver Serverの試験Buildキャッシュも撤去。
- Sliver Serverは`127.0.0.1:31337`で継続稼働。実Beacon撤去後の常設Attestationは`production_eligible=false`。

## 現在実施できない試験

- 実タスクが存在する場合のBeacon Task取消・Reconcile。

Beacon生成、Payload配布、HTTP Listener作成は本実装の受入試験に含めない。既存の承認済みBeaconが用意された後に、
読み取りと既存Task取消だけをLive Human Gateで検証する。
