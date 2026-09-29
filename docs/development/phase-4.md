# Phase 4 Tuoni C2 Adapter 開発記録

## 現在の判定

Phase 4のオフライン開発受入は完了した。実環境に依存しない契約・型・Fail Closed境界、`TuoniAdapter`本体、同一
Control VMで利用するprocess-isolated HTTPS Transport、Production形のComposition、状態を持つTest Doubleによる全操作
Scenarioを実装済みである。実Tuoni、実Target、実Credentialへの接続は未実施であり、Production Activation適格性とは
明確に分離する。

## Provider Human Gateの確定事項と実環境保留値

| 項目 | 確定値 |
| --- | --- |
| C2製品 / Edition | Tuoni / Commercial |
| Server Version | 0.16.1 |
| Source Commit | `7d9a2057b309481c530f7c7a71b4ad2f8c5a615e` |
| Server Image Digest | `sha256:e1e24a1f0fcee7ce8728f1d7fd0790da116651505c6ad88afe58daf1067d6e95` |
| OpenAPI SHA-256 | 実環境で未取得。`GET /docs/api`の実ArtifactをActivation時に固定する |
| 構成 | Red AgentとTuoni Serverを同一Control VMへ配置、Target VMは使い捨て |
| Control VM | Ubuntu 24.04 LTS / x86_64 |
| Adapter配置 | Tuoni Serverと同じControl VM。固定Loopback Endpointへ接続 |
| Target | Windows Server / Windows 11。Target構築は本プロジェクト外 |
| Tuoni Agent | Targetへ手動導入済みを前提。生成・配布は実装しない |
| API候補 | Control VM内の`https://127.0.0.1:8443`のみ |
| Target Listener | HTTPS / 8444のみ |
| Egress | 物理Uplink、Default Gateway、Internet、社内LANへのEgressをすべて禁止 |
| Command送信 | 管理者承認済みTemplateだけ。JSONのみ。`execConf`、File、Payloadを禁止 |

## オフラインで実装した範囲

- Provider中立の`C2SessionObservation` / `C2Adapter`拡張契約。
- Tuoni Provider、Connection、Authentication、vCenter隔離条件のDeep-immutable ProfileとDigest Binding。
- Tuoni 0.16.1の固定REST Path、Method、成功Status、Canonical UUID / Command ID検証。
- Tool Registry由来のCommand Template Allowlist。空Allowlistは全Submitを拒否する。
- 固定`GET /docs/api`から取得する実OpenAPI Artifactと、Activation時に承認するSHA-256の完全一致検証。公開Sourceには
  Artifact本体がないため、合成Digestを代用せず未解決のまま保持する。
- Profile、API Contract、TLS、Credential Reference、vCenter Port Group、Process Isolationを完全一致で束縛する
  `TuoniTransportAttestation`。
- EndpointやCredentialをcallerが指定できないprivate `TuoniTransport` Protocolと、Response本文をrepr・serializeしない
  ephemeral response境界。TransportへResponse上限とTimeoutを必須指定する。
- Ubuntu 24.04 LTS / x86_64専用のone-shot child-process Transport。各API操作ごとに固定Moduleを`python -I -m`で起動し、
  Shell、Retry、Redirect、Proxy、DNS解決、caller指定Endpointを使用しない。
- `LoadCredentialEncrypted=`で暗号化・認証されたCredentialをsystemdがService起動時だけ復号し、child processだけが
  read-only runtime pathの`/run/credentials/redteam-agent.service/tuoni-credential.json`を読む。Credential平文を
  `/etc`やRepositoryへ永続化しない。既存Serviceへ適用するdrop-inは
  `deployment/systemd/redteam-agent.service.d/tuoni-credential.conf`へ固定した。
- 固定`/etc/redteam-agent/tuoni-ca.pem`、CA chain検証、同一TLS接続のleaf certificate pinを検証する。
- `POST /api/v1/auth/login`のBasic認証から短時間JWTを取得し、JWTをmemory-onlyで1 API操作にだけ使用する。Credentialと
  JWTはIPC、stdout、stderr、例外文へ返さない。
- `GET /api/v2/users/me`と`GET /api/v1/permissions`の厳密な応答型を実装し、Accountが有効かつ
  `VIEW_RESOURCES + SEND_COMMANDS`だけを持つことを送信前に再検証する。管理権限や不足権限ではProvider Side Effect前に
  拒否する。
- `AgentResponse` / `CommandResponse`の重複JSON Key、未知Control Field、型Coercion、ID不整合、未知Statusを拒否する境界。
- SessionごとのCommand Templateを実行直前に再取得し、管理者Allowlistとの共通部分かつ`ENABLED` /
  `isUserCreatable`だけをCapability / Submitへ使用する。
- 送信直前にTarget Sessionを再取得し、active、Windows、判定可能なx86_64 / arm64であることを再検証する。
- Tuoni固有Session / Command StatusからProvider中立Session / Task Statusへの決定論的正規化。
- Raw Command ResultをControl Metadataへコピーしない分離。
- `TuoniAdapter`のSession、Capability、Submit、Task照会、Result収集、Cancel、Reconciliation実装。Tuoni 0.16.1に
  Idempotency Key照会がないため、応答前に失敗したSubmitを`UNSUPPORTED`として再送せず不確実Outcomeへ収束させる。
- Fake TransportによるTimeout、404、Unknown Outcome、Cancel、結果Chunk、Resume拒否、Binding不一致のオフライン試験。
- Test packageだけに存在する状態付きTuoni Transport Doubleで、Capability、Session、Submit、Task、Result、Cancel、
  Reconciliationを同一Scenarioとして検証する。Test DoubleはProduction packageへ含めない。
- Endpoint、Transport Factory、Credential Path、Command Lineを注入できない`build_tuoni_linux_adapter`で、完全なDeployment
  Identityだけから固定Linux Transportを構成する。不完全ProfileはTransport構築前に拒否する。
- 固定Release、Profile、Contract、実装Operation、未解決の実機条件をDigest Bindingした
  `TuoniOfflineReadinessReport`。常に`evidence_kind=test_double`かつ`production_eligible=false`であり、Production証跡へ
  昇格できない。
- systemd暗号化Credentialの入力形式を値なしの`deployment/tuoni-credential.schema.json`として固定し、Secret値、Default、
  ExampleをRepositoryへ格納しない。
- Foundation Adapterを誤登録しても、Secret消費・Sink書込み・Network接続より前に必ず拒否する境界。

オフラインReadiness Reportは次のコマンドで生成できる。この処理はNetwork、Credential、Targetへアクセスしない。

```bash
PYTHONPATH=src .venv/bin/python scripts/phase4_offline_readiness.py
```

## Production Activationにだけ残る実環境項目

| 未決項目 | 決める目的 | 未決の間の動作 |
| --- | --- | --- |
| vCenter隔離Port Group名 | 対象NICが承認した閉域Networkへ接続されていることを照合する | `vcenter_port_group_unresolved` |
| Tuoni API TLS証明書SHA-256 | Loopback上の接続先が承認したTuoni Serverであることを確認する | `tls_certificate_unresolved` |
| Tuoni OpenAPI SHA-256 | 稼働中の0.16.1 Serverが返すAPI契約を固定し、Capability Probeで再検証する | `openapi_digest_unresolved` |
| Tuoni用AccountのSecret Version ID | `LoadCredentialEncrypted=`で渡す暗号化CredentialのVersionを固定し、最小権限Accountを参照する | `credential_secret_reference_unresolved` |
| 許可するCommand Template名 | Tool Registryと実Tuoniの利用可能Templateを完全一致で束縛する | 空Allowlistとなり全Submitを拒否 |
| Target OS Edition / Architecture | 実機資格をWindows Server / Windows 11と実Architectureへ限定する | `target_operating_system_edition_live_unverified` / `target_architecture_live_unverified` |
| Live Provider Attestation | 稼働ServerのVersion / OpenAPI / TLS / Capabilityが固定契約と一致することを確認する | `live_provider_attestation_unverified` |

## Activation前に必要な検証

- vCenterで物理Uplink、Default Gateway、Internet、社内LAN Egressがないことを独立確認する。
- Tuoni ServerのVersion、`GET /docs/api`のOpenAPI Digest、Container Digest、TLS Certificate Digestを実機で
  完全一致確認する。公開SourceにないOpenAPIへ架空のDigestを設定しない。
- 短時間JWT、Memory-only保持、Redirect無効、Proxy無効、DNS解決なし、最小権限Accountを検証する。
- Control VMがUbuntu 24.04 LTS / x86_64であり、Adapter packageをsystem Pythonから`-I`でimportできること、Credential
  が`LoadCredentialEncrypted=`からread-only runtime fileとして渡され、CA fileがrootまたはservice owner管理で
  あることを確認する。
- 隔離LabのTest Double / 実TuoniでSession、Capability、Submit、Task Status、Result、Cancel、Reconciliation、Timeout、
  Crash、Unknown Outcome、Result Resumeを検証する。
- CIから実C2 / Targetへ接続しないことを維持する。

上記が完了するまでProduction Compositionは`TuoniAdapter`を登録せず、`TuoniAdapterFoundation`だけを使用する。
Foundationは`ExecutionAdapter`の構造だけを満たす非稼働実装であり、全Provider操作を
`C2AdapterUnavailableError`としてFail Closedする。

この制約はPhase 4オフライン開発受入を未完了に戻すものではない。一方、Test DoubleのPASS、合成したTLS Digest、架空の
Port Group、架空のSecret Versionを実機Evidenceとして扱うことは禁止する。

## 現在の検証結果

- Phase 4専用Unit / Security / Integration: 126 passed。
- 隔離`swtpm`を含む全体回帰: 949 passed / skip 0（既知のLangChain Pydantic V1互換Warning 1件のみ）。
- ruff、configured mypy 206 source files / direct strict mypy 203 source files、compileall、Pydantic / JSON境界検証、
  Wire / Deep-immutable検証、SHA256SUMS、依存整合性、`git diff --check`をすべてPASS。
- 実C2 / MCP / Targetへの通信、Credential読取、Payload生成・配布は0件。
