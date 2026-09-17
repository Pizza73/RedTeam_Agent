# Kaliローカル製品構成

`redteam-product`は、現在のKali Linux上で認証済みオペレーターUI、永続Mission/Approval状態、Phase 2 vLLM能力検証を一つのサービスとして構成する。設定は`deployment/kali/product.json`、systemd単位は`deployment/systemd/redteam-agent.service`に固定する。

この構成は安全側に閉じており、`productionEligible=false`である。UIからMission draftの作成、正式Missionへの変換、検証、Approval判断、LLM能力試験、Provider policy draftの管理はできる。一方、Missionの`start`/`resume`は実行runtimeがないため拒否する。

## 固定境界

- UI: loopbackを既定とし、隔離LAN向けに`0.0.0.0:18000`を明示選択できる。外部bindではRFC1918 literal IPv4の完全一致`uiAllowedOrigins`が必須で、Host/Origin不一致を拒否する。
- LLM: 初期値は`http://10.0.6.181:8100/v1`。UIで`vllmAllowedCidrs`内のliteral IPv4 `/v1` endpointとAPI keyを候補登録できる。モデル`gemma-4-31B-it`、署名済みManifest、Tokenizerは固定する。
- Target allowlist: `10.0.10.212/32`。Impacketの登録済みSMB/RPC操作だけに使用する。
- AD Collector: 固定DC IPv4、証明書検証済みLDAPS/TCP 636、Referral無効、LDAP write無効。AD CSは固定Certipy `find`のみ。
- Sliver: v1.7.7、operator `joe`、HTTP Beacon。systemd credentialの存在だけでは有効化されず、live gRPC/mTLS identityとBeaconの証跡が必要。
- `approvedSessionRefs`はlive inventoryで確認・承認したBeacon sessionだけを列挙する。現状はBeaconなしのため空であり、架空のsession IDではMission検証を通過できない。
- Payload生成、listener生成、任意shell、upload、injection、pivot、credential dumpはUI/APIおよびadapter契約に存在しない。

## 配備

1. 専用の`redteam-agent`システムユーザーを用意し、`ad-collector` extraを含むwheel/venvと`frontend/dist`を`/opt/redteam-agent`へ配置する。KaliのCertipyも必要である。
2. `product.json`と署名済みLLM manifest/public keyを`/etc/redteam-agent`へ配置する。秘密値は設定JSONに書かない。
3. 32 byte以上のランダムなUI token、vLLM API key、既存の`joe.cfg`に加え、読み取り用AD credential JSONを、それぞれ`systemd-creds encrypt`で`/etc/credstore.encrypted`へ保存する。AD JSONは`domain`、`username`、`password`だけを持つ。平文をjournalやコマンド引数へ渡さない。
4. `redteam-agent.service`と必要な`redteam-agent.service.d/sliver-operator.conf`を配置し、`systemctl daemon-reload`後にサービスを開始する。
5. loopbackでは`http://127.0.0.1:18000`、サンプルの隔離LAN構成では`http://10.0.1.109:18000`を開き、UI tokenを一度入力する。tokenはHttpOnly session cookieへ交換され、プロセス再起動時に全sessionが失効する。

直接外部bindでは、`uiHost=0.0.0.0`、実際のアクセスURLと一致する`uiAllowedOrigins`、管理端末の送信元CIDRを許可するsystemd `IPAddressAllow=`とhost firewallを同時に設定する。HTTP上のtoken/cookieは暗号化されないため、信頼済み隔離LANまたはVPN内に限定し、internetへ直接公開しない。

## LLM接続先とAPI keyの変更

`VLLM Settings`でBase URLとAPI keyを入力し、`Register candidate`、`Test connection & capabilities`、`Activate candidate`の順に操作する。候補試験はCapability証跡を公開せず、有効化時に同じ完全試験を再実行する。成功した場合だけactive endpointと証跡を交換し、失敗時は直前の設定と証跡を維持する。

API keyはブラウザへ再表示せず、SQLiteやログにも保存しない。`vllmSettingsDirectory`配下のservice-owned `0600`ファイルへ原子的に保存し、active endpointの公開設定だけを永続化する。再起動をまたいだ未有効化候補は破棄する。HTTP endpointではBearer keyがTLS保護されないため、承認済み隔離networkだけで使用する。

systemd単位はdefault-deny networkを設定し、loopback、管理端末CIDR、LLMの許可CIDR、固定AD Collector IPだけを許可する。`vllmAllowedCidrs`はsystemdの`IPAddressAllow`以下に狭く設定し、両方を配備時に同期する。`product.json`とsystemdのCollector IPは実DCへ同時に変更する。将来Impacket workerを有効化する場合は、control planeとは別のworker単位でTarget IPとTCP/445またはTCP/135だけを許可し、そのsandbox identityをPhase 5 live attestationへ結び付ける。

## 現時点で実環境が必要なゲート

- TPM-backedで再起動後も検証可能なkey providerとgeneration witness。
- Sliver serverのlive gRPC/mTLS identity、承認済みHTTP Beacon、対象session reference。
- Impacket workerのOS-level egress sandboxと実Target/Credentialによるlive attestation。
- `intern.local`の実DC IPv4、TCP 636到達性、LDAPS発行CA証明書。現在の`10.0.10.212`は`WS01`でありDCではない。
- 上記を登録したproduction composition rootとMission実行worker。

これらが揃うまでは、UIにblockerを表示し、Mission実行をfail-closedに保つ。
