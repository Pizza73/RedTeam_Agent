# Phase 5 MCP Adapter 開発記録

## 現在の判定

Phase 5のオフライン実装は完了した。Protocol Contract、Identity / Trust境界、Adapter本体、Tool Candidate処理、
Tool Availability連携、状態付きTest Serverに加え、選定したFortra Impacket `0.13.1`用のone-shot stdio MCP Serverと
Production-shaped Process Transportを実装している。

この判定はProduction Activationではない。実MCP Server、Credential、外部Targetへの接続は行っておらず、状態付き
Test Serverの証跡は`production_eligible=false`から変更できない。Impacket Serverも実Target、実Credential、Control VMの
OS / vCenter Egressへ接続しておらず、実環境資格が完了するまでProduction Activationしない。

## オフラインで固定した事項

| 項目 | 固定値 / 方針 |
| --- | --- |
| Protocol Revision | `2026-07-28`完全一致。旧RevisionへのFallbackと未知RevisionへのUpgradeを禁止 |
| Specification Commit | `5f5440bb26a62e2cf3440b92da5a667efa03b267` |
| Official Schema SHA-256 | `ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203` |
| Client実装 | 固定した低レベルJSON-RPC Contract。外部MCP SDKの暗黙動作へ依存しない |
| Tasks Extension | `disabled`。Task / Cancel / Reconcile Provider APIを呼ばない |
| Result Mode | `local_result`。Composition所有の`RawResultSink`へChunk Streaming |
| Tool更新 | Candidate Definitionとして隔離し、Tool Registryを自動更新しない |
| CI / 開発接続 | 状態付きin-memory Test Serverだけ。実MCP / Targetへの通信は禁止 |

Protocolの基準は公式MCP Specificationの`2026-07-28` schemaと`server/discover`を使用する。TasksはこのRevisionの
必須機能とはみなさず、Client / Server / Extensionの検証済み積集合がない現状では無効とした。

## 実装した範囲

- Application発行のStable Adapter ID / Server ID、Logical Server Identity、Transport Identityを別々に型付けした。
- `local_process`はstdio、`managed_remote` / `untrusted_remote`はStreamable HTTPだけを許可する。
- stdioはAbsolute Executable Path、Executable SHA-256、Command Configuration Digest、Package Versionの完全な
  Identity集合を要求する。RemoteはHTTPS URLと少なくとも1つの暗号学的Identityを要求する。
- Transport AttestationをProfile / Server Config / API Contract / Protocol / Execution Location / Identity集合 /
  Sandbox / Redirect無効化へ完全一致で束縛する。Test Server AttestationはProductionへ昇格できない。
- `server/discover`、`tools/list`、`tools/call`だけを閉じたContractとして実装し、各RequestにProtocol Revision、
  Client Info、Client Capabilityを明示する。
- JSON-RPC Envelope、Request ID、重複JSON Key、未知Control Field、型Coercion、Protocol Revision、Logical Name /
  Version、Capabilityを厳密に検証する。
- Live Tool ListをSize制限・文字列Sanitization・Schema Digest付きCandidateへ変換する。未承認Toolや承認Schemaと異なる
  ToolはCandidateのままとし、利用可能Capabilityへ含めない。
- Adapter Capabilityへ承認済みTool名とLive Schema Digestから成るTool固有Capability IDを発行する。Tool Registry側が
  これを要求するため、Live Schema変更時はAvailable Toolから除外される。
- Remote MCP Trust PolicyをTool Availability Resolverへ接続した。PolicyのExecution Location不一致、Digest不一致、
  untrusted remoteのState Change / Destructive / High Risk / Secret、managed remoteの必須Enforcement不足を拒否する。
- Generic MCP ProfileはTarget BindingとSecret Deliveryを明示設定しない限り従来どおり`none` / `disabled`でFail Closedする。
  Impacket local Profileだけは`exact_ip_enforced`と`ephemeral_meta_v1`を固定し、PolicyDecision由来のBindingと引数の全IP / Port /
  Protocolを再検証する。Hostname、Redirect、Allowlist外IPを拒否する。
- Tool Callの直前にDiscoveryとLive Tool Listを再検証する。未承認引数、Schema Drift、Secret Reference / JIT Binding / Versionの
  不一致はTool Call前に拒否する。Secret Deliveryはlocal one-shot stdio Processだけに限定する。
- Task非対応のためTask / Cancel / Reconcile Provider APIは送信しない。応答消失後のReconcileは`UNSUPPORTED`となり、既存
  Executor規則により副作用を再送せず`OUTCOME_UNKNOWN` / Human Reviewへ収束させる。
- 同じLogical Server名と同じTool名を持つ複数Serverを、Stable Adapter IDとTrusted Dispatch Portで一意にRoutingする。
- Test packageだけに状態付きServer / Transportを実装し、Discovery、Catalog、複数Call、Schema Drift、Revision Drift、
  Logical / Transport Identity Drift、応答ID不一致、Pagination、Response Loss、Secret拒否を検証する。
- 固定Protocol / Contract / 実装Operation / 未解決実機条件をDigest Bindingした`MCPOfflineReadinessReport`を実装した。
- Impacket Serverは`impacket.smb.negotiate`、`impacket.smb.authenticate`、`impacket.smb.list_shares`、
  `impacket.rpc.endpoint_map`の読取専用4 Toolだけを公開する。汎用CLI、任意Module / Command、`psexec`、`secretsdump`、
  `ntlmrelayx`等は実装しない。詳細は`phase-5-impacket-mcp.md`を参照する。
- stdio TransportはShellを使わず、実行IdentityをRequest直前とProcess起動直後に再測定し、時間・Memory・File・FD・Outputを
  制限する。Target CIDRは固定Command Configuration DigestへBindingし、Process内Audit Hookも固定CIDRのTCP/445・135以外の
  `socket.connect`を拒否する。

オフラインReadiness Reportは次のコマンドで生成できる。この処理はNetwork、Credential、Targetへアクセスしない。

```bash
PYTHONPATH=src .venv/bin/python scripts/phase5_offline_readiness.py
```

## Phase 4との依存関係

| 進める範囲 | Phase 4実環境の要否 |
| --- | --- |
| Phase 5のProtocol / Adapter / Test Server実装 | 不要 |
| Phase 5のオフラインContract / Integration / Security試験 | 不要 |
| MCP Server単体の隔離Lab資格 | Phase 4に依存しない |
| Tuoni C2とMCPを組み合わせる本番End-to-End | Phase 4とPhase 5の両方のProduction証跡が必要 |
| Phase 0A〜5の全製品受入完了 | Phase 4 / 5のHuman Gate、実機適格性、独立レビューがすべて必要 |

したがってPhase 4の実環境未接続はPhase 5オフライン実装のBlockerではない。一方、Phase 4を未完了のまま本番統合や
Project Completeを宣言することはできない。

## Production Activationにだけ残る項目

| 未決項目 | 決める目的 | 未決の間の動作 |
| --- | --- | --- |
| MCP Server製品 / exact Version | Fortra Impacket `0.13.1`へ固定済み | Version Driftを拒否する |
| Stable Server / Adapter ID | `impacket-local` / `mcp-impacket-local`へ固定済み | ID Driftを拒否する |
| Execution Location | Control VMの`local_process`へ固定済み | Remote Secret Deliveryを拒否する |
| Transport | one-shot `stdio` Processへ固定済み | Shell / Redirectを使用しない |
| Transport Identity | BinaryまたはHTTPS Peerの差し替えを検出する | `mcp_transport_identity_unresolved` |
| 認証方式 / Secret Reference | Password / NTLM Hash Schemaは実装済み。実Credential選択が必要 | 実Secret未登録ではCredential Toolを有効化しない |
| Sandbox / Egress | Local ProcessまたはRemote側の逸脱を強制的に制限する | `mcp_sandbox_attestation_unverified` |
| Remote Trust Evidence | managed remoteのScope / Auth / Audit / Egress / Isolation / Identityを検証する | Unsafe ToolをAvailableにしない |
| 承認Tool / Schema Digest | Impacket読取専用4 Toolへ固定済み | Schema Drift時はAvailable Toolから除外する |
| Live Discovery / Integration | 稼働Serverが固定Revision / Identity / Capability / Schemaと一致することを確認する | `mcp_live_discovery_unverified` |

Impacket用MCP Serverとstdio Process Transportは選定・実装済みである。残るのはControl VMへ導入した実ExecutableのIdentity、
vCenter隔離Target CIDR、OSレベルSandbox / Egress証跡、実Credential、Windows TargetでのLive Integrationである。これらを
架空のIdentityやCredentialで代用せず、実環境資格後にだけ`live` Attestationを構成する。Impacket以外のMCP Serverは従来どおり
Server / Transport / Trust Policy / Tool Catalog未解決のままFail Closedする。

## 現在の検証結果

- Phase 5専用Unit / Security / Integration: 56 passed。
- 全体回帰: 998 passed / 7 skipped。skipは`swtpm` / `tpm2-tools`がこのHostに未導入のためであり、Phase 5試験のskipは0件。
- ruff、configured strict mypy 218 source files、compileall、Pydantic / JSON境界検証、Wire / Deep-immutable検証、
  SHA256SUMS、依存整合性、Readiness Report生成、`git diff --check`をPASS。
- 実MCP / C2 / Targetへの通信、Credential読取、Payload生成・配布は0件。
- Common Gateと実装セッションから分離した独立レビューは、対象コミット作成後に実施する。
