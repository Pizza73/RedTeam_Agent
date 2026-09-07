# Phase 0C 開発記録 — Data Security / Audit

**STATUS: 実装レビュー・修正完了 / 現行試験PASS / 独立レビュー未実施。** Phase 0Cの実装と再現可能な検証は完了した。
Common Gateの正式受入は、実装コミットを固定した後の独立レビュー完了まで保留する。
本記録は実コード・固定コミット・再実行した試験結果と合わせて判定する。記録の更新自体は受入完了の証拠ではない。
Codexによる独立レビューは未実施。TPM/`swtpm`のProduction Witness Integration Testは、隔離展開した
`swtpm 0.10.2` / `tpm2-tools 5.7`を用いて必須経路とNV Public Area不一致経路を実行し、全件PASSした。

## 1. 対象

| 項目 | 内容 |
| --- | --- |
| 設計Revision | `system-design-v1-r3` / `ai-control-v1-r3` |
| Phase | 0C: Data Security / Audit |
| 入力コミット（完全ID） | `85f3b50e5d169230cfb4f3a9cb59953b65616a91`（Phase 0B受入記録済みbaseline、`codex/phase-0c`） |
| 実装先 | 現checkout（ブランチ `codex/phase-0c`）。ユーザー指示によりcommit / push / mergeは未実施（作業ツリー上） |
| 実装対象コミット | 未固定（未commit）。独立レビュー時に固定する |
| 独立レビュー | 未実施 |
| 実装担当 | Claude Codeによる初期実装後、ユーザー指示によりCodexが受入修正と検証を完了 |

正本 `SystemDesign.md` / `SystemDesign_AI_Control.md` / `docs/acceptance-criteria.md` / `docs/safety-invariants.md` /
`docs/threat-model.md` は変更していない（`sha256sum -c SHA256SUMS` で7ファイルの不変を確認）。

### 参照した正本

SystemDesign.md §10.3〜10.5、§21.1〜21.3、§22、§27、§32〜35、§36 Phase 0C、§37.1 / §37.2、§40。
docs/acceptance-criteria.md Phase 0C、docs/safety-invariants.md、docs/threat-model.md、
docs/development/phase-0a.md、phase-0b.md。

## 2. 実装範囲と実装ファイル

Phase 0Bで型・安全なTest Double境界として置いた機構をProduction実装へ引き上げた。新しい製品状態・独立Serviceは
設計が明示的に許す箇所以外では追加せず、Phase 0B定義の状態（Ingestion `DELETE_PENDING` 以降、Lease型、
Quarantine概念、`SecureIngestionRetryPolicy`）を再利用した。

新規（製品）:

- `canonical/digest_catalog.py`（変更）— Phase 0Cの全Security-sensitive Digestを一意登録。
- `crypto/aead.py` — 標準AEAD（`cryptography` の AES-256-GCM）だけを呼ぶ単一Cipher入口。未導入時Fail Closed。
- `crypto/models.py` / `crypto/key_provider.py` — Domain KEK + Resource DEK Envelope、Opaque Handle、Nonce再利用検出、
  Cross-domain拒否、Resource単位Cryptographic Erasure（Wrapped DEK破棄）。
- `audit/models.py` / `nv_witness.py` / `generation_store.py` / `generation.py` / `hash_chain.py` —
  Mission別Audit Sequence / Hash Chain改ざん検出、Authenticated SQLite Generation Record / Immutable Blob、
  Content-bound Commit（§34.2.1）、Genesis / Current / Reset / Rollback / NV Identity mismatch Fail Close、
  Deployment Counter、In-memory NV Witness Double + Production `Tpm2NvCliWitness`（swtpm用CLI）。
- `audit/critical_witness.py` / `wrapped_key_state.py` / `trust_recovery.py` — Critical MutationとAudit / Intentの同一Txn、
  commit後TPM read-back Barrier、256件 / 300秒Batch、暗号化Provider Stateの変更時Witness、全Worker停止証拠と単回Approvalに
  BindingしたOffline Trust Recovery、旧Lease / Authorization一括失効、Recovery消費の新Trust Epoch Witness。
- `runtime/clock.py`（変更）— Host共有Monotonic Clock、UTC Rollback / Divergence検出（`ClockIntegrityError`）。
- `leases/models.py` / `leases/service.py` — Deployment Epoch Mirror、typed Collection / Ingestion Lease、
  完全Predicate、Fencing、Monotonic Expiry、Takeover、Renewal / Release / Invalidate。
- `quarantine/blob_store.py` / `models.py` / `store.py` / `collection.py` — 永続Encrypted Quarantine、
  Fence固有Staging、Streaming AES-GCM Sink、副作用なしFactory / Reader、Path Traversal拒否。
- `secrets/models.py` / `store.py` / `migration.py` — Append-only Secret Lifecycle
  （`DETECTED -> CONFIRMED -> REVOKED / SUPERSEDED`、Logical / Active Head OCC、Confirmation Record、値の暗号保存）、
  決定的Read-only Legacy Migration。
- `ingestion/publication_rule.py` / `artifact_store.py` / `manifest.py` / `service.py` — 固定Publication Rule /
  Bounded Parser / Allowlist / Secret Detection・Redaction、Artifact Store、Manifest、Repository-bound Secure Ingestion、
  原子的公開（Artifact / Secret / Manifest / Projection / Deletion Intent / DELETE_PENDING / Lease Release / Audit）。
- `erasure/models.py` / `service.py` — 専用Verified Eraser（Reconcile-first、単回Erasure Claim、read-back後Unlink、
  3種Intent Type、Projectionのみからの結果再構築）。
- `retention/scheduler.py` — Local Retention Scheduler（Evidence Retention Expiry / Incomplete Collection Expiry、
  OCC照合、原子確定、本文Read / Publish / Submit / Resolve権限なし）。
- `storage/unit_of_work.py` — ApplicationUnitOfWork Aggregate境界（Operation-id Idempotency、Child Commit禁止、
  Commit境界Fault Injection）+ Version固定Aggregate Catalog。
- `storage/database.py`（変更）— 汎用OCC Row Store（PK Uniqueness + Version OCC + Row-integrity Digest）、`synchronous=FULL`、Schema検査Mode、
  DB commit後に成功応答を保留するCritical Witness callback、Phase 0A / 0B Ownerからの単一Critical Mutation接続点。
- `architecture.py` — 一意なLogical -> Physical Mapping + 禁止Import / Owner重複検出。
- `composition/phase0c.py` — Phase 0C Test Composition Kernel（実AES-GCM + In-memory TPM Double）。
- `composition/activation_lock.py` / `startup_self_check.py` / `production.py`（変更）— Production Composition Root、
  Host Activation Lock、順序どおりSelf-check / 逆順Cleanup、Test Double拒否、通常起動Migration禁止。
- `errors.py`（変更）— Phase 0C typed errors。

新規（試験）: `tests/support_phase0c.py`、`tests/unit/test_crypto_envelope.py`・`test_digest_catalog_phase0c.py`・
`test_clock_and_lease_policy.py`・`test_publication_rule.py`・`test_unit_of_work.py`・`test_blob_store_path_traversal.py`、
`tests/architecture/test_architecture.py`、`tests/integration/test_phase0c_pipeline.py`・`test_generation_recovery.py`・
`test_leases.py`・`test_secret_lifecycle.py`・`test_erasure_and_retention.py`・`test_secure_ingestion.py`・
`test_phase0c_witness_barriers.py`・`test_trust_recovery.py`・`test_production_composition.py`・
`test_swtpm_witness.py`、`tests/security/test_phase0c_negative.py`、
`tests/property/test_phase0c_state_machines.py`。

## 3. 実装方針とアーキテクチャ整合メモ（矛盾ではない、適用限界の明示）

- **暗号は標準AEADのみ**: 独自暗号構成（stdlib encrypt-then-MAC / XOR等）は実装していない。
  `cryptography` の AES-256-GCM（`cryptography.hazmat.primitives.ciphers.aead.AESGCM`）だけを用い、依存不在時は
  typed `EncryptionUnavailableError` でFail Close（平文 / 別方式へDowngradeしない）。exact pin `cryptography==46.0.1` を
  `pyproject.toml` へ追加し、`requirements.lock` へ `cryptography==46.0.1` / `cffi==2.1.1` / `pycparser==3.0` を固定した。
- **物理配置**: 正本§35のTreeは参考配置。既存flat package配置に合わせ、Logical -> Physical Mappingを
  `architecture.py` に一つだけ置きArchitecture Testで検証する（Phase 0Bと同じ整合方針）。
- **同期実装**: 正本§10 / §34のProtocolは`async def`で示されるが、Phase 0A〜0Cのカーネルは同期。不変条件
  （Streaming / 非Buffer / Idempotent Commit / OCC / Witness）を同期で満たす（Phase 0B採用済み方針の継承）。
- **Generation Record StoreはApplication DB内**: 正本どおりTPM NV Extend Witnessは別Restore Domain（別Component）に置き、
  SQLite Rollback（Generation Record削除）でもTPM Witnessは戻らず不一致を`ANCHOR_RECOVERY_REQUIRED`で検出する。
  この分離をIn-memory WitnessとSQLiteの分離で検証した。
- **D4 Resource REK**: 実機TPM-backed REK消去のQualificationは`NOT_EVALUATED`のまま（正本§34.1.1）。本Phaseは
  Domain KEK + Resource DEK Envelopeの暗号消去（Wrapped DEK破棄）だけを実装し、D4のTPM-sealed REK / 実機消去保証は
  前倒ししない。Production Self-checkはIn-memory Provider / Witnessを拒否し、`tpm2_nv`実装と実構成を要求する。

## 4. 既知のプレレキジット（Environment Prerequisites）

| プレレキジット | 状態 | 用途 / 未導入時の扱い |
| --- | --- | --- |
| `cryptography==46.0.1`（+ `cffi` / `pycparser`） | 導入済み（本セッション中に親が導入） | AES-256-GCM Envelope Encryption。全暗号試験を実行済み |
| `swtpm 0.10.2` + `tpm2-tools 5.7` | `/tmp/phase0c-tpm`へ隔離展開済み | Production TPM Witness実接続Integration Test。Restart / SQLite Rollback / TPM Reset / NV Identity mismatch / Missing Recordを全件実行済み |

## 5. 試験結果

実行環境: 現checkout、`.venv`（Python 3.14.6）、`cryptography 46.0.1`。`redteam_agent`は未pip installのため
`PYTHONPATH=src:tests` で実行。

| コマンド | 結果 |
| --- | --- |
| `.venv/bin/ruff check src tests scripts` | All checks passed |
| `PYTHONPATH=src .venv/bin/mypy`（package=redteam_agent, strict） | Success: no issues found in 138 source files |
| `.venv/bin/python -m compileall -q src tests` | exit 0 |
| `PATH=/tmp/phase0c-tpm/usr/bin:$PATH LD_LIBRARY_PATH=/tmp/phase0c-tpm/usr/lib/x86_64-linux-gnu:/tmp/phase0c-tpm/usr/lib/x86_64-linux-gnu/swtpm PYTHONPATH=src:tests .venv/bin/python -m pytest -q -ra` | **517 passed, 0 skipped**（swtpm 7件を含む） |
| 同じTPM環境で `coverage run --branch -m pytest -q` + `coverage json` | line 9344/10271、branch 1925/2696、combined 86.90522094547698% |
| `scripts/verify_pydantic_contract.py` / `scripts/verify_wire_and_immutable.py` | いずれも exit 0 |
| `git diff --check` | 空（whitespace / conflict markerなし） |
| `sha256sum -c SHA256SUMS` | 承認済みr3正本・別冊・受入 / 安全 / 脅威モデル・LICENSE・README すべて OK（無変更） |

- 既存Phase 0A/0B 384試験は削除・skip・xfail化していない（引き続き全PASS）。
- 必須依存の`cryptography`を理由にしたPhase 0C試験のskip guardを除去した。`swtpm`試験はtoolchainがない環境だけ
  明示skipするが、本検証では7件すべて実行し、skipは0件だった。

## 6. 受入条件とTraceability（docs/acceptance-criteria.md Phase 0C）

各条件の主なOwner / Test。swtpm実機検証以外はすべて本環境でPASS。

| 受入条件（要約） | 主なOwner / Test |
| --- | --- |
| ApplicationUnitOfWork（同一Txn Commit、Child Commit禁止、OCC、create-or-verify、Fault Injection） | `storage/unit_of_work.py`、`test_unit_of_work.py` |
| Versioned Digest Catalog一意登録 / 未登録・重複Owner・Field欠落・Fallback Fail Close | `canonical/digest_catalog.py`、`test_digest_catalog_phase0c.py` |
| Architecture Owner重複 / 禁止Import拒否 | `architecture.py`、`tests/architecture/test_architecture.py` |
| Mission別Audit Sequence / Hash Chain改ざん検出 | `audit/hash_chain.py`、`test_generation_recovery.py::test_audit_hash_chain_tamper_detected` |
| Critical Witness Barrier（Current Binding集合の世代継承、Current DB再構築照合、Mission / Epoch、Dispatch Claim、Cancel、Budget、Result Task、Secret、Publication、Erasure） | `audit/critical_witness.py`、`test_phase0c_witness_barriers.py` |
| Phase 1 Knowledge Current Stateの閉じたWitness境界 / Owner未接続時Fail Close | `composition/phase0c.py`、`test_phase0c_witness_barriers.py::test_phase1_knowledge_boundary_is_fixed_in_phase0c_policy` |
| 通常Auditの固定256件 / 300秒Batch | `audit/critical_witness.py`、`test_phase0c_witness_barriers.py::test_normal_audit_batch_*` |
| 暗号化Wrapped Key State変更時Witness / 未Witness Key利用拒否 | `audit/wrapped_key_state.py`、`crypto/key_provider.py`、`test_phase0c_witness_barriers.py::test_provider_mutation_is_witnessed_before_key_use` |
| Offline Trust Recovery（単回Approval、採用State、旧Lease / Authorization失効、消費Witness） | `audit/trust_recovery.py`、`test_trust_recovery.py` |
| Authenticated Generation + TPM NV Extend Witness / Content-bound / Genesis / Recovery / Fail Close | `audit/generation*.py`、`nv_witness.py`、`test_generation_recovery.py`（reset / rollback / identity / genesis / counter） |
| Rollback / Reset / NV mismatch / 欠落 -> `ANCHOR_RECOVERY_REQUIRED`、Local Reseedなし | `audit/generation.py`、`test_generation_recovery.py` |
| 単一Host Activation Lock / Topology / 順序Self-check / Test Double拒否 / 通常起動Migration禁止 | `composition/production.py`・`activation_lock.py`・`startup_self_check.py`、`test_production_composition.py` |
| Deployment / Trust Epoch、Monotonic Clock、UTC Rollback / Divergence -> `ClockIntegrityError` | `leases/service.py`、`runtime/clock.py`、`test_clock_and_lease_policy.py`、`test_leases.py` |
| Domain分離Envelope Encryption（Domain KEK + Resource DEK、Nonce、AAD、Cross-domain / 平文Fallback禁止、Key unavailable -> error） | `crypto/*.py`、`test_crypto_envelope.py`、`test_phase0c_negative.py` |
| 永続Encrypted Quarantine + Streaming Sink + Fence Staging + 副作用なしFactory/Reader + Crash Recovery | `quarantine/*.py`、`test_phase0c_pipeline.py`、`test_erasure_and_retention.py` |
| Append-only Secret Lifecycle + Heads OCC + Revoke/Supersede + 決定的Legacy Migration | `secrets/*.py`、`test_secret_lifecycle.py` |
| typed Collection / Ingestion Lease（完全Predicate、60s / <=20s / >=3x、Takeover増加Fence、Stale拒否） | `leases/service.py`、`test_leases.py`、`test_clock_and_lease_policy.py` |
| Repository-bound Secure Ingestion（固定Rule / Classification / Redaction、Retention、Store固定保存先、create-or-verify） | `ingestion/*.py`、`test_secure_ingestion.py`、`test_publication_rule.py` |
| 原子的公開 + Projection-only Result Rebuild + Crash境界 | `ingestion/service.py`、`erasure/service.py`、`test_phase0c_pipeline.py`、`test_erasure_and_retention.py` |
| 専用Verified Eraser（Reason別Evidence、単回Claim、Reconcile-first、read-back後Unlink、Ingestion側消去能力なし） | `erasure/service.py`、`test_erasure_and_retention.py`、`test_phase0c_negative.py` |
| Local Retention Scheduler（Collection ABANDONED / Evidence Retention / Incomplete、OCC、権限なし、Retention非短縮） | `retention/scheduler.py`、`test_erasure_and_retention.py` |
| Secret値がPrompt / 通常DB / Audit / Blobへ入らない | `test_phase0c_negative.py`、`test_phase0c_pipeline.py::test_no_plaintext_*` |
| Artifact Path Traversal / Symlink Escape拒否 | `quarantine/blob_store.py`、`test_blob_store_path_traversal.py` |
| Stateful FamilyのProperty / State-machine Evidence（Lease Fencing / Generation / Ingestion-Erasure Recovery） | `tests/property/test_phase0c_state_machines.py` |
| Integration TestがProduction TPM Witnessを`swtpm`へ接続 | `tests/integration/test_swtpm_witness.py`（Restart / SQLite Rollback / TPM Reset / NV Identity mismatch / Missing Record / Counter初期化 / Public Area不一致の7件すべてPASS） |

## 7. Codex実装レビュー（2026-09-07）

実装作業と同じ会話内のレビューであり、Common Gateが要求する独立レビューとは区別する。正本のCritical State表、
Generation Commit順序、Offline Recovery、Production Compositionをpublic entry point / recovery / failure pathまで再照合し、
次を修正した。各指摘には回帰試験を追加した。

| 重要度 | 指摘 | 修正 / Evidence |
| --- | --- | --- |
| HIGH | audit_headの最新Generationが直近Intentだけを保持し、以前のCurrent Critical Bindingを失っていた | 既存Bindingを`record_type + record_id`で世代継承し、Generationのstate digestを全ContentへBinding。Mission / Budget / Claim / Task Bindingの継承を試験 |
| HIGH | TPM read-back後にCurrent Application DBのSecurity Projectionを照合していなかった | 各Ownerの既存RecordからProjectionを再構築する`verify_current_security_state`を追加。Mission行だけを有効な旧版へ戻す選択Rollbackを拒否する試験を追加 |
| HIGH | Result Ingestionの中間 / 公開 / Retention / Erasure Claim遷移とCancel結果が、以前のWitness済みCurrent Bindingを未更新にしていた | 各既存TransactionへCritical Mutationを同居させ、Cancel結果も応答前にWitness。新しい業務状態 / Record種別は追加していない |
| HIGH | SecretのBindingがLifecycle Head Digestではなく単一Event Digestだった | exact current Lifecycle Head Digestへ修正し、Current Owner Recordから再計算して照合 |
| HIGH | 初回の通常Auditだけが続く場合、300秒のBatch期限が開始されなかった | 初回未Witness Eventを時間基準に使用する回帰試験を追加 |
| HIGH | Production Service Builderが任意Objectを返せ、Generation Store / Coordinator / Barrierの同一Rootを検証しなかった | 型付き`ProductionServiceBundle`と同一DB / TPM / Coordinator、Production Record Authentication、Durable Blob Storeの検査を追加 |
| HIGH | SQLite Generation Record / Blob Connectionが`synchronous=FULL`を明示せず、TPMの危険なNV属性を設定値として受理できた | `PRAGMA synchronous=FULL`、`ORDERLY` / `CLEAR_STCLEAR` / `POLICY_DELETE`拒否、Role別Index一意性を追加 |
| HIGH | Offline Recovery replayがWitnessとMirrorだけを照合し、回復後Mission Authorizationの選択Rollbackを検出しなかった | 消費RecordのAuthorization RootをCurrent Mission Stateから再構築して照合する試験を追加 |
| HIGH | Phase 0C起動後もRepository直呼びでRBAC Mappingを変更でき、Mission Witnessを迂回できた | 初期Provisioning後の直接変更を拒否。将来の変更はMission Authorization OwnerのWitness済みCommandだけに限定 |

修正後、上表に対応する試験と全517試験、静的検査、実`swtpm`障害経路を再実行し、未解決のBLOCKER / HIGHは0件。

## 8. 受入と残課題

- Phase 0Cの製品コードとUnit / Integration / Security / Architecture / Property-State-machine試験を実装し、
  ruff / mypy(strict) / compileall / branch coverage / verify scripts / git diff --check / sha256sums を実行済み。
  `swtpm`を含む現行チェックはPASS（517 passed, 0 skipped）。
- Codex完了時の主な受入修正: seeded test providerのKEK / DEK独立性、消去のterminal replayでのProvider再照合、
  Destroy後のread-back `CONFIRMED`、Ciphertext unlink後のinventory再読、swtpm TCTIの連続data/control port、
  未WRITTEN NV Extend / Counterの仕様どおりの初期値処理、TPM必須経路とPublic Area不一致の実試験。
- 2026-09-07レビュー修正: Current Critical Binding集合の世代継承 / Current DB照合、全Result Ingestion遷移と
  Cancel結果のWitness、Secret Lifecycle Head、初回300秒Batch、Production Root固定、SQLite FULL、危険NV属性拒否、
  Recovery Authorization Root再照合、Runtime RBAC直接変更拒否。
- **未実行 / 未達（Phase受入の残条件）**:
  - **独立レビュー未実施**: 実装セッションから分離したCodexによるRead-only Snapshotの独立レビューは行っていない。
  - **D4 実機Resource REK消去 = `NOT_EVALUATED`**（正本§34.1.1）: 本Phaseは対象外。swtpm / 文書検査を実機PASSと
    しない。PASS前はProduction採用不可。
- `encrypted_raw` Artifactの暗号化保存 / Bound AAD復号Round-tripと、Ciphertextへの平文非出現も追加検証済み。
- **未解決の仕様矛盾**: なし。**Security-critical実装残作業**: なし。
- 実C2 / MCP / 外部Targetへの操作は行っていない。全試験はTest Double / 実AES-GCM / `swtpm`だけで実施した。
- 次段階: 実装対象コミット固定、実装会話から分離したCodex独立レビュー。

## 9. Phase 1移行判定

- Phase 0C製品実装のBLOCKER / HIGHと仕様矛盾は、今回のレビュー修正後0件。
- Phase 1が実装する`knowledge_evidence_head`と`KNOWLEDGE_EVIDENCE_CHANGED`をPhase 0Cの閉じたCritical State /
  Witness Policyへ登録済み。Phase 1ではKnowledge Owner RepositoryからCurrent Projection Resolverを接続する。
  接続前のKnowledge EventはFail Closedし、未WitnessのGoal / Context採用へ進まない。
- Phase 1の実装開始に必要な技術的境界は整った。ただしCommon Gateの正式なPhase遷移は、未commitの実装対象を固定し、
  実装会話から分離したCodexのRead-only独立レビューを完了するまで保留する。
