# Phase 0C Independent Review Fix Report

## Review input

- Current phase: `Phase 0C: Data Security and Audit`
- Input review SHA: `6b55fe9ba6cf0453e8c8ba33af3a3a9368944df5`
- Latest correction input SHA: `29a9f11fc316cb348ef685c96abed8e09a5f9bc1`
- Trusted Phase 0B base PASS SHA: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`
- Implementation branch: `ai/redteam-agent-phase-loop`
- Independent-review result: `CHANGES_REQUESTED`
- Latest finding key: `CODEX-P1-59D132BD598A7EFA`
- External provider, C2, MCP side effect, local attack, and external-target execution: absent

## Resulting working-tree diff

The latest correction updates three implementation/test files and this report. No protected
governance file listed in `AGENTS.md` was modified. In particular, `SystemDesign.md`, `.github/**`,
`automation/**`, requirements, acceptance criteria, safety invariants, implementation status,
phase prompts, CI scripts, and dependency manifests are unchanged.

Modified files:

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

## Findings addressed

- [`discussion_r3892546335`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546335):
  added an Executor-compatible encrypted `RawResultSink` and trusted factory. Each stdout, stderr,
  and artifact chunk is persisted before the next chunk, with authenticated Mission revision,
  execution, sink, channel, sequence, plaintext size, ciphertext offset, artifact metadata digest,
  chunk digest, and stream-policy binding. Both from-start digest replay and exact verified-cursor
  resume are supported. Executor recovery persistence is no longer restricted to its Mock sink.
- [`discussion_r3892546340`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546340):
  made the typed audit recorder mandatory for Artifact, Secret, and Quarantine stores and recorded
  create, chunk write, commit, abort, resume, read, export, resolve, revoke, and delete operations.
  Audit failure prevents a reference, content, receipt, or successful delete result from returning.
- [`discussion_r3892546345`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546345):
  replaced arbitrary audit JSON with a strict reference-only payload. Resource type, internal stable
  reference ID, allowlisted operation, internal operation ID, and SHA-256 metadata digest are the
  only accepted fields; alternate secret-bearing keys and raw identifiers fail strict boundary
  validation.
- [`discussion_r3892546348`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546348):
  Secret resolution now authenticates the current stored metadata/tombstone and authorization
  version rather than trusting caller-provided verification state. Active metadata is verified
  without decrypting the secret before authorization, and stale references cannot bypass revocation.
- [`discussion_r3892546353`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546353):
  enforced one-way key transitions. Revoked and destroyed keys cannot return to active or
  decrypt-only states, destroyed material is wiped, and resource keys remain bound to the current
  domain parent key so parent revocation also fails closed.
- [`discussion_r3892546357`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546357):
  Artifact and Secret writes now require a trusted ingestion authorization bound to Mission,
  source execution, resource type, exact internal resource ID/version, digest, and current time.
  Missing and cross-Mission write authority is rejected before storage.
- [`discussion_r3892546363`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892546363):
  encrypted resources now use separate per-object keys under separated key domains. Delete first
  destroys the exact object key and then unlinks ciphertext, so restoring a filesystem snapshot
  cannot restore decryptability. Direct and streamed quarantine deletion are both covered.

The correction also connects committed encrypted streams to `SecureIngestor` and the Phase 0B
`SecureResultIngester` contract. A full Receipt match is required before streaming decryption;
secret detection handles arbitrary chunk boundaries with bounded pending raw memory. Only redacted
Artifact IDs enter the normalized Executor summary. Ingestion failure keeps the quarantine and never
falls back to plaintext or a normal raw Artifact.

## Second independent review correction cycle

The independent review for correction SHA
`6c1cd479a1d9fe1a574caaf184e5a5d2be918ddc` returned four P1 findings under finding key
`CODEX-P1-B57C808B534B4E5E`. All four were addressed within Phase 0C:

- [`discussion_r3892964101`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892964101):
  the bounded streaming detector now recognizes quoted structured keys and quoted values while
  preserving their delimiters. It handles nested JSON, escaped quoted values, arbitrary chunk
  boundaries, and fails closed on an over-limit or unterminated candidate instead of classifying the
  unchanged value as normal.
- [`discussion_r3892964110`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892964110):
  each Artifact now receives an authenticated durable completion marker bound to its metadata,
  first/next global chunk sequence, chunk count, declared size, and chunk-binding digest. A verified
  cursor may continue only the currently open Artifact with identical metadata; completed, reused,
  non-monotonic, and size-mismatched sequences fail closed.
- [`discussion_r3892964118`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892964118):
  stream operation IDs are now internally derived and audit insertion is idempotent. Chunk, Artifact
  completion, commit, and abort envelopes form durable reference-only audit outboxes. Restart
  reconciles every outbox before a terminal Receipt becomes usable, so a crash or recorder failure
  between terminal write and audit append cannot produce an unaudited accepted commit.
- [`discussion_r3892964125`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3892964125):
  streamed deletion now persists an authenticated intent before erasure. Restart validates that
  intent against the exact commit terminal, reconciles its delete audit idempotently, and resumes
  per-sequence object-key destruction. An unlink interruption after key destruction is also
  idempotently recoverable; metadata-only deletion/terminal records may remain, but no raw chunk
  remains decryptable.

This cycle also permits authenticated empty ciphertext for valid empty chunks and metadata markers;
nonce, tag, AAD, key-domain, digest, and plaintext-size checks remain mandatory.

## Third independent review and post-refresh correction cycle

The review for `021bfce9255def1c68cfdd8c4481aa4c2e0d1dc5` recorded four P1 findings
under `CODEX-P1-8F2A649BA8E646D5`. After the trusted default-branch refresh, review of exact
HEAD `bde842bc06e61742fe2ff84e30ab21830162ff1c` added one P1 under
`CODEX-P1-83F82756B539E4B9`. The bounded Human Resume covers these findings:

- [`discussion_r3893331936`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3893331936):
  secret detection now includes the separator-free `apikey` spelling produced by lowercasing
  camelCase `apiKey`. A JSON regression verifies that the value becomes a Secret reference and
  only `[REDACTED]` reaches the Artifact.
- [`discussion_r3893331943`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3893331943):
  `MissionAuditLog(Database)` now stores canonical events in `audit_logs` and the separately trusted
  chain tail in `audit_log_heads`. `BEGIN IMMEDIATE` covers chain verification, idempotency lookup,
  sequence allocation, event insertion, and optimistic head update. Restart, continued append, row
  binding, chain verification, and deletion tamper are tested. All SQL remains in the repository or
  storage layer.
- [`discussion_r3893331948`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3893331948):
  secure streaming ingestion persists an authenticated `SecureIngestionResult` completion record
  bound to the exact receipt, execution, sink, ingestion ID, and ingestion digest before writing the
  deletion intent. A restart after partial or completed erasure returns that same verified result
  and never reruns an external action. Secret creation is also idempotently reconciled using the
  original encrypted record and deterministic audit operation.
- [`discussion_r3893331953`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3893331953):
  Artifact IDs and deterministic audit operation IDs now make the encrypted Artifact envelope a
  durable create-audit outbox. Retry accepts only identical content and bindings, preserves the
  original creation time, and reconciles exactly one `artifact.create` event before returning a
  reference. Reads reconcile the same outbox before exposing content.
- [`discussion_r3894458359`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3894458359):
  streaming ingestion no longer retains or joins all redacted chunks. `ArtifactStore.put_stream`
  incrementally hashes and encrypts bounded 4 KiB chunks, then commits an authenticated manifest
  bound to the logical size, SHA-256 digest, classification, source execution, and per-chunk
  offsets/digests/encryption metadata. Authorized read verifies the manifest and every chunk before
  reconstructing the caller-requested Artifact.

No raw chunk, complete redacted result, secret value, or plaintext fallback is written to normal
storage. Partial Artifact chunks remain encrypted and idempotently resumable until the manifest is
committed.

## Fourth independent review correction cycle

The review for exact HEAD `0b9ce88d297179a765ad94f27ebb91eba3429890` recorded two P1 findings
under `CODEX-P1-344F930A8CCE7B53`. The exact-SHA Human Resume covers both findings:

- [`discussion_r3894970515`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3894970515):
  the bounded streaming detector now recognizes case-insensitive Bearer credential forms,
  including `Authorization: Bearer ...`. The visible scheme and surrounding structured data remain
  intact while only credential material is stored in the Secret Store and replaced by the redaction
  marker before Artifact publication.
- [`discussion_r3894970527`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3894970527):
  an authenticated revocation tombstone is now also the durable pending-erasure intent. Both the
  first revocation and any repeated `revoke()` reconcile deletion against the original encrypted
  record binding before returning revoked metadata, so interruption before resource-key destruction
  cannot leave the secret indefinitely decryptable.

## Fifth independent review correction cycle

The review for exact HEAD `68a47875eb5b77ea2ab5d2ee0570f57d7706f867` recorded two P1 findings
under `CODEX-P1-0B4FA62084F27547`. The exact-SHA Human Resume covers both findings:

- [`discussion_r3895271557`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3895271557):
  the bounded detector now recognizes `access_token`, `refresh_token`, `client_secret`, and
  `oauth_token` with underscore, hyphen, and separator-free camelCase-normalized spellings.
  Cross-chunk JSON values become Secret references and only redaction markers reach the Artifact.
- [`discussion_r3895271565`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3895271565):
  `ArtifactStore.expire()` verifies an authoritative exact reference, requires current trusted
  write authorization, and persists an authenticated reference-only deletion intent before an
  idempotent delete audit and resource-key destruction. Stream chunks are erased before the
  manifest; symlinked intent paths fail closed, and restart or repeated calls resume safely.

## Sixth independent review correction cycle

The review for exact HEAD `29a9f11fc316cb348ef685c96abed8e09a5f9bc1` recorded two P1 findings
under `CODEX-P1-59D132BD598A7EFA`. The exact-SHA Human Resume covers both findings:

- [`discussion_r3895731854`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3895731854):
  quoted structured keys containing credential-bearing components are now detected without relying
  on a finite exact-field allowlist. Complete `credential` and cross-chunk `serviceCredential`
  values become Secret references; raw values never enter the redacted Artifact or result model.
- [`discussion_r3895731866`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3895731866):
  encrypted writes now hold a store-root filesystem transaction lock across the existence check,
  verified idempotency decision, mission quota reservation, encryption, and immutable creation.
  Final creation uses an atomic no-replace hard link, so separate Store instances and processes
  cannot race an overwrite or independently admit writes beyond the shared quota.

This cycle adds complete and chunk-boundary generic credential regressions plus a controlled
two-instance concurrent write that proves the second write cannot reach creation while the first
transaction is pending and is rejected once the committed quota is re-evaluated.

## Regression tests added

The existing Phase 0C security test module now additionally covers:

- missing and cross-Mission ingestion write authorization;
- complete typed audit event coverage and rejection of extra secret-bearing audit fields;
- stale Secret reference resolution after an authenticated revocation tombstone;
- forbidden key reactivation and domain-parent revocation of resource keys;
- cryptographic erasure followed by restoration of old ciphertext;
- 64 encrypted chunks with bounded 512-byte writes, interruption, from-start replay, verified cursor
  resume, cursor mismatch rejection, commit/restart idempotency, and exact Receipt binding;
- secret detection and redaction where the secret spans two persisted chunks;
- Executor secure-ingestion adapter output containing only redacted Artifact references; and
- streamed quarantine key destruction after successful ingestion.
- nested quoted JSON secret redaction in complete and cross-chunk inputs;
- cursor resume from the middle of an Artifact followed by restart validation of its completion;
- crash after a durable commit envelope but before its audit append, followed by one-event
  reconciliation; and
- crash after the first streamed chunk erasure, followed by automatic deletion-intent recovery.
- camelCase JSON `apiKey` detection and reference-only redaction;
- encrypted redacted Artifact chunks bounded to 4 KiB, authenticated manifest reconstruction, and
  rejection of any full-result chunk;
- recovery of the exact durable ingestion result after quarantine deletion and after interrupted
  deletion;
- Artifact write success followed by audit failure, process restart with a later timestamp, and
  exactly-once create-audit reconciliation;
- idempotent Secret creation after restart; and
- SQLite audit process restart, continued atomic sequence allocation, trusted-head persistence, and
  deletion-tamper detection;
- Bearer authorization detection, sensitive classification, reference-only storage, and exact
  credential-value redaction before Artifact publication; and
- retry after interruption between durable secret revocation and encrypted-record deletion,
  including confirmation that the original resource key is destroyed;
- OAuth credential keys split across encrypted stream chunks, with sensitive classification,
  reference-only results, and exact redacted Artifact output; and
- Artifact expiry before retention and without write authority rejection, deletion-intent symlink
  rejection, interrupted erasure, process reconstruction, idempotent audit, and restored-ciphertext
  failure after per-resource key destruction;
- complete and cross-chunk generic credential-bearing structured keys, with raw-value exclusion
  from both redacted Artifact and result serialization; and
- two concurrent Artifact Store instances sharing one quota, including serialization before atomic
  creation, post-commit quota re-evaluation, and surviving ciphertext integrity.

No test was removed, weakened, skipped, or marked as an expected failure.

## Required validation

Exact command:

```text
PATH="$PWD/.venv/bin:$PATH" bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 186 passed
integration: 7 passed
security: 156 passed
full/coverage run: 349 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

Focused regression command:

```text
PATH="$PWD/.venv/bin:$PATH" python -m pytest -q \
  tests/security/test_gate_review_regressions.py::test_existing_v1_database_is_upgraded_through_current_schema \
  tests/security/test_phase_boundary.py::test_sql_is_confined_to_storage_and_repository_layers \
  tests/security/test_phase0c_data_security.py
```

Latest focused Phase 0C security result: `12 passed`. The two new targeted regressions pass with
`2 passed, 10 deselected`.

## Remaining constraints

- `MissionAuditLog(Database)` provides durable SQLite event/head persistence. Constructing it without
  a Database remains an explicit development/test mode. `InMemoryEncryptionKeyProvider` does not
  serialize key material; a deployment must supply a durable OS key-store or vault implementation.
- The streamed path rejects a request for long-term `encrypted_raw` retention until a trusted
  chunked long-term Artifact policy is configured. It keeps the quarantine and fails closed; it does
  not concatenate raw output in memory or fall back to plaintext. The compatibility full-object
  ingestion path retains encrypted raw content when explicitly requested.
- This phase adds no real adapter or external side-effect dispatch. The only execution provider in
  the repository remains the Phase 0B Mock adapter.
- This correction requires a new independent review bound to its resulting 40-character PR HEAD.
  The local PASS above is not an independent Phase Gate PASS for that future SHA.
