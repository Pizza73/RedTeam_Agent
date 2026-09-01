# Phase 0C Independent Review Fix Report

## Review input

- Current phase: `Phase 0C: Data Security and Audit`
- Input review SHA: `6b55fe9ba6cf0453e8c8ba33af3a3a9368944df5`
- Latest correction input SHA: `6a35a51244314f1f7eab980d6c5ced2b259443ee`
- Trusted Phase 0B base PASS SHA: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`
- Implementation branch: `ai/redteam-agent-phase-loop`
- Independent-review result: `CHANGES_REQUESTED`
- Latest finding key: `CODEX-P1-B7E66A94C49E09BF`
- External provider, C2, MCP side effect, local attack, and external-target execution: absent

## Resulting working-tree diff

The latest correction updates two implementation files, one test file, and this report. No protected
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

## Seventh independent review correction cycle

The review for exact HEAD `8a72be08dfb5c0e969e5e6d553353e1524a9792f` recorded two P1 findings
under `CODEX-P1-3A13D586A0128C5B`. The exact-SHA Human Resume covers both findings:

- [`discussion_r3896124690`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896124690):
  structured detection now parses the complete quoted field name before choosing an exact keyword
  or credential-bearing component. Complete `tokenValue` and cross-chunk `passwordHash` values are
  classified as Secrets and redacted instead of being bypassed by their shorter prefixes.
- [`discussion_r3896124700`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896124700):
  immutable encrypted creation now removes the temporary link and synchronizes the parent directory
  after linking the final path. Directory open and `fsync` failures are typed, fail closed before
  acknowledgement, and emit no successful audit event. Existing idempotent resources are also
  re-synchronized before a retry can return success.

This cycle adds complete and chunk-boundary prefix-key regressions plus a simulated directory-sync
failure that verifies the absence of successful audit evidence and safe idempotent recovery.

## Eighth independent review correction cycle

The review for exact HEAD `beafaff97f269472f0b629660885b1ecc65db10c` recorded two P1 findings
under `CODEX-P1-A09FB0D3791BC787`. The exact-SHA Human Resume covers both findings:

- [`discussion_r3896450121`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896450121):
  unquoted structured detection now reads the complete key through its separator before matching
  exact names or credential-bearing components. Complete `passwordHash=...` and cross-chunk
  `tokenValue: ...` values are classified and redacted instead of being bypassed by shorter
  `password` or `token` prefixes.
- [`discussion_r3896450136`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896450136):
  every write synchronizes the Store root after ensuring the Mission directory exists and before
  creating its encrypted resource. A first-Mission root-sync failure is typed and fails before
  ciphertext or successful audit creation; retry re-synchronizes both root and Mission directory.

This cycle extends the streaming credential regression with complete and cross-chunk unquoted keys,
keeps the existing Mission-directory durability regression, and adds a distinct first-write
Store-root durability failure path with verified recovery.

## Ninth independent review correction cycle

The review for exact HEAD `ea6b43bd56d305a2e7b38a8c06237582bad76af2` recorded one P1 finding
under `CODEX-P1-D863C9C4AECF87D3`. The exact-SHA Human Resume covers the finding:

- [`discussion_r3896563814`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896563814):
  Store initialization now discovers every missing root component, creates them from the nearest
  existing ancestor downward, and synchronizes each component's parent before proceeding. An
  existing root also has its parent synchronized before reuse, so a retry after an uncertain
  creation sync cannot acknowledge a write without first making the root entry durable.

The regression starts with a nonexistent two-level Store root, injects failure while synchronizing
the final root entry, verifies that construction fails before ciphertext or audit creation, and
then confirms that restart re-synchronizes the existing root before an authenticated first write.

## Tenth independent review correction cycle

The review for exact HEAD `11cd9ac0c10e6cde20fec7f8c3563bdf6b387e90` recorded four P1 findings
under `CODEX-P1-61DE840F99706095`. The exact-SHA Human Resume covers all four findings:

- [`discussion_r3896743741`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896743741):
  an `encrypted_raw` Artifact is now rejected before authorization or decryption when requested
  through the normal `read` operation used for LLM context. Only a distinct exact-resource
  `export` grant can release the encrypted raw value.
- [`discussion_r3896743746`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896743746):
  secret-bearing synchronous and streamed ingestion work now runs in an inner frame. The outer
  fail-closed boundary clears the original exception traceback and raises its replacement only
  after leaving the handler, so the replacement has no cause, context, or frame containing raw
  result bytes.
- [`discussion_r3896743753`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896743753):
  Secret references use a domain- and purpose-separated keyed token rather than an unkeyed
  plaintext digest. Public ingestion authorization binds only non-secret metadata, and Secret
  envelope integrity uses a separately purpose-keyed digest, removing exposed offline guess
  verifiers while retaining deterministic retry behavior.
- [`discussion_r3896743757`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896743757):
  Store initialization validates every existing lexical root component with `lstat` before and
  after directory creation. Any intermediate symbolic link or non-directory fails closed instead
  of resolving to an external location.

## Eleventh independent review correction cycle

The review for exact HEAD `6a35a51244314f1f7eab980d6c5ced2b259443ee` recorded two P1 findings
under `CODEX-P1-B7E66A94C49E09BF`. The exact-SHA Human Resume covers both findings:

- [`discussion_r3896956464`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896956464):
  structured secret detection now recognizes normalized `private_key`, `privateKey`, SSH key, and
  compound SSH private-key field names. Complete and cross-chunk values become Secret references;
  only redaction markers enter the LLM-visible Artifact.
- [`discussion_r3896956476`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3896956476):
  authorized Secret resolution and Artifact content release now decrypt and audit in isolated inner
  frames. Their public boundaries clear the original traceback and raise a typed fail-closed error
  only after leaving the handler, so an audit failure exposes no decrypted value through exception
  cause, context, or captured frame locals.

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
  creation, post-commit quota re-evaluation, and surviving ciphertext integrity;
- complete and cross-chunk credential field names that begin with exact shorter keywords; and
- parent-directory synchronization failure before acknowledgement, with no successful audit and
  verified retry recovery;
- complete and cross-chunk unquoted credential keys whose names begin with exact shorter keywords;
  and
- first-Mission Store-root synchronization failure before ciphertext/audit creation, followed by
  synchronized retry recovery; and
- nested Store-root component creation with parent-by-parent durability, injected final-entry sync
  failure, and restart recovery before the first acknowledged encrypted write;
- rejection of an `encrypted_raw` Artifact from context reads even when an exact read grant exists,
  while a distinct exact export grant remains usable;
- replacement ingestion exceptions with no cause, context, or ingestion traceback local containing
  the resumed raw bytes;
- low-entropy Secret creation without the former deterministic reference, plaintext-digest policy
  binding, or plaintext digest in the encrypted Store envelope; and
- configured Store roots with an intermediate symlink, including proof that no directory is created
  in the symlink target;
- complete `private_key` and cross-chunk `sshPrivateKey` detection, Secret-reference creation, and
  exact Artifact redaction; and
- audit failures after Secret resolve and encrypted-raw export, with no decrypted value in exception
  cause, context, or Store traceback locals.

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
security: 165 passed
full/coverage run: 358 passed
skipped=0, errors=0, failures=0
coverage: 83% total (branch coverage enabled)
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

Latest focused Phase 0C security result: `21 passed`. The complete/private-key, cross-chunk SSH-key,
and release-audit regressions pass with `3 passed, 18 deselected`.

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

## Twelfth independent review and post-refresh correction cycle

Current phase: `phase-0c`.

Input review SHA: `e3ca45ca314c3a469b31137dd4b6e567c58f00e2`.

Authorized post-refresh input HEAD: `a91790d30d34cc7a8205cd397dd1b5dba2b48574`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- `CODEX-P1-B9469F2665822E4D`: escaped JSON field names are now decoded with strict
  JSON-style Unicode and surrogate validation before credential matching. Complete and cross-chunk
  `api\u005fkey` / `client\u005fsecret` fields are detected, their values are isolated in the Secret
  Store, and only redacted values become Artifact or result content.
- The same gate's second retained P1: stdout, stderr, and Artifact quarantine writes now replace
  storage, encryption, audit, and other internal failures with a typed `RawResultStreamingError`
  only after the secret-bearing write frame has unwound and the raw `chunk` local has been deleted.
  The original failure traceback is cleared and no plaintext fallback is introduced.

Review findings:

- https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3897157815
- https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3897157819

### Modified files and regression tests

Resulting working-tree diff: `4 files changed, 331 insertions(+), 15 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

The Phase 0C security suite now proves complete and cross-chunk escaped credential-key redaction,
reference-only result serialization, and absence of raw provider chunks from sanitized streaming
traceback frames for storage, encryption, and audit failures across stdout, stderr, and Artifact
writes. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py -k 'oauth_fields or raw_chunk_failures'
```

Result: `4 passed, 20 deselected`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 168 passed
full/coverage run: 375 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Post-governance invariant-family correction cycle

Current phase: `phase-0c`.

Input review SHA: `66c00e7a0a58e6b453cabac833fbb4d816a85bf9`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

Trusted implementation request:
`https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5497701145`.

Invariant audit digest:
`23e05903173ed16d49706b30e2d55c1c4493eb3ad6dcdaf865e48f90255b8ebc`.

### Findings addressed

- [`discussion_r3901438381`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901438381):
  Artifact, Secret, and Quarantine retention enforcement now uses store-owned trusted clocks; a
  caller-provided timestamp cannot extend a resource lifetime or trigger premature erasure.
- [`discussion_r3901438388`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901438388):
  Secret resolution now requires the operation-specific active just-in-time execution lifecycle
  and rejects terminal or reconciliation states.
- [`discussion_r3901438395`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901438395):
  direct Quarantine plaintext resume is denied. Full-object plaintext release is restricted to the
  exact instance-bound trusted ingestion publication.
- [`discussion_r3901438405`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901438405):
  full-object ingestion now carries durable receipt/lease evidence and content-bound publication
  authority through Artifact and detected-Secret writes under the production authorizer.
- [`discussion_r3906579129`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3906579129)
  (`authorization-lifecycle`): `EncryptedRawResultSinkFactory` accepts only the exact
  repository-backed resolver, which reloads Execution, latest Mission revision, current Mission
  lifecycle/authorization epoch, and durable recovery cursor before constructing a binding.
- [`discussion_r3906579132`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3906579132)
  (`secret-plaintext-boundary`): Quarantine decryption and resume auditing run in an isolated helper
  frame; failures clear the original traceback and cross the caller boundary only as a typed,
  plaintext-free error.
- [`discussion_r3906579136`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3906579136)
  (`audit-recovery-durability`): explicit Quarantine deletion persists a strictly typed,
  authenticated intent before its deterministic audit event. Startup reconciliation completes
  cryptographic erasure and removes the intent after a crash between audit and key destruction.

### Modified files and regression tests

Resulting working-tree diff: `8 files changed, 1592 insertions(+), 159 deletions(-)`.

- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/authorization.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-invariant-audit.json`
- `docs/review/phase-0c-fix-report.md`

New and extended regressions cover production repository binding reconstruction, caller-selected
cross-Mission resolver rejection, stale Mission revision rejection, backdated/future retention
timestamps, terminal Secret resolution denial, direct Quarantine resume denial, production
full-object ingestion, plaintext-free Quarantine audit-failure tracebacks, and restart recovery
after an interruption between the Quarantine delete audit and cryptographic erasure. No test was
deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused Phase 0C data-security suite:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py --strict-markers
```

Result: `85 passed`.

Required phase-gate command:

```text
PATH=/home/kali/Red_Agent/.venv/bin:$PATH \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
INVARIANT_AUDIT=PASS:23e05903173ed16d49706b30e2d55c1c4493eb3ad6dcdaf865e48f90255b8ebc
ruff: All checks passed
mypy: Success: no issues found in 79 source files
unit: 208 passed
integration: 7 passed
security: 231 passed
full/coverage run: 446 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- Runtime publication objects and exact-type resolver checks protect the in-process application
  boundary; mutually hostile Python code still requires the later process/OS sandbox boundary.
- Quarantine, Artifact, and Secret cleanup remains operation-driven plus startup recovery; this
  phase does not add a background scheduler.
- Durable cryptographic destruction depends on the configured Key Provider. The wrapped-file
  provider supplies externally anchored generation semantics; production deployment must supply an
  equivalently protected provider.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Thirteenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `aea1a99f55a93a9445e27f56a4a26ad036b312c3`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3898809636`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3898809636):
  raw-result Store and stream-chunk integrity values now use the quarantine key domain's
  purpose-separated keyed digest. Low-entropy plaintext hashes are absent from encrypted envelopes,
  public references, and audit metadata, and resumed chunk reads verify with the persisted resource
  key metadata.
- [`discussion_r3898809644`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3898809644):
  the bounded streaming secret detector now recognizes both Basic and Bearer authorization schemes.
  It preserves the visible scheme and redacts only the credential value for complete and
  cross-chunk inputs.
- [`discussion_r3898809649`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3898809649):
  encrypted resource creation now opens the validated Mission directory once with no-follow flags.
  Temporary creation, immutable hard-link publication, cleanup, and directory synchronization all
  use that directory descriptor, preventing a concurrent symlink replacement from redirecting the
  ciphertext outside the configured Store root.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 373 insertions(+), 28 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Three regression tests cover complete and split-chunk Basic authorization, concurrent Mission
directory replacement with an external symlink, and low-entropy verifier resistance for both
full-object quarantine and resumed encrypted streams. No test was deleted, skipped, weakened, or
marked as an expected failure.

### Validation

Focused regression command:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'basic_authorization or anchored_during_mission_directory_swap or quarantine_verifiers'
```

Result: `3 passed, 24 deselected`.

Complete Phase 0C security module: `27 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 171 passed
full/coverage run: 378 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Fourteenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `705ee3bf130891f5e6aecf56fded7f0ac79fa842`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899065362`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899065362):
  secret detection now parses the `Authorization` header before interpreting its scheme. Basic and
  Bearer remain value-redacted, every other well-formed scheme is handled as credential-bearing,
  and malformed headers fail closed. Complete, quoted, and cross-chunk forms cannot publish an
  unchanged credential.
- [`discussion_r3899065367`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899065367):
  non-stream quarantine resume and from-start stream replay recompute keyed verifiers using each
  persisted envelope's resource-key metadata. Data written under a decrypt-only parent version
  remains verifiable after the quarantine domain rotates to a new active version.
- [`discussion_r3899065375`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899065375):
  atomic encrypted writes anchor both Store-root and Mission-directory descriptors and verify the
  Mission entry's device/inode identity immediately before acknowledgement. A concurrent rename or
  symlink substitution removes the detached publication and fails without an audit; a restored path
  can then be written and resumed normally.
- [`discussion_r3899065377`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899065377):
  stream abort now persists a bound abort-deletion intent, audits deletion idempotently, destroys
  every quarantined chunk, Artifact-completion, and abort-terminal resource key, and resumes
  interrupted erasure on restart before returning the durable `ABORTED` state.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 757 insertions(+), 27 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Focused regression coverage proves complete and split-chunk unsupported authorization redaction,
non-stream and streaming verification across quarantine-key rotation, detached-directory rollback
plus successful retry/resume, and interrupted abort erasure plus restart reconciliation. No test was
deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'unsupported_authorization or anchored_during_mission_directory_swap or \
  verifiers_remain_bound or aborted_stream_erasure'
```

Result: `4 passed, 26 deselected`.

Complete Phase 0C security module: `30 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 174 passed
full/coverage run: 381 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Fifteenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `32874b5b1140418629f3c57394eeff0533c554fc`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899224225`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899224225):
  a persistent key-provider adapter now encrypts and authenticates its complete parent-key,
  resource-key, rotation-state, fingerprint, and nonce registry under a root key supplied by an OS
  key store or external vault. The state file and lock are permission checked, no-follow opened,
  directory-identity anchored, size bounded, and atomically replaced. A newly constructed provider
  can resume committed encrypted stream chunks without plaintext key persistence.
- [`discussion_r3899224235`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899224235):
  durable Mission audit events now use a purpose-separated keyed digest whose signing key remains
  outside mutable SQLite. Durable construction without an external authenticator fails closed, and
  a complete database history rewritten with recomputed unkeyed hashes is rejected after restart.
- [`discussion_r3899224244`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899224244):
  the bounded streaming detector now recognizes standalone PKCS#8, RSA, EC, and OpenSSH private-key
  blocks. Complete and arbitrarily split inputs are buffered, stored only as Secret references, and
  replaced as one redaction before Artifact publication; incomplete final blocks fail closed.
- [`discussion_r3899224250`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899224250):
  encrypted erasure now opens Store root, Mission directory, and resource with no-follow
  descriptors, authenticates the descriptor-read envelope, revalidates the root/Mission identity
  immediately before key destruction, and unlinks relative to the validated Mission descriptor.
  A concurrent Mission rename/symlink replacement cannot erase a matching external resource.
- [`discussion_r3899224258`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899224258):
  committed but uningested and abandoned streams now persist a bound expiry-deletion intent at
  retention expiry. Restart reconciliation idempotently audits deletion and destroys chunk,
  Artifact-terminal, and stream-terminal keys, including after an interrupted partial erasure.

### Modified files and regression tests

Resulting working-tree diff: `8 files changed, 1592 insertions(+), 55 deletions(-)`.

- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/audit.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Five regression tests cover provider reconstruction and wrong-root-key rejection, full SQLite
chain recomputation without the external audit key, complete and split standalone private keys,
concurrent erasure-directory replacement, and restartable expiry deletion for both committed and
abandoned streams. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=src /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'wrapped_key_provider or sqlite_audit_chain or keyed_sqlite_audit or \
  standalone_private_key or erasure_is_anchored or expired_committed'
```

Result: `6 passed, 29 deselected`.

Complete Phase 0C security module: `35 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 179 passed
full/coverage run: 386 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Sixteenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `ac6d2aae8c730ad5afb27d2ffba37947026c85c7`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899412059`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899412059):
  every persistent key mutation now acquires the cross-process lock, reloads and validates the
  latest wrapped state, applies the mutation, and advances its generation. Read/decrypt paths also
  refresh the state, so two provider instances preserve each other's resource keys, nonce history,
  rotations, and destructions rather than overwriting or using a stale snapshot.
- [`discussion_r3899412070`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899412070):
  each audit event now persists its signing-key ID and version inside the authenticated event
  payload. Verification resolves that exact retained/decrypt-only signing version, allowing an
  intact pre-rotation chain to verify and accept new v2-signed events after provider reconstruction.
- [`discussion_r3899412080`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899412080):
  wrapped-key state v2 binds its encrypted inner state and authenticated outer envelope to a
  monotonically increasing generation held by an external OS-keystore/vault adapter. Missing,
  replayed, rolled-back, or mismatched generations fail closed; external advancement uses an atomic
  compare-and-set boundary.
- [`discussion_r3899412089`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899412089):
  Artifact streaming now creates an authenticated cleanup intent before the first fixed-size chunk.
  Failure cleanup erases deterministic chunk targets immediately when possible, and ArtifactStore
  reconstruction sweeps remaining intents and cryptographically erases partial chunks after an
  interrupted cleanup. Completed manifests preserve their referenced chunks.
- [`discussion_r3899412098`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899412098):
  commit and abort terminal persistence now sanitize storage, encryption, quota, filesystem, and
  audit failures into `RawResultQuarantineError` outside the failing frame. Executor collection
  routes that type through durable raw-result recovery, pauses the Mission, and blocks later
  dispatch; terminal storage, key, and audit failures remain retryable without another submission.

### Modified files and regression tests

Resulting working-tree diff: `9 files changed, 1081 insertions(+), 124 deletions(-)`.

- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/audit.py`
- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/models.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0b_execution_safety.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage reconstructs two stale provider instances and interleaves writes/destruction,
replays a pre-destruction wrapped state, rotates and reconstructs the audit signer, interrupts
partial-Artifact cleanup before restart, injects terminal Store and encryption-key failures, and
verifies Executor recovery plus Mission pause on terminal failure. No test was deleted, skipped,
weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=src:. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py \
  tests/security/test_phase0b_execution_safety.py \
  -k 'wrapped_key_provider or sqlite_audit_chain_persists or \
  partial_artifact_stream or terminal_storage_and_key or terminal_persistence_failure'
```

Result: `5 passed, 68 deselected`.

Combined Phase 0B execution-safety and Phase 0C data-security modules: `73 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 182 passed
full/coverage run: 389 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Seventeenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `20b8ab5c8339bafadc3daf1030794417e4e4050b`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899574060`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899574060):
  quoted structured keys are now fully buffered and JSON-decoded before Authorization dispatch.
  Complete and arbitrarily split Unicode escapes such as `authoriz\\u0061tion` therefore reach the
  scheme-aware parser, and Bearer, Basic, and unknown schemes are redacted before any Artifact is
  LLM-visible.
- [`discussion_r3899574062`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899574062):
  standalone PEM detection now derives the matching END delimiter for every label containing
  `PRIVATE KEY` rather than relying on four allowlisted labels. Encrypted, DSA, PKCS#8, RSA, EC,
  OpenSSH, and future explicit private-key labels are buffered across chunks and fail closed when
  incomplete.
- [`discussion_r3899574067`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899574067):
  wrapped key state now alternates authenticated generations across two durable slots. A candidate
  generation is fsynced without replacing the externally anchored prior slot, then the OS-keystore
  or vault generation is advanced by compare-and-set. Restart selects only the anchored slot, so an
  interruption before anchor advancement recovers generation N and an interruption after
  advancement recovers generation N+1 while rollback remains rejected.
- [`discussion_r3899574071`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899574071):
  Artifact streams with identical authorization metadata are serialized by a no-follow,
  identity-anchored OS file lock. Chunk IDs, chunk bindings, manifests, and cleanup decisions are
  also bound to a unique authenticated attempt ID, so a losing attempt can erase only its own keys
  and chunks. Same-content retries safely converge on the existing manifest.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 707 insertions(+), 106 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage includes complete and split escaped Authorization keys, complete encrypted and
split DSA private-key PEM blocks, wrapped-state recovery on both sides of the external-generation
commit boundary, and two conflicting concurrent Artifact streams followed by an idempotent retry.
No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=src:. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'unsupported_authorization or additional_private_key or \
  wrapped_key_state_recovers_both or conflicting_artifact_stream or \
  partial_artifact_stream'
```

Result: `6 passed, 35 deselected`.

Combined Phase 0B execution-safety and Phase 0C data-security modules: `77 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 186 passed
full/coverage run: 393 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Eighteenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `cc50997d7895f8a9609a38448b9e13dabf3a5e5d`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899678577`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899678577):
  committed-ingestion deletion recovery now decrypts and revalidates the durable receipt against
  the terminal, deletion intent, and ingestion-result binding before removing remaining chunks. A
  reconstructed deleted sink retains committed receipt, byte, and chunk metadata; idempotent
  `commit()` returns that receipt without making the sink writable. Executor crash recovery can
  therefore collect stable adapter metadata and consume the durable secure-ingestion result without
  retransmitting raw chunks or resubmitting the action.
- [`discussion_r3899678582`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899678582):
  non-stream quarantine objects now use an authenticated expiry-deletion intent and constructor
  sweep. The target reference, retention, digest, encryption metadata, and deterministic audit
  operation are revalidated before cryptographic erasure; target-first and intent-last cleanup is
  restartable after interruption, and expired `resume()` purges rather than merely denying access.
- [`discussion_r3899678585`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899678585):
  unquoted credential keys now accept one or more whitespace bytes as a value delimiter in addition
  to `:` and `=`. Complete and split netrc-style `password value` records are stored only as Secret
  references and redacted before the Artifact becomes LLM-visible.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 600 insertions(+), 12 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage simulates an Executor crash after durable secure ingestion and quarantine
deletion but before `ExecutionResult` persistence, interrupts non-stream expiry after target-key
destruction and completes it on restart, and verifies complete plus split whitespace-delimited
credentials. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=src:. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'oauth_fields or executor_resumes_deleted or expired_non_stream'
```

Result: `3 passed, 40 deselected`.

Combined Phase 0B execution-safety and Phase 0C data-security modules: `79 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 188 passed
full/coverage run: 395 passed
skipped=0, errors=0, failures=0
coverage: 82% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Nineteenth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `61a6e5f875335e462f3e1e816b7d36b1ccad7714`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899788926`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899788926):
  durable audit logs now require an independently protected `AuditHeadStore`. The concrete keyed
  file adapter authenticates all mission heads with the audit-signing domain and binds alternating
  state slots to an external compare-and-set generation anchor. A valid keyed database suffix can
  repair an interrupted post-commit head update, while deletion of the final event plus rollback of
  SQLite's own head is rejected against the independently monotonic head.
- [`discussion_r3899788935`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899788935):
  artifact identity version 2 includes media type and source execution provenance in addition to
  mission, content digest, classification, variant, and derivation. Identical empty or non-empty
  output from separate executions therefore creates separately bound artifacts without weakening
  integrity or access checks.
- [`discussion_r3899788941`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899788941):
  the bounded streaming detector now recognizes complete and arbitrarily split XML credential
  elements, including qualified tag names, redacts their content before Artifact persistence, and
  fails closed on credential elements with unsupported attributes or unterminated content.
- [`discussion_r3899788948`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899788948):
  all encrypted-envelope content reads now open the verified root, mission directory, and resource
  relative to no-follow descriptors, enforce a serialized-size bound, and revalidate directory
  identity after the read. Both caller-bound and stored-binding reads reject a concurrent mission
  directory rename and symlink replacement without following the replacement.
- [`discussion_r3899788951`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899788951):
  encrypted sink construction converts storage, integrity, audit, and key failures to the typed
  quarantine boundary. Executor collection now persists deterministic `RECOVERY_REQUIRED` metadata,
  pauses through Mission Manager, and releases the unstarted collection claim even when no sink
  instance was returned; no provider result collection or action resubmission occurs.

### Modified files and regression tests

Resulting working-tree diff: `10 files changed, 1224 insertions(+), 54 deletions(-)`.

- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/audit.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `src/redteam_agent/executor/raw_results.py`
- `src/redteam_agent/executor/service.py`
- `tests/security/test_phase0b_execution_safety.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage truncates a keyed SQLite audit suffix while rolling back its database head,
persists identical empty streamed artifacts from two executions, redacts complete and split XML
credentials, swaps a mission directory during both `read()` and `read_bound()`, and forces sink
construction to fail after provider dispatch. No test was deleted, skipped, weakened, or marked as
an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=src:. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0b_execution_safety.py \
  tests/security/test_phase0c_data_security.py \
  -k 'sink_construction_failure or oauth_fields or cross_execution_provenance \
      or concurrent_mission_directory_swap \
      or sqlite_audit_chain or keyed_sqlite_audit'
```

Result: `7 passed, 76 deselected`.

Combined Phase 0B execution-safety and Phase 0C data-security modules: `83 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 192 passed
full/coverage run: 399 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- The external audit-head generation adapter remains an integration boundary supplied by an OS
  keystore, vault, or equivalently protected monotonic service; the application does not emulate
  that authority in mutable SQLite.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twentieth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `e8277a167d18cc6057473aa432a68820dfb0047c`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3899934799`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899934799):
  each durable append now persists the complete signed next event as an authenticated prepared
  append in the independently generation-anchored audit-head store before changing SQLite. After
  the database transaction commits, the prepared append advances the external committed head.
  Restart recovery can finish either interruption boundary and reinsert the authenticated prepared
  suffix if an attacker deleted the committed database row and rolled SQLite's head back.
- [`discussion_r3899934808`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899934808):
  the audit-head store now opens and identity-checks its state directory with no-follow semantics,
  retains that descriptor while locking, reading, creating the temporary state, replacing the
  alternating state slot, and syncing, and only uses descriptor-relative names for those writes.
  A concurrent parent rename and symlink replacement is detected without writing to the replacement
  directory or advancing the external generation.
- [`discussion_r3899934817`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3899934817):
  encrypted-store writes now retain one verified root and mission-directory descriptor across the
  existing-resource check, envelope verification, quota enumeration, and atomic resource creation.
  A transient mission-directory replacement during quota calculation therefore cannot substitute an
  empty directory and then restore the original path to bypass the mission quota.

### Modified files and regression tests

Resulting working-tree diff: `4 files changed, 1235 insertions(+), 349 deletions(-)`.

- `src/redteam_agent/data_security/audit.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage interrupts a durable audit append before the database insert and after the
database commit, truncates the latter suffix and rolls back SQLite's head before restart, swaps the
audit-head parent immediately before replacement, and swaps an encrypted-store mission directory to
an empty replacement during quota enumeration before restoring it. No test was deleted, skipped,
weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'quota_is_serialized or quota_scan_stays or recovers_prepared_appends \
      or audit_head_write_stays'
```

Result: `4 passed, 45 deselected`.

Phase 0C data-security module: `49 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 195 passed
full/coverage run: 402 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- The external audit-head generation adapter remains an integration boundary supplied by an OS
  keystore, vault, or equivalently protected monotonic service; the application does not emulate
  that authority in mutable SQLite.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-first independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `3d985b9408e7a1ff893344cccefb11861e06bdd3`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900089264`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900089264):
  encrypted-store existence checks now open the verified store root and mission directory with
  no-follow semantics, retain both descriptors while checking the resource entry, and revalidate the
  mission identity afterward. A transient empty-directory replacement during expired-quarantine
  discovery therefore cannot suppress creation and completion of the cryptographic-erasure intent.
- [`discussion_r3900089267`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900089267):
  wrapped-key providers now open the key-state parent once, validate and retain that descriptor while
  opening the shared lock, loading the current generation, writing the alternating state slot, and
  advancing the external generation. Two provider instances remain serialized when the parent path
  is briefly replaced, so the winning generation cannot name another provider's conflicting state.
- [`discussion_r3900089274`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900089274):
  completed stream cleanup recovery now decrypts and strictly validates the durable manifest,
  reconstructs its bound Artifact reference, and reconciles the deterministic `artifact.create`
  event before erasing the cleanup intent. A process crash after manifest persistence but before the
  original create-audit call therefore cannot leave a readable artifact permanently unaudited.

### Modified files and regression tests

Resulting working-tree diff: `4 files changed, 679 insertions(+), 154 deletions(-)`.

- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage swaps an expired quarantine's mission directory only during its target-existence
probe, runs two wrapped-key providers concurrently while swapping the key-state parent only during
lock open, and simulates a process-level interruption after a stream manifest is durable but before
its creation audit. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'providers_share_lock or quarantine_existence_check \
      or completed_stream_cleanup'
```

Result: `3 passed, 49 deselected`.

Phase 0C data-security module: `52 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 198 passed
full/coverage run: 405 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service; the application does not
  emulate either authority in mutable SQLite or ordinary state files.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-second independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `6c21d2986ebe1b1c4bce9f5d69c603320018b67a`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900200945`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900200945):
  each encrypted Store opens and validates its root with no-follow semantics, retains that root
  descriptor while opening and holding the quota transaction lock, and verifies root reachability
  around the transaction. Two Store instances therefore cannot acquire different lock inodes during
  a transient root rename and then overcommit one restored mission directory.
- [`discussion_r3900200950`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900200950):
  mission accounting now charges at least one quota unit for every durable encrypted record as an
  explicit record-count cap in addition to plaintext-size accounting. Repeated empty Artifacts,
  terminals, or intents can no longer grow encrypted envelopes and resource-key state without
  consuming the configured mission quota.
- [`discussion_r3900200956`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900200956):
  Artifact Store startup now resumes authenticated deletion intents and discovers expired durable
  Artifacts using a trusted clock. It reconstructs each authoritative reference, reconciles its
  creation and deterministic deletion audits, and cryptographically erases all manifest/chunk or
  non-stream target keys without requiring a caller to retain and submit the reference.
- [`discussion_r3900200963`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900200963):
  Store mission and resource discovery now enumerates verified root and mission descriptors, checks
  every entry without following links, and revalidates path identity after enumeration. Constructor
  recovery sees quarantine expiry work and Artifact stream cleanup work even when the mission path is
  temporarily replaced with an empty directory during the scan.
- [`discussion_r3900200967`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900200967):
  after the external key-state generation advances, the provider now reopens the configured parent,
  validates the original identity, decrypts and authenticates the generation-named slot through that
  fresh descriptor, and verifies path reachability again before acknowledging the operation. A swap
  between the pre-CAS check and generation commit is reported as an uncertain failure; restoring the
  expected directory lets restart reconcile the externally committed generation.

### Modified files and regression tests

Resulting working-tree diff: `4 files changed, 835 insertions(+), 57 deletions(-)`.

- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage runs two quota writers through a transient Store-root swap, fills a mission with
zero-byte Artifacts, restarts after an Artifact expires without invoking `expire()`, swaps a mission
directory during quarantine and stream-cleanup discovery, and moves the key-state parent only during
external generation commit. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'post_commit_state_reachability or quota_lock_stays \
      or empty_artifacts_consume or expiry_sweeps_without \
      or restart_enumeration or partial_artifact_stream_cleanup'
```

Result: `6 passed, 51 deselected`.

Phase 0C data-security module: `57 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 203 passed
full/coverage run: 410 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service; the application treats an
  advanced but temporarily unreachable generation as an uncertain failure and never acknowledges
  dependent ciphertext as durable.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-third independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `087ecfc5df7efe4a7f796768cbaea65100432e77`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900292223`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900292223):
  credential-valued YAML literal and folded block-scalar indicators now fail closed before their
  arbitrarily chunked, indentation-sensitive body can reach redacted Artifact publication. Complete
  and split-stream regressions verify that neither an Artifact nor a Secret record is published and
  that the sanitized failure does not expose the scalar body.
- [`discussion_r3900292227`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900292227):
  mission quota now sums the verified canonical encrypted envelope's actual durable file size rather
  than plaintext length. A separate one-record-per-KiB ceiling bounds resource-key state growth even
  for empty records. Existing quota tests use capacities sized for encrypted envelopes, and a new
  on-disk regression proves that a zero-byte plaintext still consumes its complete envelope quota.
- [`discussion_r3900292236`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900292236):
  a strictly parsed and deterministically bound Artifact deletion intent has a cleanup-only durable
  write path that cannot be blocked by caller-data quota. Restart at an exact full mission quota now
  records the intent, performs audited cryptographic erasure, and removes the cleanup record.
- [`discussion_r3900292244`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900292244):
  completed Artifact expiry erases the deletion-intent envelope and its live resource key after all
  targets are durably absent. Repeated calls verify exact completion in the trusted audit chain,
  while a later same-ID Artifact receives a deterministic successor resource-key identity and
  incarnation-bound create/delete audit operation IDs. A stale reference cannot erase that new
  incarnation, and repeated lifecycles leave no deletion-intent tombstone.

### Modified files and regression tests

Resulting working-tree diff: `6 files changed, 710 insertions(+), 63 deletions(-)`.

- `src/redteam_agent/data_security/audit.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage rejects complete and split YAML block scalars before publication, accounts for
encrypted envelope bytes on disk, reconstructs an expired Artifact when its existing envelope
exactly fills the configured quota, and runs two same-ID Artifact lifecycles through repeated expiry,
intent removal, successor-key creation, restart, stale-reference rejection, and final erasure. Quota
fixtures unrelated to quota enforcement were increased only to preserve their prior logical workload
under physical-envelope accounting. No test was deleted, skipped, weakened, or marked as an expected
failure.

### Validation

Focused regression command:

```text
PYTHONPATH=src /home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'yaml_block_scalar or durable_envelope_bytes \
      or full_quota_artifact_expiry or completed_expiry_removes_intent'
```

Result: `4 passed, 57 deselected`.

Phase 0C data-security module: `61 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 207 passed
full/coverage run: 414 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- YAML block scalars on credential-classified keys are deliberately rejected rather than partially
  parsed; this is the fail-closed branch allowed by the finding until a complete indentation-aware
  streaming YAML grammar is introduced.
- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-fourth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `a4b391a7475d47709010c8d300c86d9962c0d227`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900470887`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900470887):
  the wrapped key-state provider now rejects an oversized serialized state before writing either
  alternating state file and before advancing the external generation CAS. The threshold-crossing
  regression fixes the limit at the current committed file size, proves the next resource-key write
  is rejected without changing the generation or committed bytes, and reconstructs the provider
  from that still-readable generation.
- [`discussion_r3900470897`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900470897):
  non-stream expiry and all streaming delete/abort/expiry intents now use a cleanup-only writer that
  accepts only strict typed bindings with their exact deterministic resource ID. Caller data cannot
  use this path, while an exact-full quota can no longer prevent cryptographic erasure. Both
  non-stream and streaming full-quota lifecycles are exercised through restart.
- [`discussion_r3900470908`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900470908):
  the secure-ingestion contract now has an Executor-only acknowledgment after the immutable
  `ExecutionResult` is persisted. A result-bound, quota-independent temporary ACK makes reclamation
  of chunks, artifact terminals, the commit terminal, ingestion result, deletion intent, and ACK
  itself idempotent across crashes. Existing persisted results are resumed before provider
  recollection, and exact trusted delete-audit evidence makes repeated acknowledgment safe after all
  temporary records are gone.
- [`discussion_r3900470912`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900470912):
  the streaming secret grammar recognizes supported credential-bearing URI authorities and replaces
  only the password portion of `scheme://user:password@host`. Complete PostgreSQL and arbitrarily
  split Redis regressions verify `uri_password` secret references and prove the password never
  reaches the readable redacted Artifact.

### Modified files and regression tests

Resulting working-tree diff: `8 files changed, 952 insertions(+), 66 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/data_security/streaming.py`
- `src/redteam_agent/executor/ingestion.py`
- `src/redteam_agent/executor/service.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises the wrapped-state threshold before CAS, complete and split connection
URI credentials, exact-full non-stream and streaming quarantine expiry, and an Executor result that
is persisted immediately before cleanup is interrupted. Restart consumes the temporary ACK, removes
all quarantine metadata, and a repeated successful resume neither recollects provider output nor
recreates metadata. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'wrapped_key_state_limit_is_enforced or connection_uri_credentials \
      or full_quota_quarantine_cleanup or executor_resumes_deleted_ingestion'
```

Result: `4 passed, 60 deselected`.

Phase 0C data-security module: `64 passed`.

Executor integration and safety regression command:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/integration/test_phase0b_flow.py \
  tests/security/test_phase0b_execution_safety.py
```

Result: `40 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 210 passed
full/coverage run: 417 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- URI user-info detection is deliberately limited to the explicit supported connection and network
  schemes; an unrecognized scheme is not treated as authorization evidence.
- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-fifth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `982c4a37d088532665443984141074ebcec46c16`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900605989`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900605989):
  credential-bearing URI detection now parses the generic RFC scheme grammar instead of consulting
  an allowlist. It recognizes complete `ssh://` and arbitrarily split `sftp://` authority user-info,
  redacts only the password, and fails closed for ambiguous multiple-authority separators, missing
  principals, or empty passwords.
- [`discussion_r3900605993`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900605993):
  successful expiry and abort recovery now erase their quota-independent stream deletion intent and
  its resource key after every target and deterministic delete audit is durable. On later restart,
  the verified audit chain supplies the exact completion evidence, so the sink remains terminal
  without recreating a tombstone. Existing interrupted expiry and abort regressions now repeat the
  reconstruction and assert no deletion-intent envelope remains.
- [`discussion_r3900605996`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900605996):
  an audit-head generation CAS is now followed by a no-follow reopen and authenticated reload through
  the configured path, with parent identity and external generation rechecked before acknowledgment.
  A parent-swap regression advances the anchor only after moving the prepared state, observes the
  typed reachability failure, restores the detached validated directory, and proves restart recovers
  the exact prepared event.
- [`discussion_r3900605998`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900605998):
  deterministic audit operations are looked up and fully verified before resolving a new mission
  context or appending. A PAUSE/Resume-style authorization-epoch change therefore returns the
  original event rather than creating a second operation ID; mismatched or duplicate bindings still
  fail closed. The regression proves one epoch-zero event remains after an epoch-one retry.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 429 insertions(+), 44 deletions(-)`.

- `src/redteam_agent/data_security/audit.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/streaming.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises complete and split URI schemes absent from the former allowlist,
interrupted and repeated stream expiry/abort cleanup with no retained intent, audit-head parent
replacement in the post-write/pre-CAS window, detached-directory recovery across restart, and a
deterministic audit retry after authorization-epoch advancement. No test was deleted, skipped,
weakened, or marked as an expected failure.

### Validation

Focused regression command:

```text
/home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'connection_uri_credentials or aborted_stream_erasure \
      or expired_committed_and_abandoned or audit_head_generation_requires \
      or deterministic_audit_operation'
```

Result: `5 passed, 61 deselected`.

Phase 0C data-security module: `66 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 212 passed
full/coverage run: 419 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- URI authority candidates with malformed credential user-info are deliberately rejected rather than
  partially published.
- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service. A detected post-CAS path swap
  requires restoring or reconciling the validated state directory before normal operation resumes.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-sixth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `22f0b2f0e3c62a206ac58e0fcc832a814c5c2dde`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900679640`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900679640):
  encrypted resource creation now fsyncs a strictly typed, keyed-digest-authenticated preparation
  before the resource key is sealed. The durable envelope is the commit record. Recovery removes
  abandoned atomic-write files, fully verifies a linked envelope before retaining its key, and
  destroys every deterministic resource-key generation when no envelope committed. Wrapped key
  state therefore cannot accumulate unreachable keys after a crash inside key sealing or before
  envelope linkage. Ordinary `_atomic_write_anchored()` failures reconcile immediately; process
  interruption remains restart-recoverable. Regressions interrupt both before and after the link,
  restart the wrapped provider and store, and prove rollback creates a new key while commit recovery
  preserves the linked key.
- [`discussion_r3900679652`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900679652):
  URI-scheme and unquoted structured-key lookahead are bounded at 256 bytes. A long ordinary token
  can no longer consume the 64 KiB pending-secret budget merely because it starts with alphabetic
  scheme characters, while the generic short-scheme URI grammar and fail-closed credential checks
  remain intact. Complete and arbitrarily split 70 KiB provider chunks traverse the encrypted
  streaming ingestion path unchanged and produce no false secret detection.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 872 insertions(+), 14 deletions(-)`.

- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/keys.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises wrapped-key recovery on process interruption before and after the
envelope link, immediate retry after directory-sync failure, repeated failed writes without wrapped
record growth, keyed intent validation and durable prepare/commit sync boundaries, and
complete/split long ordinary provider output. Existing complete and split credential-bearing URI
tests continue to prove password-only redaction. No test was deleted, skipped, weakened, or marked
as an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=/tmp/redteam-phase0c-a91790d3 \
  /home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'resource_creation_reconciles_wrapped_keys or atomic_envelope_failures \
      or long_ordinary_tokens or connection_uri_credentials'
```

Result: `5 passed, 65 deselected`.

Phase 0C data-security module: `70 passed`.

Required phase-gate command:

```text
PATH="/home/kali/Red_Agent/.venv/bin:$PATH" \
  bash scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 78 source files
unit: 200 passed
integration: 7 passed
security: 216 passed
full/coverage run: 423 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- Resource-creation intent recovery assumes the configured key provider retains deterministic
  resource-key generations and performs cryptographic destruction durably; the wrapped-file
  provider does so through its externally anchored generation protocol.
- URI and structured-key lookahead deliberately cap candidate names at 256 bytes. Longer prefixes
  are treated as ordinary data rather than credential syntax; credential values remain subject to
  the fail-closed pending-match bound.
- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-seventh independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `343f6edf54b065faabab702cbf485ff93cdf81b5`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900814207`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900814207):
  resource-creation intent publication now writes a uniquely named same-directory temporary file to
  completion, synchronizes it, atomically hard-links the complete authenticated record at its final
  name, removes the temporary link, and synchronizes the Mission directory before sealing a resource
  key. Recovery removes only strictly named pending files and validates link count, intent digest,
  key domain, Mission, and resource bindings. Partial-write and pre-fsync process-interruption
  regressions prove that no truncated final intent, envelope, or unreachable resource key survives.
- [`discussion_r3900814212`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900814212):
  every public Artifact, Secret, and non-stream Quarantine creation marks its authenticated creation
  intent as audit-required. The intent remains after the encrypted envelope commits and is removed
  only after the deterministic create/commit audit append succeeds. Store reconstruction verifies
  the complete envelope and reconciles the pending audit before exposing normal wrapper operation;
  regressions interrupt each store between envelope commit and audit append and prove exactly one
  event is recovered before the intent is acknowledged.
- [`discussion_r3900814217`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900814217):
  Secret Store startup now enumerates expired Secret envelopes and authenticated expiry intents.
  Expiry persists a quota-independent reference-only intent, appends one deterministic delete audit,
  cryptographically erases the target resource key, and finally erases the intent key. Resolution
  also invokes this path before authorization when expiry has elapsed. A restart regression
  interrupts target erasure, then proves both keys are destroyed and the delete audit remains
  exactly-once across repeated reconstruction.
- [`discussion_r3900814222`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900814222):
  `RepositoryDataAccessAuthorizer` now constructs its current-state resolver exclusively from the
  supplied trusted Database. It reloads and verifies immutable PolicyDecision child grants,
  current Mission revision/epoch/lifecycle/TTL, policy and capability bindings, snapshot TTL, and
  exact resource version/digest/operation. Ingestion writes additionally require a persisted,
  post-dispatch ExecutionRecord bound to its current non-denied decision and current Data Access
  Policy. Artifact and Secret constructors accept only the exact final repository-backed type;
  structural lookalikes and subclasses cannot become production authorization adapters. The
  regression uses a real SQLite repository set and Artifact Store for execution-bound creation,
  persisted exact-grant reading, missing-execution denial, stale-resource denial, and policy-state
  invalidation.

### Modified files and regression tests

Resulting working-tree diff: `8 files changed, 1547 insertions(+), 103 deletions(-)`.

- `src/redteam_agent/data_security/authorization.py`
- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/repositories/policy.py`
- `tests/helpers.py`
- `tests/phase0b_helpers.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises partial and pre-sync intent publication interruptions, creation-audit
recovery for all three public stores, restartable Secret expiry and key destruction, rejection of
structural authorization lookalikes, and a repository-backed Artifact create/read flow with stale
and missing authority failures. Existing concurrency, quota, directory-swap, stream cleanup, key,
audit, ingestion, and detector regressions continue to pass. No test was deleted, skipped, weakened,
or marked as an expected failure.

### Validation

Focused regression command:

```text
PYTHONPATH=/tmp/redteam-phase0c-a91790d3 \
  /home/kali/Red_Agent/.venv/bin/python -m pytest -q \
  tests/security/test_phase0c_data_security.py \
  -k 'creation_intent_publication or creation_audit_pending \
      or expired_secret_erasure or repository_authorizer \
      or structural_authorizer'
```

Result: `8 passed, 70 deselected`.

Phase 0C data-security module: `78 passed`.

Required phase-gate command:

```text
source /home/kali/Red_Agent/.venv/bin/activate
scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 79 source files
unit: 200 passed
integration: 7 passed
security: 224 passed
full/coverage run: 431 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- The repository-backed authorizer intentionally accepts only immutable PolicyDecision grants for
  direct store access; LLM Context grants continue through the separately identity-bound
  `ContextAccessGate` and cannot resolve Secret values.
- Resource-creation and Secret-expiry recovery assume the configured key provider performs durable
  cryptographic destruction. The wrapped-file provider supplies that property through its externally
  anchored generation protocol.
- The key-state and audit-head external generation adapters remain integration boundaries supplied by
  an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-eighth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `c0688d5316db71ce4208651b057e727ca05ebe25`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3900976716`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900976716):
  Artifact reads/exports/expiry and Secret resolution/revocation now require an exact trusted
  `execution_id`. The repository-backed authorizer reloads that ExecutionRecord and its immutable
  PolicyDecision, verifies the current Mission/runtime/approval bindings, requires one exact
  decision grant for the resource version, digest, type, and operation, and requires the same
  binding to remain current in the Context Resource Index. Concrete repository regressions prove
  that an output-producing execution cannot borrow a reader execution's Artifact or Secret grant
  and that superseded Artifact and Secret index bindings fail closed.
- [`discussion_r3900976723`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900976723):
  Artifact and Secret creation through the production authorizer now requires immutable
  `IngestionWriteEvidence` bound to the exact ExecutionRecord, current INGESTING record and state
  version, attempt, non-expired lease, persisted receipt/digest, and Quarantine identifier. The
  PolicyDecision must explicitly grant the plan-bound prospective output authority for the
  corresponding resource type, while the actual generated output must still satisfy the current
  Mission Data Access Policy. `SecureIngestor` obtains this evidence only from the trusted
  repository-backed boundary and propagates it to every Artifact and Secret write. Regressions deny
  direct writes before result ingestion starts and replay of the same evidence after ingestion
  succeeds.
- [`discussion_r3900976729`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3900976729):
  authenticated resource-creation intent files now contribute their verified physical size and one
  record to Mission quota accounting. After publishing a new intent, the store recalculates exact
  usage and record count before allocating a resource key, reserves capacity for the encrypted
  envelope, and removes the uncommitted intent if that reservation fails. A repeated create-audit
  interruption regression proves pending intent/envelope pairs remain within the configured
  physical quota and that further creation is denied rather than growing storage without bound.

### Modified files and regression tests

Resulting working-tree diff: `8 files changed, 1035 insertions(+), 162 deletions(-)`.

- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/authorization.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `src/redteam_agent/repositories/policy.py`
- `tests/phase0b_helpers.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises cross-execution Artifact and Secret denial, current binding
supersession, missing ingestion evidence, completed-ingestion evidence replay, plan-bound output
authority, and repeated audit-failure quota exhaustion. Existing directory anchoring, key
destruction, audit recovery, streaming, lifecycle, scope, and detector regressions continue to
pass. No test was deleted, skipped, weakened, or marked as an expected failure.

### Validation

Focused review regressions:

```text
PYTHONPATH=. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py::test_repository_authorizer_revalidates_decision_execution_and_current_policy \
  tests/security/test_phase0c_data_security.py::test_audit_pending_creation_intents_are_charged_to_mission_quota
```

Result: `2 passed`.

Phase 0C data-security module: `79 passed`.

Required phase-gate command:

```text
PATH=/home/kali/Red_Agent/.venv/bin:$PATH PYTHONPATH=. \
  scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 79 source files
unit: 200 passed
integration: 7 passed
security: 225 passed
full/coverage run: 432 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- Plan-bound ingestion output authorities are reference-only metadata grants. They do not replace
  exact grants for later reads/resolution, and actual generated resource identifiers must still
  satisfy the current Mission Data Access Policy.
- Resource-creation recovery assumes the configured key provider performs durable cryptographic
  destruction. The wrapped-file provider supplies that property through its externally anchored
  generation protocol.
- The key-state and audit-head external generation adapters remain integration boundaries supplied
  by an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Twenty-ninth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `60a6a79e7385792fa584f8975f717f02547eb0b7`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3901131587`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901131587):
  ingestion write authority is now internal to the trusted repository authorizer, Artifact Store,
  and encrypted Secure Ingestor path rather than an exported caller-supplied capability. The
  internal evidence is bound to the exact active Execution/ingestion state, persisted receipt,
  Quarantine identifier, and encrypted Quarantine ciphertext digest. Public Artifact and Secret
  creation methods cannot accept that evidence. A concrete repository/executor regression invokes
  direct public writes while the exact receipt is persisted and the Execution is INGESTING, proves
  both writes fail closed, and then proves the trusted encrypted pipeline can publish the redacted
  Artifact and Secret reference.
- [`discussion_r3901131590`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901131590):
  every repository-authorized Artifact/Secret access and ingestion write now reloads and verifies
  the trusted ApprovalRequest and ApprovalRecord for `REQUIRE_APPROVAL` decisions. Both records must
  be within their issued/expiry intervals and remain bound to the exact authorization digest,
  PolicyDecision, request digest, structured presentation digest, and APPROVED result. The concrete
  repository regression advances time beyond approval expiry before the decision or resource
  expires and proves data access is rejected as stale.
- [`discussion_r3901131595`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901131595):
  live Quarantine, Artifact, and Secret stores now run operation-driven retention sweeps after
  construction. Writes/creates and relevant reads/resumes sweep the active Mission at the supplied
  trusted operation time, resume durable deletion/expiry intents first, audit deletion, erase the
  ciphertext, and destroy the resource key. Parameterized regressions leave each resource untouched
  past expiry, perform an unrelated operation in the same live store without restart or resource
  access, and prove both the expired ciphertext and key are gone.

### Modified files and regression tests

Resulting working-tree diff: `7 files changed, 680 insertions(+), 148 deletions(-)`.

- `src/redteam_agent/data_security/__init__.py`
- `src/redteam_agent/data_security/authorization.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/phase0b_helpers.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises direct Artifact and Secret writes during an exact active ingestion
receipt, successful trusted encrypted ingestion, approval expiry before decision/resource expiry,
and operation-driven Artifact, Secret, and Quarantine retention expiry without restart or direct
access. Existing directory anchoring, key destruction, audit recovery, quota, streaming, lifecycle,
scope, and detector regressions continue to pass. No test was deleted, skipped, weakened, or marked
as an expected failure.

### Validation

Phase 0C data-security module:

```text
PYTHONPATH=. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py -x
```

Result: `82 passed`.

Required phase-gate command:

```text
PATH=/home/kali/Red_Agent/.venv/bin:$PATH \
  scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 79 source files
unit: 200 passed
integration: 7 passed
security: 228 passed
full/coverage run: 435 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- Retention cleanup is operation-driven per active Mission and also performs a full recovery sweep
  when a store instance starts. An entirely idle long-lived Mission therefore relies on the next
  same-Mission store operation; no background thread or external scheduler is introduced in this
  phase.
- Resource-creation and expiry recovery assume the configured key provider performs durable
  cryptographic destruction. The wrapped-file provider supplies that property through its
  externally anchored generation protocol.
- The key-state and audit-head external generation adapters remain integration boundaries supplied
  by an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.

## Thirtieth independent review correction cycle

Current phase: `phase-0c`.

Input review SHA: `47a58ab068c092ddff320fc17387ce053cf46215`.

Phase base: `5cda9a5f8792ee33c3e153d8e791499f5619d82e`.

### Findings addressed

- [`discussion_r3901278173`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901278173):
  repository-backed Artifact and Secret authorization now obtains the decision time from an
  injected trusted Clock inside `RepositoryDataAccessAuthorizer`. Caller-supplied timestamps are no
  longer authorization evidence for Mission/runtime, PolicyDecision, grant, approval, or ingestion
  lease freshness. The concrete repository regression advances the trusted Clock beyond Approval
  expiry while passing a backdated access timestamp and proves the read is rejected as stale.
- [`discussion_r3901278180`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901278180):
  Store methods that accepted arbitrary bytes/streams together with ingestion evidence were
  removed. Streaming publication now requires a one-shot runtime-checked transaction constructed
  only from the exact encrypted Quarantine sink and persisted receipt; the transaction itself owns
  streaming secret detection, Secret isolation, and redaction. Artifact Store ignores all
  caller-provided stream content for that path and consumes only the transaction's redacted stream,
  while Secret Store accepts only one-shot detected-secret publications created inside the same
  redactor. The active-receipt regression proves that even directly obtaining current evidence does
  not provide a callable arbitrary Artifact/Secret publication API and that forged transactions
  fail closed before storage.
- [`discussion_r3901278184`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3901278184):
  Secret `resolve` and `revoke` entry points now run the same Mission-scoped crash-safe expiry sweep
  used by creation. The sweep resumes durable expiry intents before scanning detected secrets,
  audits deletion, erases ciphertext, and destroys the resource key. The live-store regression now
  expires one Secret while the only subsequent workload resolves a different live Secret; no
  restart, expired-resource access, or new Secret creation is used to trigger cleanup.

### Modified files and regression tests

Resulting working-tree diff: `5 files changed, 490 insertions(+), 163 deletions(-)`.

- `src/redteam_agent/data_security/authorization.py`
- `src/redteam_agent/data_security/ingestion.py`
- `src/redteam_agent/data_security/stores.py`
- `tests/security/test_phase0c_data_security.py`
- `docs/review/phase-0c-fix-report.md`

Regression coverage exercises backdated authorization attempts after trusted-clock expiry,
direct active-receipt/evidence publication attempts, forged publication objects, successful
Quarantine-bound redaction and Secret isolation, and Secret expiry during an unrelated read-only
resolve workload. Existing directory anchoring, key destruction, audit recovery, quota, streaming,
lifecycle, scope, and detector regressions continue to pass. No test was deleted, skipped, weakened,
or marked as an expected failure.

### Validation

Focused review regressions:

```text
PYTHONPATH=. /home/kali/Red_Agent/.venv/bin/pytest -q \
  tests/security/test_phase0c_data_security.py::test_repository_authorizer_revalidates_decision_execution_and_current_policy \
  tests/security/test_phase0c_data_security.py::test_live_store_operation_sweeps_expired_resources_without_access_or_restart \
  -x
```

Result: `4 passed`.

Phase 0C data-security module: `82 passed`.

Required phase-gate command:

```text
PATH=/home/kali/Red_Agent/.venv/bin:$PATH \
  scripts/ci/run_phase_gate.sh phase-0c
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 79 source files
unit: 200 passed
integration: 7 passed
security: 228 passed
full/coverage run: 435 passed
skipped=0, errors=0, failures=0
coverage: 81% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0c PASS
```

### Remaining constraints

- Runtime publication transactions protect the in-process Store boundary from ordinary callers;
  they do not attempt to defend against arbitrary interpreter memory mutation or monkey-patching.
  Process/OS isolation of mutually hostile Python code is outside Phase 0C.
- Retention cleanup remains operation-driven per active Mission plus a full startup recovery sweep.
  An entirely idle long-lived Mission relies on the next same-Mission Store operation.
- Resource-creation and expiry recovery assume the configured key provider performs durable
  cryptographic destruction. The wrapped-file provider supplies that property through its
  externally anchored generation protocol.
- The key-state and audit-head external generation adapters remain integration boundaries supplied
  by an OS keystore, vault, or equivalently protected monotonic service.
- No real C2, MCP, provider, subprocess, local-attack, credential-collection, or external-target
  action was executed.
- No protected governance file was modified.
- A fresh independent Phase 0C review remains required on the resulting 40-character PR HEAD; this
  local PASS is not an independent Phase Gate PASS.
