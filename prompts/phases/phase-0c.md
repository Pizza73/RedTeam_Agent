# Phase 0C: Data Security and Audit

## Preconditions

- Phase 0B Gate PASS and all earlier invariants preserved.
- A recurrence-stop resume must use a valid `RESUME_AFTER_DESIGN_APPROVAL` request and implement the complete mapping in `docs/review/phase-0c-coherent-redesign.md`; a generic Resume or partial-finding patch is not authorized.

## Implement

- Artifact Store with mission-scoped access, internal paths, traversal/symlink defense, quota, integrity, retention and audit
- Encrypted Raw Result Quarantine with crash-safe chunk metadata and resume
- Secure ingestion from a repository-bound `ingestion_id` only: classification, secret detection, redaction and reference generation; remove plaintext-returning full-object compatibility paths and caller-minted publication authority
- Durable Secure Ingestion Manifest, plaintext-free ExecutionResultProjection and Quarantine Deletion Intent with side-effect-free lookup plus explicit verified `INGESTED_DURABLE -> DELETE_PENDING -> QUARANTINE_ERASED -> SUCCEEDED` recovery
- Secret Store interface and reference-only application model
- Executor-owned, non-public Secret delivery transaction that durably consumes the exact post-pre-dispatch Claim before plaintext release and invokes only the composition-root-fixed Adapter dispatch port; `AUTHORIZED` alone must never resolve plaintext
- Result Collection Authority bound to an Executor-owned trusted Clock reading, exact Tool Registry / `ToolDefinition.max_output_bytes`, provider task, sink and mission deadline; security entry points must not accept caller `now`
- EncryptionKeyProvider with separated secret/quarantine/artifact domains
- Shared Authenticated Generation Coordinator for Audit Head and Wrapped Key State, with a wired durable Production backend whose external CAS anchors bind generation, state digest and immutable blob identity; Production rejects integer-only, local-slot and in-memory fallbacks
- Authenticated encryption metadata and AAD bindings
- Key rotation/revocation/unavailable fail-closed behavior
- Data access enforcement for artifact and secret operations
- Application-level append-only, mission-scoped audit log and hash chain
- Atomic mission sequence allocation and chain verification
- Sandbox interface/policy/capability models required for later execution

## Test

- No secret/raw output in prompt, normal DB/log, exception or traceback
- Path traversal, symlink escape, quota and digest corruption
- Quarantine streaming crash/resume and secure deletion lifecycle
- Direct full-object factory / compatibility loader / caller receipt and quarantine-reference plaintext release denial
- No caller-constructible/exported Secret Broker, channel registry or callback path; Pre-dispatch blocked, `AUTHORIZED`, expired or consumed Dispatch Claim, and Tool / Adapter / Secret-set mismatch secret-resolution denial
- Crash before/after Claim consumption, Adapter entry/return and Provider submit never replays Secret delivery or submit; test adapters retain no plaintext
- Long-running provider collection retention starts at trusted collection time, remains stable across restart and cannot exceed the mission deadline
- Future/backdated caller timestamps cannot influence collection start, lease or retention
- Cross-tool output limits use the exact trusted Tool Definition and cannot be expanded by caller or global configuration
- Sink/reader/factory/lookup construction cannot erase data; crash before / after Manifest Commit, Projection Commit, complete resource verification, Deletion Intent, key destruction, ciphertext unlink and ExecutionResult acknowledgement recovers without provider replay
- `INGESTED_DURABLE` and later recovery reconstructs ExecutionResult from Manifest / Projection with no Adapter collection, Provider query or Quarantine decrypt
- Secret/Quarantine/Artifact key ID/tag reuse rejection
- Nonce/AAD/domain mismatch and unavailable/revoked key fail-closed
- Audit deletion/reorder/content/previous-hash tamper detection
- Sequence conflict and independent mission chain verification
- Audit / key generation crash and directory-replacement restart recovers from the durable Production digest/blob-bound backend without manual path repair; missing or corrupt committed blobs fail closed and Production test-double/legacy configuration is rejected
- Property-based or rule-based state-machine evidence covers Dispatch / Secret delivery, ingestion / erasure / result recovery, collection timing and authenticated generation

Do not introduce plaintext or normal-artifact fallback.
