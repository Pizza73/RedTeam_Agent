# Phase 0C: Data Security and Audit

## Preconditions

- Phase 0B Gate PASS and all earlier invariants preserved.
- Treat the continuation, Secret lifecycle, typed lease/fencing, dedicated erasure and TPM witness requirements below as Phase 0C hardening; do not retroactively redefine the trusted Phase 0B base PASS.
- A recurrence-stop resume must use a valid `RESUME_AFTER_DESIGN_APPROVAL` request and implement the complete current-Phase mapping in `SystemDesign.md`, its normative `SystemDesign_AI_Control.md` companion and `docs/acceptance-criteria.md`; a generic Resume or partial-finding patch is not authorized. `docs/review/phase-0c-coherent-redesign.md` preserves historical finding rationale, not superseded runtime contracts.
- Apply `system-design-v1-r1`: Section 37.1 / 37.2 assigns D / F criteria to their phases. Implement the Phase 0C foundation and safe interfaces here, not the Phase 1 controller or Phase 2 real-LLM evaluation. D4 physical qualification remains NOT_EVALUATED and production activation is prohibited before its independent PASS.

## Implement

- Artifact Store with mission-scoped access, internal paths, traversal/symlink defense, quota, integrity, retention and audit
- Encrypted Raw Result Quarantine with crash-safe chunk metadata and resume
- Secure ingestion from a repository-bound `ingestion_id` only: classification, secret detection, redaction and reference generation; remove plaintext-returning full-object compatibility paths and caller-minted publication authority
- Durable Secure Ingestion Manifest, plaintext-free ExecutionResultProjection and Quarantine Deletion Intent with side-effect-free lookup plus explicit verified `INGESTED_DURABLE -> DELETE_PENDING -> ERASURE_CLAIMED -> QUARANTINE_ERASED -> SUCCEEDED` recovery
- Secret Store interface with stable logical `secret_id`, immutable `secret_version_id`, and append-only chained `DETECTED -> CONFIRMED -> REVOKED / SUPERSEDED` lifecycle events committed with their audit events
- Executor-owned, non-public Secret delivery transaction that durably consumes the exact post-pre-dispatch Claim before plaintext release and gives only the winning call a non-serializable one-call continuation into the composition-root-fixed Adapter dispatch port; no module-level token, standalone resolver or per-Secret lifetime usage counter; `AUTHORIZED` alone must never resolve plaintext
- PolicyDecision, DataAccessGrant and Dispatch Claim binding to exact Secret version IDs and current lifecycle heads; current `CONFIRMED` validation and Claim consumption share one OCC transaction as the revocation linearization point; revoke-first atomically invalidates the unsent Claim and enters `BLOCKED / SECRET_VERSION_STALE`
- Preserve the existing nested `ResourceBinding` / string-version DataAccessGrant shape while binding the exact Secret-version metadata record digest and adding the lifecycle-head `authorization_state_digest`; migrate each legacy Secret reference one-to-one without grouping or latest-version inference, and fail closed on ambiguity
- Define both BLOCKED forms exactly: pre-dispatch BLOCKED has zero attempts/no Claim, while `SECRET_VERSION_STALE` after `DISPATCH_CLAIMED` has one claimed attempt and the exact invalidated Claim but no Provider task
- Result Collection Authority bound to an Executor-owned trusted Clock reading, exact Tool Registry / `ToolDefinition.max_output_bytes`, the exact `ResultTaskBinding` union (`provider_task | local_capture`), sink and purpose-specific mission deadline; synchronous capture occurs in the original one-use submit without a fabricated provider ID; security entry points must not accept caller `now`
- Separate typed collection and ingestion leases with mandatory authority/resource/state bindings, TPM-backed `deployment_epoch + fencing_token`, same-boot host-shared monotonic deadlines, UTC rollback detection, a complete storage-side mutation predicate, 60-second default lease, heartbeat at most every 20 seconds, cancellation propagation and fence-specific staging / conditional publication; Phase 0C production is single-host and rejects multi-host workers
- A composition-root-fixed `VerifiedQuarantineEraser` separate from ingestion; it atomically creates/consumes a fully bound claim, and the Key Provider destroys or reconciles only the same immutable `erasure_id + key_metadata_digest` before ciphertext unlink
- EncryptionKeyProvider with separated secret/quarantine/artifact domains
- Shared Authenticated Generation Coordinator for Audit Head and Wrapped Key State, fixed in Production to an authenticated `synchronous=FULL` SQLite generation-record store plus namespace-separated TPM 2.0 NV Extend Digest witnesses; the current witness digest binds the exact prepared payload / immutable blob, not merely a logical generation number. Explicit provisioning extends the approved Genesis payload from verified unWRITTEN NV state; logical generation 0 is distinct from the separately measured deployment NV counter. Validate fixed provisioned identity and permitted dynamic NV Name / WRITTEN transitions. Production accepts only `tpm2_nv`; reset/mismatch enters `ANCHOR_RECOVERY_REQUIRED` and recovery approval binds exact old/new trust identities and adopted state without automatic reseed
- `generation-witness-policy-v5` critical state projection / synchronous barrier, including Mission / Epoch, Claim / Budget and verified Knowledge; no GoalRoutingHead compatibility authority. Preserve current-state rollback protection when replacing the old AI routing contract
- Atomic successful publication of manifest, result projection, referenced resources, deletion intent, DELETE_PENDING and lease release; mandatory read-back verification before post-ingestion erasure. Separate typed retention-expiry / incomplete-collection-expiry claims and orphan cleanup authority validate their own evidence without inventing a manifest or successful result
- Distinct valid / recovery / evidence-retention deadlines, continuously reauthorized recovery streams, independently renewable leases, task-unknown reconciliation versus known-task operations, single-use cancel attempts and explicit unresolved-item finalization
- Resource-specific cryptographic erasure with copy inventory / backup-restore coverage, REK slot incarnation / capacity and the D4 qualification gate; no domain-wide key destruction or wrapped-key-row removal as proof of resource erasure
- Authenticated encryption metadata and AAD bindings
- Key rotation/revocation/unavailable fail-closed behavior
- Data access enforcement for artifact and secret operations
- Application-level append-only, mission-scoped audit log and hash chain
- Atomic mission sequence allocation and chain verification
- Sandbox interface/policy/capability models required for later execution
- Section 32.1 transaction aggregate catalog and `ApplicationUnitOfWork`: each owner commits state transition,
  audit and outbox/intent atomically; child repositories cannot independently commit, and external work is never
  performed inside the database transaction
- Section 32.2 normative versioned digest catalog and one canonical digest service for every security-sensitive
  digest; missing/duplicate definitions, field/version/canonicalization drift and parallel fallback implementations fail closed
- A single Production Composition Root that acquires the shared Activation Lock, then constructs and self-checks config, digest catalog, read-only DB/schema compatibility, TPM,
  trusted clock/epoch, key domains, stores, unit of work/repositories, adapters/services and graph in the specified
  order; reject test doubles, unsupported providers, multiple roots and mission-time trusted-dependency replacement,
  and close partial startup/shutdown in reverse dependency order
- Explicit stopped-worker migration / restore under the same Activation Lock; normal startup never mutates schemas or reseeds trust. Preserve immutable legacy history / consumed claims and budgets; legacy missions are read-only archives, not sources of new dispatch authority
- One reviewable logical-component-to-physical-module map enforcing the Section 35 ownership boundaries; context,
  approval, ingestion and planner-information responsibilities must have one owner, with no forbidden dependency,
  owner-external state-transition command or duplicate digest definition

## Test

- No secret/raw output in prompt, normal DB/log, exception or traceback
- Secret update creates a new immutable version without overwriting the old ciphertext; lifecycle-event replay, reorder, gap, digest tamper or head rollback fails closed; a revoke-before-consume race invalidates the unsent Claim and blocks the Execution while consume-before-revoke permits only that already-claimed attempt
- Pre-dispatch and post-claim BLOCKED records enforce their distinct attempt/Claim invariants; nested ResourceBinding remains wire-compatible and legacy Secret migration never groups identities, activates a revoked record or accepts ambiguous state
- Path traversal, symlink escape, quota and digest corruption
- Quarantine streaming crash/resume and secure deletion lifecycle
- Direct full-object factory / compatibility loader / caller receipt and quarantine-reference plaintext release denial
- No caller-constructible/exported Secret Broker, channel registry or callback path; Pre-dispatch blocked, `AUTHORIZED`, expired or consumed Dispatch Claim, and Tool / Adapter / Secret-set mismatch secret-resolution denial
- Crash before/after Claim consumption, Adapter entry/return and Provider submit never replays Secret delivery or submit; test adapters retain no plaintext
- Concurrent dispatch calls have one Claim-consumption winner; its continuation cannot be imported, serialized, reused or invoked after the enclosing call, while a later separately authorized Execution may use the same `CONFIRMED` and unexpired Secret version
- Long-running provider collection retention starts at trusted collection time, remains stable across restart and cannot exceed the mission deadline
- Future/backdated caller timestamps cannot influence collection start, lease or retention
- Long-running collection and ingestion heartbeat renewal succeeds only under the complete lease/owner/deployment-epoch/fence/release/monotonic-expiry/authority/state-version predicate and cannot extend Mission / Retention authority; forced expiry, UTC rollback, process restart, database rollback or takeover rejects every later mutation, abort or release from the old worker, including when an Adapter ignores cancellation; multi-host configuration is rejected
- Cross-tool output limits use the exact trusted Tool Definition and cannot be expanded by caller or global configuration
- Sink/reader/factory/lookup construction and ingestion cannot erase data; the dedicated eraser atomically persists only its consumed claim, its typed Key Provider contract reconciles the same `erasure_id + key_metadata_digest` after an unknown outcome, and crash before / after Manifest Commit, Projection Commit, complete resource verification, Deletion Intent, Erasure Claim, key destruction, ciphertext unlink and ExecutionResult acknowledgement recovers without provider replay
- `INGESTED_DURABLE` and later recovery reconstructs ExecutionResult from Manifest / Projection with no Adapter collection, Provider query or Quarantine decrypt
- Secret/Quarantine/Artifact key ID/tag reuse rejection
- Nonce/AAD/domain mismatch and unavailable/revoked key fail-closed
- Audit deletion/reorder/content/previous-hash tamper detection
- Sequence conflict and independent mission chain verification
- Audit / key generation crash and directory-replacement restart recovers from the exact TPM-witnessed Production record/blob pair; only an empty explicitly provisioned store can create the generation-0 Genesis pair; missing or corrupt Current records fail closed; SQLite rollback cannot roll back TPM; TPM reset/NV mismatch enters `ANCHOR_RECOVERY_REQUIRED`, and a fully bound single-use recovery approval either adopts an externally verified exact state or initializes empty without auto-reseed; Production non-TPM configurations are rejected; the same Production witness implementation passes restart/rollback/reset tests against `swtpm`
- D1 / D2 / F7 test same-generation different prepared content, extend-response uncertainty, duplicate extend, third digest, fixed/dynamic NV identity, Genesis crash and deployment-counter initial read failure; swtpm tests do not qualify physical resource erasure
- R1 / R3 / D3 / F6 test successful-publication versus expiry races, synchronous local capture crash boundaries, short-lived authority expiry during renewed leases, late chunks and stale fences; neither recovery nor expiry creates a new provider submit
- R10 / R13 / F2 test exact-version Operator confirmation, active-version replacement, archived legacy missions, schema mismatch without startup migration, second-root / migration contention, and preservation of unresolved execution and consumed-budget history
- D4 records physical qualification as NOT_EVALUATED until independently tested; production constructors fail closed without applicable TPM / firmware / TSS / copy-inventory / restore / capacity evidence
- Property-based or rule-based state-machine evidence covers Dispatch / Secret delivery, ingestion / erasure / result recovery, collection / ingestion lease timing and fencing, and authenticated generation
- Fault injection around every transaction aggregate proves there is no partial state/audit/intent commit and no child-repository commit; same-operation/different-payload retries conflict
- Digest-catalog tests reject unregistered families, duplicate owners, missing included fields, version/canonicalization mismatch and any alternate digest path
- Composition-root startup-step fault injection proves mission admission stays disabled, resources close in reverse order,
  production test doubles and second roots are rejected, trusted dependencies cannot be swapped mid-mission, and shutdown is deterministic
- Architecture tests reject missing/duplicate logical-component mappings, forbidden dependency directions,
  owner-external state-transition commands and digest definitions outside the canonical owner

Do not introduce plaintext or normal-artifact fallback.
