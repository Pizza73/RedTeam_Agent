# Phase 0C Coherent Redesign: Durable Execution Lifecycle v3

## Historical scope — superseded implementation details (2026-09-06)

This report preserves the v3 finding-to-design rationale and its historical review / HEAD references.
The status, code examples, sequences and imperative decisions below describe that revision, not the
current runtime contract. They are not current GitHub authority or a second implementation specification.
Use [SystemDesign.md](../../SystemDesign.md), its [AI Control companion](../../SystemDesign_AI_Control.md),
[acceptance criteria](../acceptance-criteria.md) and the current Phase prompt for `system-design-v1-r1`.
The existing formal Design Stop and exact-HEAD approval procedure remain unchanged.

| Historical detail | Current normative replacement |
| --- | --- |
| TPM numeric generation selection / counter-zero Genesis | SystemDesign §34.2: content-bound NV Extend Digest, fixed versus dynamic NV identity, explicit Genesis; deployment epoch uses a separate measured NV counter |
| Provider task required for all results | §10 / §13 / §33: exact provider_task or local_capture binding, no fake provider ID and no recovery submit |
| Manifest required for every kind of erasure | §10 / §33.2: successful-publication atomic unit and read-back; separate typed expiry / incomplete / orphan evidence |
| Fixed authority while a lease renews | §10.3 / §21.1: independently reauthorized recovery and lease renewal, purpose-specific deadlines and continuous sink checks |
| Per-resource erasure inferred from metadata deletion | §34.1.1: D4 copy/restore/hardware qualification remains NOT_EVALUATED; production fail-closed |
| Legacy active-state conversion / startup migrations | §35.2 / §38: shared Activation Lock, read-only startup validation, explicit stopped-worker migration and read-only legacy archive |
| Runtime completion of the historical redesign | §37.1 / §37.2 plus current acceptance criteria: full current-Phase invariant mapping, not only the three historical findings |

## Status

- Design status: human-approved third coherent-redesign direction; governance merge and exact-HEAD Design Approval remain pending
- Current implementation PR: #3 (`ai/redteam-agent-phase-loop`)
- Blocked implementation HEAD: `ae09f40f6b593060d060cfb9a5090e0de4e2875d`
- Formal review: <https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5094547758>
- Trusted recurrence gate: <https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692085>
- Trusted design stop: <https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692776>
- Prior coherent-redesign review: <https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5085287765>

This document records the coherent redesign required after the following invariant families
recurred again in the latest Phase 0C formal review:

- `secret-plaintext-boundary`
- `integrity-cryptography-keys`
- `filesystem-concurrency-retention`

The latest review retained three P1 findings. The implementation still exposes a reusable
post-consumption Secret-resolution capability, stores authenticated generation blobs and their
rollback witness in one rollback unit, and permits a collection lease to expire while the original
worker continues without renewal or fencing. This revision closes those gaps while preserving the
already-approved durable lifecycle design. It does not authorize a new implementation request by
itself. Resume requires the dedicated current-HEAD Design Approval defined in
`docs/ai-development-loop.md`.

All new continuation, Secret lifecycle, typed lease-fencing, dedicated erasure and TPM-witness
requirements in this revision are Phase 0C hardening of interfaces introduced earlier. They are
evaluated by the Phase 0C gate and do not retroactively redefine the already trusted Phase 0B base
PASS.

## Problem statement

The current code applies security checks at individual methods, but authority and durable outcome
are split across Executor, Secret Store, RawResultSink Factory, Quarantine, Secure Ingestion, Audit
Head Store and Key State Store. This permits adjacent paths to reconstruct partial authority or to
observe different commit boundaries.

The redesign makes six facts explicit:

1. Policy authorization is not immediate authority to obtain plaintext or perform a side effect.
2. Raw-result ingestion and quarantine erasure form one recoverable lifecycle but use separate,
   non-interchangeable authorities.
3. A committed generation must be identified by its authenticated content, not only by an integer
   and a replaceable local path.
4. Secret release is at-most-once per Dispatch Claim and dispatch attempt, not once per Secret
   version over its lifetime.
5. A renewable or takeover-capable collection / ingestion lease is safe only when every durable
   mutation is rejected for a stale fencing token.
6. A rollback witness cannot share the same storage and restore boundary as the data whose rollback
   it is meant to detect.

## Decision 1: purpose-specific durable authority

### Authorization semantics

`AUTHORIZED` means that a trusted PolicyDecision has been bound to one Execution candidate. It
does not permit Secret plaintext resolution, Provider submission or RawResultSink creation.

Pre-dispatch validation rechecks current Mission state / validity, authorization epoch,
PolicyDecision and Approval binding / TTL, Session freshness, Tool snapshot, Adapter / Sandbox /
Remote MCP capability, required encryption keys and all canonical digests.

On failure:

```text
AUTHORIZED -> BLOCKED
```

No Dispatch Claim, Secret injection, Provider call, Result Collection Authority, Quarantine or
ExecutionResult may exist.

On success, one OCC transaction performs both operations:

```text
AUTHORIZED -> DISPATCH_CLAIMED
persist DispatchClaim
```

`DISPATCH_CLAIMED` means that the single external submit attempt has been claimed. It does not
assert that the Provider received the request. A crash or unknown submit outcome after this commit
enters Reconciliation and never causes automatic submit replay.

### DispatchClaim binding

The immutable record binds:

- execution ID and execution state version;
- PolicyDecision ID and authorization digest;
- Mission revision and authorization epoch;
- exact ToolRef and resolved Adapter ID;
- the exact Secret version IDs and their Current lifecycle-event-head digest;
- ApprovalRequest / ApprovalRecord when required;
- issued / expiry time and `unconsumed / consumed / invalidated` state; and
- idempotency identity used for Reconciliation.

The Claim is not a bearer token. Services load the Current Claim through the Execution ID and
revalidate all bindings. A caller-provided Claim object or copied Claim ID is insufficient.

### Executor-owned Secret delivery transaction

Plans, PolicyDecision, ExecutionRequest and Graph State carry Secret Reference metadata only.
There is no general application API that returns plaintext bytes, accepts a plaintext consumer, or
constructs a Secret delivery channel.

Secret delivery is not a separately constructible service. The trusted Application composition
root creates Executor with its fixed `TrustedAdapterRegistry`, Secret Store and Dispatch Claim
Repository. Executor owns one private delivery transaction and invokes it only as part of the same
non-retryable Adapter submit attempt. The package must not export a `SecretInjectionBroker`,
`TrustedSecretChannelRegistry`, `SecretAdapterChannel`, callback protocol, or public injection
method that an Application caller can assemble with caller-owned code. Runtime type checks or
nominally private names are not construction provenance.

The fixed transaction is ordered as follows:

1. load and verify Current Mission, Execution, PolicyDecision, exact DataAccessGrant, Tool and
   fixed Adapter from trusted repositories;
2. load the Current unconsumed Dispatch Claim and the complete authorization-bound set of exact
   Secret version IDs / lifecycle-event-head digests;
3. in one Application Database OCC transaction, verify those event heads are still Current and
   `CONFIRMED`; on success consume that exact Claim for the one Adapter dispatch, and on mismatch
   atomically invalidate the still-unconsumed Claim plus transition the known-unsent Execution to
   terminal `BLOCKED / SECRET_VERSION_STALE`;
4. read back the consumed record and verify its digest, state version and consumption identity;
5. only after durable consumption, load the exact pinned Secret records, verify ciphertext / key
   bindings without re-resolving lifecycle or "latest", decrypt into bounded mutable buffers and
   invoke the already-selected trusted Adapter dispatch port exactly once;
6. zero all temporary buffers on every return, cancellation and exception path; and
7. persist a confirmed Task identity when available, otherwise enter Reconciliation without
   replaying Secret delivery or Provider submit.

The two BLOCKED paths retain distinct durable invariants. An ordinary pre-dispatch
`AUTHORIZED -> BLOCKED` has `dispatch_attempts=0` and no Dispatch Claim. The lifecycle-race
`DISPATCH_CLAIMED -> BLOCKED / SECRET_VERSION_STALE` has `dispatch_attempts=1`, no Provider task or
result state, and exactly one Claim for the Execution in `invalidated` state. Dispatch Claim
integrity verification permits a BLOCKED binding only for that exact combination; an unconsumed or
consumed Claim, another block reason, or Provider state fails closed. Here `dispatch_attempts`
counts claimed external-submit attempts, not Provider acknowledgements.

The winning Claim-consumption transaction creates a process-local, non-serializable dispatch
continuation for that exact call. It is neither a module-level token nor an object obtainable by an
Application caller. The continuation can only invoke the composition-root-fixed Adapter dispatch
function with the complete authorization-bound Secret set, and it invalidates itself when invoked
or when the enclosing call exits. Secret Store exposes no independently callable plaintext method,
including a nominally private resolver that accepts a reusable token. Dispatch Claim Repository,
Secret key access and plaintext buffers remain internal dependencies of the Executor composition.
An idempotent repeat carrying the same consumption identity may read and compare the stored record
for Reconciliation, but returns `consumed_now=false` and never creates another continuation.

Claim consumption is the linearization point between Secret revocation and dispatch. A revocation
or supersession event committed before that transaction makes consumption fail. If consumption
commits first, the already claimed single Adapter attempt may finish using the exact pinned Secret
versions; the later lifecycle event denies every subsequent Claim. The Executor never resolves
"latest Secret" after PolicyDecision issuance. Emergency key unavailability can still abort before
Adapter entry, but cannot cause the same Claim or submit attempt to be retried.

Lifecycle-mismatch invalidation occurs before decryption, releases no plaintext and cannot be
reopened. A crash after consumption
but before, during, or after Adapter entry is deliberately at-most-once: restart does not inject
again and does not call submit again. It reconciles using the immutable execution identity and
idempotency key; an unresolvable outcome becomes `OUTCOME_UNKNOWN`. This chooses safety over
availability instead of claiming cross-process exactly-once delivery.

No persistent `secret_usage_count` or lifetime single-use flag is added. `secret_id` identifies the
logical credential while `secret_version_id` identifies one immutable ciphertext version. Planner
may carry a logical reference, but PolicyDecision, DataAccessGrant and Dispatch Claim bind the exact
version ID and Current lifecycle-event-head digest. The same confirmed, non-revoked version may be
referenced by a later, separately authorized Execution with a new Dispatch Claim.

The shared DataAccessGrant shape remains compatible with the implemented model: it contains the
nested `ResourceBinding(resource_id, resource_version: str, resource_digest)` plus a required
`authorization_state_digest`. A Secret grant uses the exact `secret_version_id` as `resource_id`,
the canonical decimal version as the string `resource_version`, the immutable Secret-version
metadata record digest as `resource_digest`, and the lifecycle head digest as
`authorization_state_digest`. No resource type may omit its content or authorization-state digest.

Lifecycle is represented only by append-only events:

```text
DETECTED -> CONFIRMED -> REVOKED
                      -> SUPERSEDED
```

Changing a Secret creates a new immutable version. Revocation / supersession appends a chained
event, Current eligibility is derived from the verified maximal sequence plus expiry, and terminal
versions cannot be reactivated. Event append and the corresponding Audit event commit together;
event replay, gap, duplicate sequence, chain mismatch or whole-record substitution fails closed.
Appending a version OCC-checks the current logical head, requires a contiguous version number and
same-secret predecessor, and rejects branches or cross-secret predecessor substitution.

The Phase 0C schema migration does not infer that two legacy `secret_reference_id` values represent
one credential. Each legacy ID maps one-to-one to the same immutable version ID under a
deterministically derived logical ID and version 1. Detected / confirmed states become verified
lifecycle chains; terminal revoked data remains unavailable and is never manufactured into a
confirmed history. Missing provenance, duplicate identity, conflicting payload or digest ambiguity
stops startup with `SecretMigrationRequiredError`; no compatibility loader or plaintext re-ingest
fallback is allowed.

The caller cannot choose a callback, consumer, environment variable, command line, endpoint,
registry or alternate Adapter channel. `AUTHORIZED`, `BLOCKED`, `RUNNING`, terminal states,
expired / consumed Claims and Mission / Epoch / Tool / Adapter / Secret-set mismatch all deny
Secret delivery.

Phase 0C uses an Executor-owned test Adapter that validates the supplied value inside the call and
records only call count / non-secret control metadata; it must not retain or copy plaintext.
Phase 4 / 5 production Adapters use the process-isolated channel required by the Sandbox policy.
Untrusted plugin code must not execute inside the Executor / Adapter composition TCB.

## Decision 2: trusted result-collection authority

Executor receives one trusted `Clock` from the Application composition root. Security-sensitive
collection and ingestion entry points do not accept a caller-supplied `now`; caller timestamps are
observation metadata only and never authorization, lease or retention evidence.

Before `ExecutionAdapter.collect_result()` receives a sink, Executor reads that Clock once and persists one
`ResultCollectionAuthority` bound to:

- execution ID and provider task ID;
- exact ToolRef and Tool Registry digest;
- `ToolDefinition.max_output_bytes`;
- trusted `collection_started_at`;
- persisted `retention_until`;
- deterministic sink ID. The mutable resume cursor is persisted separately under the collection
  fence.

The values are calculated once:

```text
retention_until = min(
    collection_started_at + quarantine_retention_policy,
    mission.valid_until,
)

max_result_bytes = min(
    ToolDefinition.max_output_bytes,
    system_hard_output_cap,
)
```

The system hard cap may reduce, but never expand, the Tool-specific limit. A caller-provided or
global max is not authoritative. If the Mission deadline has already passed, the Tool or exact
Registry revision is missing, or the Provider task does not match, no new sink is issued.

The same trusted reading is used for authority creation and the initial collection lease. The
authority is immutable. Lease ownership is not represented by one generic record. Collection uses
a typed `ResultCollectionLease` bound to collection, execution, authority digest, Provider task,
sink and expected Execution state version. Ingestion uses a separate typed
`SecureIngestionLease` bound to ingestion, execution, receipt / quarantine digests and expected
Ingestion state version. Each record carries `owner_id`, `lease_id`, `deployment_epoch`,
`fencing_token`, acquisition / UTC expiry / host-monotonic deadline / release timestamps and its
canonical digest. Optional work-kind fields cannot erase a binding required by one workflow.

Phase 0C Production supports one host, one TPM, one Application Database and one trusted composition
root. That root obtains `deployment_epoch` from a dedicated TPM 2.0 NV monotonic counter. Under a
host-wide activation lock, it advances the epoch once at root start and after an authorized offline
restore, then persists and read-back verifies the matching Current Epoch mirror before any lease can
be acquired. Child workers share that epoch and cannot write the mirror. Starting another root
advances the epoch and invalidates the earlier root; a multi-host worker topology is rejected rather
than assuming that host-local TPM, lock or clock state is shared. Every Repository mutation compares
the lease epoch to the Current mirror; startup / recovery also compares the mirror to TPM. Restore
occurs only while all workers are stopped. Each acquisition / takeover allocates a strictly greater
database fencing token within that epoch. The ordered fence is therefore
`(deployment_epoch, fencing_token)`: restoring the Application Database cannot make a pre-restore
worker current. Release marks the exact record inactive rather than deleting it, and neither epoch
nor token is reused.

Every renewal, write, publish, transition, abort and release must satisfy one exact storage-side
predicate in the same OCC transaction:

```text
lease_id == current.lease_id
AND owner_id == current.owner_id
AND deployment_epoch == trusted_current_deployment_epoch
AND fencing_token == current.fencing_token
AND released_at IS NULL
AND trusted_monotonic_now_ns < lease_deadline_monotonic_ns
AND immutable authority / resource binding digest matches
AND expected state version matches
```

The Repository owns the trusted Clock; no caller or Adapter supplies `now`. One read returns audited
UTC plus a same-boot, cross-process monotonic value such as Linux `CLOCK_BOOTTIME`. Lease validity
uses only `lease_deadline_monotonic_ns`; `lease_expires_at` is retained for audit and Mission /
retention cap verification. A monotonic deadline is never reused across deployment epochs. A
persisted UTC high-water rollback or excessive wall/monotonic divergence raises typed
`ClockIntegrityError`, stops new authorization, Claims, leases and renewals, and never extends a
Mission TTL. Renewal changes only the paired UTC expiry and monotonic deadline and caps them at
Mission validity and `retention_until`; it cannot change authority, collection start, output limits,
sink, task identity, status version or cursor. The default lease is 60 seconds with a heartbeat
interval of at most 20 seconds, and configuration enforces
`lease_duration >= 3 * heartbeat_interval`. Executor runs the heartbeat independently of
`collect_result(task, sink, cancellation_token)`. Renewal failure, expiry or ownership mismatch
signals cancellation. A non-cooperative Adapter may continue local computation or reads, but the
sink still rejects every subsequent mutation under the exact predicate.

A state-changing mutation compares the lease's expected state version to the pre-state and advances
the domain record plus the lease's expected state version in the same transaction. Non-state writes
must not alter it. The `DELETE_PENDING` transition advances the Ingestion state and releases its
lease atomically, so no ingestion mutation remains authorized after handoff to the eraser.

```text
new_lease_expires_at = min(
    trusted_utc_now + configured_lease_duration,
    retention_until,
    mission.valid_until,
)
new_lease_deadline_monotonic_ns =
    trusted_monotonic_now_ns
    + duration_to_ns(new_lease_expires_at - trusted_utc_now)
```

Every chunk append, receipt commit, abort, resume-cursor update and terminal collection transition
uses that predicate. Filesystem / blob writes are staged under
`work_id/deployment_epoch/fencing_token/sequence`; only a storage-side conditional publication may
make their metadata Current. The Application Database metadata is the source of truth. Bytes from a
stale fence remain unreachable staging garbage and may be collected later. Restart reuses the
stored collection start, retention, output limit, sink and cursor. It may retrieve the same Provider
task result but never resubmits the external action.
Running one Executor process is the recommended deployment default, but it is not a security
assumption: same-host child workers, duplicate root startup and delayed workers remain fail-closed
through deployment-epoch invalidation, OCC and fencing. Multi-host workers are outside Phase 0C.

## Decision 3: one repository-bound ingestion entry point

The application-facing ingestion API accepts only `ingestion_id`:

```text
SecureIngestionCoordinator.run(ingestion_id)
```

The Coordinator loads and verifies ResultIngestionRecord, ExecutionRecord, RawResultReceipt,
Quarantine metadata, ResultCollectionAuthority and Current Mission. It acquires the typed
`SecureIngestionLease` before decrypting. Every staging write, output publication, manifest commit,
state transition and deletion-intent commit uses the same exact lease predicate and a
`ingestion_id/deployment_epoch/fencing_token` staging namespace. Takeover resumes only from a
verified durable checkpoint. Ingestion ends after the manifest and deletion intent are durable and
the state reaches `DELETE_PENDING`; it releases its lease and never receives a key-destruction or
unlink capability.

The following paths are removed, not hardened with nominal privacy:

- optional or synthesized legacy receipts;
- caller-supplied Receipt or QuarantineReference as authority;
- module-level full-object publication factories;
- Quarantine methods returning full plaintext bytes;
- arbitrary publication / callback / consumer objects; and
- compatibility readers that bypass the committed streaming receipt.

Quarantine decrypts committed chunks only inside the fixed Secure Ingestion pipeline. Plaintext is
fed directly to classification, secret detection and redaction. Only references and redacted
metadata cross the boundary.

## Decision 4: durable ingestion before erasure

### State machine

```text
NOT_AVAILABLE
  -> PENDING
  -> INGESTING
  -> INGESTED_DURABLE
  -> DELETE_PENDING
  -> ERASURE_CLAIMED
  -> QUARANTINE_ERASED
  -> SUCCEEDED

INGESTING -> FAILED -> PENDING       explicit same-result remediation only
                    -> QUARANTINED   unrecoverable / human review
```

`INGESTED_DURABLE` requires a committed and read-back-verified `SecureIngestionManifest`.

### SecureIngestionManifest

The immutable manifest binds:

- ingestion, execution, receipt and quarantine identities / digests;
- redaction / classification rule versions;
- every Redacted Artifact reference and digest;
- every retained Encrypted Raw Artifact reference and digest;
- every Secret Reference and metadata digest;
- Redaction Metadata;
- an immutable, plaintext-free `ExecutionResultProjection` containing every normalized Provider
  control field required to build the final ExecutionResult;
- the Result Projection digest and its binding to the exact Receipt and Provider task;
- creation time; and
- its own canonical digest.

Output IDs are deterministic from Execution, Receipt, Quarantine digest, rule version and output
sequence. Output stores implement create-or-verify: replay of identical payload is idempotent and a
different digest at the same identity fails closed. Artifact bodies and Secret ciphertext may be
durably written to an internal staging namespace first, but their metadata is not a Current Context
Resource. After read-back verification, public Artifact / Secret metadata, the manifest and the
`INGESTED_DURABLE` transition commit in one Application Database transaction. Context Selector,
Knowledge Reducer and normal read APIs cannot observe partially prepared output.

`ExecutionResultProjection` contains only typed control metadata and safe references: confirmed
Provider status, exit code, started / finished timestamps, timeout / cancellation flags, redacted
preview references and the exact Artifact / Redaction bindings. It contains no Raw bytes, Secret
Value or Provider temporary path. Once `INGESTED_DURABLE` is reached, every path that invokes
`collect_result()`, decrypts Quarantine, or queries the Provider for result reconstruction is
rejected. Recovery builds the final result from the verified manifest and projection only.

### Erasure ordering

Opening or reconstructing a Quarantine sink/reader is side-effect free. Constructors, factories,
repository reads and `for_execution()`-style lookup methods must not resume a deletion intent,
destroy a key or unlink ciphertext. Destructive authority belongs only to a composition-root-fixed
`VerifiedQuarantineEraser.run(deletion_intent_id)`; the ingestion worker cannot construct or call
its key-destruction port.

The eraser loads and authenticates the complete prerequisite graph, then creates an immutable
`QuarantineErasureClaim` bound to the deletion-intent digest, manifest / projection / resource
digests, quarantine key metadata and a deterministic `erasure_id`. One OCC transaction performs
`DELETE_PENDING -> ERASURE_CLAIMED` and creates/consumes that claim. No repository-visible
unconsumed erasure claim exists: the stored record has `claim_state=consumed` and non-null
consumption identity / time. Only the transaction winner may invoke key destruction.

The Key Provider exposes a purpose-specific typed contract:

```text
destroy_resource_key(erasure_id, key metadata, key_metadata_digest)
reconcile_resource_key_destruction(erasure_id, key metadata, key_metadata_digest)
    -> NOT_STARTED | CONFIRMED | UNKNOWN | FAILED
```

The pair `erasure_id + key_metadata_digest` is the Provider idempotency and reconciliation identity.
Only `NOT_STARTED` may begin the one destructive operation. After `UNKNOWN`, transport failure or
process crash, recovery calls reconcile only; it must not issue a new destroy identity. The Provider
returns `CONFIRMED` only when the exact resource key is durably unrecoverable. Ciphertext unlink
occurs only after that result is read-back verified; `FAILED`, ambiguity or a different Provider
operation stops for human review.

1. load and verify Execution, Receipt, Result Collection Authority and Quarantine metadata;
2. prepare and verify output ciphertext / artifact bodies in an internal staging namespace;
3. construct and verify the plaintext-free ExecutionResultProjection;
4. atomically publish output metadata, commit the SecureIngestionManifest and transition to
   `INGESTED_DURABLE` in the Application Database;
5. read-back verify the committed manifest, projection and every referenced Artifact / Secret;
6. commit and read-back verify a manifest-bound Quarantine Deletion Intent;
7. transition to `DELETE_PENDING` and release the ingestion lease;
8. let the dedicated eraser atomically consume the exact erasure claim and transition to
   `ERASURE_CLAIMED`;
9. reconcile or perform the single immutable `erasure_id`, confirm resource-key destruction, then
   unlink ciphertext;
10. transition to `QUARANTINE_ERASED`;
11. construct / persist ExecutionResult from the manifest and projection without Adapter access;
    and
12. acknowledge `SUCCEEDED`.

Recovery first loads the current ingestion state. For `INGESTED_DURABLE`, `DELETE_PENDING`,
`ERASURE_CLAIMED` or `QUARANTINE_ERASED`, it loads and authenticates the manifest, projection and
every referenced durable resource before constructing any deletion-capable object. The eraser also
loads the exact intent and claim. Missing or corrupt evidence stops with no additional deletion.

### Crash matrix

| Crash boundary | Required restart behavior |
|---|---|
| Before manifest commit | Re-run deterministic create-or-verify against the same Quarantine; never re-run Provider action |
| After manifest commit, before deletion intent | Verify manifest, projection and every referenced resource, then continue at deletion intent |
| After deletion intent, before erasure claim | Dedicated eraser verifies all evidence and creates / consumes the one exact claim |
| After erasure claim, before key destruction | Reconcile the same immutable `erasure_id`; never create a replacement destructive operation |
| After key destruction, before ciphertext unlink | Verify the same erasure outcome and finish unlink / acknowledgement |
| After ciphertext unlink, before `QUARANTINE_ERASED` | Reconcile absence against the durable intent and manifest |
| After erasure, before ExecutionResult | Reconstruct from manifest / projection without sink construction, decryption, Adapter collection or Provider retrieval |
| After ExecutionResult, before `SUCCEEDED` | Verify identical result digest and acknowledge only |

## Decision 5: TPM-witnessed authenticated generations

Audit Head and Wrapped Key State use one generic `AuthenticatedGenerationCoordinator`. Production
uses exactly one implementation family: an authenticated SQLite generation-record store plus
separate TPM 2.0 NV monotonic witnesses. The authenticated generation record is:

```text
namespace
generation
immutable_blob_id
state_digest
previous_anchor_digest
schema_version
tpm_nv_index_identity
trust_epoch
```

Fresh provisioning is a separate, explicit operation. Under the host-wide lock it requires an empty
namespace in the SQLite record/blob store, TPM counter 0, a provisioned NV identity matching trusted
operator configuration and a never-used trust epoch. It then durably writes and authenticates the
initial immutable state blob plus a `generation=0` Genesis record and reads both back; the TPM stays
at 0. That exact pair is the Current `g=0` input to the normal commit protocol. Counter 0 plus any
pre-existing local state, or a nonzero counter without the exact record, is recovery-required—not a
fresh installation. Normal startup and Mission input cannot create Genesis or seed it from local
state.

Commit protocol:

1. under the host-wide OS generation lock, read TPM generation `g` and authenticate the exact
   SQLite record / blob for `g`, using only the explicitly provisioned Genesis pair when `g=0`;
2. serialize and authenticate the next complete state and prepare immutable record `g + 1`;
3. insert the encrypted content-addressed blob and create-or-verify record in a dedicated SQLite
   database using `synchronous=FULL`, durable commit and read-back verification;
4. re-read TPM and require it still equals `g`, then increment the namespace's TPM NV counter to
   `g + 1` and read it back; and
5. reload and authenticate the exact record / blob selected by the TPM value.

The pair `(current TPM generation, exact authenticated SQLite record)` is authority. A prepared
`g + 1` record with TPM still at `g` is an orphan, not Current. If TPM advanced but the exact record
or blob is missing / corrupt, recovery fails closed. Restoring the entire SQLite database cannot
restore TPM, so rollback leaves the higher witnessed generation without a valid matching record and
is detected.

Phase 0C supplies and wires this durable Production composition rather than only protocols and
in-memory test doubles. `AuthenticatedGenerationCoordinator` composes:

- `SqliteGenerationRecordStore.put_blob_if_absent/create_record_or_verify/get_exact`, which stores
  encrypted, content-addressed immutable generations and authenticated commit records durably; and
- `TpmNvMonotonicWitness.read/increment`, using separate provisioned TPM NV counter / identity for
  `audit_head`, `wrapped_key_state` and `deployment_epoch`.

The TPM witness is outside the SQLite filesystem, snapshot, backup and restore domain. Production
configuration accepts only `provider=tpm2_nv` for these witnesses; a path, generic service name,
Vault alternative, local slot, integer file or in-memory object is rejected. Mission / caller input
cannot choose a witness provider. Record authentication keys are opaque TPM-sealed or OS-keystore
handles and are not stored with generation data or Application configuration.

TPM unavailable, NV identity mismatch, counter decrease, reset indication, ambiguous provisioning
or missing Current record produces typed `AnchorRecoveryRequiredError` and durable operational
state `ANCHOR_RECOVERY_REQUIRED`. All Missions remain paused; Production never automatically
re-seeds from local data. Recovery is offline and requires all workers stopped plus a single-use
human approval bound to namespace, reason, old/new trust epochs, old/new NV identities, the last
externally verified generation-record digest, exact adopted state digest / immutable blob ID,
approver and issuance/expiry. Only externally verified state named by that record may be adopted. If
none exists, recovery creates an explicitly empty generation-0 state and discards local candidates.
It then records and verifies the audit discontinuity, advances the dedicated deployment epoch and
consumes the approval before work resumes. Missing, stale, reused or ambiguous approval/evidence
fails closed.

Audit Head and Wrapped Key constructors require both capabilities in Production. There is no
Production overload or fallback that accepts a generic anchor provider. Unit tests may use explicit
in-memory doubles; integration tests run the same Production `TpmNvMonotonicWitness` implementation
against `swtpm`, including process restart, SQLite rollback, TPM reset and missing-record cases.

The blob-store root and anchor authority are both independent of the replaceable Audit / Wrapped
Key state directories and of each other. Loss, replacement, rollback ambiguity or authentication
failure of either fails closed; it does not authorize local alternate state. Wrapped Key State
remains encrypted in the blob store and uses its separate key domain.

## Decision 6: Design Stop is a terminal authority event

The latest trusted Current-Phase gate dominates old base-refresh, Resume, label and request
evidence. An invariant-family recurrence emits:

```text
loop_state = BLOCKED_LIMIT
stop_reason = INVARIANT_FAMILY_RECURRENCE
effective_state = DESIGN_CHANGE_REQUIRED
```

A base-refresh status authorizes one exact expected-HEAD branch update only. It cannot remove the
stop label or issue a fix request. The transition is consumed by the resulting old-head / new-head /
target-base / gate tuple and cannot be reused after another gate.

Resume requires a dedicated, single-use `redteam-design-approval` record bound to:

- the latest blocking gate permalink;
- Current Phase and full current PR HEAD;
- full approved design commit SHA incorporated in both `main` and the PR;
- repository design permalink;
- invariant-family policy digest; and
- approver identity.

Immediately before a Codex trigger, the runner re-queries all of those inputs, current checks and
complete label state. Generic Resume, free-text resolution, old refresh status or manual label
removal does not authorize implementation.

## Finding coverage

### Latest formal review (`ae09f40f6b593060d060cfb9a5090e0de4e2875d`)

| Formal-review issue | Design decision |
|---|---|
| [Consumed Claim can still release plaintext repeatedly through an importable token](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3918170344) | Decision 1 removes the standalone resolver/token and makes the winning consume operation return only an ephemeral, one-call Executor continuation; the at-most-once counter is the Dispatch Claim, not the Secret |
| [Blob and anchor share one rollback unit](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3918170352) | Decision 5 fixes Production to authenticated SQLite generation records selected by a TPM 2.0 NV monotonic witness, so a whole-file rollback cannot restore a Current old pair |
| [Expired collection owner remains able to mutate after takeover](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3918170356) | Decision 2 adds typed leases, TPM-backed deployment epochs, heartbeat renewal, an exact mutation predicate and conditional publication; Decision 3 applies the contract to ingestion and separates erasure |

### Prior formal review (`4e86a7e4f5a6578133cd3579fbb5a004ab5c80c3`)

| Formal-review issue | Design decision |
|---|---|
| Direct full-object publication minting releases plaintext | Decisions 3 and 4 remove the factory / raw-return path and require repository-bound ingestion |
| Secret resolution permitted before final dispatch validation | Decision 1 separates `AUTHORIZED` from a post-gate Dispatch Claim and fixed-channel injection |
| Raw-result limit comes from global caller configuration | Decision 2 binds the exact trusted Tool Definition and only permits a stricter system cap |
| Full-object ingestion deletes Quarantine while result is memory-only | Decision 4 commits / verifies the durable manifest before deletion intent |
| Audit / key generation becomes unreachable after CAS and path swap | Decision 5 anchors digest and immutable blob identity in a trusted durable store |
| Retention begins at Execution creation | Decision 2 persists trusted collection-start retention and reuses it across restart |

### Pre-implementation specification consistency closure

| Consistency risk | Closed specification |
|---|---|
| Secret revocation after Claim creation conflicted with the older `BLOCKED` attempt invariant | Decision 1 defines two disjoint durable `BLOCKED` forms and repository read/write validation for every Claim / attempt combination |
| A flattened or numeric DataAccessGrant migration would break the implemented wire shape | Decision 1 preserves nested `ResourceBinding` and string versions, maps exact lifecycle heads, and defines a one-to-one fail-closed legacy migration |
| Renewable leases could be revived by UTC rollback or interpreted across unrelated hosts | Decision 2 uses deployment-epoch-scoped monotonic deadlines, stops on UTC integrity failure, and fixes Phase 0C to one host / TPM / database / root |
| Erasure had no exact Provider operation identity after an unknown outcome | Decision 4 atomically stores only a consumed Claim and binds destroy / reconcile to one `erasure_id + key_metadata_digest` |
| TPM counter zero did not distinguish first provisioning from reset / lost state | Decision 5 defines authenticated Generation 0 provisioning and exact, single-use recovery-approval bindings |
| State transition, audit and external-work intent could be committed by different repositories | SystemDesign Section 32.1 assigns each transition to one transaction aggregate owner and `ApplicationUnitOfWork`; external work starts only after durable intent / authority commit |
| Security-sensitive digest definitions were distributed across components | SystemDesign Section 32.2 makes the versioned digest catalog and canonical digest service normative and rejects alternate implementations |
| Production dependency wiring could admit a test double, alternate authority or partial startup | SystemDesign Section 35.2 fixes one composition root, startup self-check, mission-admission barrier, immutable trusted wiring and reverse-order cleanup |

## Required implementation sequence

1. Merge this Source-of-Truth revision and issue a current-HEAD Design Approval. Do not restart the
   current loop before both the design commit and approval are incorporated and validated.
2. Replace exported Secret delivery components with the Executor-owned consume-before-release
   transaction, ephemeral one-call continuation and no standalone plaintext resolver/token; split
   logical Secret IDs from immutable Version IDs, add audited lifecycle events and enforce the
   revoke / consume linearization transaction; preserve the existing nested `ResourceBinding` and
   string version schema, migrate each legacy Secret Reference one-to-one and fail closed on
   ambiguity; encode the distinct pre-dispatch and stale-Secret `BLOCKED` counter / Claim
   invariants; do not add a per-Secret usage counter.
3. Inject a composition-root trusted Clock into Executor and remove caller security timestamps
   from collection / lease / retention decisions. Add separate typed collection / ingestion
   leases, TPM-backed deployment epochs, the exact mutation predicate, heartbeat / cancellation and
   fence-specific storage publication. Use same-boot monotonic deadlines for expiry, fail closed on
   UTC rollback and reject unsupported multi-host topology.
4. Make all Quarantine construction and lookup side-effect free; implement explicit verified
   erasure as a dedicated component after ingestion releases its lease; consume one fully bound
   erasure claim in the state-transition transaction, expose no unconsumed erasure claim and bind
   destroy / reconcile to the same immutable erasure ID and key-metadata digest.
5. Persist the plaintext-free ExecutionResultProjection with the manifest and prohibit result
   collection or Provider access after `INGESTED_DURABLE`.
6. Wire the authenticated SQLite generation record store to provisioned TPM 2.0 NV witnesses for
   Audit Head, Wrapped Key State and deployment epoch; reject every non-TPM Production fallback and
   implement explicit Generation 0 provisioning and approval-bound `ANCHOR_RECOVERY_REQUIRED`
   handling.
7. Review every public entry point and sibling path in all affected invariant families; update the
   invariant audit and add state-machine evidence.
8. Implement the Section 32.1 transaction aggregates and `ApplicationUnitOfWork` so each state
   transition, audit event and outbox / intent record commits atomically and no child repository
   can commit independently. Implement the Section 32.2 versioned digest catalog and route all
   security-sensitive digest calculations through its single canonical service.
9. Implement the Section 35.2 production composition root, including fixed construction order,
   startup self-check, mission-admission barrier, production-provider / test-double validation,
   immutable trusted wiring and reverse-order startup failure / shutdown cleanup. Record one
   logical-component-to-physical-module mapping and enforce Section 35 ownership / dependency
   boundaries without requiring a wholesale source-tree move.
10. Run the complete Phase 0C gate and request one exhaustive
   fresh formal review.

## Required tests

- No importable/public Broker, channel registry, callback protocol or plaintext-returning Secret
  API can be used to construct a delivery path outside Executor.
- Secret injection denial from `AUTHORIZED`, `BLOCKED`, stale Mission / Epoch, expired / consumed
  Claim and mismatched Tool / Adapter / Secret set.
- Crash before / after Claim consumption, Adapter entry / return and Provider submit without
  Secret delivery or submit replay; the Adapter test double retains no plaintext.
- Concurrent dispatch calls prove exactly one Claim consumer receives the ephemeral continuation;
  it cannot be serialized, imported, reused or invoked after the enclosing call. A later separately
  authorized Execution may use the same `CONFIRMED` and unexpired Secret version without a
  lifetime usage counter.
- Secret updates append immutable Version IDs under a stable logical ID; lifecycle replay, reorder,
  gap, digest tampering or head rollback fails closed. Revoke-before-consume denies by atomically
  invalidating the unsent Claim and blocking the Execution; consume-before-revoke permits only that
  already-claimed attempt.
- Pre-dispatch `BLOCKED` has attempt count zero and no Claim; stale-Secret `BLOCKED` has attempt
  count one and the exact invalidated Claim. Every other state / counter / Claim combination fails
  both repository write and read verification.
- Existing nested `ResourceBinding` and string resource versions migrate without schema flattening.
  Each legacy Secret Reference becomes exactly one logical Secret Version 1; ambiguous state,
  digest or provenance raises `SecretMigrationRequiredError` without grouping, latest-version
  inference, compatibility loading or plaintext re-ingest.
- Cross-tool output limits and caller / global attempted expansion.
- Caller future/backdated timestamps do not affect a long-running Provider collection; trusted
  Clock start, Mission deadline cap and restart values remain stable.
- Long-running collection and ingestion heartbeats renew only under the exact
  lease/owner/deployment-epoch/fence/release/expiry/authority/state-version predicate and never
  extend Mission / retention authority. Forced expiry, process restart, database rollback and
  takeover reject delayed writes, including when an Adapter ignores cancellation.
- Same-boot monotonic time determines expiry. Wall-clock rollback and excessive wall/monotonic
  divergence raise `ClockIntegrityError` and cannot extend authorization or TTL. Child workers share
  one root epoch, a second root invalidates the first and multi-host startup is rejected.
- Direct full-object factory, caller receipt / reference and compatibility-loader denial.
- Positive, negative and failure-path tests at every ingestion / deletion crash boundary, proving
  no sink/factory/ingestion construction can erase before complete durable verification; concurrent
  erasers have one Claim winner and unknown key-destruction outcomes reconcile only the same ID.
- Erasure-claim creation, consumption and `ERASURE_CLAIMED` transition are atomic; no unconsumed
  claim is repository-visible. Destroy and reconcile use the exact same erasure / key-metadata
  identity, and ciphertext remains linked until a read-back-verified `CONFIRMED` result.
- Recovery from durable manifest / projection after Quarantine erasure with zero Adapter or
  Provider collection calls.
- Audit / Key generation property or state-machine tests for prepare, SQLite record/blob commit,
  TPM increment, directory replacement and restart.
- The Production TPM witness implementation passes `swtpm` integration tests for restart, SQLite
  rollback, TPM reset, NV identity mismatch and missing / corrupt Current records. Production
  rejects every non-TPM / same-restore-domain / test-double configuration and never auto-reseeds.
- Fresh provisioning accepts only an empty namespace, configured NV identity, counter zero and an
  unused trust epoch, then read-back verifies the Generation 0 record / blob without incrementing
  the counter. Recovery rejects stale or incomplete approvals and binds the adopted state to old /
  new trust epochs and NV identities plus the last externally verified record digest.
- Rule-based state-machine tests cover Dispatch/Secret delivery, ingestion/erasure/result recovery,
  collection / ingestion lease timing and fencing, and authenticated generation transitions in
  addition to example regressions.
- Fault injection before and after every transaction aggregate commit proves no partial
  state/audit/outbox-or-intent commit, child repository commit or same-ID/different-payload retry is accepted.
- Digest-catalog tests reject unregistered families, duplicate owners, missing included fields,
  version/canonicalization drift and every alternate digest implementation.
- Composition-root startup-step fault injection proves Mission admission remains disabled on any
  failure, partially created dependencies close in reverse order, Production rejects test doubles /
  unsupported providers / multiple roots, trusted dependencies cannot be swapped after startup,
  and shutdown follows the dependency order.
- Architecture tests reject missing or duplicate logical-component mappings, forbidden dependency
  directions, owner-external state-transition commands and digest definitions outside the canonical owner.
- Design Stop precedence, old refresh reuse denial, generic Resume denial, one-use Design Approval
  and final trigger-time drift tests.

## Non-goals

- No real C2, MCP, external target, credential discovery or payload behavior is added.
- No Secret value is placed in a test report, snapshot, exception or prompt.
- This design does not weaken the one-submit / unknown-outcome policy.
- This document does not itself remove the current stop label or authorize implementation.
