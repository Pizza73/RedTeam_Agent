# Phase 0C Coherent Redesign: Durable Execution Lifecycle

## Status

- Design status: human-approved second coherent-redesign direction; governance merge and exact-HEAD Design Approval remain pending
- Current implementation PR: #3 (`ai/redteam-agent-phase-loop`)
- Blocked implementation HEAD: `4e86a7e4f5a6578133cd3579fbb5a004ab5c80c3`
- Formal review: <https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5085287765>
- Trusted recurrence gate: <https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5503904111>
- Trusted design stop: <https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5503904489>
- Prior coherent-redesign review: <https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5081290374>

This document records the coherent redesign required after the following invariant families
recurred in a second Phase 0C formal review:

- `authorization-lifecycle`
- `secret-plaintext-boundary`
- `audit-recovery-durability`

The latest review retained six P1 findings across those families plus
`filesystem-concurrency-retention` and `integrity-cryptography-keys`. They show that the first
coherent redesign did not yet fix construction provenance, consume-before-release ordering,
side-effect-free recovery, result reconstruction, trusted-clock ownership, or a durable
Production generation composition. This revision closes those gaps as one state-transition and
durability redesign. It does not authorize a new implementation request by itself. Resume requires
the dedicated current-HEAD Design Approval defined in `docs/ai-development-loop.md`.

## Problem statement

The current code applies security checks at individual methods, but authority and durable outcome
are split across Executor, Secret Store, RawResultSink Factory, Quarantine, Secure Ingestion, Audit
Head Store and Key State Store. This permits adjacent paths to reconstruct partial authority or to
observe different commit boundaries.

The redesign makes three facts explicit:

1. Policy authorization is not immediate authority to obtain plaintext or perform a side effect.
2. Raw-result ingestion and quarantine erasure are one recoverable logical transaction.
3. A committed generation must be identified by its authenticated content, not only by an integer
   and a replaceable local path.

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
- ApprovalRequest / ApprovalRecord when required;
- issued / expiry time and consumed state; and
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
2. load the Current unconsumed Dispatch Claim and the complete authorization-bound set of Secret
   Reference IDs;
3. in one OCC transaction, transition that exact Claim to consumed for the one Adapter dispatch;
4. read back the consumed record and verify its digest, state version and consumption identity;
5. only after durable consumption, load Current Secret metadata, verify retention / revocation,
   decrypt into bounded mutable buffers and invoke the already-selected trusted Adapter dispatch
   port exactly once;
6. zero all temporary buffers on every return, cancellation and exception path; and
7. persist a confirmed Task identity when available, otherwise enter Reconciliation without
   replaying Secret delivery or Provider submit.

Consumption failure occurs before decryption and releases no plaintext. A crash after consumption
but before, during, or after Adapter entry is deliberately at-most-once: restart does not inject
again and does not call submit again. It reconciles using the immutable execution identity and
idempotency key; an unresolvable outcome becomes `OUTCOME_UNKNOWN`. This chooses safety over
availability instead of claiming cross-process exactly-once delivery.

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
- deterministic sink ID and resume cursor; and
- collection lease expiry.

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

The same trusted reading is used for authority creation and the initial collection lease. Restart
reuses the stored collection start, retention, output limit, sink and cursor. It does not
recalculate them from Execution creation time, restart time or a caller parameter. Collection
recovery may retrieve the same Provider task result but never resubmits the external action.

## Decision 3: one repository-bound ingestion entry point

The application-facing ingestion API accepts only `ingestion_id`:

```text
SecureIngestionCoordinator.run(ingestion_id)
```

The Coordinator loads and verifies ResultIngestionRecord, ExecutionRecord, RawResultReceipt,
Quarantine metadata, ResultCollectionAuthority and Current Mission. It acquires an ingestion lease
with OCC before decrypting.

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
destroy a key or unlink ciphertext. Erasure is exposed only through an explicit internal
`erase_verified(intent, manifest)` operation after all prerequisite read-back checks succeed.

1. load and verify Execution, Receipt, Result Collection Authority and Quarantine metadata;
2. prepare and verify output ciphertext / artifact bodies in an internal staging namespace;
3. construct and verify the plaintext-free ExecutionResultProjection;
4. atomically publish output metadata, commit the SecureIngestionManifest and transition to
   `INGESTED_DURABLE` in the Application Database;
5. read-back verify the committed manifest, projection and every referenced Artifact / Secret;
6. commit and read-back verify a manifest-bound Quarantine Deletion Intent;
7. transition to `DELETE_PENDING`;
8. call the explicit erasure operation, destroy the resource key and unlink ciphertext;
9. transition to `QUARANTINE_ERASED`;
10. construct / persist ExecutionResult from the manifest and projection without Adapter access;
    and
11. acknowledge `SUCCEEDED`.

Recovery first loads the current ingestion state. For `INGESTED_DURABLE`, `DELETE_PENDING` or
`QUARANTINE_ERASED`, it loads and authenticates the manifest, projection and every referenced
durable resource before constructing any deletion-capable object. For `DELETE_PENDING`, it also
loads and authenticates the exact deletion intent before calling erasure. Missing or corrupt
evidence stops with no additional deletion.

### Crash matrix

| Crash boundary | Required restart behavior |
|---|---|
| Before manifest commit | Re-run deterministic create-or-verify against the same Quarantine; never re-run Provider action |
| After manifest commit, before deletion intent | Verify manifest, projection and every referenced resource, then continue at deletion intent |
| After deletion intent, before key destruction | Verify manifest, projection, resources and intent, then resume the same deletion intent |
| After key destruction, before ciphertext unlink | Verify cryptographic erasure and finish unlink / acknowledgement |
| After ciphertext unlink, before `QUARANTINE_ERASED` | Reconcile absence against the durable intent and manifest |
| After erasure, before ExecutionResult | Reconstruct from manifest / projection without sink construction, decryption, Adapter collection or Provider retrieval |
| After ExecutionResult, before `SUCCEEDED` | Verify identical result digest and acknowledge only |

## Decision 5: content-bound authenticated generations

Audit Head and Wrapped Key State use one generic `AuthenticatedGenerationCoordinator`. The
external anchor is:

```text
namespace
generation
immutable_blob_id
state_digest
previous_anchor_digest
schema_version
```

Commit protocol:

1. serialize and authenticate the next complete state;
2. write it to a content-addressed immutable trusted blob store;
3. perform durable-write and read-back authentication;
4. CAS the complete external anchor from the expected prior anchor;
5. reload the exact anchored blob and verify generation / digest / namespace; and
6. update a non-authoritative local cache / marker.

Recovery always starts from the external anchor. A prepared blob without an advanced anchor is not
committed and can be collected. An advanced anchor with a missing local marker is finalized from
the anchored blob. An advanced anchor whose blob is missing or invalid fails closed and never
falls back to an older alternate file.

Phase 0C supplies and wires a durable Production composition rather than only protocols and
in-memory test doubles. The local-first reference composition is a
`DurableAuthenticatedGenerationBackend` stored in a separately configured control-plane root. Its
closed API is `put_blob_if_absent`, `get_blob` and `compare_and_set_anchor`; callers cannot update
rows or paths directly. The reference backend stores immutable encrypted blobs and namespace-scoped
anchors in a dedicated SQLite database using `synchronous=FULL`: it commits and read-back verifies
the blob before a later atomic anchor CAS transaction, so a crash can create only a non-authoritative
orphan blob, never an anchor to absent content. Anchors are authenticated with an opaque key
supplied by the configured OS key store or equivalent `AnchorAuthenticator`. The authentication
key is not stored in the generation database or Application configuration.

Audit Head and Wrapped Key constructors require this complete backend in Production. There is no
Production overload or fallback that accepts only an integer GenerationStore, local slot files or
in-memory anchor/blob objects. Development test doubles are accepted only by an explicit test
composition root that cannot be selected by Mission or caller input.

The backend root is independent of the replaceable Audit / Wrapped Key state directories. Loss,
replacement, rollback ambiguity or authentication failure of the backend itself fails closed; it
does not authorize local alternate state. A Vault or OS-keystore-backed remote state service can
replace the local-first backend through the same atomic contract. Wrapped Key State remains
encrypted in the trusted blob store and uses its separate key domain.

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

### Latest formal review (`4e86a7e4f5a6578133cd3579fbb5a004ab5c80c3`)

| Formal-review issue | Design decision |
|---|---|
| [Caller can construct the exported Broker with a caller-owned channel](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3910452535) | Decision 1 removes separately constructible / exported delivery components and puts delivery inside the Executor-owned fixed Adapter transaction |
| [Claim is consumed after plaintext delivery](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3910452541) | Decision 1 durably consumes and verifies the exact Claim before decrypting or releasing plaintext; every later crash is non-replayable |
| [Sink construction erases Quarantine before manifest/resource verification](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3910452545) | Decision 4 makes all construction/read paths side-effect free and requires complete read-back verification before explicit erasure |
| [Result finalization recollects after Quarantine erasure](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3910452550) | Decision 4 makes the manifest-bound ExecutionResultProjection sufficient and prohibits Adapter/Provider access after `INGESTED_DURABLE` |
| [Collection start accepts caller `now`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3910452561) | Decision 2 makes Executor's composition-root Clock the only security time source and removes caller time from collection APIs |
| [Authenticated generation exists only as in-memory test doubles](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3910452566) | Decision 5 requires and wires a durable Production backend; integer-only/local/in-memory alternatives are test-only and unavailable to Mission input |

### Prior formal review

| Formal-review issue | Design decision |
|---|---|
| Direct full-object publication minting releases plaintext | Decisions 3 and 4 remove the factory / raw-return path and require repository-bound ingestion |
| Secret resolution permitted before final dispatch validation | Decision 1 separates `AUTHORIZED` from a post-gate Dispatch Claim and fixed-channel injection |
| Raw-result limit comes from global caller configuration | Decision 2 binds the exact trusted Tool Definition and only permits a stricter system cap |
| Full-object ingestion deletes Quarantine while result is memory-only | Decision 4 commits / verifies the durable manifest before deletion intent |
| Audit / key generation becomes unreachable after CAS and path swap | Decision 5 anchors digest and immutable blob identity in a trusted durable store |
| Retention begins at Execution creation | Decision 2 persists trusted collection-start retention and reuses it across restart |

## Required implementation sequence

1. Merge this Source-of-Truth revision and issue a current-HEAD Design Approval. Do not restart the
   current loop before both the design commit and approval are incorporated and validated.
2. Replace exported Secret delivery components with the Executor-owned consume-before-release
   transaction and remove every caller construction / callback path.
3. Inject a composition-root trusted Clock into Executor and remove caller security timestamps
   from collection / lease / retention decisions.
4. Make all Quarantine construction and lookup side-effect free; implement explicit verified
   erasure after manifest, projection, resource and intent read-back.
5. Persist the plaintext-free ExecutionResultProjection with the manifest and prohibit result
   collection or Provider access after `INGESTED_DURABLE`.
6. Implement and wire the durable authenticated generation backend, removing Production
   integer-only / local-slot fallback.
7. Review every public entry point and sibling path in all affected invariant families; update the
   invariant audit and add state-machine evidence.
8. Run the complete Phase 0C gate and request one exhaustive
   fresh formal review.

## Required tests

- No importable/public Broker, channel registry, callback protocol or plaintext-returning Secret
  API can be used to construct a delivery path outside Executor.
- Secret injection denial from `AUTHORIZED`, `BLOCKED`, stale Mission / Epoch, expired / consumed
  Claim and mismatched Tool / Adapter / Secret set.
- Crash before / after Claim consumption, Adapter entry / return and Provider submit without
  Secret delivery or submit replay; the Adapter test double retains no plaintext.
- Cross-tool output limits and caller / global attempted expansion.
- Caller future/backdated timestamps do not affect a long-running Provider collection; trusted
  Clock start, Mission deadline cap and restart values remain stable.
- Direct full-object factory, caller receipt / reference and compatibility-loader denial.
- Positive, negative and failure-path tests at every ingestion / deletion crash boundary, proving
  no sink/factory construction can erase before complete durable verification.
- Recovery from durable manifest / projection after Quarantine erasure with zero Adapter or
  Provider collection calls.
- Audit / Key generation property or state-machine tests for prepare, blob write, CAS, local marker,
  directory replacement and restart.
- Durable Production backend restart plus missing / corrupt anchored blob fail-closed tests without
  alternate fallback; Production rejects test-double and integer-only configurations.
- Rule-based state-machine tests cover Dispatch/Secret delivery, ingestion/erasure/result recovery,
  collection timing and authenticated generation transitions in addition to example regressions.
- Design Stop precedence, old refresh reuse denial, generic Resume denial, one-use Design Approval
  and final trigger-time drift tests.

## Non-goals

- No real C2, MCP, external target, credential discovery or payload behavior is added.
- No Secret value is placed in a test report, snapshot, exception or prompt.
- This design does not weaken the one-submit / unknown-outcome policy.
- This document does not itself remove the current stop label or authorize implementation.
