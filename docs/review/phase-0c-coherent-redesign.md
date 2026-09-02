# Phase 0C Coherent Redesign: Durable Execution Lifecycle

## Status

- Design status: human-approved direction; governance implementation and exact-HEAD Design Approval remain pending
- Current implementation PR: #3 (`ai/redteam-agent-phase-loop`)
- Blocked implementation HEAD: `39859abf240c05d932df515b84e4932918577688`
- Formal review: <https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5081290374>
- Trusted recurrence stop: <https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5498115527>
- Operator correction after invalid old-Resume reuse: <https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5498152000>

This document records the coherent redesign required after the following invariant families
recurred in a second Phase 0C formal review:

- `authorization-lifecycle`
- `secret-plaintext-boundary`
- `audit-recovery-durability`

The same review also retained a `filesystem-concurrency-retention` finding. The design closes all
six retained P1 findings as one state-transition and durability redesign. It does not authorize a
new implementation request by itself. Resume requires the dedicated current-HEAD Design Approval
defined in `docs/ai-development-loop.md`.

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

### Secret injection

Plans, PolicyDecision, ExecutionRequest and Graph State carry Secret Reference metadata only.
There is no general application API that returns plaintext bytes.

`SecretInjectionBroker` performs the following fixed transaction:

1. load the Current unconsumed Dispatch Claim;
2. load Current Mission / Execution / PolicyDecision / exact DataAccessGrant;
3. load and verify Current Secret metadata and retention / revocation state;
4. resolve the fixed trusted Adapter channel from the Tool / Adapter registry;
5. decrypt and inject the value into that channel immediately before submit;
6. destroy the temporary buffer and mark the Claim consumed regardless of submit result.

The caller cannot choose a callback, consumer, environment variable, command line, endpoint or
alternate Adapter channel. `AUTHORIZED`, `BLOCKED`, `RUNNING`, terminal states, expired / consumed
Claims and Mission / Epoch / Tool / Adapter mismatch all deny Secret injection.

Phase 0C uses a test double of the same channel interface. Phase 4 / 5 production Adapters must use
the process-isolated channel required by the Sandbox policy. In-process trusted components remain
part of the TCB; untrusted plugin code must not execute inside that TCB.

## Decision 2: trusted result-collection authority

Before `ExecutionAdapter.collect_result()` receives a sink, Executor persists one
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

Restart reuses the stored collection start, retention, output limit, sink and cursor. It does not
recalculate them from Execution creation time or restart time. Collection recovery may retrieve
the same Provider task result but never resubmits the external action.

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
- creation time; and
- its own canonical digest.

Output IDs are deterministic from Execution, Receipt, Quarantine digest, rule version and output
sequence. Output stores implement create-or-verify: replay of identical payload is idempotent and a
different digest at the same identity fails closed. Artifact bodies and Secret ciphertext may be
durably written to an internal staging namespace first, but their metadata is not a Current Context
Resource. After read-back verification, public Artifact / Secret metadata, the manifest and the
`INGESTED_DURABLE` transition commit in one Application Database transaction. Context Selector,
Knowledge Reducer and normal read APIs cannot observe partially prepared output.

### Erasure ordering

1. prepare and verify output ciphertext / artifact bodies in an internal staging namespace;
2. atomically publish output metadata, commit the SecureIngestionManifest and transition to
   `INGESTED_DURABLE` in the Application Database;
3. read-back verify the committed manifest and every referenced publication;
4. commit a manifest-bound Quarantine Deletion Intent;
5. transition to `DELETE_PENDING`;
6. destroy the resource key and unlink ciphertext;
7. transition to `QUARANTINE_ERASED`;
8. construct / persist ExecutionResult from the manifest; and
9. acknowledge `SUCCEEDED`.

### Crash matrix

| Crash boundary | Required restart behavior |
|---|---|
| Before manifest commit | Re-run deterministic create-or-verify against the same Quarantine; never re-run Provider action |
| After manifest commit, before deletion intent | Verify manifest and continue at deletion intent |
| After deletion intent, before key destruction | Resume the same deletion intent |
| After key destruction, before ciphertext unlink | Verify cryptographic erasure and finish unlink / acknowledgement |
| After ciphertext unlink, before `QUARANTINE_ERASED` | Reconcile absence against the durable intent and manifest |
| After erasure, before ExecutionResult | Reconstruct from manifest without decryption or Provider retrieval |
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

Production may use a Vault, OS-keystore-backed state service or equivalent trusted durable store.
An external integer combined with a blob that exists only beneath a replaceable local directory is
development-only and rejected in Production. Wrapped Key State remains encrypted in the trusted
blob store and uses its separate key domain.

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

| Formal-review issue | Design decision |
|---|---|
| Direct full-object publication minting releases plaintext | Decisions 3 and 4 remove the factory / raw-return path and require repository-bound ingestion |
| Secret resolution permitted before final dispatch validation | Decision 1 separates `AUTHORIZED` from a post-gate Dispatch Claim and fixed-channel injection |
| Raw-result limit comes from global caller configuration | Decision 2 binds the exact trusted Tool Definition and only permits a stricter system cap |
| Full-object ingestion deletes Quarantine while result is memory-only | Decision 4 commits / verifies the durable manifest before deletion intent |
| Audit / key generation becomes unreachable after CAS and path swap | Decision 5 anchors digest and immutable blob identity in a trusted durable store |
| Retention begins at Execution creation | Decision 2 persists trusted collection-start retention and reuses it across restart |

## Required implementation sequence

1. Implement the `DESIGN_CHANGE_REQUIRED` / Design Approval governance path and tests. Do not
   restart the current loop before this is human-merged.
2. Add schema / repository migrations for Dispatch Claim, Result Collection Authority,
   SecureIngestionManifest and Quarantine Deletion Intent.
3. Implement `DISPATCH_CLAIMED`, SecretInjectionBroker and submit reconciliation.
4. Implement exact-Tool Result Collection Authority and stable retention.
5. Remove full-object / legacy receipt ingestion and implement the repository-bound stream path.
6. Implement durable ingestion / deletion reconciliation and manifest-based result recovery.
7. Replace duplicate Audit / Key generation commit logic with the shared Coordinator and trusted
   blob / anchor provider.
8. Run the complete Phase 0C gate, update the invariant-family audit and request one exhaustive
   fresh formal review.

## Required tests

- Secret injection denial from `AUTHORIZED`, `BLOCKED`, stale Mission / Epoch, expired / consumed
  Claim and mismatched Tool / Adapter.
- Crash before / after Claim commit, Secret injection and Provider submit without automatic replay.
- Cross-tool output limits and caller / global attempted expansion.
- Long-running Provider collection with trusted start retention, Mission deadline cap and stable
  restart values.
- Direct full-object factory, caller receipt / reference and compatibility-loader denial.
- Positive, negative and failure-path tests at every ingestion / deletion crash boundary.
- Recovery from durable manifest after Quarantine erasure.
- Audit / Key generation property or state-machine tests for prepare, blob write, CAS, local marker,
  directory replacement and restart.
- Missing / corrupt anchored blob fail-closed tests without alternate fallback.
- Design Stop precedence, old refresh reuse denial, generic Resume denial, one-use Design Approval
  and final trigger-time drift tests.

## Non-goals

- No real C2, MCP, external target, credential discovery or payload behavior is added.
- No Secret value is placed in a test report, snapshot, exception or prompt.
- This design does not weaken the one-submit / unknown-outcome policy.
- This document does not itself remove the current stop label or authorize implementation.
