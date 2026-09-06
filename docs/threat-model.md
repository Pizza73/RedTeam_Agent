# AI Development Loop Threat Model

## Assets

- Source code and Git history
- Requirements, safety invariants and acceptance criteria
- GitHub Actions token and ChatGPT-authenticated Codex access
- Private repository contents
- C2/MCP credentials and endpoint identities
- Review verdicts and phase state

## Trust Boundaries

```text
PR content/comments --untrusted--> fresh read-only local reviewer
Repository files   --untrusted--> scoped local implementation worker
GitHub bot markers --validated--> Local phase orchestrator
Operator host / sandbox / clean-main launcher --TCB--> isolated local workers
Local worker result --untrusted until validated--> launcher-authenticated local-review-v1
Local gh identity  --trusted dispatcher--> GitHub workflow_dispatch
GitHub Actions      --trusted controller--> PR labels, comments and status
CI evidence         --trusted when re-queried and bound to SHA--> phase gate
External C2/MCP     --untrusted until approved/bound--> Adapter
```

## Threats and Controls

| Threat | Control |
|---|---|
| PR/Source prompt injection | Reviewer/implementer prompts treat repository content as data; protected governance files; sanitize structured requests |
| Codex changes tests/spec to pass | Base-branch protected-path checker; checker self-protection; separate governance PR; independent review; local exact-SHA final merge gate |
| Forged PASS comment | Closed result/schema validation; launcher actor check; unique local start/result/finding permalink lookup; full head/base/source/policy, session, timeline and actual Check Run revalidation by the trusted workflow; model output is not attestation |
| Forged implementation/ready marker | Local orchestrator accepts only `github-actions[bot]`, exact current phase and exact current HEAD SHA |
| Stale review applied to new code | Exact 40-char `reviewed_sha == PR head.sha` |
| Infinite loop/cost exhaustion | Max 5 iterations per phase; same exact finding max 5; semantic family stops on its second formal-review occurrence; concurrency cancellation |
| Fork steals secret/token | Same-repository branch check; no AI implementation workflow on forks; minimal workflow permissions |
| Local worker steals GitHub token or alters its own gate | Only the clean-main parent accesses `gh`; worker filesystem/process isolation excludes the GitHub credential store, parent journal and governance checkout, and disables inherited plugins/MCP/user settings; no worker commit/push/workflow tools; missing isolation blocks startup |
| Duplicate/stale local dispatch or lost push acknowledgement | Durable exact-request/ready claim and parent journal precede spawn; full-SHA/digest evidence, bounded runtime/cancellation and current authority are revalidated; uncertain spawn/process/publication/push stops for reconciliation and never replays automatically |
| Implementer reuses its conversation as independent review | Launcher creates a different ephemeral process/session and read-only snapshot without implementation conversation; verifies actual completion and snapshot integrity, then publishes a single complete result; model cannot self-issue provenance |
| An old Cloud task races local cutover | No new Cloud tasks/triggers/fallback; reconcile already-sent exact-input work and late output before local consumption; stopping polling is not cancellation evidence; historical native gates and retry consumption remain |
| OpenAI key exposed to repository code | OpenAI API use is disabled and `OPENAI_API_KEY` is not a repository secret |
| Malicious test exfiltration | No unrelated credentials in test jobs; CI egress should be organization-restricted where possible |
| Local launcher/operator host compromised | Host/sandbox/clean-main launcher is explicitly trusted; GitHub workflow independently revalidates durable bindings/checks but cannot attest an uncompromised local model run; audit trail and emergency stop remain; no claim of a second independent reviewer account |
| Phase gate bypass | Ordered phase plan; label/current phase match; unique maximal incorporated adjacent PASS; required Check Runs queried from GitHub |
| Runner observes or races a Phase transition | Keep `ai-review-passed` as a transition marker, add next before removing current, make the Runner wait on a marked single/adjacent-dual Phase state, mutate only named managed labels, and revalidate every boundary; stale full-label replacement is forbidden |
| Stale static Phase status blocks or authorizes work | Active PR authority requires an exact label + workflow-authored current-HEAD request + unique maximal incorporated adjacent PASS; the status document is bootstrap-only |
| Cumulative later-Phase code is reviewed as an earlier Phase | Recovery validates trusted current-Phase finding/gate, identical reviewed/current trees and the incorporated phase base, then restores the same source Phase for a fresh review; it never rolls the unchanged tree to the prior Phase |
| Blocked PR cannot read newly merged governance and bypasses refresh evidence | Approver workflow binds the current-Phase `BLOCKED_LIMIT` gate, its unique adjacent base PASS, exact old HEAD and current default SHA; local update preserves the Phase and verifies both resulting ancestries and current checks. Non-design stops may then use a gate-bound Resume; recurrence stops remain blocked for Design Approval |
| Old base-refresh Resume overrides a later design stop | Latest trusted Current-Phase gate dominates older statuses and Resume markers; refresh transitions are one-use branch-update authority only; recurrence requires a current-HEAD, blocking-gate/design-commit-bound single-use Design Approval |
| Planner uses a retrieval hint as an arbitrary query or authorization expansion | Hints are strict typed purpose/fact/entity filters; the selector reads only index metadata, applies deterministic system-owned bounds and current data-access authorization, and rejects SQL/path/full-text expressions, unknown fields, cross-mission entities and caller-expanded limits |
| Stale context, denial feedback or working hypothesis is treated as authority | PlannerContextEnvelope is bound to current mission revision, epoch, grant, tool snapshot and TTL; safe feedback and application-owned plan state are data only and are rejected as PolicyDecision, Approval, Goal Evidence or Secret authority |
| Policy/error feedback leaks hidden tools, prohibited targets, raw output or secrets | A versioned feedback projector emits only allowlisted reason codes, already-visible tool references or coarse capability classes, and redacted summaries; raw provider data and exceptions never enter planner context |
| Alias collision or fuzzy matching merges different hosts, principals or sessions | Automatic canonical merge requires a matching strong identifier; alias-only and conflicting observations remain candidate records with provenance, and merge/split revisions are append-only |
| Analyzer binds valid evidence to the wrong success condition or entity | Reducer and Goal Evaluator reload the current condition and canonical entity, verify evidence kind, provenance, record revision and session/security context, and return indeterminate or reject on mismatch |
| OperationalPhase or operator acknowledgement silently grants more authority | OperationalPhase is only a weak planning/ranking/audit signal; acknowledgement, attention clearing and outcome review are distinct from PolicyDecision, Human Approval and Resume records |
| Local model passes a simple canary but fails the real output schema | Capability results bind every actual Planner/Analyzer schema digest to a versioned corpus and exact model/tokenizer/template/mode/runtime; required valid-rate, zero unsafe acceptance and cancellation checks fail closed without weakening validation or executing partial staged output |
| State, audit and intent partially commit across repositories | The transaction aggregate catalog assigns one application-service owner and ApplicationUnitOfWork to each transition; child repositories cannot commit, and external work starts only from a durable intent/authority record |
| Two components compute the same named digest differently | One versioned digest catalog declares owner, included/excluded fields, sorting, domain tag and algorithm; the canonical digest service rejects missing/duplicate definitions, version drift and parallel fallback implementations |
| A coarse graph retry repeats dispatch while recovering a context or persistence failure | Composite application services persist operation IDs and repository references, while context, transaction commit, dispatch, collection, ingestion and reconciliation keep separate retry policies; no external call is inside a database transaction |
| Production is miswired with a test double, alternate clock/key/provider or mutable adapter | A single production composition root builds and self-checks dependencies in fixed order, rejects unsupported/test providers and multiple roots, freezes trusted capabilities before mission admission, and closes partial startup in reverse order |
| `AUTHORIZED` execution resolves Secret before final dispatch validation | `AUTHORIZED` grants no plaintext access; one OCC transaction creates `DISPATCH_CLAIMED` and a short-lived single-use Claim after pre-dispatch succeeds; only the fixed trusted Adapter channel receives JIT injection |
| Importable token or standalone resolver reuses a consumed Claim to release Secret plaintext | Claim-consumption winner receives only an in-call, non-serializable, one-use dispatch continuation; Secret Store has no separately callable plaintext path. Single-use is scoped to the Claim/dispatch attempt, not a lifetime counter on the Secret version |
| Secret revocation races Dispatch Claim consumption or a caller silently substitutes the latest value | PolicyDecision, Grant and Claim bind exact `secret_version_id` plus lifecycle head; Current `CONFIRMED` check and Claim consumption share one OCC linearization transaction. Revoke-first atomically invalidates the unsent Claim and blocks the Execution, consume-first permits only that already-claimed attempt, and latest-version lookup is forbidden |
| Invalidated Dispatch Claim cannot coexist with the legacy BLOCKED counter invariant | Pre-dispatch BLOCKED has `dispatch_attempts=0` and no Claim; only `BLOCKED / SECRET_VERSION_STALE` has `dispatch_attempts=1` and the exact invalidated Claim. Repository integrity rejects every other BLOCKED / Claim combination |
| Secret schema migration merges unrelated credentials or changes a version binding | DataAccessGrant retains nested ResourceBinding and string versions. Each legacy reference migrates one-to-one without latest-version inference; ambiguous state, identity or digest stops with `SecretMigrationRequiredError` |
| Caller mints an ingestion publication or reference to obtain plaintext | Secure Ingestion accepts only repository-bound `ingestion_id`; no full-object plaintext-returning loader, caller Receipt / Quarantine Reference, arbitrary publication or callback is authoritative |
| Quarantine is erased while ingestion outcome exists only in memory or by a stale ingestion worker | Successful publication atomically commits manifest/projection/resources/intent/DELETE_PENDING and lease release; post-ingestion erasure requires complete read-back verification. Expiry and incomplete-collection erasure use separate typed evidence, not fake manifests. Only the dedicated eraser consumes the bound claim; the same erasure_id + key_metadata_digest is reconciled, and confirmed key destruction precedes unlink |
| Audit/key generation advances to a record whose local path is swapped or unreachable | Production TPM NV Extend Digest binds the exact prepared payload, authenticated SQLite record and immutable blob; a logical generation number alone is not authority. Restart fails closed without an older local alternate |
| A filesystem/database snapshot rolls generation state back to a mutually valid old pair | TPM NV Extend witness is outside the SQLite restore domain. The current digest rejects same-generation different-content records and missing committed blobs; generation-witness-policy-v5 synchronously protects critical Mission/Epoch, Claim/Budget and verified Knowledge projections. TPM reset or identity mismatch enters ANCHOR_RECOVERY_REQUIRED, never auto-reseed |
| Empty startup or TPM reset is mistaken for a fresh install and re-anchors attacker-selected local state | Genesis requires an explicitly fresh empty store, unused trust epoch, fixed provisioned NV identity and approved unWRITTEN-to-WRITTEN transition with a content-bound Genesis extend. Dynamic NV Name is checked separately; deployment uses a distinct measured NV counter and read failure is not zero. Recovery approval binds exact old/new identities and externally verified adopted state; unverifiable local state is not re-seeded |
| A renewed lease outlives the authority to read a provider stream | Recovery authority and lease renewal independently revalidate current purpose, task binding and deadline; every sink mutation rejects expired authority or a stale fence. Sync local_capture never gains provider-task authority or re-submits to recover lost output |
| A wrapped-key backup resurrects an erased resource or TPM slot reuse aliases old keys | Per-resource REK, copy inventory, slot incarnation and backup-restore / hardware qualification are required; D4 remains NOT_EVALUATED and cannot enable production before applicable qualification PASS |
| A second root migrates a live database or legacy records become new authority | One shared Activation Lock covers startup and explicit stopped-worker migration/restore; normal startup checks schemas read-only. Legacy history and consumed budgets remain, legacy missions are archived, and new dispatch requires new current authority |
| LLM confidence, unverified output or predicted effects overwrite established facts | AI Control AI-01–12 separates verified_fact, observation and hypothesis; source-specific proof and current-state validation alone change facts. Context authorization is required for every class and does not itself prove truth |
| Goal unknown creates a permanent refusal loop or an investigation bypass | A common controller uses bounded registered ActionContract prerequisite search; each ready action independently follows normal policy/approval/claim checks. Goal truth, action feasibility and authorization are distinct, with durable non-resetting budgets |
| All-stop behavior or a model judging itself appears to pass agent evaluation | Independent environment/history oracles, fixed D11 300-run corpus, zero safety violations and explicit utility/recall thresholds; report normal/adversarial results and diagnostic pass^3 separately from schema capability |
| Long-running Provider causes immediate Quarantine expiry or cross-tool output-limit confusion | Result Collection Authority persists trusted collection start, Mission deadline, exact Tool Registry digest and Tool-specific output limit; restart reuses those values |
| A collection or ingestion worker continues writing after expiry, process restart, database rollback or takeover | Typed leases bind exact authority/resources/state and every mutation validates lease, owner, TPM-backed deployment epoch, fence, release, host-shared monotonic deadline and state version atomically. Fence-specific staging is published only conditionally, so stale bytes stay unreachable even if an Adapter ignores cancellation |
| UTC rollback extends a Mission or revives a Lease | Lease validity uses a same-boot monotonic deadline bound to the deployment epoch; UTC is audit/cap metadata only. UTC high-water rollback or excessive wall/monotonic divergence stops new authority and renewal with `ClockIntegrityError` |
| Workers on different hosts assume a shared fence while using different TPM/clock authorities | Phase 0C production is explicitly single-host with one TPM, Application DB and composition root. Only child workers share its epoch; multi-host topology is rejected at startup |
| Default-branch refresh reuses an old PASS | Approver-restricted workflow binds old HEAD/current base/prior PASS in a status; the local orchestrator verifies full PR state before and after an exact one-Phase label rollback and requires a new gate after synchronization |
| Base-refresh status changes around a local write | Re-fetch and compare the unique PASS/status transition snapshot, PR state and default branch immediately before and after label replacement and expected-HEAD branch update |
| Default branch advances during a rolled-back review | Bind the review to the trusted target actually incorporated in its HEAD; after recording it, the next-Phase pre-implementation check rolls back and refreshes again |
| Historical refresh status order selects an older review base | Resolve all incorporated statuses by paired old-HEAD/target-base ancestry and require one unique maximal transition; reject incomparable maxima instead of trusting API or lexical order |
| Base refresh races a Codex/human commit | GitHub branch update includes the full old `expected_head_sha`; mismatch fails closed |
| Branch synchronization becomes an early final merge | Base-refresh workflow has read-only PR permission and writes status only; the local expected-HEAD update is separate from the Phase 5 project-complete final merge gate |
| Forged or stale project-complete state triggers merge | Local runner reconstructs one exact base-linked Phase 0A→5 PASS chain, validates bot status/checks/labels/current main ancestry, re-reads PR state and supplies the exact HEAD to GitHub |
| Overlapping local runners both attempt final merge | Atomically create one repository Git ref keyed by exact PR/HEAD; only the successful creator may persist the bound marker and dispatch |
| Claim or merge endpoint returns an unknown outcome | Preserve the exact-PR/HEAD claim and PR/HEAD/default-base/gate/policy/actor/claim marker; any existing or uncertain claim/marker blocks redispatch until explicit live-state reconciliation |
| Merge gates drift while claim/marker remote writes complete | After confirming the marker, re-query the Phase chain, PR state, default branch/ancestry, checks and trusted status; drift or unknown state enters reconciliation before dispatch |
| Real offensive action from CI | No external credentials; Mock/Test servers; Human Gate for Phase 4/5 |
| Secret in logs/artifacts | Reference-only prompts; redaction; no raw output upload |
| Workflow supply-chain change | Pin third-party actions by commit SHA in production; advisory CODEOWNERS routing; separate human-reviewed governance PR |

## Residual Risk

- Registered proof rules, catalogs, the host OS/composition root and TPM provisioning remain in the trusted computing base. TPM witnesses do not validate source truth or protect against every compromise of that base.
- Fixed-corpus agent results do not guarantee success or prompt-injection immunity on unseen inputs; this design does not claim CaMeL-equivalent information-flow guarantees or a complete planner.
- D4 physical resource-erasure qualification remains NOT_EVALUATED. Documentation, simulator tests and LLM-quality results cannot establish the actual device/firmware/backup destruction guarantee.
- An LLM reviewer can miss a flaw even with independent context.
- Local review provenance is authenticated by the launcher's operator GitHub account. It does
  not prove account-independent review or resist a compromised operator host/sandbox/launcher.
  Process/context separation and closed-schema GitHub verification do not remotely attest that
  the local process ran correctly. Routine reviews are unattended; initial governance review and
  the existing Design/Provider Human Gates remain human boundaries.
- Local Codex CLI execution still uses ChatGPT account authentication and model-service network.
  The repository adds no OpenAI API-key integration, but this does not guarantee offline inference
  or eliminate the model service from the data-handling boundary.
- Branch protection and rulesets are unavailable on the current private-repository plan. Required
  reviews, checks, conversation resolution, and direct/force-push prohibitions are manual controls
  and are not enforced by GitHub.
- A compromised write-capable GitHub account can direct-push or merge outside the orchestrator.
- The GitHub merge endpoint binds the PR head SHA but not an explicit base SHA. The runner requires
  current `main` ancestry immediately before the call, but the current plan cannot provide a
  server-enforced merge queue for the remaining base-branch race.
- A compromised GitHub account with repository administration can change repository controls.
- GitHub-hosted runner egress is broader than a dedicated isolated runner unless organization controls restrict it.
- Phase 4/5 vendor behavior may differ from mocks and requires isolated integration testing.

The repository owner explicitly accepts the current plan-limit residual risk. Deterministic CI,
independent SHA-bound review, Phase gates, provider Human Gates, recorded merge evidence and the
local exact-SHA final gate are retained. Server-enforced branch protection or a merge queue should
replace the remaining manual/account boundary when the repository plan supports it.
