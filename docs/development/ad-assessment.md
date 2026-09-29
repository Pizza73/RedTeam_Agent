# Active Directory Configuration Assessment

## Scope

This increment adds an offline-first, read-only assessment boundary for five registered checks:

- privileged and tier-zero access configuration;
- Kerberos SPN service-account hardening relevant to Kerberoasting exposure;
- Kerberos preauthentication settings relevant to AS-REP roasting exposure;
- AD CS ESC1 through ESC8 configuration evidence;
- unconstrained, constrained, protocol-transition, and resource-based constrained delegation settings.

The feature assesses normalized configuration metadata. It does not acquire or export Kerberos tickets, crack
passwords or hashes, enroll certificates, authenticate with certificates, impersonate through delegation, change
directory state, or execute arbitrary commands.

## Trust model

`src/redteam_agent/ad_assessment/` contains the closed operation catalog, strict evidence models, deterministic
verifier, Planner candidate guard, and five-category consensus evaluator. For each category, the local LLM must
select exactly one of three typed candidates: `misconfiguration_detected`, `no_misconfiguration_detected`, or
`indeterminate`. It cannot alter the evidence digest, target, operation, or arguments. The verifier evaluates the
same snapshot independently; only fixed rules over typed evidence produce findings.

Missing evidence is `indeterminate`; it is never treated as a clean result. Unknown fields and inconsistent counts
are rejected at the JSON boundary. Evidence objects have no fields for tickets, hashes, credentials, certificate
private keys, payloads, or raw command output.

The same-origin UI exposes the catalog and a simulator-only verifier endpoint. A caller cannot label browser input
as verified LDAP or directory-export evidence. The separate `collect-and-evaluate` endpoint has an empty request body;
DC IP, domain, LDAPS trust, credential file, thresholds, and tier-zero baseline are owned by the server.

## Live collector

The Kali composition can attach `VerifiedADCollector`. It binds one fixed IPv4 address over certificate-validated
LDAPS/TCP 636, disables referrals and LDAP writes, checks RootDSE against the configured domain, and emits counts
only. Its credential is read from a mode-0600 JSON file and never enters command arguments, API responses, findings,
or evidence references.

The fixed LDAP queries cover tier-zero direct membership, stale privileged passwords, protected accounts outside the
tier-zero chain, SPN encryption/password/managed-account settings, disabled Kerberos preauthentication, unconstrained
delegation excluding DC accounts, high-impact or excessively broad constrained delegation, protocol transition, and
configured RBCD descriptors. Optional expected tier-zero account names are a server policy input.

AD CS uses only the installed Certipy `find` enumeration in a subprocess. The secret crosses subprocess stdin, not
argv. The worker deletes raw output with its private temporary directory and returns ESC1-ESC8 counts only. Any
unknown/failed CA, RPC, or enrollment-endpoint result makes coverage incomplete and blocks snapshot issuance.

The Kali product composition also exposes an advisory recommendation endpoint backed by the existing
`planner_output` schema. It runs only after a passing real-local-LLM Planner capability result is found for the exact
profile, model, runtime, tokenizer, template, schema, corpus, and output mode. The response discards model-authored
prose and returns only metadata looked up from the trusted catalog. A recommendation is never a finding or execution
authorization.

`POST /api/v1/ad-assessment/evaluate-with-llm` runs five bounded Planner invocations over normalized evidence and
returns one category result for every registered operation. The overall status is `completed` only when all five LLM
classifications agree with the verifier and none is `indeterminate`. A mismatch, malformed/unknown candidate, missing
evidence, failed capability gate, request-budget failure, or local-LLM transport failure blocks completion. The API
never returns model-authored prose and retains `decision_authority=deterministic_verifier`.

`POST /api/v1/ad-assessment/collect-and-evaluate` collects a verified snapshot and passes it directly to that same
five-call consensus path. The browser cannot supply a target, LDAP filter, credential, threshold, or evidence value.

## Current status

- Deterministic simulator and verifier: implemented.
- Strict Planner candidate construction and post-LLM exact-match guard: implemented.
- Qualified local-LLM advisory recommendation in the Kali composition: implemented.
- Qualified five-category local-LLM classification with deterministic consensus: implemented.
- Existing Tool Registry / Action Contract compatibility: implemented and tested.
- Operator UI catalog, deterministic simulator, complete local-LLM evaluation, and per-category consensus: implemented.
- Live LDAPS and AD CS collector: implemented and attached when `adCollectorEnabled=true`.
- Current lab target validation: blocked. `10.0.10.212` identifies as member workstation `WS01`; TCP 636 and the
  Global Catalog ports time out, so it is not usable as the DC endpoint.
- Real-domain result: not produced until the actual `intern.local` DC IPv4 address and its LDAPS issuing CA are
  configured.

The collector does not acquire tickets, crack credentials, enroll/authenticate certificates, impersonate delegation,
modify directory objects, or execute commands. Those actions remain outside this feature.
