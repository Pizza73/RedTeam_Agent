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
PR content/comments --untrusted--> Codex/ChatGPT reviewer
Repository files   --untrusted--> Codex implementer
GitHub bot markers --validated--> Local phase orchestrator
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
| Forged PASS comment | Local schema validation; gate actor check; reviewer permalink lookup; reviewer login, head SHA, phase base and actual Check Run revalidation |
| Forged implementation/ready marker | Local orchestrator accepts only `github-actions[bot]`, exact current phase and exact current HEAD SHA |
| Stale review applied to new code | Exact 40-char `reviewed_sha == PR head.sha` |
| Infinite loop/cost exhaustion | Max 5 iterations per phase; same finding max 3; concurrency cancellation |
| Fork steals secret/token | Same-repository branch check; no AI implementation workflow on forks; minimal workflow permissions |
| Codex steals GitHub token | Orchestrator invokes Codex through GitHub comments, never a token-bearing process; CI checkout does not persist credentials |
| Duplicate/stale local dispatch | SHA/digest trigger markers, trusted GitHub state and bounded runtime make restart idempotent and fail closed |
| OpenAI key exposed to repository code | OpenAI API use is disabled and `OPENAI_API_KEY` is not a repository secret |
| Malicious test exfiltration | No unrelated credentials in test jobs; CI egress should be organization-restricted where possible |
| Review actor compromised | Independent Phase-chain revalidation; audit trail; emergency stop labels/workflow disable |
| Phase gate bypass | Ordered phase plan; label/current phase match; prior PASS marker; required Check Runs queried from GitHub |
| Runner observes a zero/multiple-Phase transition window | Replace the complete managed label set atomically from a fresh PR snapshot, then re-fetch and compare the exact HEAD, next Phase and full label set |
| Stale static Phase status blocks or authorizes work | Active PR authority requires an exact label + workflow-authored current-HEAD request + adjacent prior PASS; the status document is bootstrap-only |
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

- An LLM reviewer can miss a flaw even with independent context.
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
