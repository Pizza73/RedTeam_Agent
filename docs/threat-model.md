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
GitHub Actions      --trusted controller--> branch and status
CI evidence         --trusted when re-queried and bound to SHA--> phase gate
External C2/MCP     --untrusted until approved/bound--> Adapter
```

## Threats and Controls

| Threat | Control |
|---|---|
| PR/Source prompt injection | Reviewer/implementer prompts treat repository content as data; protected governance files; sanitize structured requests |
| Codex changes tests/spec to pass | Protected path diff check; branch protection; independent review |
| Forged PASS comment | Local schema validation; gate actor check; reviewer permalink lookup; reviewer login, head SHA, phase base and actual Check Run revalidation |
| Forged implementation/ready marker | Local orchestrator accepts only `github-actions[bot]`, exact current phase and exact current HEAD SHA |
| Stale review applied to new code | Exact 40-char `reviewed_sha == PR head.sha` |
| Infinite loop/cost exhaustion | Max 5 iterations per phase; same finding max 3; concurrency cancellation |
| Fork steals secret/token | Same-repository branch check; no AI implementation workflow on forks; minimal workflow permissions |
| Codex steals GitHub token | Orchestrator invokes Codex through GitHub comments, never a token-bearing process; CI checkout does not persist credentials |
| Duplicate/stale local dispatch | SHA/digest trigger markers, trusted GitHub state and bounded runtime make restart idempotent and fail closed |
| OpenAI key exposed to repository code | OpenAI API use is disabled and `OPENAI_API_KEY` is not a repository secret |
| Malicious test exfiltration | No unrelated credentials in test jobs; CI egress should be organization-restricted where possible |
| Review actor compromised | Human final merge; audit trail; emergency stop labels/workflow disable |
| Phase gate bypass | Ordered phase plan; label/current phase match; prior PASS marker; required Check Runs queried from GitHub |
| Real offensive action from CI | No external credentials; Mock/Test servers; Human Gate for Phase 4/5 |
| Secret in logs/artifacts | Reference-only prompts; redaction; no raw output upload |
| Workflow supply-chain change | Pin third-party actions by commit SHA in production; CODEOWNERS for `.github/` |

## Residual Risk

- An LLM reviewer can miss a flaw even with independent context.
- A compromised GitHub account with repository administration can change protection rules.
- GitHub-hosted runner egress is broader than a dedicated isolated runner unless organization controls restrict it.
- Phase 4/5 vendor behavior may differ from mocks and requires isolated integration testing.

These risks are why deterministic CI, independent review, phase gates, Human Gate, and final human merge are all retained.
