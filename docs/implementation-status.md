# Implementation Status

## Authority and scope

This file is a default-branch snapshot for humans and for bootstrapping a new implementation PR.
It is not mutable Phase authorization for an active `ai-loop` PR. In an active PR, the current
Phase is resolved from the exact `phase-*` label, the current-HEAD implementation request, and the
unique maximal adjacent prior-Phase PASS incorporated in that HEAD as defined in `AGENTS.md`.
Requirements, acceptance criteria, safety invariants, protected-file rules, and Human Gates remain
authoritative in all contexts.

## Default-branch bootstrap state

```text
BOOTSTRAP PHASE: Phase 0A
BOOTSTRAP PHASE 0A GATE: NO-GO
BOOTSTRAP PHASE 0B ALLOWED: NO
ACTIVE PR STATE: Resolve from trusted GitHub evidence; do not copy from this snapshot
```

## Active implementation PR snapshot

- Long-lived implementation PR: #3, branch `ai/redteam-agent-phase-loop`
- Trusted Phase 0A PASS / Phase 0B base:
  `9060c6c7ded3158072989035cab78c5f97946642`
- Current Phase: Phase 0C (`phase-0c`, `ai-loop-blocked`)
- Current implementation HEAD:
  `91392eb375bd10d840cae542acf36d79a00a3f4f`
- The latest formal Phase 0C review retained six P1 findings across
  `authorization-lifecycle`, `secret-plaintext-boundary`, `audit-recovery-durability`,
  `filesystem-concurrency-retention`, and `integrity-cryptography-keys`:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5085287765`.
- The trusted recurrence gate and design stop require a second coherent redesign before another
  implementation request:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5503904111` and
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5503904489`.
- The human-approved second coherent redesign was merged by PR #30 as
  `0e092ad8117e196eb9496db30fa71f6f7237e524`; its design commit
  `a3cca860dc2cf7fb43ecef9af536d39a7463a56c` is incorporated in the current implementation HEAD.
- Required checks passed on the refreshed HEAD, but Design Approval run `33601359533` correctly
  emitted no marker because CI had projected `ai-needs-review` while the stop latch was present and
  the approval workflow treated that projection as a conflicting authority state.
- PR #31 merged the lifecycle-projection simplification as
  `3adac80f42842631208ea59ef3593cf99a75db82`: stopped CI emits checks only, trusted evidence
  selects the next action, and an older `ai-needs-review` projection is normalized during the
  exact-HEAD Design Approval transition.
- A post-merge dry run then exposed that the first refresh output could not receive another
  exact-HEAD refresh authorization when `main` advanced again. The follow-up governance change
  certifies each completed two-parent refresh on its new current HEAD and permits another update
  only from that digest-bound checkpoint; it does not authorize Resume or implementation.

This snapshot does not itself authorize work. The trusted current-Phase gate, adjacent Phase 0A
base PASS, exact Phase label / stop latch, SHA-bound request, and current default-branch evidence
remain the active authority.

## Phase 0A evidence snapshot

- Phase 0A implementation candidate: `9060c6c7ded3158072989035cab78c5f97946642`
- Deterministic checks and the native Codex review passed on that exact SHA.
- The B-01 through B-06 and H-01 through H-07 findings were addressed on that SHA. It is the
  incorporated adjacent phase base for the cumulative Phase 0B tree; it is not a Phase 0B PASS.
- Review bot identity: `chatgpt-codex-connector[bot]` (exact GitHub login, including suffix).
- Required review identity: every implementation and review result is bound to the full PR HEAD
  SHA; shortened display IDs are corroborating evidence only.
- Repository control mode: the current private-repository plan does not expose branch protection
  or rulesets. Direct/force pushes remain prohibited. Final merge is performed only by the local
  orchestrator after its exact-SHA Phase 0A–5 evidence-chain gate and an atomic exact-PR/HEAD Git
  ref claim; Codex and GitHub Actions retain no final-merge path.

## Next allowed action

Do not restart the local runner or issue a generic Resume while the latest Phase 0C gate is the
recurrence stop above. After the current-HEAD refresh-checkpoint governance change is human-reviewed
and merged:

1. certify PR #3's existing `91392eb...` refresh edge using the confirmation mode of
   **Prepare AI Loop Base Refresh**, then
   incorporate the resulting governance commit using only the next exact-HEAD base-refresh
   operation; certify that new HEAD too and keep the Phase 0C label and stop latch;
2. wait for the four current-HEAD required checks; stopped CI must not publish Review Ready;
3. issue the dedicated Design Approval bound to the latest recurrence gate, full current HEAD,
   Phase 0C and the incorporated PR #30 design commit;
4. resume once with `RESUME_AFTER_DESIGN_APPROVAL` and implement Executor-owned
   consume-before-release Secret delivery, trusted collection Clock ownership, side-effect-free
   verified erasure, manifest/projection-only result recovery and the durable Production generation
   backend as one coherent redesign; and
5. run the complete Phase 0C gate, update all invariant-family state-machine evidence and request
   one fresh exhaustive formal review.

After Phase 5 PASS, the local orchestrator revalidates all configured Phase records, the latest
Phase status, current-HEAD checks, stop labels and current `main` ancestry. It then submits one
GitHub merge request bound to the current 40-character PR HEAD. A conflict, drift, malformed record
or uncertain response stops without automatic retry. Governance and fork PRs never qualify.
