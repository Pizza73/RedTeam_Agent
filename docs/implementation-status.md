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
- Phase 0B reviewed HEAD with a trusted P1:
  `6c4d973fb943fb6cd7c1e33ba2ee972c435fcdd5`
- Current audit-only HEAD with the identical Git tree:
  `e8d3b193b662ab4f594bfa826b99fbd5b49690b7`
- The current-Phase recovery restored Phase 0B and produced a fresh trusted P1 gate at that HEAD:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5473651491`.
- The P1 requires an atomic current Mission state/revision/authorization-epoch check in the same
  transaction as the dispatch claim. The subsequent Codex task correctly stopped because the PR
  HEAD still contains the superseded exact-current-HEAD prior-PASS governance from before the
  recovery correction was merged to `main`.

This snapshot does not itself authorize work. The trusted current-Phase gate, adjacent Phase 0A
base PASS, exact labels/request, and current default-branch evidence remain the active authority.

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

After this governance change is human-reviewed and merged:

1. restart `automation/run_phase_loop.py` from clean, current `main`;
2. let it bind **Prepare AI Loop Base Refresh** to the current Phase 0B `BLOCKED_LIMIT` gate,
   Phase 0A base PASS, exact old HEAD, and current default-branch SHA;
3. let the local runner perform the expected-HEAD update without changing the Phase 0B label and
   verify both required ancestries;
4. after current-HEAD CI, use only the gate-bound bounded Resume to authorize the atomic dispatch
   claim fix and regression test; and
5. continue normal bounded Phase progression after a fresh Phase 0B PASS.

After Phase 5 PASS, the local orchestrator revalidates all configured Phase records, the latest
Phase status, current-HEAD checks, stop labels and current `main` ancestry. It then submits one
GitHub merge request bound to the current 40-character PR HEAD. A conflict, drift, malformed record
or uncertain response stops without automatic retry. Governance and fork PRs never qualify.
