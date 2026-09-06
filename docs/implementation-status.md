# Implementation Status

## Authority and scope

This file is a default-branch snapshot for humans and for bootstrapping a new implementation PR.
It is not mutable Phase authorization for an active `ai-loop` PR. In an active PR, the current
Phase is resolved from the exact `phase-*` label, the current-HEAD implementation request, and the
unique maximal adjacent prior-Phase PASS incorporated in that HEAD as defined in `AGENTS.md`.
Requirements, acceptance criteria, safety invariants, protected-file rules, and Human Gates remain
authoritative in all contexts.

## Specification adoption — 2026-09-06

- `system-design-v1-r1` has been reflected locally in `SystemDesign.md` together with the normative
  `ai-control-v1-r1` companion, requirements, safety invariants, acceptance criteria and applicable Phase prompts.
- `SystemDesign_update.md` is now the preserved pre-adoption snapshot. Review reports, including the
  older Phase 0C v3 redesign below, provide historical rationale and do not override current contracts.
- The current specification includes R1–R13, D1–D11, F1–F7 and the common AI controller / ActionContract
  redesign. The inherited Secret reuse, one-use dispatch, renewable lease/fencing and no automatic
  unknown-outcome retry boundaries remain in force.
- This adoption subsection records the specification-only change. Product implementation, DB state, GitHub
  PR state and Phase authority have not been advanced. D4 physical erasure qualification remains
  `NOT_EVALUATED`; document validation is not a Phase PASS or production qualification.
- The AGENTS.md / R1 erasure-rule conflict was resolved locally with explicit user approval:
  successful publication retains complete manifest verification, while the two expiry types
  require their own exact evidence, current state/deadline and one-use dedicated-erasure path.
  This resolves that documentation blocker only, not the PR Design Stop or implementation authority;
  see `docs/review/systemdesign-canonical-adoption.md`.
- Review/merge and incorporated-design / exact-HEAD Design Approval remain required before any
  authorized implementation. The PR details below are historical snapshots, not freshly queried status.

## Development-loop strategy integration — 2026-09-06 (local, not deployed)

- The local runner, request/audit schemas, implementation/review prompts and CI/gate checks now
  carry Section 38's reuse/replace/new strategy in the existing invariant-audit evidence chain.
- New requests require `implementation_strategy_version=1.0`; old requests/audits remain readable
  for history but do not authorize a new-policy implementation or omit its strategy evidence.
- `SystemDesign_AI_Control.md` is protected like the main specification. Review questions now
  follow the approved Secret lifecycle, TPM witness and purpose-typed erasure contracts.
- Governance regression tests and operating instructions were updated; product source/tests,
  persistent data, GitHub PR state, Design Stop and Phase authority were not advanced by this work.
- Local validation and the changed-file map are in `docs/review/ai-loop-strategy-update.md`.
  This is not a deployed loop, a Phase PASS or D4 production qualification. Human governance
  review/merge, authorized incorporation, current-HEAD checks and dedicated Design Approval
  are still required before live implementation resumes.

## Governance submission — 2026-09-06

- The approved canonical design and development-loop strategy integration were committed as
  `435576ee1040047581311d6af3b3ccc4fc5ab491` and pushed to `codex/phase-0c-coherent-redesign-v3`.
- [PR #40](https://github.com/Pizza73/RedTeam_Agent/pull/40) submits the changes to `main` under
  `governance-change`; it is not an implementation-phase PR or a Phase PASS. Its current HEAD/checks
  are authoritative for submission status; later publication-report commits do not alter phase authority.
- PR #39's AGENTS guidance was already merged. The fetched default-branch SHA was
  `353fb13cf635f560058754ded438c85504fd143d`. PR #38 remains a separate open governance change.
- PR #3 remains at `ae09f40f6b593060d060cfb9a5090e0de4e2875d` with `phase-0c` and `ai-loop-blocked`.
  Its latest trusted recurrence gate is still `issuecomment-5515692085`; no current-HEAD dedicated
  Design Approval was found. Product implementation and the live runner have not resumed.
- Human review/merge of the design, authorized incorporation/checkpoint, current-HEAD checks and
  dedicated Design Approval remain required. This snapshot never authorizes merge or Resume.

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
  `ae09f40f6b593060d060cfb9a5090e0de4e2875d`
- The latest formal Phase 0C review retained three P1 findings across
  `secret-plaintext-boundary`, `integrity-cryptography-keys`, and
  `filesystem-concurrency-retention`:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#pullrequestreview-5094547758`.
- The trusted recurrence gate and design stop require a third coherent redesign before another
  implementation request:
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692085` and
  `https://github.com/Pizza73/RedTeam_Agent/pull/3#issuecomment-5515692776`.
- The human-approved second coherent redesign was merged by PR #30 as
  `0e092ad8117e196eb9496db30fa71f6f7237e524`; its design commit
  `a3cca860dc2cf7fb43ecef9af536d39a7463a56c` is incorporated in the current implementation HEAD.
- That implementation closed the prior six findings, but the latest review found three remaining
  design gaps: reusable post-consumption Secret resolution, blob and anchor in one rollback unit,
  and unfenced fixed-duration collection ownership.
- At the time of this snapshot, `docs/review/phase-0c-coherent-redesign.md` defined the third redesign: an
  Executor-call-local one-use dispatch continuation with exact Secret-version lifecycle
  linearization, typed renewable leases using TPM-backed deployment epochs and storage-side
  conditional publication, a dedicated claim-consuming Quarantine eraser, and concrete
  TPM-witnessed authenticated generations.
- The Source-of-Truth specification has been reconciled across `SystemDesign.md`, acceptance
  criteria, safety invariants, threat model and the Phase 0C prompt. It now fixes the legacy Secret
  migration, `BLOCKED` / Dispatch Claim invariants, same-host monotonic lease topology, exact key
  destruction identity, and TPM Genesis / approval-bound recovery semantics. This records the
  design only; the implementation branch remains unchanged until the design is merged and the
  dedicated current-HEAD Design Approval authorizes implementation.
- The independent AI-agent design review items C1-C9 and S2-S8 are now specified across the same
  source-of-truth documents: bounded planner retrieval and safe feedback, application-owned working
  state, strong-key entity resolution, actual-schema LLM capability evidence, explicit
  evidence-to-condition binding, non-authoritative operational phases, supervised intervention,
  transaction aggregates, a normative digest catalog, coarse retry-isolated orchestration,
  responsibility boundaries and a single production composition root. S1 is intentionally excluded
  by owner decision: the existing Phase 0C -> Phase 1 -> Phase 2 order is unchanged and no new
  pre-Phase-0C thin-slice gate is introduced. These are specification changes only; no source or test
  implementation is claimed by this snapshot.

This snapshot does not itself authorize work. The trusted current-Phase gate, adjacent prior-Phase
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
recurrence stop above.

1. Human-review and merge the current coherent specification (`system-design-v1-r1` and its normative
   companion plus related acceptance/safety/Phase documents) to `main`; do not implement superseded
   examples from the historical v3 report.
2. Incorporate that exact design commit into PR #3 only through the authorized exact-HEAD
   base-refresh / checkpoint path; keep the Phase 0C label and stop latch.
3. Wait for the required checks, then issue the dedicated Design Approval bound to the latest
   recurrence gate, full refreshed HEAD, Phase 0C and the incorporated current-design commit.
4. Resume once with `RESUME_AFTER_DESIGN_APPROVAL` and implement the complete mapping: remove the
   reusable Secret token / resolver; add the Executor-call-local one-use continuation, immutable
   Secret versions and lifecycle linearization; implement typed collection / ingestion leases with
   TPM-backed deployment epochs, heartbeat and conditional publication; separate ingestion from
   one-use-claim erasure; and wire the authenticated SQLite generation records to TPM 2.0 NV
   Extend Digest witnesses with explicit `ANCHOR_RECOVERY_REQUIRED` handling. Apply the complete
   current-Phase R / D / F matrix, including typed result/expiry/recovery paths, critical-state barriers,
   stopped-worker migration and the independent D4 qualification gate. Also implement the Phase 0C
   transaction aggregate / `ApplicationUnitOfWork`, normative digest catalog / canonical digest
   service, and production composition-root startup / self-check / shutdown boundaries before
   Phase 1 work begins.
5. Run the complete Phase 0C gate, update all affected invariant-family state-machine evidence and
   request one fresh exhaustive formal review.

After Phase 5 PASS, the local orchestrator revalidates all configured Phase records, the latest
Phase status, current-HEAD checks, stop labels and current `main` ancestry. It then submits one
GitHub merge request bound to the current 40-character PR HEAD. A conflict, drift, malformed record
or uncertain response stops without automatic retry. Governance and fork PRs never qualify.
