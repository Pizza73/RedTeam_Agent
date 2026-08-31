# Cumulative Phase Authority Governance Review

## Finding

The blocked-phase recovery control required the adjacent prior-Phase PASS to have
`reviewed_sha == current HEAD` and then relabeled the unchanged cumulative pull-request tree to that
prior Phase. Once Phase 0B code exists, a Phase 0A reviewer must correctly reject that tree as
out-of-scope. Repeating the rollback therefore cannot produce a valid Phase 0A PASS and creates an
authorization loop.

The phase-gate workflow also selected the last prior PASS by GitHub comment order. Comment order is
not a security-relevant ancestry relation and can select a stale or unrelated record.

## Correction

- Phase 0B and later use the adjacent prior-Phase PASS whose reviewed SHA is incorporated in the
  current HEAD. If several are incorporated, Git ancestry must yield exactly one maximal SHA.
- The local orchestrator and the phase-gate workflow both reject missing, unrelated, or incomparable
  maximal PASS candidates.
- The recovery workflow no longer rolls cumulative code to an earlier Phase. It binds the trusted
  current-Phase finding and gate, the gate's adjacent phase-base PASS, reviewed/current ancestry,
  identical Git trees, current checks, actor, repository/default-branch state, and exact labels.
- Validation runs the complete current-Phase gate. Publication restores the same source Phase and
  emits current-HEAD implementation/ready evidence for a fresh independent review; it creates no
  PASS.
- Evidence and label digests are rechecked after the read-only validation job and before the
  separately permissioned publication job writes comments, status, or labels.

## Recovery scope

The special recovery accepts only automatic Phase 0B through Phase 3, a same-repository open
`ai-loop` PR, a trusted Codex P0/P1 on the supplied reviewed HEAD, exactly one matching workflow gate,
exactly one adjacent PASS matching that gate's `base_sha`, and a current HEAD with an identical tree.
Any code change between the reviewed and current HEAD fails closed.

## Security impact

This change preserves phase ordering: the earlier PASS remains only the immutable phase-base
ancestor for the later cumulative Phase. It prevents later-Phase code from being reviewed under an
earlier prompt, removes comment-order authority, and does not grant Codex, GitHub Actions, or the
recovery workflow any final-merge path.
