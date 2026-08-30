# Phase 0B Implementation Report

## Review input

- Current phase: `Phase 0B: Execution Safety`
- Input independent-review SHA: `9060c6c7ded3158072989035cab78c5f97946642`
- Implementation branch: `ai/redteam-agent-phase-loop`
- External execution boundary: `MockExecutionAdapter` only
- Real provider, C2, MCP side effect, local shell execution, and external-target calls: absent

## Resulting working-tree diff

The implementation changes 7 tracked files and adds 12 source/test files plus this report.
No protected governance file listed in `AGENTS.md` was modified. In particular,
`SystemDesign.md`, `.github/**`, `automation/**`, requirements, acceptance criteria,
safety invariants, threat model, and phase prompts are unchanged.

Modified files:

- `src/redteam_agent/errors.py`
- `src/redteam_agent/executor/__init__.py`
- `src/redteam_agent/mission/manager.py`
- `src/redteam_agent/models/__init__.py`
- `src/redteam_agent/repositories/__init__.py`
- `src/redteam_agent/storage/migrations.py`
- `tests/security/test_gate_review_regressions.py`

Added files:

- `src/redteam_agent/models/execution.py`
- `src/redteam_agent/repositories/execution.py`
- `src/redteam_agent/executor/adapter.py`
- `src/redteam_agent/executor/finalization.py`
- `src/redteam_agent/executor/ingestion.py`
- `src/redteam_agent/executor/raw_results.py`
- `src/redteam_agent/executor/service.py`
- `src/redteam_agent/executor/workflow.py`
- `tests/phase0b_helpers.py`
- `tests/unit/test_phase0b_execution.py`
- `tests/integration/test_phase0b_flow.py`
- `tests/security/test_phase0b_execution_safety.py`
- `docs/review/phase-0b-implementation.md`

## Findings addressed

- Added separate provider-execution and result-ingestion state machines, including terminal
  pre-dispatch `BLOCKED`, reconciliation-only `OUTCOME_UNKNOWN`, cancellation, failed-ingestion
  quarantine, and OCC state versions.
- Added a database `UNIQUE` constraint for one `PolicyDecision` per execution and a deterministic,
  immutable idempotency key. External dispatch is persisted before submit and is limited to one
  attempt with zero automatic transport or graph retry.
- Revalidated current Mission state, revision, authorization epoch, Mission/Decision/Snapshot TTL,
  approval presentation binding, session context, live adapter/sandbox capability, remote MCP trust,
  and integrity immediately before submit. A failure transitions `AUTHORIZED -> BLOCKED` without a
  provider call or `ExecutionResult`.
- Added provider-neutral `ExecutionAdapter` and `RawResultSink` protocols. The only implementation is
  a deterministic mock; it invokes no external service or OS command.
- Added incremental raw-result hashing/quota enforcement, metadata-only receipts, recovery metadata,
  idempotent commit, a mock durable quarantine store, and streaming resume without action resubmit.
- Added application-owned `ExecutionRequest` construction from the complete immutable authorization
  envelope and application-owned `ExecutionResult` normalization only after secure-ingestion success.
- Added read/write digest verification and denormalized-row/parent-envelope binding checks for runs,
  executions, receipts, recovery metadata, ingestion records, and normalized results. Direct
  repository calls cannot reduce authorization provenance or create a result for an un-ingested,
  blocked, or unknown execution.
- Added `thread_id = mission_id:mission_revision:run_id` issuance and checkpoint-load validation.
- Added the FINALIZING coordinator skeleton. Goal completion enters FINALIZING, Mission expiry blocks
  dispatch and requests FINALIZING, and the Mission state machine continues to reject a direct
  `RUNNING -> COMPLETED` transition.

## Independent review correction cycle

The independent review for implementation SHA
`c2ec88545bc0e31dafde1e0d3d72c8ea4f46f99c` returned six P1 findings. All six were addressed in
the same Phase 0B scope:

- [`discussion_r3889834343`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3889834343):
  removed caller-supplied adapters from public dispatch/reconcile/collect/cancel APIs. Executor now
  resolves the exact adapter type and ID from an immutable trusted composition-root registry.
- [`discussion_r3889834345`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3889834345):
  made the live session/sandbox/remote-trust capability probe a mandatory Executor dependency;
  construction fails closed if it is absent.
- [`discussion_r3889834349`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3889834349):
  made `CANCEL_REQUESTED` a public restart/reconciliation state so a crash after durable cancel intent
  never leaves an execution without a recovery path or causes a resubmit.
- [`discussion_r3889834352`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3889834352):
  added expiration-bound ingestion leases and OCC lease takeover. An active lease blocks takeover;
  an expired lease can resume ingestion without resubmitting the provider action.
- [`discussion_r3889834356`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3889834356):
  reconciliation now treats a changed provider task ID as `OUTCOME_UNKNOWN` and preserves the
  original immutable task binding.
- [`discussion_r3889834360`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3889834360):
  made a Mission-Manager-backed `FinalizationCoordinator` mandatory. Mission expiry always routes
  through FINALIZING after the pre-dispatch BLOCKED record is committed.

The correction also removed caller-supplied `AdapterRawResult` from the ingestion API. Ingestion
re-collects metadata through the trusted registered adapter and the committed quarantine sink,
without submitting the external action again.

## Second independent review correction cycle

The independent review for correction SHA
`3ec3cbb8007b3d04e9d1a1130163693c1ea4d0cc` returned two P1 findings. Both were addressed within
Phase 0B:

- [`discussion_r3890552732`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3890552732):
  a secure-ingestion failure now routes immediately through a dedicated Mission Manager safety
  transition to `PAUSED` before recording the ingestion/execution failure. The pause invalidates the
  authorization epoch, so a separately authorized later action is blocked before adapter submit.
  Repeated ingestion recovery failures keep an already-PAUSED Mission paused.
- [`discussion_r3890552734`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3890552734):
  an existing normalized result now converges both ingestion records across the legal
  `INGESTING`/`SUCCEEDED` crash states. A restart after the ingestion record commits `SUCCEEDED` but
  before the Execution record does so advances the latter without calling the ingester or
  resubmitting the external action. Inconsistent existing-result states fail closed.

## Third independent review correction cycle

The independent review for correction SHA
`6d59df85205c2c17f08ceffbee982b49490140b2` returned two P1 findings. Both were addressed within
Phase 0B:

- [`discussion_r3890853717`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3890853717):
  adapter, streaming, and quarantine exceptions during raw-result collection now route through the
  Mission Manager to `PAUSED`, mark the bound sink as recovery-required, and persist integrity-bound
  recovery metadata. Quarantine and streaming error types are preserved; adapter failures are
  wrapped in the typed streaming error. A separately authorized later action is blocked before
  adapter submit by the invalidated authorization epoch.
- [`discussion_r3890853721`](https://github.com/Pizza73/RedTeam_Agent/pull/3#discussion_r3890853721):
  the mock adapter can now exercise an interruption inside an artifact stream. Partial byte count
  and chunk sequence are durably represented as `RECOVERY_REQUIRED`, no receipt is created, the
  Mission enters `PAUSED` for human recovery, and neither result collection nor the external action
  is automatically retried.

## Regression tests added

The Phase 0B test set covers positive, negative, and failure paths, including:

- one decision / one execution and deterministic execution identity;
- crash or uncertainty before a provider task ID, crash/restart after task state persistence, and no
  duplicate submit;
- `UNKNOWN`, `UNSUPPORTED`, and uncertain `NOT_FOUND` reconciliation to `OUTCOME_UNKNOWN`;
- stale authorization TTL, epoch, adapter capability, sandbox capability, approval, and Mission TTL
  blocking before any provider call;
- exact approval requirement and immutable approval binding;
- confirmed cancellation without resubmit;
- chunk streaming without a whole-result sink buffer, quota failure, partial-stream restart, durable
  receipt commit idempotency, and raw marker absence from normal database JSON;
- provider `SUCCEEDED` with ingestion `FAILED`, retry of ingestion only, and idempotent retry after
  normalized-result commit;
- recomputed self-digest with a reduced parent authorization binding being rejected;
- normalized result persistence before secure ingestion being rejected;
- revision-specific run/thread identities and checkpoint mismatch rejection;
- FINALIZING entry and direct-completion rejection;
- caller adapter replacement rejection and missing live-probe/finalization dependency rejection;
- cancellation crash recovery, provider task-ID replacement rejection, and expired-ingestion-lease
  takeover without action resubmit;
- secure-ingestion failure pausing the Mission and blocking a separately authorized later dispatch;
- split ingestion-success commit recovery without an ingester call or external action resubmit;
- integrated quarantine quota failure with durable recovery metadata, Mission pause, and later
  dispatch rejection; and
- mid-artifact interruption with partial sequence evidence and PAUSED human recovery.

No test was skipped, weakened, deleted, or marked as an expected failure.

## Required validation

Exact command:

```text
bash scripts/ci/run_phase_gate.sh phase-0b
```

Result:

```text
AUTOMATION_VALIDATION=PASS
ruff: All checks passed
mypy: Success: no issues found in 69 source files
unit: 172 passed
integration: 7 passed
security: 134 passed
full/coverage run: 313 passed
skipped=0, errors=0, failures=0
coverage: 83% total (branch coverage enabled)
pip check: No broken requirements found
PHASE_GATE=phase-0b PASS
```

Additional focused command executed during development:

```text
.venv/bin/python -m pytest -q tests/unit/test_phase0b_execution.py \
  tests/integration/test_phase0b_flow.py \
  tests/security/test_phase0b_execution_safety.py --strict-markers
```

Focused result: `32 passed`.

## Remaining findings and constraints

- Phase 0B intentionally provides only mock execution, mock quarantine, and a metadata-only mock
  secure-ingestion boundary. It does not implement a real C2/MCP/local execution adapter.
- Encryption key domains, production encrypted quarantine storage, secret classification/detection,
  redaction, artifact storage, and audit-chain implementation remain Phase 0C work and must not be
  inferred from the mock SHA-256 quarantine test double.
- No external side-effect dispatch path exists outside the injected `ExecutionAdapter` protocol.
- Automatic final merge remains governed by the repository phase loop and is not performed by the
  Executor implementation itself.
- No acceptance criterion in the Phase 0B specification remains unverified by the repository gate or
  the listed tests.
