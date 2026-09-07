"""JIT secret injection: claim-gated, no plaintext leak, no standalone resolver."""

from __future__ import annotations

import redteam_agent.execution.secret_injection as secret_injection
import support
import support_phase0b as p0b
from redteam_agent.resources.secret_metadata import SecretVersionMetadata


def test_secret_injected_just_in_time_via_fixed_port() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, with_secret=True)
    p0b.authorize(seeded)
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "DISPATCHED"
    sub = kernel.mock_adapter.submissions[-1]
    assert sub.secret_binding_count == 1
    assert sub.secret_binding_lengths == (len(p0b.SECRET_VALUE),)
    assert sub.secret_version_ids == ("sv-1",)


def test_no_plaintext_in_adapter_records_or_repository() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, with_secret=True)
    p0b.authorize(seeded)
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    leaked = p0b.SECRET_VALUE.decode()
    for log in kernel.mock_adapter.submissions:
        assert leaked not in repr(log.__dict__)
    # The stored claim and execution record never carry plaintext.
    claim = kernel.claim_repository.get("claim-exec-1")
    assert claim is not None and leaked not in claim.model_dump_json()
    record = kernel.execution_repository.get("exec-1")
    assert record is not None and leaked not in record.model_dump_json()


def test_authorized_does_not_resolve_secret_until_claim_consumed() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, with_secret=True)
    p0b.authorize(seeded)
    # AUTHORIZED alone: no claim, adapter never called, secret never opened.
    assert kernel.claim_repository.get("claim-exec-1") is None
    assert kernel.mock_adapter.submit_calls == 0


def test_secret_version_revoked_before_dispatch_blocks_pre_dispatch() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, with_secret=True)  # CONFIRMED at issuance
    p0b.authorize(seeded)
    # The version is revoked (no longer CONFIRMED) after AUTHORIZED, before dispatch.
    ds = kernel.phase0a.digest_service
    revoked = support.confirmed_secret_metadata(ds, version_id="sv-1").model_copy(update={"state": "REVOKED"})
    kernel.phase0a.secret_metadata_store.put(revoked)
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    # Fail closed before any provider call or claim: the pre-dispatch revalidation
    # (gate authorization re-derivation and/or the executor's secret-version check)
    # cannot re-derive an authorization bound to a revoked secret version.
    assert out.provider_execution_state == "BLOCKED"
    assert out.pre_dispatch_block_reason in ("SECRET_VERSION_STALE", "DIGEST_INTEGRITY_FAILURE")
    assert out.dispatch_attempts == 0
    assert kernel.claim_repository.get("claim-exec-1") is None
    assert kernel.mock_adapter.submit_calls == 0


class _ChangingHeadSecretMetadata:
    """Returns CONFIRMED but with a lifecycle head that changes each read, to force
    a head-mismatch at claim consumption (secret revoked/superseded race)."""

    def __init__(self, base: SecretVersionMetadata) -> None:
        self._base = base
        self._n = 0

    def get(self, secret_version_id: str) -> SecretVersionMetadata | None:
        if secret_version_id != self._base.secret_version_id:
            return None
        self._n += 1
        return self._base.model_copy(update={"lifecycle_head_digest": f"head-{self._n}"})


def test_secret_head_change_at_consumption_blocks_with_invalidated_claim() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, with_secret=True)  # CONFIRMED at issuance
    p0b.authorize(seeded)
    ds = kernel.phase0a.digest_service
    base = support.confirmed_secret_metadata(ds, version_id="sv-1")
    # Swap in a metadata reader whose head changes between the claim and its
    # consumption; the version stays CONFIRMED so this is a head-rollback race.
    kernel.executor._secret_metadata = _ChangingHeadSecretMetadata(base)  # type: ignore[assignment]
    out = kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    assert out.provider_execution_state == "BLOCKED"
    assert out.pre_dispatch_block_reason == "SECRET_VERSION_STALE"
    assert out.dispatch_attempts == 1
    claim = kernel.claim_repository.get("claim-exec-1")
    assert claim is not None and claim.claim_state == "invalidated"
    assert kernel.mock_adapter.submit_calls == 0


def test_dispatch_continuation_cannot_be_fabricated() -> None:
    assert not hasattr(secret_injection, "SecretDispatchContinuation")
    assert not hasattr(secret_injection, "open_dispatch_continuation")


def test_no_public_standalone_secret_resolver_or_broker() -> None:
    kernel = p0b.make_kernel()
    # The secret source exposes only open_version(secret_version_id); there is no
    # resolve(reference, execution_id), broker, channel registry or callback.
    assert not hasattr(kernel, "secret_source")
    assert not hasattr(kernel, "secret_dispatch")


def test_same_confirmed_version_reusable_by_another_execution() -> None:
    kernel = p0b.make_kernel()
    seeded = p0b.seed_authorized(kernel, with_secret=True, execution_id="exec-1")
    p0b.authorize(seeded)
    kernel.executor.dispatch(execution_id="exec-1", plan=seeded.plan)
    # A second proposal/decision for the same mission reuses the same secret
    # version through a brand-new claim.
    proposal2 = support.make_proposal(
        tool=seeded.seeded.tool,
        arguments={"destinations": ["10.1.2.4"], "port": 443, "protocol": "tcp",
                   "credential": support.secret_reference("sv-1")},
    )
    plan2 = support.make_plan(kernel.phase0a, seeded=seeded.seeded, proposal=proposal2, plan_id="plan-2")
    decision2 = support.issue_decision(kernel.phase0a, plan=plan2, decision_id="decision-2")
    kernel.executor.create_execution(
        execution_id="exec-2", task_id="task-2", decision_id=decision2.decision_id, plan=plan2
    )
    out2 = kernel.executor.dispatch(execution_id="exec-2", plan=plan2)
    assert out2.provider_execution_state == "DISPATCHED"
    assert kernel.mock_adapter.submit_calls == 2
    assert kernel.mock_adapter.submissions[-1].secret_binding_lengths == (len(p0b.SECRET_VALUE),)
