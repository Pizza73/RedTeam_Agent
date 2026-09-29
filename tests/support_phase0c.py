"""Reusable builders for Phase 0C data-security / audit tests.

These drive the real Phase 0A/0B services to a dispatched execution, then build the
Phase 0C kernel (real AES-256-GCM envelope encryption + the deterministic in-memory TPM
witness double) so tests exercise the public entry points and perturb one input.
"""

from __future__ import annotations

from dataclasses import dataclass

import support
import support_phase0b as sp
from redteam_agent.composition.phase0c import Phase0CKernel, build_phase0c_kernel
from redteam_agent.execution.models import AdapterCollectionControl
from redteam_agent.runtime.clock import ManualMonotonicClock

DEFAULT_STDOUT = b'{"host": "10.1.2.3", "status": "open", "port": 443, "credential": "SECRET-TOKEN"}'


@dataclass
class DispatchedExecution:
    kernel: Phase0CKernel
    execution_id: str
    mission_id: str


def collection_control() -> AdapterCollectionControl:
    return AdapterCollectionControl(
        provider_status="succeeded", exit_code=0, timed_out=False, started_at=support.T0,
        finished_at=support.T0, status_normalization_rule_id="status-normalization-v1",
    )


def make_phase0c(*, monotonic_clock: ManualMonotonicClock | None = None) -> Phase0CKernel:
    k0b = sp.make_kernel(result_delivery_mode="provider_task")
    clock = monotonic_clock if monotonic_clock is not None else ManualMonotonicClock(support.T0)
    return build_phase0c_kernel(phase0b=k0b, monotonic_clock=clock)


def seed_dispatched(kernel: Phase0CKernel, *, execution_id: str = "exec-1") -> DispatchedExecution:
    """Seed + authorize + dispatch a provider-mode execution (DISPATCHED) on the 0B kernel."""
    seeded = sp.seed_authorized(kernel.phase0b, execution_id=execution_id)
    sp.authorize(seeded)
    kernel.phase0b.executor.dispatch(execution_id=execution_id, plan=seeded.plan)
    return DispatchedExecution(kernel=kernel, execution_id=execution_id, mission_id=seeded.seeded.revision.mission_id)


def collect(kernel: Phase0CKernel, *, execution_id: str = "exec-1", stdout: bytes = DEFAULT_STDOUT) -> str:
    """Run the Phase 0C encrypted collection; return the ingestion_id."""
    result = kernel.collection_service.collect(
        execution_id=execution_id, stdout=stdout, stderr=b"", control=collection_control()
    )
    return result.ingestion_id
