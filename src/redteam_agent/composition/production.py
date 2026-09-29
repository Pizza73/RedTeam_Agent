"""Production composition root (SystemDesign §35.2).

The production root acquires the shared host activation lock, then builds and self-checks
dependencies in the fixed order, rejecting a test double, an in-memory witness, a
multi-host topology or an unknown schema, and closing everything in reverse order on any
failure. It does not migrate or re-seed on a normal start. Because the production TPM
(``tpm2_nv`` / ``swtpm``) and production key provider are external prerequisites, a start
attempt without them fails closed with a typed error (never a test-double fallback).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass

from redteam_agent.audit.critical_witness import CriticalWitnessBarrier
from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.generation_store import GenerationRecordStore
from redteam_agent.audit.nv_witness import NvExtendDigestWitness
from redteam_agent.audit.wrapped_key_state import WrappedKeyStateService
from redteam_agent.composition.activation_lock import HostActivationLock
from redteam_agent.composition.startup_self_check import (
    ProductionTopology,
    check_aead_backend,
    check_key_provider,
    check_schema_read_only,
    check_topology,
    check_tpm_witness,
    reject_test_doubles,
)
from redteam_agent.errors import AuthorizationKernelError, ProductionCompositionError
from redteam_agent.storage.database import Database


class ProductionCompositionUnavailableError(ProductionCompositionError):
    """Raised when the production TPM / key-provider prerequisites are not present."""


@dataclass(frozen=True)
class ProductionServiceBundle:
    """The security-critical services a production builder must return as one root."""

    application: object
    key_provider: object
    generation_store: GenerationRecordStore
    generation_coordinator: AuthenticatedGenerationCoordinator
    critical_witness_barrier: CriticalWitnessBarrier
    wrapped_key_state_service: WrappedKeyStateService
    close: Callable[[], None]


@dataclass
class ProductionStartupPlan:
    activation_lock_path: str
    application_db_path: str
    topology: ProductionTopology
    witness: NvExtendDigestWitness
    key_provider: object
    # Injected builders for the trusted stores/services (run only after self-checks pass).
    build_services: Callable[[Database], ProductionServiceBundle] | None = None


@dataclass
class _Opened:
    label: str
    close: Callable[[], None]


class ProductionCompositionRoot:
    """Runs the §35.2 ordered startup, self-check and reverse-order cleanup."""

    def __init__(self, plan: ProductionStartupPlan) -> None:
        self._plan = plan
        self._opened: list[_Opened] = []
        self._lock: HostActivationLock | None = None

    def _track(self, label: str, close: Callable[[], None]) -> None:
        self._opened.append(_Opened(label, close))

    def _cleanup(self) -> None:
        for opened in reversed(self._opened):
            with contextlib.suppress(Exception):  # best-effort reverse cleanup
                opened.close()
        self._opened.clear()

    def start(self) -> object:
        try:
            # Step 1-2: config already loaded; acquire the shared activation lock.
            self._lock = HostActivationLock(self._plan.activation_lock_path)
            self._lock.acquire()
            self._track("activation_lock", self._lock.release)

            # Step 2: single-host topology, single tpm2_nv, single DB, single root.
            check_topology(self._plan.topology)

            # Reject any test double before touching real state.
            reject_test_doubles(witness=self._plan.witness, key_provider=self._plan.key_provider)

            # Step 3: open the application DB read-only and verify the schema exists.
            database = Database(self._plan.application_db_path, create_schema=False)
            self._track("application_db", database.close)
            check_schema_read_only(database)

            # AEAD backend must be present (fail closed, no downgrade).
            check_aead_backend()
            check_key_provider(self._plan.key_provider)

            # Step 4-5: verify the TPM anchor (tpm2_nv witness tools present + usable).
            check_tpm_witness(self._plan.witness)

            # Step 6-11: build the remaining trusted services only after checks pass.
            if self._plan.build_services is not None:
                services = self._plan.build_services(database)
                self._track("services", services.close)
                validate_production_service_bundle(
                    services,
                    database=database,
                    witness=self._plan.witness,
                    key_provider=self._plan.key_provider,
                )
                return services.application
            raise ProductionCompositionUnavailableError(
                "production services require the real key provider / adapters (external prerequisites)"
            )
        except AuthorizationKernelError:
            self._cleanup()
            raise
        except Exception:
            self._cleanup()
            raise

    def shutdown(self) -> None:
        self._cleanup()


def validate_production_service_bundle(
    services: ProductionServiceBundle,
    *,
    database: Database,
    witness: NvExtendDigestWitness,
    key_provider: object,
) -> None:
    """Reject builders that split the trusted root or inject test authentication."""
    if services.key_provider is not key_provider:
        raise ProductionCompositionError("production services use a different key provider")
    if services.generation_store.database is not database:
        raise ProductionCompositionError("generation records must use the application SQLite database")
    if not services.generation_store.authentication_is_production:
        raise ProductionCompositionError("generation records require production authentication")
    coordinator = services.generation_coordinator
    if (
        coordinator.database is not database
        or coordinator.witness is not witness
        or coordinator.record_store is not services.generation_store
    ):
        raise ProductionCompositionError("generation coordinator is outside the trusted production root")
    if (
        services.critical_witness_barrier.database is not database
        or services.critical_witness_barrier.coordinator is not coordinator
        or services.wrapped_key_state_service.database is not database
        or services.wrapped_key_state_service.coordinator is not coordinator
    ):
        raise ProductionCompositionError("audit and wrapped-key barriers must share one coordinator")
    if not services.wrapped_key_state_service.blob_store_is_production:
        raise ProductionCompositionError("wrapped-key state requires a durable production blob store")
    services.critical_witness_barrier.verify_current_security_state()
    services.wrapped_key_state_service.current()


def build_production_root() -> None:
    """No-arg production build is unavailable: production needs the external TPM/provider."""
    raise ProductionCompositionUnavailableError(
        "production composition (single-host tpm2_nv witness, production key provider, real adapters) "
        "requires external prerequisites not present in this environment"
    )
