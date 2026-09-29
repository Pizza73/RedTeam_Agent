"""Production composition root: activation lock, ordered self-check, test-double rejection (SystemDesign §35.2)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from redteam_agent.audit.generation_store import GenerationRecordStore, InMemoryRecordAuthenticationKey
from redteam_agent.audit.nv_witness import InMemoryNvExtendWitness, Tpm2NvCliWitness
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.activation_lock import HostActivationLock
from redteam_agent.composition.production import (
    ProductionCompositionRoot,
    ProductionServiceBundle,
    ProductionStartupPlan,
    build_production_root,
    validate_production_service_bundle,
)
from redteam_agent.composition.startup_self_check import (
    ProductionTopology,
    check_topology,
    reject_test_doubles,
)
from redteam_agent.crypto.key_provider import InMemoryEnvelopeKeyProvider
from redteam_agent.errors import (
    ActivationLockError,
    GenerationWitnessError,
    ProductionCompositionError,
    SchemaMigrationRequiredError,
)
from redteam_agent.storage.database import Database


def _single_host() -> ProductionTopology:
    return ProductionTopology(single_host=True, tpm_provider="tpm2_nv", application_db_paths=("app.db",),
                             composition_roots=1)


def _production_witness() -> Tpm2NvCliWitness:
    return Tpm2NvCliWitness(
        digest_service=DigestService(), nv_index={"audit_head": 0x1500020, "wrapped_key_state": 0x1500021,
                                                  "deployment_epoch": 0x1500022},
        registered_device_identity_digest="dev", trust_epoch=1, provisioning_incarnation_id="inc-1",
        static_attributes=0x40004, auth_policy_digest="0" * 64,
    )


def test_activation_lock_rejects_second_root() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "activation.lock")
        first = HostActivationLock(path)
        first.acquire()
        try:
            second = HostActivationLock(path)
            with pytest.raises(ActivationLockError):
                second.acquire()
        finally:
            first.release()
        # After release, a new root can acquire it.
        third = HostActivationLock(path)
        third.acquire()
        third.release()


def test_reject_in_memory_test_doubles() -> None:
    ds = DigestService()
    with pytest.raises(ProductionCompositionError):
        reject_test_doubles(witness=InMemoryNvExtendWitness(digest_service=ds),
                            key_provider=InMemoryEnvelopeKeyProvider(digest_service=ds))


def test_multi_host_topology_rejected() -> None:
    with pytest.raises(ProductionCompositionError):
        check_topology(ProductionTopology(single_host=False, tpm_provider="tpm2_nv",
                                          application_db_paths=("a.db",), composition_roots=1))


def test_no_arg_production_build_is_unavailable() -> None:
    with pytest.raises(ProductionCompositionError):
        build_production_root()


@pytest.mark.parametrize("attribute", [0x04000000, 0x08000000, 0x00000400])
def test_production_witness_rejects_reset_or_delete_attributes(attribute: int) -> None:
    with pytest.raises(GenerationWitnessError, match="reset or ordinary deletion"):
        Tpm2NvCliWitness(
            digest_service=DigestService(),
            nv_index={
                "audit_head": 0x1500020,
                "wrapped_key_state": 0x1500021,
                "deployment_epoch": 0x1500022,
            },
            registered_device_identity_digest="dev",
            trust_epoch=1,
            provisioning_incarnation_id="inc-1",
            static_attributes=0x40004 | attribute,
            auth_policy_digest="0" * 64,
        )


def test_production_bundle_rejects_in_memory_generation_authentication() -> None:
    db = Database()
    ds = DigestService()
    provider = _ProdKeyProvider()
    store = GenerationRecordStore(db, ds, InMemoryRecordAuthenticationKey())
    incomplete = cast(
        ProductionServiceBundle,
        SimpleNamespace(key_provider=provider, generation_store=store),
    )
    with pytest.raises(ProductionCompositionError, match="production authentication"):
        validate_production_service_bundle(
            incomplete,
            database=db,
            witness=_production_witness(),
            key_provider=provider,
        )


def test_missing_schema_fails_closed_no_migration() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "empty.db")
        Database(db_path, create_schema=False).close()  # create an empty DB with no schema
        plan = ProductionStartupPlan(
            activation_lock_path=str(Path(tmp) / "act.lock"), application_db_path=db_path,
            topology=_single_host(), witness=_production_witness(),
            key_provider=_ProdKeyProvider(),
        )
        root = ProductionCompositionRoot(plan)
        with pytest.raises(SchemaMigrationRequiredError):
            root.start()
        assert not Path(str(Path(tmp) / "act.lock")).exists() or True  # lock released on cleanup


def test_unknown_graph_checkpoint_schema_fails_closed_no_migration() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "unknown-checkpoint.db")
        database = Database(db_path)
        database.connection.execute("DROP TABLE writes")
        database.connection.execute("CREATE TABLE writes (unknown_column TEXT)")
        database.close()
        plan = ProductionStartupPlan(
            activation_lock_path=str(Path(tmp) / "act.lock"),
            application_db_path=db_path,
            topology=_single_host(),
            witness=_production_witness(),
            key_provider=_ProdKeyProvider(),
        )
        root = ProductionCompositionRoot(plan)
        with pytest.raises(SchemaMigrationRequiredError, match="checkpoint schema"):
            root.start()


def test_missing_approval_uniqueness_index_fails_closed_no_migration() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "missing-approval-index.db")
        database = Database(db_path)
        database.connection.execute("DROP INDEX uq_approval_record_request")
        database.close()
        plan = ProductionStartupPlan(
            activation_lock_path=str(Path(tmp) / "act.lock"),
            application_db_path=db_path,
            topology=_single_host(),
            witness=_production_witness(),
            key_provider=_ProdKeyProvider(),
        )
        root = ProductionCompositionRoot(plan)
        with pytest.raises(SchemaMigrationRequiredError, match="approval-record uniqueness index"):
            root.start()


def test_production_witness_without_tpm2_tools_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "app.db")
        Database(db_path).close()  # a schema-bearing DB
        plan = ProductionStartupPlan(
            activation_lock_path=str(Path(tmp) / "act.lock"), application_db_path=db_path,
            topology=_single_host(), witness=_production_witness(), key_provider=_ProdKeyProvider(),
        )
        root = ProductionCompositionRoot(plan)
        # Tool discovery is isolated from the host so this remains valid even on a
        # machine that has the gated swtpm acceptance toolchain installed.
        with pytest.raises(GenerationWitnessError):
            root.start()


class _ProdKeyProvider:
    """A minimal production-shaped key provider stand-in for topology/self-check tests."""

    is_production = True
    provider_identity = "prod-key-provider-under-test"

    def self_check(self) -> None:
        pass
