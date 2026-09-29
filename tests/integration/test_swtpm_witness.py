"""Production TPM witness integration test against ``swtpm`` (SystemDesign §34.2.2).

This is the required real-TPM acceptance test. It is gated on ``swtpm`` + ``tpm2-tools``
being installed; when they are absent it skips with an explicit environment prerequisite
(Phase 0C is not complete until this has actually run). When present it provisions the NV
indices, drives the production ``Tpm2NvCliWitness`` through genesis/commit/current, and
checks restart, SQLite rollback, TPM reset and a missing record all fail closed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from redteam_agent.audit.generation import AuthenticatedGenerationCoordinator
from redteam_agent.audit.generation_store import GenerationRecordStore, InMemoryRecordAuthenticationKey
from redteam_agent.audit.nv_witness import Tpm2NvCliWitness
from redteam_agent.canonical.digest_catalog import CATALOG_REVISION
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AnchorRecoveryRequiredError, GenerationWitnessError
from redteam_agent.storage.database import Database

_REQUIRED = ("swtpm", "tpm2_startup", "tpm2_nvdefine", "tpm2_nvundefine", "tpm2_nvextend",
             "tpm2_nvread", "tpm2_nvreadpublic", "tpm2_nvincrement")
_MISSING = [tool for tool in _REQUIRED if shutil.which(tool) is None]

pytestmark = pytest.mark.skipif(
    bool(_MISSING),
    reason=f"swtpm/tpm2-tools prerequisite not installed: missing {', '.join(_MISSING)}",
)

_NV_INDEX = {"audit_head": 0x1500020, "wrapped_key_state": 0x1500021, "deployment_epoch": 0x1500022}


def _free_port_pair() -> int:
    """Return a free data port whose following port is also free.

    The swtpm TCTI derives the control port as ``data port + 1``; the emulator must
    therefore be launched with that exact consecutive pair.
    """
    for _attempt in range(100):
        with socket.socket() as data:
            data.bind(("127.0.0.1", 0))
            port = int(data.getsockname()[1])
            if port == 65535:
                continue
            with socket.socket() as control:
                try:
                    control.bind(("127.0.0.1", port + 1))
                except OSError:
                    continue
                return port
    raise RuntimeError("could not allocate consecutive swtpm ports")


@pytest.fixture()
def swtpm_tcti(tmp_path: Path) -> Iterator[str]:
    state = tmp_path / "swtpm-state"
    state.mkdir()
    server_port = _free_port_pair()
    ctrl_port = server_port + 1
    proc = subprocess.Popen(
        ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}", "--flags", "not-need-init",
         "--server", f"type=tcp,port={server_port}", "--ctrl", f"type=tcp,port={ctrl_port}"],
    )
    tcti = f"swtpm:host=127.0.0.1,port={server_port}"
    try:
        time.sleep(0.5)
        env = {"TPM2TOOLS_TCTI": tcti}
        subprocess.run(["tpm2_startup", "-c"], check=True, env={**_os_environ(), **env}, timeout=15)
        yield tcti
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def _os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)


def _provision(tcti: str) -> None:
    env = {**_os_environ(), "TPM2TOOLS_TCTI": tcti}
    for role in ("audit_head", "wrapped_key_state"):
        subprocess.run(
            ["tpm2_nvdefine", hex(_NV_INDEX[role]), "-C", "o", "-s", "32",
             "-a", "nt=extend|ownerwrite|ownerread|authwrite|authread"],
            check=True, env=env, timeout=15,
        )
    subprocess.run(
        ["tpm2_nvdefine", hex(_NV_INDEX["deployment_epoch"]), "-C", "o", "-s", "8",
         "-a", "nt=counter|ownerwrite|ownerread|authwrite|authread"],
        check=True, env=env, timeout=15,
    )


def _reset_extend_index(tcti: str, role: str) -> None:
    env = {**_os_environ(), "TPM2TOOLS_TCTI": tcti}
    index = hex(_NV_INDEX[role])
    subprocess.run(["tpm2_nvundefine", index, "-C", "o"], check=True, env=env, timeout=15)
    subprocess.run(
        ["tpm2_nvdefine", index, "-C", "o", "-s", "32",
         "-a", "nt=extend|ownerwrite|ownerread|authwrite|authread"],
        check=True, env=env, timeout=15,
    )


def _witness(tcti: str) -> Tpm2NvCliWitness:
    return Tpm2NvCliWitness(
        digest_service=DigestService(), nv_index=dict(_NV_INDEX), registered_device_identity_digest="swtpm-dev",
        trust_epoch=1, provisioning_incarnation_id="inc-1",
        static_attributes={"audit_head": 0x60046, "wrapped_key_state": 0x60046, "deployment_epoch": 0x60016},
        auth_policy_digest="0" * 64,
        tcti=tcti,
    )


def _coordinator(db: Database, witness: Tpm2NvCliWitness) -> AuthenticatedGenerationCoordinator:
    ds = DigestService()
    store = GenerationRecordStore(db, ds, InMemoryRecordAuthenticationKey(b"swtpm-key-" + b"0" * 22))
    return AuthenticatedGenerationCoordinator(database=db, witness=witness, record_store=store, digest_service=ds,
                                              digest_catalog_revision=CATALOG_REVISION)


def test_genesis_commit_and_current_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    witness = _witness(swtpm_tcti)
    witness.self_check()
    db = Database(":memory:")
    coordinator = _coordinator(db, witness)
    coordinator.genesis("audit_head", initial_state_digest="s0", initial_content="c0")
    r1 = coordinator.commit("audit_head", new_state_digest="s1", new_content="c1", operation_id="op-1")
    assert coordinator.current("audit_head").generation == r1.generation == 1
    # Restart: a fresh coordinator over the same DB + TPM resolves the same current.
    restarted = _coordinator(db, _witness(swtpm_tcti))
    assert restarted.current("audit_head").generation == 1


def test_missing_record_fails_closed_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    witness = _witness(swtpm_tcti)
    db = Database(":memory:")
    coordinator = _coordinator(db, witness)
    coordinator.genesis("audit_head", initial_state_digest="s0", initial_content="c0")
    r1 = coordinator.commit("audit_head", new_state_digest="s1", new_content="c1", operation_id="op-1")
    # The witness index still resolves, but its authenticated generation record is gone.
    db.connection.execute("DELETE FROM occ_store WHERE namespace = 'generation_record' AND key = ?",
                          (f"audit_head/1/{r1.generation}",))
    db.connection.commit()
    with pytest.raises(AnchorRecoveryRequiredError):
        coordinator.current("audit_head")


def test_sqlite_rollback_fails_closed_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    db = Database(":memory:")
    coordinator = _coordinator(db, _witness(swtpm_tcti))
    coordinator.genesis("audit_head", initial_state_digest="s0", initial_content="c0")
    r1 = coordinator.commit("audit_head", new_state_digest="s1", new_content="c1", operation_id="op-1")
    # Model restoration of the SQLite store to generation 0 while TPM NV remains at 1.
    db.connection.execute("DELETE FROM occ_store WHERE namespace = 'generation_record' AND key = ?",
                          (f"audit_head/1/{r1.generation}",))
    db.connection.execute("DELETE FROM occ_store WHERE namespace = 'generation_record_witness' AND key = ?",
                          (f"audit_head/1/{r1.witness_digest}",))
    db.connection.commit()
    with pytest.raises(AnchorRecoveryRequiredError):
        coordinator.current("audit_head")


def test_tpm_reset_fails_closed_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    db = Database(":memory:")
    coordinator = _coordinator(db, _witness(swtpm_tcti))
    coordinator.genesis("audit_head", initial_state_digest="s0", initial_content="c0")
    _reset_extend_index(swtpm_tcti, "audit_head")
    with pytest.raises(AnchorRecoveryRequiredError):
        coordinator.current("audit_head")


def test_nv_identity_mismatch_fails_closed_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    db = Database(":memory:")
    coordinator = _coordinator(db, _witness(swtpm_tcti))
    coordinator.genesis("audit_head", initial_state_digest="s0", initial_content="c0")
    mismatched = Tpm2NvCliWitness(
        digest_service=DigestService(), nv_index=dict(_NV_INDEX),
        registered_device_identity_digest="different-device", trust_epoch=1,
        provisioning_incarnation_id="inc-2",
        static_attributes={"audit_head": 0x60046, "wrapped_key_state": 0x60046, "deployment_epoch": 0x60016},
        auth_policy_digest="0" * 64, tcti=swtpm_tcti,
    )
    with pytest.raises(AnchorRecoveryRequiredError):
        _coordinator(db, mismatched).current("audit_head")


def test_deployment_counter_requires_explicit_initialization_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    coordinator = _coordinator(Database(":memory:"), _witness(swtpm_tcti))
    with pytest.raises(GenerationWitnessError):
        coordinator.read_deployment_epoch()
    first = coordinator.initialize_deployment_epoch()
    assert first > 0
    assert coordinator.advance_deployment_epoch() > first


def test_static_nv_public_area_mismatch_fails_closed_against_swtpm(swtpm_tcti: str) -> None:
    _provision(swtpm_tcti)
    mismatched = Tpm2NvCliWitness(
        digest_service=DigestService(), nv_index=dict(_NV_INDEX),
        registered_device_identity_digest="swtpm-dev", trust_epoch=1,
        provisioning_incarnation_id="inc-1",
        static_attributes={
            "audit_head": 0x60047,
            "wrapped_key_state": 0x60046,
            "deployment_epoch": 0x60016,
        },
        auth_policy_digest="0" * 64,
        tcti=swtpm_tcti,
    )
    with pytest.raises(AnchorRecoveryRequiredError, match="public area"):
        mismatched.self_check()
