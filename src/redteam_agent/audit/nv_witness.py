"""TPM 2.0 NV Extend digest witness (SystemDesign §34.2 / §34.2.2).

The witness is the rollback-detecting anchor: audit_head and wrapped_key_state are
SHA-256 NV Extend indices whose current value is ``SHA256(previous || data)``, and
deployment_epoch is a monotonic NV counter. The witness lives in a restore domain
separate from the SQLite generation store, so rolling the database back cannot roll
the witness back.

* :class:`NvExtendDigestWitness` is the interface used by the generation coordinator.
* :class:`InMemoryNvExtendWitness` is a deterministic test double (Unit/Fault tests).
  It is explicitly *not* production (the composition self-check rejects it).
* :class:`Tpm2NvCliWitness` is the production implementation. It shells out to the
  ``tpm2_nv*`` CLI (tpm2-tools) against a real TPM or ``swtpm``. It performs no work at
  import time and is exercised only by the gated swtpm integration test.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Protocol

from redteam_agent.audit.models import NvPublicArea, NvRole, ProvisionedNvIdentity
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AnchorRecoveryRequiredError, GenerationWitnessError

_ZERO32 = "00" * 32
_EXTEND_ROLES: tuple[NvRole, ...] = ("audit_head", "wrapped_key_state")
# NV attribute bit modelled for WRITTEN in the in-memory double's public area.
_TPMA_NV_WRITTEN = 0x20000000
_TPMA_NV_WRITELOCKED = 0x00000800
_TPMA_NV_READLOCKED = 0x10000000
_DYNAMIC_ATTRIBUTE_MASK = _TPMA_NV_WRITTEN | _TPMA_NV_WRITELOCKED | _TPMA_NV_READLOCKED
_TPMA_NV_POLICY_DELETE = 0x00000400
_TPMA_NV_ORDERLY = 0x04000000
_TPMA_NV_CLEAR_STCLEAR = 0x08000000
_PROHIBITED_STATIC_ATTRIBUTES = _TPMA_NV_POLICY_DELETE | _TPMA_NV_ORDERLY | _TPMA_NV_CLEAR_STCLEAR


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_identity_digest(
    *, registered_device_identity_digest: str, trust_epoch: int, provisioning_incarnation_id: str,
    nv_index: int, role: NvRole, static_attributes: int, auth_policy_digest: str, data_size: int,
    digest_service: DigestService,
) -> str:
    payload = {
        "identity_schema": "nv-index-identity-v1",
        "registered_device_identity_digest": registered_device_identity_digest,
        "trust_epoch": trust_epoch, "provisioning_incarnation_id": provisioning_incarnation_id,
        "nv_index": nv_index, "role": role, "name_algorithm": "sha256",
        "static_attributes": static_attributes, "auth_policy_digest": auth_policy_digest,
        "data_size": data_size,
    }
    return digest_service.compute("nv_index_identity_digest", payload)


class NvExtendDigestWitness(Protocol):
    is_production: bool
    provider_kind: str

    def identity(self, role: NvRole) -> ProvisionedNvIdentity: ...
    def public_area(self, role: NvRole) -> NvPublicArea: ...
    def read_witness(self, role: NvRole) -> str: ...
    def extend(self, role: NvRole, data_hex: str) -> str: ...
    def read_counter(self, role: NvRole) -> int: ...
    def increment_counter(self, role: NvRole) -> int: ...


class InMemoryNvExtendWitness:
    """Deterministic in-memory NV Extend witness (test double, never production)."""

    is_production = False
    provider_kind = "in_memory"

    def __init__(
        self,
        *,
        digest_service: DigestService,
        trust_epoch: int = 1,
        device_identity: str = "device-a",
        incarnation: str = "incarnation-1",
    ) -> None:
        self._ds = digest_service
        self._trust_epoch = trust_epoch
        self._device_identity = device_identity
        self._incarnation = incarnation
        self._nv_index = {"audit_head": 0x01500020, "wrapped_key_state": 0x01500021,
                          "deployment_epoch": 0x01500022}
        self._static_attributes = 0x00040004  # AUTHREAD|AUTHWRITE-shaped constant (fixed)
        self._auth_policy_digest = _ZERO32
        self._data_size = {"audit_head": 32, "wrapped_key_state": 32, "deployment_epoch": 8}
        self._witness: dict[str, str] = dict.fromkeys(_EXTEND_ROLES, _ZERO32)
        self._written: dict[NvRole, bool] = {"audit_head": False, "wrapped_key_state": False,
                                             "deployment_epoch": False}
        self._counter = 0

    # --- fault-injection controls (tests only) ---------------------------

    def simulate_reset(self) -> None:
        """TPM Clear/Reset: NV Extend values return to zero and WRITTEN=0."""
        for role in _EXTEND_ROLES:
            self._witness[role] = _ZERO32
            self._written[role] = False
        self._written["deployment_epoch"] = False
        self._counter = 0

    def simulate_identity_change(self, device_identity: str) -> None:
        self._device_identity = device_identity

    def simulate_counter_decrease(self) -> None:
        if self._counter > 0:
            self._counter -= 1

    # --- interface --------------------------------------------------------

    def identity(self, role: NvRole) -> ProvisionedNvIdentity:
        digest = compute_identity_digest(
            registered_device_identity_digest=self._device_identity, trust_epoch=self._trust_epoch,
            provisioning_incarnation_id=self._incarnation, nv_index=self._nv_index[role], role=role,
            static_attributes=self._static_attributes, auth_policy_digest=self._auth_policy_digest,
            data_size=self._data_size[role], digest_service=self._ds,
        )
        return ProvisionedNvIdentity(
            registered_device_identity_digest=self._device_identity, trust_epoch=self._trust_epoch,
            provisioning_incarnation_id=self._incarnation, nv_index=self._nv_index[role], role=role,
            static_attributes=self._static_attributes, auth_policy_digest=self._auth_policy_digest,
            data_size=self._data_size[role], identity_digest=digest,
        )

    def public_area(self, role: NvRole) -> NvPublicArea:
        attributes = self._static_attributes | (_TPMA_NV_WRITTEN if self._written[role] else 0)
        name = _sha256_hex(
            f"{role}:{self._nv_index[role]}:{attributes}:{self._auth_policy_digest}".encode()
        )
        return NvPublicArea(
            role=role, nv_index=self._nv_index[role], static_attributes=self._static_attributes,
            written=self._written[role], write_locked=False, read_locked=False,
            auth_policy_digest=self._auth_policy_digest, data_size=self._data_size[role], name=name,
        )

    def read_witness(self, role: NvRole) -> str:
        if role not in _EXTEND_ROLES:
            raise GenerationWitnessError(f"{role} is not an extend index")
        return self._witness[role]

    def extend(self, role: NvRole, data_hex: str) -> str:
        if role not in _EXTEND_ROLES:
            raise GenerationWitnessError(f"{role} is not an extend index")
        if len(bytes.fromhex(data_hex)) != 32:
            raise GenerationWitnessError("extend data must be 32 bytes")
        current = bytes.fromhex(self._witness[role])
        self._witness[role] = _sha256_hex(current + bytes.fromhex(data_hex))
        self._written[role] = True
        return self._witness[role]

    def read_counter(self, role: NvRole) -> int:
        if role != "deployment_epoch":
            raise GenerationWitnessError("counter read is only for deployment_epoch")
        return self._counter

    def increment_counter(self, role: NvRole) -> int:
        if role != "deployment_epoch":
            raise GenerationWitnessError("counter increment is only for deployment_epoch")
        self._counter += 1
        self._written["deployment_epoch"] = True
        return self._counter


class Tpm2NvCliWitness:
    """Production NV Extend witness driving tpm2-tools against a TPM / swtpm.

    Requires ``tpm2_nvread`` / ``tpm2_nvextend`` / ``tpm2_nvreadpublic`` /
    ``tpm2_nvincrement`` on PATH and a TCTI environment (``TPM2TOOLS_TCTI``) pointing at
    the device. No CLI is invoked at construction; :meth:`self_check` verifies the tools
    exist so the composition self-check can fail closed before admitting missions.
    """

    is_production = True
    provider_kind = "tpm2_nv"

    _REQUIRED_TOOLS = ("tpm2_nvread", "tpm2_nvextend", "tpm2_nvreadpublic", "tpm2_nvincrement")

    def __init__(
        self,
        *,
        digest_service: DigestService,
        nv_index: dict[NvRole, int],
        registered_device_identity_digest: str,
        trust_epoch: int,
        provisioning_incarnation_id: str,
        static_attributes: int | dict[NvRole, int],
        auth_policy_digest: str,
        tcti: str | None = None,
    ) -> None:
        self._ds = digest_service
        self._nv_index = nv_index
        self._device_identity = registered_device_identity_digest
        self._trust_epoch = trust_epoch
        self._incarnation = provisioning_incarnation_id
        if isinstance(static_attributes, int):
            self._static_attributes: dict[NvRole, int] = dict.fromkeys(
                ("audit_head", "wrapped_key_state", "deployment_epoch"), static_attributes
            )
        else:
            self._static_attributes = {}
            self._static_attributes.update(static_attributes)
        expected_roles = {"audit_head", "wrapped_key_state", "deployment_epoch"}
        if set(self._nv_index) != expected_roles or set(self._static_attributes) != expected_roles:
            raise GenerationWitnessError("production TPM configuration must define each NV role exactly once")
        if len(set(self._nv_index.values())) != len(expected_roles):
            raise GenerationWitnessError("production TPM roles require distinct NV indices")
        if any(value & _PROHIBITED_STATIC_ATTRIBUTES for value in self._static_attributes.values()):
            raise GenerationWitnessError(
                "production TPM NV attributes permit reset or ordinary deletion"
            )
        try:
            policy = bytes.fromhex(auth_policy_digest)
        except ValueError as exc:
            raise GenerationWitnessError("production TPM authorization policy is not hex") from exc
        if len(policy) not in (0, 32):
            raise GenerationWitnessError("production TPM authorization policy must be empty or SHA-256")
        self._auth_policy_digest = auth_policy_digest
        self._data_size: dict[NvRole, int] = {"audit_head": 32, "wrapped_key_state": 32,
                                              "deployment_epoch": 8}
        self._tcti = tcti

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        if self._tcti is not None:
            env["TPM2TOOLS_TCTI"] = self._tcti
        return env

    def _run(self, args: list[str], *, capture: bool = True) -> bytes:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed tpm2-tools argv, no shell
                args, check=True, capture_output=capture, env=self._env(), timeout=30,
            )
        except FileNotFoundError as exc:
            raise GenerationWitnessError(f"tpm2 tool not found: {args[0]}") from exc
        except subprocess.CalledProcessError as exc:  # pragma: no cover - requires swtpm
            raise GenerationWitnessError(f"tpm2 command failed: {args[0]} rc={exc.returncode}") from exc
        return completed.stdout if capture else b""

    def self_check(self) -> None:
        missing = [t for t in self._REQUIRED_TOOLS if shutil.which(t) is None]
        if missing:
            raise GenerationWitnessError(f"missing tpm2 tools: {', '.join(missing)}")
        for role in ("audit_head", "wrapped_key_state", "deployment_epoch"):
            public = self.public_area(role)
            if (
                public.nv_index != self._nv_index[role]
                or public.static_attributes != self._static_attributes[role]
                or public.auth_policy_digest != self._auth_policy_digest
                or public.data_size != self._data_size[role]
            ):
                raise AnchorRecoveryRequiredError(f"{role} NV public area does not match provisioned identity")
            if public.write_locked or public.read_locked:
                raise AnchorRecoveryRequiredError(f"{role} NV index is unexpectedly locked")

    def identity(self, role: NvRole) -> ProvisionedNvIdentity:
        digest = compute_identity_digest(
            registered_device_identity_digest=self._device_identity, trust_epoch=self._trust_epoch,
            provisioning_incarnation_id=self._incarnation, nv_index=self._nv_index[role], role=role,
            static_attributes=self._static_attributes[role], auth_policy_digest=self._auth_policy_digest,
            data_size=self._data_size[role], digest_service=self._ds,
        )
        return ProvisionedNvIdentity(
            registered_device_identity_digest=self._device_identity, trust_epoch=self._trust_epoch,
            provisioning_incarnation_id=self._incarnation, nv_index=self._nv_index[role], role=role,
            static_attributes=self._static_attributes[role], auth_policy_digest=self._auth_policy_digest,
            data_size=self._data_size[role], identity_digest=digest,
        )

    def public_area(self, role: NvRole) -> NvPublicArea:  # pragma: no cover - requires swtpm
        out = self._run(["tpm2_nvreadpublic", hex(self._nv_index[role])]).decode()
        name_match = re.search(r"(?m)^\s*name:\s*([0-9a-fA-F]+)\s*$", out)
        attributes_match = re.search(
            r"(?ms)^\s*attributes:\s*\n(?:.*\n)*?\s*value:\s*(0x[0-9a-fA-F]+)\s*$", out
        )
        size_match = re.search(r"(?m)^\s*size:\s*(\d+)\s*$", out)
        algorithm_match = re.search(r"(?m)^\s*friendly:\s*sha256\s*$", out)
        if name_match is None or attributes_match is None or size_match is None or algorithm_match is None:
            raise GenerationWitnessError("tpm2_nvreadpublic returned an incomplete NV public area")
        name = name_match.group(1).lower()
        if len(name) != 68 or not name.startswith("000b"):
            raise GenerationWitnessError("tpm2_nvreadpublic returned an invalid SHA-256 NV Name")
        attributes = int(attributes_match.group(1), 16)
        policy_match = re.search(r"(?m)^\s*authorization policy:\s*([0-9a-fA-F]+)\s*$", out)
        policy_bytes = bytes.fromhex(policy_match.group(1)) if policy_match is not None else b""
        auth_policy = policy_bytes.hex() if policy_bytes else _ZERO32
        data_size = int(size_match.group(1))
        marshaled_public = (
            struct.pack(">IHIH", self._nv_index[role], 0x000B, attributes, len(policy_bytes))
            + policy_bytes
            + struct.pack(">H", data_size)
        )
        expected_name = "000b" + hashlib.sha256(marshaled_public).hexdigest()
        if name != expected_name:
            raise AnchorRecoveryRequiredError("TPM NV Name does not match the returned public area")
        return NvPublicArea(
            role=role, nv_index=self._nv_index[role], static_attributes=attributes & ~_DYNAMIC_ATTRIBUTE_MASK,
            written=bool(attributes & _TPMA_NV_WRITTEN),
            write_locked=bool(attributes & _TPMA_NV_WRITELOCKED),
            read_locked=bool(attributes & _TPMA_NV_READLOCKED), auth_policy_digest=auth_policy,
            data_size=data_size, name=name,
        )

    def read_witness(self, role: NvRole) -> str:  # pragma: no cover - requires swtpm
        if role not in _EXTEND_ROLES:
            raise GenerationWitnessError(f"{role} is not an extend index")
        # TPM2_NV_Read rejects a newly defined, unwritten NV Extend index with
        # TPM2_RC_NV_UNINITIALIZED.  Its logical initial witness is the all-zero
        # digest, verified here from the public WRITTEN attribute before reading.
        if not self.public_area(role).written:
            return _ZERO32
        raw = self._run(["tpm2_nvread", hex(self._nv_index[role])])
        if len(raw) != 32:
            raise AnchorRecoveryRequiredError("tpm2_nvread returned an unexpected size")
        return raw.hex()

    def extend(self, role: NvRole, data_hex: str) -> str:  # pragma: no cover - requires swtpm
        if role not in _EXTEND_ROLES:
            raise GenerationWitnessError(f"{role} is not an extend index")
        data = bytes.fromhex(data_hex)
        if len(data) != 32:
            raise GenerationWitnessError("extend data must be 32 bytes")
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(data)
            handle.flush()
            self._run(["tpm2_nvextend", "-i", handle.name, hex(self._nv_index[role])], capture=False)
        return self.read_witness(role)

    def read_counter(self, role: NvRole) -> int:  # pragma: no cover - requires swtpm
        if role != "deployment_epoch":
            raise GenerationWitnessError("counter read is only for deployment_epoch")
        if not self.public_area(role).written:
            raise GenerationWitnessError("deployment epoch counter is uninitialized")
        raw = self._run(["tpm2_nvread", hex(self._nv_index[role])])
        return int.from_bytes(raw, "big")

    def increment_counter(self, role: NvRole) -> int:  # pragma: no cover - requires swtpm
        if role != "deployment_epoch":
            raise GenerationWitnessError("counter increment is only for deployment_epoch")
        self._run(["tpm2_nvincrement", hex(self._nv_index[role])], capture=False)
        return self.read_counter(role)
