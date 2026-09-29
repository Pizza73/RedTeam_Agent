"""Server-side owner for staged vLLM endpoint and API-key rotation.

The browser may submit a key once, but it can never read it back.  Candidate
configuration is qualified without publishing Mission capability evidence.  Promotion
atomically keeps the previous endpoint active unless the complete Phase 2 check passes.
"""

from __future__ import annotations

import json
import os
import re
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from redteam_agent.ad_assessment.models import ADAssessmentSnapshot
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.ui.control_plane import UIActionBlockedError, UIConflictError
from redteam_agent.ui.models import VllmCandidateInput, VllmConfigInput
from redteam_agent.ui.vllm_capability import Phase2VllmCapabilityPort, Phase2VllmCapabilitySettings

_CAPABILITY_NAMESPACE = "llm_capability_results"
_STATE_REVISION = "vllm-settings-v1"
_MANAGED_KEY_NAME = re.compile(r"^candidate-[0-9a-f]{32}\.key$")


class ManagedVllmPort(Protocol):
    @property
    def public_config(self) -> VllmConfigInput: ...

    @property
    def profile(self) -> Any: ...

    def __call__(self, config: VllmConfigInput) -> dict[str, object]: ...

    def evaluate_capability(
        self, config: VllmConfigInput, *, persist_results: bool
    ) -> dict[str, object]: ...

    def recommend_ad_assessment(self) -> dict[str, object]: ...

    def evaluate_ad_assessment_with_llm(self, snapshot: ADAssessmentSnapshot) -> dict[str, object]: ...

    def close(self) -> None: ...


class PortFactory(Protocol):
    def __call__(self, *, settings: Phase2VllmCapabilitySettings) -> ManagedVllmPort: ...


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Candidate:
    version: int
    base_url: str
    key_file: Path
    port: ManagedVllmPort
    test_status: str = "not_run"
    tested_at: datetime | None = None


class VllmSettingsManager:
    """Own active/candidate state and serialize all LLM use during rotation."""

    def __init__(
        self,
        *,
        initial_port: ManagedVllmPort,
        settings_template: Phase2VllmCapabilitySettings,
        settings_directory: Path,
        allowed_cidrs: tuple[str, ...],
        port_factory: PortFactory = Phase2VllmCapabilityPort,
        clock: Clock = _utc_now,
    ) -> None:
        if not settings_directory.is_absolute():
            raise ValueError("vLLM settings directory must be absolute")
        networks = tuple(ip_network(value, strict=True) for value in allowed_cidrs)
        if not networks or any(not isinstance(network, IPv4Network) for network in networks):
            raise ValueError("vLLM allowed CIDRs must contain at least one canonical IPv4 network")
        self._directory = settings_directory
        self._ensure_private_directory()
        self._template = settings_template
        self._networks = networks
        self._factory = port_factory
        self._clock = clock
        self._lock = threading.RLock()
        self._active: ManagedVllmPort = initial_port
        self._active_version = 1
        self._activated_at: datetime | None = None
        self._active_key_file = settings_template.api_key_file
        self._candidate: _Candidate | None = None
        self._load_persisted_active()
        self._discard_stale_candidates()

    @property
    def profile(self) -> Any:
        with self._lock:
            return self._active.profile

    @property
    def public_config(self) -> VllmConfigInput:
        with self._lock:
            return self._active.public_config

    def public_state(self) -> dict[str, object]:
        with self._lock:
            active = self._active.public_config
            candidate = self._candidate
            return {
                "enabled": True,
                "active": {
                    "version": self._active_version,
                    "config": active.model_dump(mode="json"),
                    "apiKeyConfigured": self._is_private_regular_file(self._active_key_file),
                    "activatedAt": None if self._activated_at is None else self._iso(self._activated_at),
                    "transportSecurity": (
                        "encrypted" if active.baseUrl.startswith("https://") else "isolated_network_required"
                    ),
                },
                "candidate": None if candidate is None else self._candidate_view(candidate),
                "allowedCidrs": [str(network) for network in self._networks],
                "settingsMutable": True,
                "modelMutable": False,
            }

    def stage(self, request: VllmCandidateInput) -> dict[str, object]:
        with self._lock:
            base_url = self._validate_and_normalize_endpoint(request.baseUrl)
            version = max(
                self._active_version,
                0 if self._candidate is None else self._candidate.version,
            ) + 1
            key_file = self._directory / f"candidate-{uuid4().hex}.key"
            self._atomic_write(key_file, request.apiKey.get_secret_value().encode("ascii"), mode=0o600)
            port: ManagedVllmPort | None = None
            previous = self._candidate
            try:
                port = self._build_port(base_url=base_url, key_file=key_file)
                candidate = _Candidate(version=version, base_url=base_url, key_file=key_file, port=port)
                self._persist_candidate(candidate)
                self._candidate = candidate
            except Exception:
                self._unlink_private_file(key_file)
                if port is not None:
                    self._close_port(port)
                raise
            if previous is not None:
                self._close_port(previous.port)
                self._unlink_private_file(previous.key_file)
            return self.public_state()

    def test_candidate(self, *, expected_version: int) -> dict[str, object]:
        with self._lock:
            candidate = self._require_candidate(expected_version)
            result = candidate.port.evaluate_capability(
                candidate.port.public_config,
                persist_results=False,
            )
            candidate.test_status = str(result["status"])
            candidate.tested_at = self._clock().astimezone(UTC)
            self._persist_candidate(candidate)
            return {"settings": self.public_state(), "capability": result}

    def activate_candidate(self, *, expected_version: int) -> dict[str, object]:
        with self._lock:
            candidate = self._require_candidate(expected_version)
            if candidate.test_status != "passed":
                raise UIActionBlockedError(
                    code="VLLM_CANDIDATE_TEST_REQUIRED",
                    message="The candidate LLM endpoint has not passed its capability check.",
                    resolution="Test the current candidate successfully before activation.",
                )
            profile_digest = str(candidate.port.profile.profile_digest)
            backup = self._capability_rows(profile_digest)
            self._delete_capability_rows(profile_digest)
            try:
                result = candidate.port.evaluate_capability(
                    candidate.port.public_config,
                    persist_results=True,
                )
                if result.get("status") != "passed":
                    self._replace_capability_rows(profile_digest, backup)
                    candidate.test_status = str(result.get("status", "failed"))
                    candidate.tested_at = self._clock().astimezone(UTC)
                    self._persist_candidate(candidate)
                    return {"activated": False, "settings": self.public_state(), "capability": result}
                activated_at = self._clock().astimezone(UTC)
                self._persist_active(candidate, activated_at=activated_at)
            except Exception:
                self._replace_capability_rows(profile_digest, backup)
                raise

            previous = self._active
            previous_key_file = self._active_key_file
            self._active = candidate.port
            self._active_version = candidate.version
            self._activated_at = activated_at
            self._active_key_file = candidate.key_file
            self._candidate = None
            self._unlink_private_file(self._directory / "candidate.json")
            if previous is not candidate.port:
                self._close_port(previous)
            if previous_key_file.parent == self._directory and previous_key_file != candidate.key_file:
                self._unlink_private_file(previous_key_file)
            return {"activated": True, "settings": self.public_state(), "capability": result}

    def __call__(self, config: VllmConfigInput) -> dict[str, object]:
        with self._lock:
            if config != self._active.public_config:
                raise UIConflictError("vLLM capability request does not match the active configuration")
            profile_digest = str(self._active.profile.profile_digest)
            backup = self._capability_rows(profile_digest)
            self._delete_capability_rows(profile_digest)
            try:
                result = self._active(config)
            except Exception:
                self._replace_capability_rows(profile_digest, backup)
                raise
            if result.get("status") != "passed":
                self._replace_capability_rows(profile_digest, backup)
            return result

    def recommend_ad_assessment(self) -> dict[str, object]:
        with self._lock:
            return self._active.recommend_ad_assessment()

    def evaluate_ad_assessment_with_llm(self, snapshot: ADAssessmentSnapshot) -> dict[str, object]:
        with self._lock:
            return self._active.evaluate_ad_assessment_with_llm(snapshot)

    def close(self) -> None:
        with self._lock:
            self._close_port(self._active)
            if self._candidate is not None and self._candidate.port is not self._active:
                self._close_port(self._candidate.port)

    def _build_port(self, *, base_url: str, key_file: Path) -> ManagedVllmPort:
        return self._factory(
            settings=replace(self._template, base_url=base_url, api_key_file=key_file)
        )

    def _validate_and_normalize_endpoint(self, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path.rstrip("/") != "/v1"
        ):
            raise ValueError("vLLM endpoint must be a canonical HTTP(S) /v1 URL")
        try:
            address = ip_address(parsed.hostname)
        except ValueError:
            raise ValueError("vLLM endpoint must use an approved literal IPv4 address") from None
        if not isinstance(address, IPv4Address) or not any(address in network for network in self._networks):
            raise ValueError("vLLM endpoint is outside the deployment allowlist")
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError("vLLM endpoint address class is not allowed")
        port = (443 if parsed.scheme == "https" else 80) if parsed.port is None else parsed.port
        return f"{parsed.scheme}://{address}:{port}/v1"

    def _require_candidate(self, expected_version: int) -> _Candidate:
        candidate = self._candidate
        if candidate is None or candidate.version != expected_version:
            raise UIConflictError("the vLLM candidate is missing or stale")
        return candidate

    def _candidate_view(self, candidate: _Candidate) -> dict[str, object]:
        return {
            "version": candidate.version,
            "config": candidate.port.public_config.model_dump(mode="json"),
            "apiKeyConfigured": self._is_private_regular_file(candidate.key_file),
            "testStatus": candidate.test_status,
            "testedAt": None if candidate.tested_at is None else self._iso(candidate.tested_at),
            "transportSecurity": (
                "encrypted" if candidate.base_url.startswith("https://") else "isolated_network_required"
            ),
        }

    def _ensure_private_directory(self) -> None:
        self._directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = self._directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError("vLLM settings directory must be a real directory")
        if metadata.st_uid != os.geteuid():
            raise ValueError("vLLM settings directory ownership is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            os.chmod(self._directory, 0o700)

    def _load_persisted_active(self) -> None:
        path = self._directory / "active.json"
        if not path.exists():
            return
        raw = self._read_private_json(path)
        if set(raw) != {"revision", "version", "baseUrl", "keyFile", "activatedAt"}:
            raise ValueError("persisted vLLM active settings are malformed")
        if (
            raw["revision"] != _STATE_REVISION
            or not isinstance(raw["version"], int)
            or isinstance(raw["version"], bool)
            or raw["version"] < 1
        ):
            raise ValueError("persisted vLLM active settings revision is invalid")
        if not isinstance(raw["baseUrl"], str) or not isinstance(raw["keyFile"], str):
            raise ValueError("persisted vLLM active settings types are invalid")
        if _MANAGED_KEY_NAME.fullmatch(raw["keyFile"]) is None:
            raise ValueError("persisted vLLM key reference is invalid")
        key_file = self._directory / raw["keyFile"]
        if not self._is_private_regular_file(key_file):
            raise ValueError("persisted vLLM API key is unavailable or unsafe")
        base_url = self._validate_and_normalize_endpoint(raw["baseUrl"])
        if not isinstance(raw["activatedAt"], str):
            raise ValueError("persisted vLLM activation time is invalid")
        activated_at = datetime.fromisoformat(raw["activatedAt"].replace("Z", "+00:00"))
        if activated_at.tzinfo is None or activated_at.utcoffset() is None:
            raise ValueError("persisted vLLM activation time must include a timezone")
        self._close_port(self._active)
        self._active = self._build_port(base_url=base_url, key_file=key_file)
        self._active_version = raw["version"]
        self._activated_at = activated_at.astimezone(UTC)
        self._active_key_file = key_file

    def _persist_candidate(self, candidate: _Candidate) -> None:
        payload = {
            "revision": _STATE_REVISION,
            "version": candidate.version,
            "baseUrl": candidate.base_url,
            "keyFile": candidate.key_file.name,
            "testStatus": candidate.test_status,
            "testedAt": None if candidate.tested_at is None else self._iso(candidate.tested_at),
        }
        self._atomic_write(
            self._directory / "candidate.json",
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            mode=0o600,
        )

    def _discard_stale_candidates(self) -> None:
        """A restart invalidates a staged test; remove every non-active candidate key."""

        self._unlink_private_file(self._directory / "candidate.json")
        for path in self._directory.glob("candidate-*.key"):
            if path != self._active_key_file:
                self._unlink_private_file(path)

    def _persist_active(self, candidate: _Candidate, *, activated_at: datetime) -> None:
        payload = {
            "revision": _STATE_REVISION,
            "version": candidate.version,
            "baseUrl": candidate.base_url,
            "keyFile": candidate.key_file.name,
            "activatedAt": self._iso(activated_at),
        }
        self._atomic_write(
            self._directory / "active.json",
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            mode=0o600,
        )

    def _capability_rows(self, profile_digest: str) -> tuple[tuple[str, int, str], ...]:
        database = Database(str(self._template.database_path), create_schema=False)
        try:
            return tuple(
                row
                for row in database.occ_get_all(_CAPABILITY_NAMESPACE)
                if json.loads(row[2]).get("profile_digest") == profile_digest
            )
        finally:
            database.close()

    def _delete_capability_rows(self, profile_digest: str) -> None:
        database = Database(str(self._template.database_path), create_schema=False)
        try:
            keys = [
                key
                for key, _version, raw in database.occ_get_all(_CAPABILITY_NAMESPACE)
                if json.loads(raw).get("profile_digest") == profile_digest
            ]
            with UnitOfWork(database):
                for key in keys:
                    database.occ_delete(_CAPABILITY_NAMESPACE, key)
        finally:
            database.close()

    def _replace_capability_rows(
        self,
        profile_digest: str,
        rows: tuple[tuple[str, int, str], ...],
    ) -> None:
        self._delete_capability_rows(profile_digest)
        database = Database(str(self._template.database_path), create_schema=False)
        try:
            with UnitOfWork(database):
                for key, version, raw in rows:
                    database.occ_insert(_CAPABILITY_NAMESPACE, key, version, raw)
        finally:
            database.close()

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _atomic_write(path: Path, payload: bytes, *, mode: int) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _is_private_regular_file(path: Path) -> bool:
        try:
            metadata = path.lstat()
        except OSError:
            return False
        return (
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid in {0, os.geteuid()}
            and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        )

    @classmethod
    def _read_private_json(cls, path: Path) -> dict[str, object]:
        if not cls._is_private_regular_file(path):
            raise ValueError("vLLM settings state file is unavailable or unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("vLLM settings state must be an object")
        return value

    @classmethod
    def _unlink_private_file(cls, path: Path) -> None:
        if cls._is_private_regular_file(path):
            path.unlink()

    @staticmethod
    def _close_port(port: ManagedVllmPort) -> None:
        close = getattr(port, "close", None)
        if callable(close):
            close()


__all__ = ["ManagedVllmPort", "VllmSettingsManager"]
