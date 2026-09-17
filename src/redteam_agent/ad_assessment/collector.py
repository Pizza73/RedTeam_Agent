"""Trusted, read-only collection of normalized Active Directory evidence."""

from __future__ import annotations

import json
import re
import ssl
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from ldap3 import AUTO_BIND_NO_TLS, BASE, NONE, NTLM, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars
from pydantic import Field

from redteam_agent.ad_assessment.models import (
    ADAssessmentSnapshot,
    ADCSEvidence,
    ADCSExposureCount,
    ADCSExposureId,
    DelegationEvidence,
    KerberosPreauthEvidence,
    KerberosServiceAccountEvidence,
    PrivilegedAccessEvidence,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import PydanticBoundaryValidationError
from redteam_agent.models.base import StrictImmutableBoundaryModel

_TIER_ZERO_GROUPS = ("Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins")
_DEFAULT_EXPECTED_TIER_ZERO_NAMES = frozenset(
    {"administrator", "administrators", "domain admins", "enterprise admins", "schema admins"}
)
_HIGH_IMPACT_DELEGATION_SERVICES = frozenset({"cifs", "host", "ldap", "rpcss", "wsman"})
_UAC_DISABLED = 0x2
_UAC_PREAUTH_NOT_REQUIRED = 0x400000
_UAC_TRUSTED_FOR_DELEGATION = 0x80000
_UAC_TRUSTED_TO_AUTH = 0x1000000
_WEAK_KERBEROS_ENCRYPTION_BITS = 0x7
_ESC_IDS: tuple[ADCSExposureId, ...] = ("ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8")


class ADCollectorError(RuntimeError):
    """Content-free internal cause plus an operator-safe remediation."""

    def __init__(self, *, code: str, message: str, resolution: str) -> None:
        super().__init__(message)
        self.code = code
        self.user_message = message
        self.resolution = resolution


class ADCollectorCredential(StrictImmutableBoundaryModel):
    domain: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=4096)


@dataclass(frozen=True)
class ADCollectorSettings:
    server_ip: IPv4Address
    port: int
    domain: str
    credential_file: Path
    tls_ca_file: Path | None
    certipy_python: Path
    stale_password_days: int = 180
    max_constrained_delegation_targets: int = 10
    expected_tier_zero_names: tuple[str, ...] = ()
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535 or self.port != 636:
            raise ValueError("verified AD collection requires the fixed LDAPS port 636")
        if not re.fullmatch(
            r"(?i)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", self.domain
        ):
            raise ValueError("AD collector domain must be a canonical DNS name")
        if any(not path.is_absolute() for path in (self.credential_file, self.certipy_python)):
            raise ValueError("AD collector secret and interpreter paths must be absolute")
        if self.tls_ca_file is not None and not self.tls_ca_file.is_absolute():
            raise ValueError("AD collector CA path must be absolute")
        if self.stale_password_days < 1 or self.max_constrained_delegation_targets < 1:
            raise ValueError("AD collector thresholds must be positive")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("AD collector timeout must be between 1 and 60 seconds")
        canonical = tuple(item.strip().casefold() for item in self.expected_tier_zero_names)
        if any(not item or len(item) > 255 for item in canonical) or len(canonical) != len(set(canonical)):
            raise ValueError("expected tier-zero names must be unique and canonical")

    @property
    def base_dn(self) -> str:
        return ",".join(f"DC={label}" for label in self.domain.split("."))


@dataclass(frozen=True)
class DirectoryEvidence:
    privileged_access: PrivilegedAccessEvidence
    kerberos_service_accounts: KerberosServiceAccountEvidence
    kerberos_preauth: KerberosPreauthEvidence
    delegation: DelegationEvidence


class DirectoryEvidenceSource(Protocol):
    def collect(self, credential: ADCollectorCredential) -> DirectoryEvidence: ...


class ADCSAssessmentSource(Protocol):
    def collect(self, credential: ADCollectorCredential) -> ADCSEvidence: ...


class Ldap3DirectoryEvidenceSource:
    """One fixed-IP LDAPS bind with certificate validation and no referrals."""

    def __init__(
        self,
        settings: ADCollectorSettings,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._settings = settings
        self._clock = clock

    def collect(self, credential: ADCollectorCredential) -> DirectoryEvidence:
        if credential.domain.casefold() != self._settings.domain.casefold():
            raise ADCollectorError(
                code="AD_COLLECTOR_SECRET_DOMAIN_MISMATCH",
                message="The AD collector credential is for a different domain.",
                resolution="Install a credential file for the configured AD domain.",
            )
        connection = self._connect(credential)
        try:
            self._attest_naming_context(connection)
            privileged, tier_zero_dns = self._collect_privileged(connection)
            return DirectoryEvidence(
                privileged_access=privileged,
                kerberos_service_accounts=self._collect_service_accounts(connection),
                kerberos_preauth=self._collect_preauth(connection),
                delegation=self._collect_delegation(connection, tier_zero_dns=tier_zero_dns),
            )
        except ADCollectorError:
            raise
        except LDAPException:
            raise ADCollectorError(
                code="AD_COLLECTOR_QUERY_FAILED",
                message="The domain controller did not complete the fixed read-only LDAP queries.",
                resolution="Verify read access to the domain and configuration naming contexts.",
            ) from None
        finally:
            connection.unbind()

    def _connect(self, credential: ADCollectorCredential) -> Connection:
        ca_file = self._settings.tls_ca_file
        if ca_file is not None and not ca_file.is_file():
            raise ADCollectorError(
                code="AD_COLLECTOR_TLS_CA_MISSING",
                message="The configured LDAPS trust anchor is unavailable.",
                resolution="Install the issuing CA certificate at the configured read-only path.",
            )
        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=None if ca_file is None else str(ca_file),
            version=ssl.PROTOCOL_TLS_CLIENT,
        )
        server = Server(
            str(self._settings.server_ip),
            port=self._settings.port,
            use_ssl=True,
            tls=tls,
            get_info=NONE,
            connect_timeout=self._settings.timeout_seconds,
        )
        try:
            return Connection(
                server,
                user=f"{self._settings.domain}\\{credential.username}",
                password=credential.password,
                authentication=NTLM,
                auto_bind=AUTO_BIND_NO_TLS,
                auto_referrals=False,
                read_only=True,
                raise_exceptions=True,
                receive_timeout=self._settings.timeout_seconds,
            )
        except LDAPSocketOpenError:
            raise ADCollectorError(
                code="AD_COLLECTOR_LDAPS_UNREACHABLE",
                message="The configured domain controller LDAPS endpoint is unreachable or untrusted.",
                resolution="Provide the DC IP, allow TCP/636, and install its issuing CA certificate.",
            ) from None
        except LDAPBindError:
            raise ADCollectorError(
                code="AD_COLLECTOR_BIND_FAILED",
                message="The read-only AD collector credential was rejected.",
                resolution="Replace the credential file with a valid domain read account.",
            ) from None

    def _attest_naming_context(self, connection: Connection) -> None:
        ok = connection.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=("defaultNamingContext", "configurationNamingContext"),
        )
        if not ok or not connection.entries:
            raise ADCollectorError(
                code="AD_COLLECTOR_ROOT_DSE_MISSING",
                message="The LDAPS endpoint did not return an Active Directory RootDSE.",
                resolution="Configure the IP address of an Active Directory domain controller.",
            )
        attributes = connection.entries[0].entry_attributes_as_dict
        default_context = str(_first(attributes.get("defaultNamingContext"), ""))
        if default_context.casefold() != self._settings.base_dn.casefold():
            raise ADCollectorError(
                code="AD_COLLECTOR_DOMAIN_MISMATCH",
                message="The LDAPS server naming context does not match the configured domain.",
                resolution="Correct the fixed DC IP or the configured AD DNS domain.",
            )

    def _collect_privileged(
        self,
        connection: Connection,
    ) -> tuple[PrivilegedAccessEvidence, tuple[str, ...]]:
        group_filter = (
            "(|" + "".join(f"(sAMAccountName={escape_filter_chars(name)})" for name in _TIER_ZERO_GROUPS) + ")"
        )
        groups = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=f"(&(objectClass=group){group_filter})",
            attributes=("sAMAccountName",),
        )
        names = {str(_first(entry.get("sAMAccountName"), "")).casefold() for entry in groups}
        if not {item.casefold() for item in _TIER_ZERO_GROUPS} <= names:
            raise ADCollectorError(
                code="AD_COLLECTOR_TIER_ZERO_BASELINE_INCOMPLETE",
                message="The collector could not resolve every tier-zero baseline group.",
                resolution="Use the forest-root DC and verify directory read access.",
            )
        group_dns = tuple(str(entry["_dn"]) for entry in groups)
        direct_filter = "(|" + "".join(f"(memberOf={escape_filter_chars(group_dn)})" for group_dn in group_dns) + ")"
        direct_members = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=direct_filter,
            attributes=("sAMAccountName",),
        )
        expected = _DEFAULT_EXPECTED_TIER_ZERO_NAMES | {
            item.strip().casefold() for item in self._settings.expected_tier_zero_names
        }
        unexpected = {
            str(entry["_dn"]).casefold()
            for entry in direct_members
            if str(_first(entry.get("sAMAccountName"), "")).casefold() not in expected
        }
        chain_filter = _chain_membership_filter(group_dns)
        privileged_users = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=(
                f"(&(objectCategory=person)(objectClass=user)"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:={_UAC_DISABLED})){chain_filter})"
            ),
            attributes=("pwdLastSet",),
        )
        stale_before = self._clock() - timedelta(days=self._settings.stale_password_days)
        stale = sum(_is_stale(entry.get("pwdLastSet"), stale_before) for entry in privileged_users)
        protected_non_tier_zero = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=(
                f"(&(objectCategory=person)(objectClass=user)(adminCount=1)"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:={_UAC_DISABLED}))(!{chain_filter}))"
            ),
            attributes=("distinguishedName",),
        )
        return (
            PrivilegedAccessEvidence(
                unexpected_tier_zero_membership_count=len(unexpected),
                stale_privileged_account_count=stale,
                excessive_delegated_admin_count=len(protected_non_tier_zero),
            ),
            group_dns,
        )

    def _collect_service_accounts(self, connection: Connection) -> KerberosServiceAccountEvidence:
        entries = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=(
                f"(&(|(objectClass=user)(objectClass=msDS-GroupManagedServiceAccount)"
                f"(objectClass=msDS-ManagedServiceAccount))(servicePrincipalName=*)"
                f"(!(objectClass=computer))"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:={_UAC_DISABLED})))"
            ),
            attributes=("objectClass", "msDS-SupportedEncryptionTypes", "pwdLastSet"),
        )
        stale_before = self._clock() - timedelta(days=self._settings.stale_password_days)
        weak = 0
        stale = 0
        unmanaged = 0
        for entry in entries:
            encryption = _optional_int(entry.get("msDS-SupportedEncryptionTypes"))
            if encryption is None or encryption & _WEAK_KERBEROS_ENCRYPTION_BITS:
                weak += 1
            stale += _is_stale(entry.get("pwdLastSet"), stale_before)
            classes = {str(value).casefold() for value in _values(entry.get("objectClass"))}
            if not classes & {"msds-groupmanagedserviceaccount", "msds-managedserviceaccount"}:
                unmanaged += 1
        return KerberosServiceAccountEvidence(
            service_account_with_spn_count=len(entries),
            weak_encryption_service_account_count=weak,
            stale_password_service_account_count=stale,
            unmanaged_service_account_count=unmanaged,
        )

    def _collect_preauth(self, connection: Connection) -> KerberosPreauthEvidence:
        entries = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=(
                f"(&(objectCategory=person)(objectClass=user)"
                f"(userAccountControl:1.2.840.113556.1.4.803:={_UAC_PREAUTH_NOT_REQUIRED})"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:={_UAC_DISABLED})))"
            ),
            attributes=("distinguishedName",),
        )
        return KerberosPreauthEvidence(preauthentication_disabled_account_count=len(entries))

    def _collect_delegation(
        self,
        connection: Connection,
        *,
        tier_zero_dns: tuple[str, ...],
    ) -> DelegationEvidence:
        del tier_zero_dns
        unconstrained = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=(
                f"(&(|(objectClass=user)(objectClass=computer))"
                f"(userAccountControl:1.2.840.113556.1.4.803:={_UAC_TRUSTED_FOR_DELEGATION})"
                f"(!(primaryGroupID=516))(!(primaryGroupID=521)))"
            ),
            attributes=("distinguishedName",),
        )
        constrained = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter="(&(|(objectClass=user)(objectClass=computer))(msDS-AllowedToDelegateTo=*))",
            attributes=("msDS-AllowedToDelegateTo",),
        )
        broad = sum(
            _delegation_targets_are_broad(
                _values(entry.get("msDS-AllowedToDelegateTo")),
                maximum=self._settings.max_constrained_delegation_targets,
            )
            for entry in constrained
        )
        transition = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter=(
                f"(&(|(objectClass=user)(objectClass=computer))"
                f"(userAccountControl:1.2.840.113556.1.4.803:={_UAC_TRUSTED_TO_AUTH}))"
            ),
            attributes=("distinguishedName",),
        )
        rbcd = self._search(
            connection,
            base=self._settings.base_dn,
            ldap_filter="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            attributes=("distinguishedName",),
        )
        return DelegationEvidence(
            unconstrained_delegation_account_count=len(unconstrained),
            broad_constrained_delegation_account_count=broad,
            protocol_transition_account_count=len(transition),
            risky_rbcd_acl_count=len(rbcd),
        )

    @staticmethod
    def _search(
        connection: Connection,
        *,
        base: str,
        ldap_filter: str,
        attributes: tuple[str, ...],
    ) -> tuple[dict[str, object], ...]:
        results: list[dict[str, object]] = []
        responses = connection.extend.standard.paged_search(
            search_base=base,
            search_filter=ldap_filter,
            attributes=attributes,
            paged_size=500,
            generator=True,
        )
        for response in responses:
            if response.get("type") != "searchResEntry":
                continue
            values = dict(response.get("attributes", {}))
            values["_dn"] = str(response.get("dn", ""))
            results.append(values)
        return tuple(results)


class CertipyADCSAssessmentSource:
    """Run only Certipy's enumeration command; secret crosses stdin, never argv."""

    def __init__(self, settings: ADCollectorSettings) -> None:
        self._settings = settings

    def collect(self, credential: ADCollectorCredential) -> ADCSEvidence:
        if not self._settings.certipy_python.is_file():
            raise ADCollectorError(
                code="AD_COLLECTOR_CERTIPY_UNAVAILABLE",
                message="The fixed Certipy worker runtime is unavailable.",
                resolution="Install Certipy and configure its system Python interpreter.",
            )
        worker = Path(__file__).with_name("certipy_worker.py")
        request = {
            "server_ip": str(self._settings.server_ip),
            "port": self._settings.port,
            "domain": self._settings.domain,
            "username": credential.username,
            "password": credential.password,
            "timeout_seconds": self._settings.timeout_seconds,
        }
        try:
            completed = subprocess.run(  # noqa: S603 - executable and worker are server-owned fixed paths
                [str(self._settings.certipy_python), str(worker)],
                input=json.dumps(request, separators=(",", ":")),
                text=True,
                capture_output=True,
                timeout=max(60, self._settings.timeout_seconds * 12),
                check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1"},
            )
        except (OSError, subprocess.TimeoutExpired):
            raise ADCollectorError(
                code="AD_COLLECTOR_ADCS_TIMEOUT",
                message="The read-only AD CS enumeration did not complete within its fixed deadline.",
                resolution="Verify DC, CA, and enrollment endpoint reachability, then retry.",
            ) from None
        if completed.returncode != 0:
            raise ADCollectorError(
                code="AD_COLLECTOR_ADCS_FAILED",
                message="The read-only AD CS enumeration failed.",
                resolution="Verify Certipy availability and read access to AD CS configuration.",
            )
        try:
            output = json.loads(completed.stdout)
            if output.get("coverage_complete") is not True:
                raise ValueError
            counts = output["exposure_counts"]
            evidence = ADCSEvidence(
                exposure_counts=tuple(
                    ADCSExposureCount(esc_id=esc_id, affected_object_count=int(counts[esc_id])) for esc_id in _ESC_IDS
                )
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ADCollectorError(
                code="AD_COLLECTOR_ADCS_INCOMPLETE",
                message="AD CS enumeration returned incomplete ESC1-ESC8 coverage.",
                resolution="Restore CA/RPC/Web Enrollment read reachability and rerun collection.",
            ) from None
        return evidence


class VerifiedADCollector:
    """Load one protected credential and issue a verified, normalized snapshot."""

    def __init__(
        self,
        *,
        settings: ADCollectorSettings,
        directory_source: DirectoryEvidenceSource,
        adcs_source: ADCSAssessmentSource,
        digest_service: DigestService,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._settings = settings
        self._directory = directory_source
        self._adcs = adcs_source
        self._digests = digest_service
        self._clock = clock

    def collect(self) -> ADAssessmentSnapshot:
        credential = _read_credential(self._settings.credential_file)
        directory = self._directory.collect(credential)
        adcs = self._adcs.collect(credential)
        collected_at = self._clock()
        evidence_payload = {
            "domain": self._settings.domain,
            "server_ip": str(self._settings.server_ip),
            "collected_at": collected_at,
            "privileged_access": directory.privileged_access.model_dump(mode="python"),
            "kerberos_service_accounts": directory.kerberos_service_accounts.model_dump(mode="python"),
            "kerberos_preauth": directory.kerberos_preauth.model_dump(mode="python"),
            "adcs": adcs.model_dump(mode="python"),
            "delegation": directory.delegation.model_dump(mode="python"),
        }
        evidence_digest = self._digests.compute("security_projection_digest", evidence_payload)
        return ADAssessmentSnapshot(
            snapshot_id=f"verified-ldap-{uuid4()}",
            domain_ref=f"domain:{self._settings.domain}",
            source_type="verified_ldap_snapshot",
            source_artifact_ids=(f"collector-evidence:{evidence_digest}",),
            collected_at=collected_at,
            privileged_access=directory.privileged_access,
            kerberos_service_accounts=directory.kerberos_service_accounts,
            kerberos_preauth=directory.kerberos_preauth,
            adcs=adcs,
            delegation=directory.delegation,
        )


def _read_credential(path: Path) -> ADCollectorCredential:
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ADCollectorError(
                code="AD_COLLECTOR_SECRET_PERMISSIONS",
                message="The AD collector credential file is accessible outside its owner.",
                resolution="Set the credential file mode to 0600 and retry.",
            )
        return ADCollectorCredential.from_untrusted_json(path.read_bytes())
    except ADCollectorError:
        raise
    except (OSError, PydanticBoundaryValidationError, ValueError):
        raise ADCollectorError(
            code="AD_COLLECTOR_SECRET_UNAVAILABLE",
            message="The AD collector credential file is missing or invalid.",
            resolution="Install a 0600 JSON credential with domain, username, and password fields.",
        ) from None


def _values(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(value)
    return (value,)


def _first(value: object, default: object) -> object:
    values = _values(value)
    return default if not values else values[0]


def _optional_int(value: object) -> int | None:
    first = _first(value, None)
    if first is None or first == "":
        return None
    if not isinstance(first, (str, bytes, bytearray, int)):
        return None
    try:
        return int(first)
    except (TypeError, ValueError):
        return None


def _is_stale(value: object, stale_before: datetime) -> int:
    first = _first(value, None)
    if first is None:
        return 1
    if isinstance(first, datetime):
        observed = first if first.tzinfo is not None else first.replace(tzinfo=UTC)
        return int(observed < stale_before)
    if not isinstance(first, (str, bytes, bytearray, int)):
        return 1
    try:
        windows_ticks = int(first)
    except (TypeError, ValueError):
        return 1
    if windows_ticks <= 0:
        return 1
    observed = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=windows_ticks / 10)
    return int(observed < stale_before)


def _chain_membership_filter(group_dns: tuple[str, ...]) -> str:
    return (
        "(|"
        + "".join(f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)})" for group_dn in group_dns)
        + ")"
    )


def _delegation_targets_are_broad(values: tuple[object, ...], *, maximum: int) -> int:
    targets = [str(value) for value in values]
    if len(targets) > maximum:
        return 1
    return int(any(target.partition("/")[0].casefold() in _HIGH_IMPACT_DELEGATION_SERVICES for target in targets))


__all__ = [
    "ADCollectorError",
    "ADCollectorSettings",
    "CertipyADCSAssessmentSource",
    "DirectoryEvidence",
    "Ldap3DirectoryEvidenceSource",
    "VerifiedADCollector",
]
