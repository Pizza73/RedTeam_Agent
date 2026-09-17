"""Kali-local control-plane composition for the approved isolated lab.

This root connects authenticated UI sessions, real Phase 2 capability evidence,
and the authoritative Mission/Approval owner services.  It deliberately remains
``production_eligible=False`` until a real TPM/key provider and the Phase 4/5
live-environment attestations are supplied to ``ProductionCompositionRoot``.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from redteam_agent.ad_assessment.collector import (
    ADCollectorSettings,
    CertipyADCSAssessmentSource,
    Ldap3DirectoryEvidenceSource,
    VerifiedADCollector,
)
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.composition.testing import Phase0AKernel, build_test_kernel
from redteam_agent.llm.attestation_store import ServerAttestationRepository
from redteam_agent.llm.capability import CapabilityRepository, MissionCapabilityVerifier
from redteam_agent.llm.capability_corpus import build_schema_capability_corpus
from redteam_agent.llm.profile import LocalLLMProfile
from redteam_agent.mission.models import MissionRevision
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.storage.database import Database
from redteam_agent.ui.auth import OperatorSessionAuthenticator, read_operator_token
from redteam_agent.ui.control_plane import UIControlPlane
from redteam_agent.ui.kali_provider_status import KaliProviderStatusPort
from redteam_agent.ui.mission_commands import MissionCommandOwner
from redteam_agent.ui.server import DIRECT_EXTERNAL_BIND_HOST, build_server, validate_direct_ui_origins
from redteam_agent.ui.vllm_capability import (
    Phase2VllmCapabilityPort,
    Phase2VllmCapabilitySettings,
)
from redteam_agent.ui.vllm_settings import VllmSettingsManager


class _DeferredCapabilityVerifier:
    def __init__(self) -> None:
        self._delegate: MissionCapabilityVerifier | None = None

    def bind(self, delegate: MissionCapabilityVerifier) -> None:
        if self._delegate is not None:
            raise ValueError("mission capability verifier is already bound")
        self._delegate = delegate

    def verify_mission_capability(self, profile: LocalLLMProfile, revision: MissionRevision) -> None:
        if self._delegate is None:
            raise RuntimeError("mission capability verifier is unavailable")
        self._delegate.verify_mission_capability(profile, revision)


class KaliProductSettings(StrictImmutableBoundaryModel):
    schemaVersion: Literal["kali-product-v1"] = "kali-product-v1"
    databasePath: str = "/var/lib/redteam-agent/redteam-agent.db"
    staticDirectory: str = "/opt/redteam-agent/frontend/dist"
    operatorTokenFile: str = "/run/credentials/redteam-agent.service/ui-operator.token"
    operatorPrincipal: str = Field(default="redteam-operator", min_length=1, max_length=200)
    uiHost: Literal["127.0.0.1", "localhost", "0.0.0.0"] = "127.0.0.1"  # noqa: S104
    uiPort: int = Field(default=18000, ge=1, le=65535)
    uiOriginPolicy: Literal["exact", "rfc1918_same_origin", "local_ipv4_same_origin"] = "exact"
    uiAllowedOrigins: tuple[str, ...] = ()
    vllmBaseUrl: Literal["http://10.0.6.181:8100/v1"] = "http://10.0.6.181:8100/v1"
    vllmModel: Literal["gemma-4-31B-it"] = "gemma-4-31B-it"
    vllmApiKeyFile: str = "/run/credentials/redteam-agent.service/vllm-api.key"
    vllmSettingsDirectory: str = "/var/lib/redteam-agent/llm-settings"
    vllmAllowedCidrs: tuple[str, ...] = ("10.0.6.0/24",)
    vllmManifest: str = "/etc/redteam-agent/gemma-4-31b.manifest.json"
    vllmPublicKey: str = "/etc/redteam-agent/attestation-signing-public.pem"
    vllmTokenizerDirectory: str = "/opt/redteam-agent/gemma-4-31b-tokenizer"
    impacketExecutable: str = "/opt/redteam-agent/venv/bin/redteam-impacket-mcp"
    impacketAllowedTargets: tuple[Literal["10.0.10.212/32"], ...] = ("10.0.10.212/32",)
    sliverOperatorCredential: Literal["/run/credentials/redteam-agent.service/sliver-operator.cfg"] = (
        "/run/credentials/redteam-agent.service/sliver-operator.cfg"
    )
    adCollectorEnabled: bool = False
    adCollectorServerIp: str = "10.0.10.212"
    adCollectorPort: Literal[636] = 636
    adCollectorDomain: str = Field(default="intern.local", min_length=3, max_length=255)
    adCollectorCredentialFile: str = "/run/credentials/redteam-agent.service/ad-collector-credential.json"
    adCollectorTlsCaFile: str | None = None
    adCollectorCertipyPython: str = "/usr/bin/python3"
    adCollectorExpectedTierZeroNames: tuple[str, ...] = Field(default=(), max_length=100)
    adCollectorStalePasswordDays: int = Field(default=180, ge=1, le=3650)
    adCollectorMaxConstrainedDelegationTargets: int = Field(default=10, ge=1, le=1000)
    adCollectorTimeoutSeconds: int = Field(default=15, ge=1, le=60)
    approvedSessionRefs: tuple[str, ...] = Field(default=(), max_length=100)
    productionEligible: Literal[False] = False

    @model_validator(mode="after")
    def _absolute_paths(self) -> KaliProductSettings:
        for value in (
            self.databasePath,
            self.staticDirectory,
            self.operatorTokenFile,
            self.vllmApiKeyFile,
            self.vllmSettingsDirectory,
            self.vllmManifest,
            self.vllmPublicKey,
            self.vllmTokenizerDirectory,
            self.impacketExecutable,
            self.sliverOperatorCredential,
            self.adCollectorCredentialFile,
            self.adCollectorCertipyPython,
        ):
            if not Path(value).is_absolute():
                raise ValueError("Kali product paths must be absolute")
        if self.adCollectorTlsCaFile is not None and not Path(self.adCollectorTlsCaFile).is_absolute():
            raise ValueError("AD collector TLS CA path must be absolute")
        if not isinstance(ip_address(self.adCollectorServerIp), IPv4Address):
            raise ValueError("AD collector server must be a fixed IPv4 address")
        try:
            llm_networks = tuple(ip_network(value, strict=True) for value in self.vllmAllowedCidrs)
        except ValueError:
            raise ValueError("vLLM allowed CIDRs must be canonical networks") from None
        if not llm_networks or any(not isinstance(network, IPv4Network) for network in llm_networks):
            raise ValueError("vLLM allowed CIDRs must contain at least one IPv4 network")
        if self.operatorPrincipal != self.operatorPrincipal.strip():
            raise ValueError("operator principal must be canonical")
        direct_origins = validate_direct_ui_origins(self.uiAllowedOrigins)
        dynamic_origin = self.uiOriginPolicy in {"rfc1918_same_origin", "local_ipv4_same_origin"}
        if self.uiHost == DIRECT_EXTERNAL_BIND_HOST and not direct_origins and not dynamic_origin:
            raise ValueError("direct external UI bind requires an exact origin or a same-origin mode")
        if direct_origins and dynamic_origin:
            raise ValueError("exact UI origins cannot be combined with a dynamic same-origin mode")
        if self.uiHost != DIRECT_EXTERNAL_BIND_HOST and dynamic_origin:
            raise ValueError("dynamic same-origin mode requires direct external UI bind")
        if self.uiHost == DIRECT_EXTERNAL_BIND_HOST and any(
            int(origin.rsplit(":", 1)[1]) != self.uiPort for origin in direct_origins
        ):
            raise ValueError("direct external UI origin port must match uiPort")
        if len(set(self.approvedSessionRefs)) != len(self.approvedSessionRefs):
            raise ValueError("approved session references must be unique")
        if any(
            not reference or reference != reference.strip() or len(reference) > 500
            for reference in self.approvedSessionRefs
        ):
            raise ValueError("approved session references must be canonical")
        return self


@dataclass
class KaliProductApplication:
    settings: KaliProductSettings
    kernel: Phase0AKernel
    mission_owner: MissionCommandOwner
    control_plane: UIControlPlane
    authenticator: OperatorSessionAuthenticator
    vllm_port: VllmSettingsManager
    ad_collector: VerifiedADCollector | None

    def close(self) -> None:
        self.vllm_port.close()
        self.kernel.database.close()


def build_kali_product_application(settings: KaliProductSettings) -> KaliProductApplication:
    """Build the persistent control plane without enabling unqualified adapters."""
    database_path = Path(settings.databasePath)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    if not database_path.exists():
        Database(str(database_path)).close()

    deferred = _DeferredCapabilityVerifier()
    kernel = build_test_kernel(
        db_path=str(database_path),
        allowed_profile_types=frozenset({"vllm"}),
        capability_verifier=deferred,
        registered_session_refs=frozenset(settings.approvedSessionRefs),
    )
    corpus = build_schema_capability_corpus()
    vllm_settings = Phase2VllmCapabilitySettings(
        database_path=database_path,
        base_url=settings.vllmBaseUrl,
        model=settings.vllmModel,
        api_key_file=Path(settings.vllmApiKeyFile),
        manifest_path=Path(settings.vllmManifest),
        public_key_path=Path(settings.vllmPublicKey),
        manifest_key_id="llm001-gemma4-2026",
        tokenizer_directory=Path(settings.vllmTokenizerDirectory),
    )
    initial_vllm_port = Phase2VllmCapabilityPort(settings=vllm_settings)
    vllm_port = VllmSettingsManager(
        initial_port=initial_vllm_port,
        settings_template=vllm_settings,
        settings_directory=Path(settings.vllmSettingsDirectory),
        allowed_cidrs=settings.vllmAllowedCidrs,
        port_factory=Phase2VllmCapabilityPort,
    )
    deferred.bind(
        MissionCapabilityVerifier(
            repository=CapabilityRepository(
                database=kernel.database,
                digest_service=kernel.digest_service,
            ),
            digest_service=kernel.digest_service,
            corpus=corpus,
            attestation_repository=ServerAttestationRepository(
                kernel.database,
                kernel.digest_service,
            ),
            endpoint_provider=lambda: vllm_port.public_config.baseUrl,
        )
    )
    owner = MissionCommandOwner(
        kernel=kernel,
        profile=vllm_port.profile,
        principal_id=settings.operatorPrincipal,
        execution_enabled=False,
    )
    provider_status = KaliProviderStatusPort(
        sliver_credential=Path(settings.sliverOperatorCredential),
        impacket_executable=Path(settings.impacketExecutable),
        impacket_allowed_targets=settings.impacketAllowedTargets,
    )
    ad_collector = None
    if settings.adCollectorEnabled:
        collector_settings = ADCollectorSettings(
            server_ip=IPv4Address(settings.adCollectorServerIp),
            port=settings.adCollectorPort,
            domain=settings.adCollectorDomain,
            credential_file=Path(settings.adCollectorCredentialFile),
            tls_ca_file=(None if settings.adCollectorTlsCaFile is None else Path(settings.adCollectorTlsCaFile)),
            certipy_python=Path(settings.adCollectorCertipyPython),
            stale_password_days=settings.adCollectorStalePasswordDays,
            max_constrained_delegation_targets=settings.adCollectorMaxConstrainedDelegationTargets,
            expected_tier_zero_names=settings.adCollectorExpectedTierZeroNames,
            timeout_seconds=settings.adCollectorTimeoutSeconds,
        )
        ad_collector = VerifiedADCollector(
            settings=collector_settings,
            directory_source=Ldap3DirectoryEvidenceSource(collector_settings),
            adcs_source=CertipyADCSAssessmentSource(collector_settings),
            digest_service=DigestService(),
        )

    def collect_and_evaluate_ad() -> dict[str, object]:
        if ad_collector is None:
            raise RuntimeError("AD collector is not attached")
        return vllm_port.evaluate_ad_assessment_with_llm(ad_collector.collect())

    control_plane = UIControlPlane(
        database_path=str(database_path),
        approval_decision_port=owner.submit_approval,
        mission_command_port=owner,
        provider_status_port=provider_status,
        approved_session_refs=frozenset(settings.approvedSessionRefs),
        ad_assessment_reasoning_port=vllm_port.recommend_ad_assessment,
        ad_assessment_evaluation_port=vllm_port.evaluate_ad_assessment_with_llm,
        ad_assessment_collector_port=(collect_and_evaluate_ad if ad_collector is not None else None),
        vllm_capability_port=vllm_port,
        vllm_public_config=vllm_port.public_config,
        vllm_settings_port=vllm_port,
    )
    authenticator = OperatorSessionAuthenticator(
        principal_id=settings.operatorPrincipal,
        operator_token=read_operator_token(Path(settings.operatorTokenFile)),
    )
    return KaliProductApplication(
        settings=settings,
        kernel=kernel,
        mission_owner=owner,
        control_plane=control_plane,
        authenticator=authenticator,
        vllm_port=vllm_port,
        ad_collector=ad_collector,
    )


def serve_kali_product(application: KaliProductApplication) -> None:
    server = build_server(
        control_plane=application.control_plane,
        host=application.settings.uiHost,
        port=application.settings.uiPort,
        static_root=Path(application.settings.staticDirectory),
        authenticator=application.authenticator,
        allowed_origins=application.settings.uiAllowedOrigins,
        allow_rfc1918_same_origin=application.settings.uiOriginPolicy == "rfc1918_same_origin",
        allow_local_ipv4_same_origin=application.settings.uiOriginPolicy == "local_ipv4_same_origin",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        application.close()


__all__ = [
    "KaliProductApplication",
    "KaliProductSettings",
    "build_kali_product_application",
    "serve_kali_product",
]
