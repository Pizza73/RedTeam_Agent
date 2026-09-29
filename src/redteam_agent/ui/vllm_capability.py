"""Trusted Phase 2 vLLM capability adapter for the local operator UI.

Endpoint selection and API-key custody remain server-side.  A settings owner may build
an isolated candidate adapter, run a non-persisting qualification, and promote it only
after the same signed manifest, tokenizer and model identity have been attested.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

from redteam_agent.ad_assessment.consensus import ADAssessmentLLMConsensusEvaluator
from redteam_agent.ad_assessment.models import ADAssessmentSnapshot
from redteam_agent.ad_assessment.reasoning import ADAssessmentReasoner
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import (
    AuthorizationKernelError,
    LLMCapabilityError,
    LLMEvaluationError,
    LLMTransportError,
)
from redteam_agent.llm.adapters import LocalLLMPlanner
from redteam_agent.llm.artifact_manifest import load_and_verify_remote_model_artifact_manifest
from redteam_agent.llm.attestation import (
    HttpServerMetadataProvider,
    SignedManifestArtifactSource,
    attest_local_llm_server,
    require_attestation_binding,
)
from redteam_agent.llm.attestation_store import ServerAttestationRepository
from redteam_agent.llm.budget import build_request_budget_policy
from redteam_agent.llm.capability import MIN_VALID_RATIO, CapabilityRepository
from redteam_agent.llm.capability_corpus import build_schema_capability_corpus
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.evaluation import (
    LiveCapabilityProbe,
    LocalEvaluationHarness,
    TimedInFlightCancellation,
    build_evaluation_run_budget,
)
from redteam_agent.llm.evaluation_gateway import EvaluationGateway
from redteam_agent.llm.profile import LocalLLMProfile, build_local_llm_profile
from redteam_agent.llm.schemas import compute_schema_digest
from redteam_agent.llm.secrets import FileAPIKeySource
from redteam_agent.llm.tokenizer import HuggingFaceTokenCounter
from redteam_agent.runtime.clock import SystemMonotonicClock
from redteam_agent.storage.database import Database
from redteam_agent.ui.control_plane import UIConflictError
from redteam_agent.ui.models import VllmConfigInput

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class Phase2VllmCapabilitySettings:
    """Server-owned inputs needed to produce real capability evidence."""

    database_path: Path
    base_url: str
    model: str
    api_key_file: Path
    manifest_path: Path
    public_key_path: Path
    manifest_key_id: str
    tokenizer_directory: Path
    profile_revision: str = "gemma-4-31b-it-vllm-0.25.1-r2"
    max_context_tokens: int = 131_072
    max_output_tokens: int = 1_024
    structured_output_mode: Literal["native", "tool_output"] = "native"
    attestation_timeout_seconds: int = 60
    capability_deadline_seconds: int = 900

    def __post_init__(self) -> None:
        path_fields = (
            self.database_path,
            self.api_key_file,
            self.manifest_path,
            self.public_key_path,
            self.tokenizer_directory,
        )
        if any(not path.is_absolute() for path in path_fields):
            raise ValueError("vLLM database, secret and artifact paths must be absolute")
        if not self.database_path.is_file():
            raise ValueError("vLLM capability requires an existing application database")
        if not self.manifest_key_id or not self.profile_revision:
            raise ValueError("vLLM manifest key and profile revisions are required")
        if self.max_context_tokens <= 0 or not 0 < self.max_output_tokens <= self.max_context_tokens:
            raise ValueError("vLLM profile token limits are invalid")
        if self.attestation_timeout_seconds <= 0 or self.capability_deadline_seconds <= 0:
            raise ValueError("vLLM capability timeouts must be positive")

    @property
    def profile_output_mode(self) -> str:
        return "native_json_schema" if self.structured_output_mode == "native" else "tool_output_json"

    def public_config(self) -> VllmConfigInput:
        return VllmConfigInput(
            baseUrl=self.base_url.rstrip("/"),
            modelName=self.model,
            wireApi="chat_completions",
            structuredOutputMode=self.structured_output_mode,
        )


class Phase2VllmCapabilityPort:
    """Synchronous, single-flight adapter invoked by the same-origin UI endpoint."""

    def __init__(
        self,
        *,
        settings: Phase2VllmCapabilitySettings,
        clock: Clock = _utc_now,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._single_flight = threading.Lock()

        database = Database(str(settings.database_path), create_schema=False)
        try:
            if not database.has_table("kv_store") or not database.has_table("occ_store"):
                raise ValueError("vLLM capability requires a provisioned application database")
        finally:
            database.close()

        self._endpoint = LocalLLMEndpointConfig(
            base_url=settings.base_url,
            model=settings.model,
            api_key_file=str(settings.api_key_file),
            request_timeout_seconds=settings.attestation_timeout_seconds,
        )
        digest_service = DigestService()
        manifest = load_and_verify_remote_model_artifact_manifest(
            manifest_path=settings.manifest_path,
            public_key_path=settings.public_key_path,
            expected_key_id=settings.manifest_key_id,
            digest_service=digest_service,
        )
        if manifest.served_model_id != settings.model:
            raise ValueError("configured vLLM model does not match the signed manifest")
        self._profile = build_local_llm_profile(
            profile_revision=settings.profile_revision,
            structured_output_mode=settings.profile_output_mode,
            max_context_tokens=settings.max_context_tokens,
            max_output_tokens=settings.max_output_tokens,
            model_name=manifest.served_model_id,
            model_hash=manifest.model_hash,
            chat_template_digest=manifest.chat_template_digest,
            tokenizer_revision=manifest.tokenizer_revision,
            runtime_version=manifest.runtime_version,
            digest_service=digest_service,
        )
        self._key_source = FileAPIKeySource(settings.api_key_file)
        self._artifact_source = SignedManifestArtifactSource(
            manifest_path=settings.manifest_path,
            public_key_path=settings.public_key_path,
            expected_key_id=settings.manifest_key_id,
            digest_service=digest_service,
        )
        self._token_counter = HuggingFaceTokenCounter(
            model_directory=settings.tokenizer_directory,
            tokenizer_revision=self._profile.tokenizer_revision,
            chat_template_digest=self._profile.chat_template_digest,
        )

    @property
    def public_config(self) -> VllmConfigInput:
        return self._settings.public_config()

    @property
    def profile(self) -> LocalLLMProfile:
        """Immutable model identity used by the Mission owner composition."""
        return self._profile

    def __call__(self, config: VllmConfigInput) -> dict[str, object]:
        return self.evaluate_capability(config, persist_results=True)

    def evaluate_capability(
        self,
        config: VllmConfigInput,
        *,
        persist_results: bool,
    ) -> dict[str, object]:
        """Run the bounded corpus, optionally publishing qualification evidence.

        Candidate settings use ``persist_results=False`` so an endpoint that has not
        been activated cannot authorize Planner use or a Mission transition.
        """
        expected = self.public_config
        if config != expected:
            raise UIConflictError("vLLM capability request does not match server-managed configuration")
        if not self._single_flight.acquire(blocking=False):
            raise UIConflictError("a vLLM capability evaluation is already running")
        started = time.monotonic()
        try:
            return self._evaluate(started=started, persist_results=persist_results)
        finally:
            self._single_flight.release()

    def recommend_ad_assessment(self) -> dict[str, object]:
        """Produce one non-authoritative, exact-candidate recommendation."""

        if not self._single_flight.acquire(blocking=False):
            raise UIConflictError("a vLLM capability or reasoning request is already running")
        database = None
        try:
            database = Database(str(self._settings.database_path), create_schema=False)
            digest_service = DigestService()
            self._require_current_planner_capability(database, digest_service)
            reasoning_clock = SystemMonotonicClock()
            planner = self._build_planner(clock=reasoning_clock, digest_service=digest_service)
            recommendation = ADAssessmentReasoner(
                planner=planner,
                capability_checker=lambda: None,
                clock=reasoning_clock,
                digest_service=digest_service,
            ).recommend()
            return recommendation.model_dump(mode="json")
        finally:
            if database is not None:
                database.close()
            self._single_flight.release()

    def evaluate_ad_assessment_with_llm(
        self,
        snapshot: ADAssessmentSnapshot,
    ) -> dict[str, object]:
        """Classify all five categories, then require deterministic consensus."""

        if not self._single_flight.acquire(blocking=False):
            raise UIConflictError("a vLLM capability or reasoning request is already running")
        database = None
        try:
            database = Database(str(self._settings.database_path), create_schema=False)
            digest_service = DigestService()
            self._require_current_planner_capability(database, digest_service)
            reasoning_clock = SystemMonotonicClock()
            planner = self._build_planner(clock=reasoning_clock, digest_service=digest_service)
            result = ADAssessmentLLMConsensusEvaluator(
                planner=planner,
                capability_checker=lambda: None,
                clock=reasoning_clock,
                digest_service=digest_service,
            ).evaluate(snapshot)
            return result.model_dump(mode="json")
        finally:
            if database is not None:
                database.close()
            self._single_flight.release()

    def _build_planner(
        self,
        *,
        clock: SystemMonotonicClock,
        digest_service: DigestService,
    ) -> LocalLLMPlanner:
        return LocalLLMPlanner(
            profile=self._profile,
            policy=build_request_budget_policy(
                profile=self._profile,
                request_timeout_seconds=min(60, self._settings.attestation_timeout_seconds),
                digest_service=digest_service,
            ),
            client=VLLMChatClient(
                base_url=self._settings.base_url,
                api_key_source=self._key_source,
            ),
            token_counter=self._token_counter,
            clock=clock,
            digest_service=digest_service,
        )

    def _require_current_planner_capability(
        self,
        database: Database,
        digest_service: DigestService,
    ) -> None:
        corpus = build_schema_capability_corpus()
        result = CapabilityRepository(database=database, digest_service=digest_service).get(
            profile_digest=self._profile.profile_digest,
            model_hash=self._profile.model_hash,
            runtime_version=self._profile.runtime_version,
            tokenizer_revision=self._profile.tokenizer_revision,
            chat_template_digest=self._profile.chat_template_digest,
            schema_name="planner_output",
            schema_digest=compute_schema_digest("planner_output", digest_service),
            corpus_version=corpus.corpus_version,
            corpus_digest=corpus.corpus_digest(digest_service),
            prompt_set_digest=corpus.prompt_set_digest("planner_output", digest_service),
            structured_output_mode=self._profile.structured_output_mode,
        )
        if (
            result is None
            or not result.passed
            or result.evidence_kind != "real_local_llm"
            or result.server_attestation_digest is None
            or result.valid_within_retry_budget / result.sample_count < MIN_VALID_RATIO
            or result.unsafe_boundary_acceptances != 0
            or result.cancellation_failures != 0
        ):
            raise LLMCapabilityError("current Planner capability evidence is required")
        attestation = ServerAttestationRepository(database, digest_service).get(
            result.server_attestation_digest
        )
        if attestation is None:
            raise LLMCapabilityError("current Planner server attestation is unavailable")
        try:
            require_attestation_binding(
                attestation,
                profile=self._profile,
                base_url=self._settings.base_url,
                digest_service=digest_service,
            )
        except AuthorizationKernelError:
            raise LLMCapabilityError("current Planner capability is bound to another endpoint") from None

    def _evaluate(self, *, started: float, persist_results: bool) -> dict[str, object]:
        database = None
        try:
            # Compose only the dedicated Phase 2 evaluation boundary here.  Constructing
            # the complete authorization kernel would incorrectly replay its fresh-install
            # audit genesis on every UI request.  This request-local DB connection also
            # remains on the ThreadingHTTPServer worker that owns it.
            database = Database(str(self._settings.database_path), create_schema=False)
            digest_service = DigestService()
            attestation = attest_local_llm_server(
                profile=self._profile,
                endpoint=self._endpoint,
                provider=HttpServerMetadataProvider(api_key_source=self._key_source),
                artifact_source=self._artifact_source,
                digest_service=digest_service,
                timeout_seconds=self._settings.attestation_timeout_seconds,
            )
            ServerAttestationRepository(database, digest_service).save(attestation)
            client = VLLMChatClient(
                base_url=self._settings.base_url,
                api_key_source=self._key_source,
            )
            phase2_clock = SystemMonotonicClock()
            run_id = f"ui-capability-{uuid4()}"
            probe = LiveCapabilityProbe(
                profile=self._profile,
                policy=build_request_budget_policy(
                    profile=self._profile,
                    request_timeout_seconds=min(60, self._settings.attestation_timeout_seconds),
                    digest_service=digest_service,
                ),
                endpoint=self._endpoint,
                client=client,
                token_counter=self._token_counter,
                gateway=EvaluationGateway(
                    database=database,
                    digest_service=digest_service,
                    clock=phase2_clock,
                    run_id=run_id,
                ),
                cancellation=TimedInFlightCancellation(delay_seconds=0.01),
                run_budget=build_evaluation_run_budget(
                    clock=phase2_clock,
                    max_calls=256,
                    max_total_tokens=10_000_000,
                    deadline_seconds=self._settings.capability_deadline_seconds,
                ),
                attestation=attestation,
                clock=phase2_clock,
                digest_service=digest_service,
            )
            results = LocalEvaluationHarness(
                digest_service=digest_service,
                corpus=build_schema_capability_corpus(),
            ).run_capability(profile=self._profile, probe=probe)
            if probe.evidence_kind != "real_local_llm":
                raise LLMEvaluationError("UI capability evaluation did not produce direct-network evidence")
            if persist_results:
                repository = CapabilityRepository(database=database, digest_service=digest_service)
                for result in results:
                    repository.save(result)
        except AuthorizationKernelError as exc:
            return self._failure_view(exc=exc, started=started)
        finally:
            if database is not None:
                database.close()

        checks: list[dict[str, object]] = [
            {
                "name": "Server attestation",
                "status": "passed",
                "detail": "Health, runtime, model identity and structured-output probe are bound.",
            }
        ]
        for result in results:
            checks.append(
                {
                    "name": result.schema_name,
                    "status": "passed" if result.passed else "failed",
                    "detail": (
                        f"{result.valid_within_retry_budget}/{result.sample_count} valid; "
                        f"unsafe {result.unsafe_boundary_acceptances}; "
                        f"cancellation failures {result.cancellation_failures}."
                    ),
                }
            )
        passed = all(result.passed for result in results)
        return {
            "status": "passed" if passed else "failed",
            "summary": (
                "Profile meets the attested Phase 2 capability contract."
                if passed
                else "One or more Phase 2 schema capability checks failed."
            ),
            "latencyMs": max(0, round((time.monotonic() - started) * 1000)),
            "checkedAt": self._clock().astimezone(UTC).isoformat(),
            "checks": checks,
        }

    def _failure_view(self, *, exc: AuthorizationKernelError, started: float) -> dict[str, object]:
        is_timeout = isinstance(exc, LLMTransportError) and exc.reason == "timeout"
        return {
            "status": "timeout" if is_timeout else "failed",
            "summary": (
                "The bounded Phase 2 capability check timed out."
                if is_timeout
                else "The trusted Phase 2 capability check failed closed."
            ),
            "latencyMs": max(0, round((time.monotonic() - started) * 1000)),
            "checkedAt": self._clock().astimezone(UTC).isoformat(),
            "checks": [
                {
                    "name": "Trusted Phase 2 gateway",
                    "status": "failed",
                    "detail": f"{type(exc).__name__}; no capability was granted.",
                }
            ],
        }

    def close(self) -> None:
        """Release hook for symmetry with other UI ports; calls own their DB handles."""


__all__ = ["Phase2VllmCapabilityPort", "Phase2VllmCapabilitySettings"]
