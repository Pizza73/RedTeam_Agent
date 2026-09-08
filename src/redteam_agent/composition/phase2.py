"""Phase 2 composition: local LLM capability, adapters and quality gate.

Extends the Phase 1 kernel with the schema-capability infrastructure, the Local LLM
planner/analyzer adapter factories, the isolated Local Evaluation Entry Point and the
agent-quality-policy-v2 gate. The mission validation path is parameterized so a Phase 2
mission accepts only a ``vllm`` profile and requires a passed capability result bound to
its profile digest (a mock profile cannot bypass the capability check). No new workflow
state, authorization path or duplicate service is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass

from redteam_agent.composition.execution_testing import build_phase0b_kernel
from redteam_agent.composition.phase0c import build_phase0c_kernel
from redteam_agent.composition.phase1 import Phase1Kernel, build_phase1_kernel
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.errors import LLMCapabilityError, LLMEvaluationError
from redteam_agent.execution.adapter import MockExecutionAdapter
from redteam_agent.llm.adapters import (
    LocalLLMAnalyzer,
    LocalLLMPlanner,
    quality_prompt_set_digests,
)
from redteam_agent.llm.attestation import (
    ModelArtifactSource,
    ServerAttestation,
    ServerMetadataProvider,
    attest_local_llm_server,
    require_attestation_binding,
)
from redteam_agent.llm.attestation_store import ServerAttestationRepository
from redteam_agent.llm.binding import MissionBindingChecker
from redteam_agent.llm.budget import LLMRequestBudgetPolicy, build_request_budget_policy
from redteam_agent.llm.capability import (
    MIN_VALID_RATIO,
    CapabilityEvaluator,
    CapabilityRepository,
    LLMSchemaCapabilityResult,
    MissionCapabilityVerifier,
    SchemaCapabilityCorpus,
    derive_evidence_kind,
    evaluate_all_schemas,
)
from redteam_agent.llm.capability_corpus import build_schema_capability_corpus
from redteam_agent.llm.client import VLLMChatClient
from redteam_agent.llm.config import LocalLLMEndpointConfig
from redteam_agent.llm.evaluation import (
    LiveCapabilityProbe,
    LocalEvaluationHarness,
    SyntheticCapabilityProbe,
    assert_endpoint_matches_profile,
    build_evaluation_run_budget,
)
from redteam_agent.llm.evaluation_gateway import EvaluationGateway, EvaluationRunBudget
from redteam_agent.llm.profile import LocalLLMProfile, verify_profile_digest
from redteam_agent.llm.schemas import ACTUAL_SCHEMA_NAMES, compute_schema_digest
from redteam_agent.llm.tokenizer import TokenCounter
from redteam_agent.mission.models import MissionRevision
from redteam_agent.mission.validation import LLMCapabilityVerifier
from redteam_agent.quality.corpus import build_agent_quality_corpus
from redteam_agent.quality.evidence import QualityEvidenceRepository
from redteam_agent.quality.gate import (
    REAL_LLM_PREREQUISITES,
    blocked_report,
    not_run_report,
    run_agent_quality_gate,
)
from redteam_agent.quality.local_llm_driver import LocalLLMQualityDriver
from redteam_agent.quality.models import (
    AgentQualityCorpus,
    EvaluationBinding,
    QualityReport,
    build_run_seeds,
)
from redteam_agent.quality.runner import RunDriver, derive_driver_evidence_kind
from redteam_agent.quality.scenario_runner import IsolatedPhase1ScenarioRunner
from redteam_agent.quality.workflow_driver import (
    IsolatedPhase1WorkflowRunExecutor,
    Phase1WorkflowRunExecutor,
    RunWorkflow,
    WorkflowBackedQualityDriver,
)


def _require_bound_tokenizer(token_counter: TokenCounter, profile: LocalLLMProfile) -> None:
    if token_counter.tokenizer_revision != profile.tokenizer_revision:
        raise LLMCapabilityError("token counter tokenizer_revision must match the profile's fixed tokenizer_revision")


class _LazyMissionCapabilityVerifier:
    """A capability verifier bound after the kernel database exists."""

    def __init__(self) -> None:
        self._delegate: MissionCapabilityVerifier | None = None

    def bind(self, delegate: MissionCapabilityVerifier) -> None:
        if self._delegate is not None:
            raise LLMCapabilityError("capability verifier already bound")
        self._delegate = delegate

    def verify_mission_capability(self, profile: LocalLLMProfile, revision: MissionRevision) -> None:
        if self._delegate is None:
            raise LLMCapabilityError("capability verifier is not bound")
        self._delegate.verify_mission_capability(profile, revision)


@dataclass(frozen=True)
class Phase2Kernel:
    phase1: Phase1Kernel
    schema_corpus: SchemaCapabilityCorpus
    quality_corpus: AgentQualityCorpus
    capability_repository: CapabilityRepository
    capability_evaluator: CapabilityEvaluator
    capability_verifier: MissionCapabilityVerifier
    evaluation_harness: LocalEvaluationHarness
    endpoint: LocalLLMEndpointConfig | None
    qualification_commit_id: str | None
    dependency_lock_digest: str | None

    # --- capability -------------------------------------------------------

    def run_capability_evaluation(
        self,
        *,
        profile: LocalLLMProfile,
        probe: SyntheticCapabilityProbe | LiveCapabilityProbe,
    ) -> tuple[LLMSchemaCapabilityResult, ...]:
        """Run the schema capability evaluation.

        Provenance and persistence are decided by the *concrete probe*, never a caller
        flag: only the live probe with the direct network transport yields
        ``real_local_llm`` results, and only those are written to the production repository. Test-double
        results are returned for inspection but are non-persistent by construction (the
        repository itself also rejects test-double evidence).
        """
        results = self.evaluation_harness.run_capability(profile=profile, probe=probe)
        if derive_evidence_kind(probe) == "real_local_llm":
            for result in results:
                self.capability_repository.save(result)
        return results

    def server_attestation_repository(self) -> ServerAttestationRepository:
        a = self.phase1.phase0c.phase0b.phase0a
        return ServerAttestationRepository(database=a.database, digest_service=a.digest_service)

    def attest_server(
        self,
        *,
        profile: LocalLLMProfile,
        provider: ServerMetadataProvider,
        artifact_source: ModelArtifactSource,
        timeout_seconds: float = 10.0,
    ) -> ServerAttestation:
        """Attest the configured server against the profile; persist only direct evidence."""
        self.verify_endpoint_binds_profile(profile)
        assert self.endpoint is not None
        attestation = attest_local_llm_server(
            profile=profile,
            endpoint=self.endpoint,
            provider=provider,
            artifact_source=artifact_source,
            digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service,
            timeout_seconds=timeout_seconds,
        )
        if attestation.provenance == "direct_network":
            self.server_attestation_repository().save(attestation)
        return attestation

    def _require_persisted_attestation(
        self, attestation: ServerAttestation | None, profile: LocalLLMProfile
    ) -> ServerAttestation:
        if attestation is None:
            raise LLMEvaluationError("a real qualification requires a live server attestation")
        assert self.endpoint is not None and self.endpoint.base_url is not None
        require_attestation_binding(
            attestation,
            profile=profile,
            base_url=self.endpoint.base_url,
            digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service,
        )
        stored = self.server_attestation_repository().get(attestation.attestation_digest)
        if attestation.provenance != "direct_network" or stored is None:
            raise LLMEvaluationError("a real qualification requires a persisted direct_network server attestation")
        return attestation

    def build_evaluation_gateway(self, *, run_id: str) -> EvaluationGateway:
        """Assemble the isolated evaluation gateway from the kernel's durable store.

        The gateway holds only the attempt store, digest service and clock; it never
        receives a production adapter, mission manager or dispatch port.
        """
        a = self.phase1.phase0c.phase0b.phase0a
        return EvaluationGateway(
            database=a.database,
            digest_service=a.digest_service,
            clock=self.phase1.phase0c.monotonic_clock,
            run_id=run_id,
        )

    def build_live_capability_probe(
        self,
        *,
        profile: LocalLLMProfile,
        policy: LLMRequestBudgetPolicy,
        client: VLLMChatClient,
        token_counter: TokenCounter,
        run_id: str,
        cancellation: object | None = None,
        run_budget: EvaluationRunBudget | None = None,
        attestation: ServerAttestation | None = None,
    ) -> LiveCapabilityProbe:
        """Wire a live capability probe to the endpoint, gateway and a finite run budget.

        Endpoint/profile binding is mandatory: this raises unless an endpoint is
        configured and serves the profile's model.
        """
        self.verify_endpoint_binds_profile(profile)
        _require_bound_tokenizer(token_counter, profile)
        assert self.endpoint is not None
        if self.endpoint.base_url is None or client.base_url != self.endpoint.base_url.rstrip("/"):
            raise LLMEvaluationError("capability client base_url does not match the configured endpoint")
        a = self.phase1.phase0c.phase0b.phase0a
        clock = self.phase1.phase0c.monotonic_clock
        assert self.endpoint is not None  # narrowed by verify_endpoint_binds_profile
        gateway = self.build_evaluation_gateway(run_id=run_id)
        budget = run_budget if run_budget is not None else build_evaluation_run_budget(clock=clock)
        return LiveCapabilityProbe(
            profile=profile,
            policy=policy,
            endpoint=self.endpoint,
            client=client,
            token_counter=token_counter,
            gateway=gateway,
            run_budget=budget,
            clock=clock,
            digest_service=a.digest_service,
            cancellation=cancellation,  # type: ignore[arg-type]
            attestation=attestation,
        )

    def request_budget_policy(self, profile: LocalLLMProfile) -> LLMRequestBudgetPolicy:
        return build_request_budget_policy(
            profile=profile, digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service
        )

    def build_planner(
        self,
        *,
        profile: LocalLLMProfile,
        policy: LLMRequestBudgetPolicy,
        client: VLLMChatClient,
        token_counter: TokenCounter,
    ) -> LocalLLMPlanner:
        # The tokenizer is caller-supplied and must be the model's tokenizer bound to the
        # profile's fixed revision. There is no production fallback counter.
        _require_bound_tokenizer(token_counter, profile)
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        return LocalLLMPlanner(
            profile=profile,
            policy=policy,
            client=client,
            token_counter=token_counter,
            clock=self.phase1.phase0c.monotonic_clock,
            digest_service=ds,
        )

    def build_binding_checker(
        self,
        *,
        mission_id: str,
        expected_profile_digest: str,
        expected_revision: int,
        expected_epoch: int,
    ) -> MissionBindingChecker:
        a = self.phase1.phase0c.phase0b.phase0a
        return MissionBindingChecker(
            context_resolver=a.context_resolver,
            clock=self.phase1.phase0c.monotonic_clock,
            mission_id=mission_id,
            expected_profile_digest=expected_profile_digest,
            expected_revision=expected_revision,
            expected_epoch=expected_epoch,
        )

    def build_analyzer(
        self,
        *,
        profile: LocalLLMProfile,
        policy: LLMRequestBudgetPolicy,
        client: VLLMChatClient,
        token_counter: TokenCounter,
    ) -> LocalLLMAnalyzer:
        _require_bound_tokenizer(token_counter, profile)
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        return LocalLLMAnalyzer(
            profile=profile,
            policy=policy,
            client=client,
            token_counter=token_counter,
            clock=self.phase1.phase0c.monotonic_clock,
            digest_service=ds,
        )

    # --- quality gate -----------------------------------------------------

    def quality_evidence_repository(self) -> QualityEvidenceRepository:
        """The append-only durable D11 evidence sink over the kernel database."""
        a = self.phase1.phase0c.phase0b.phase0a
        return QualityEvidenceRepository(database=a.database, digest_service=a.digest_service)

    def run_quality_gate(
        self,
        *,
        driver: RunDriver,
        external_prerequisites: tuple[str, ...] = (),
        evaluation_id: str | None = None,
    ) -> QualityReport:
        """Run the gate; with an ``evaluation_id`` every attempted run is persisted."""
        return run_agent_quality_gate(
            corpus=self.quality_corpus,
            digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service,
            driver=driver,
            external_prerequisites=external_prerequisites,
            evidence_sink=self.quality_evidence_repository() if evaluation_id else None,
            evaluation_id=evaluation_id,
        )

    def quality_gate_not_run(self, *, reason: str) -> QualityReport:
        return not_run_report(
            corpus=self.quality_corpus,
            digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service,
            reason=reason,
        )

    def build_evaluation_binding(
        self,
        *,
        profile: LocalLLMProfile,
        capability_results: tuple[LLMSchemaCapabilityResult, ...],
        attestation: ServerAttestation | None = None,
    ) -> EvaluationBinding:
        """Build the complete manifest from trusted composition inputs.

        With an attestation the manifest is bound to the persisted direct-network server
        evidence and every capability result must reference that same attestation.
        """
        if self.qualification_commit_id is None or self.dependency_lock_digest is None:
            raise LLMEvaluationError("qualification build identity is not configured")
        verify_profile_digest(profile, self.phase1.phase0c.phase0b.phase0a.digest_service)
        self._verify_real_capability_results(profile, capability_results, attestation)
        fields = self._expected_binding_fields(profile, capability_results, attestation)
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        binding_digest = ds.compute("agent_quality_evaluation_binding_digest", fields)
        return EvaluationBinding(**fields, binding_digest=binding_digest)  # type: ignore[arg-type]

    def build_quality_driver(
        self,
        *,
        profile: LocalLLMProfile,
        policy: LLMRequestBudgetPolicy,
        client: VLLMChatClient,
        token_counter: TokenCounter,
        evaluation_binding: EvaluationBinding,
        run_id: str,
        run_budget: EvaluationRunBudget | None = None,
        attestation: ServerAttestation | None = None,
    ) -> LocalLLMQualityDriver:
        """Build the model-only diagnostic driver.

        It exercises the bounded planner/analyzer endpoint but remains
        ``test_double`` evidence until a workflow-backed D11 driver supplies
        observations from Phase1AgentWorkflow and the safe adapter.
        """
        self.verify_endpoint_binds_profile(profile)
        _require_bound_tokenizer(token_counter, profile)
        assert self.endpoint is not None
        if self.endpoint.base_url is None or client.base_url != self.endpoint.base_url.rstrip("/"):
            raise LLMEvaluationError("quality client base_url does not match the configured endpoint")
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        ds.verify(
            "llm_request_budget_policy_digest",
            {k: v for k, v in policy.model_dump(mode="python").items() if k != "policy_digest"},
            policy.policy_digest,
        )
        if evaluation_binding.gateway_budget_policy_digest != policy.policy_digest:
            raise LLMEvaluationError("quality driver policy does not match the evaluation binding")
        clock = self.phase1.phase0c.monotonic_clock
        return LocalLLMQualityDriver(
            profile=profile,
            policy=policy,
            client=client,
            token_counter=token_counter,
            gateway=self.build_evaluation_gateway(run_id=run_id),
            run_budget=(run_budget if run_budget is not None else build_evaluation_run_budget(clock=clock)),
            clock=clock,
            evaluation_binding=evaluation_binding,
            attestation=attestation,
        )

    def build_workflow_quality_driver(
        self,
        *,
        profile: LocalLLMProfile,
        policy: LLMRequestBudgetPolicy,
        client: VLLMChatClient,
        token_counter: TokenCounter,
        evaluation_binding: EvaluationBinding,
        run_workflow: RunWorkflow,
        attestation: ServerAttestation | None = None,
    ) -> WorkflowBackedQualityDriver:
        """Build the formal D11 driver around the real Phase 1 workflow.

        The composition-owned callback creates an isolated scenario from
        ``fixture.environment_spec`` and returns raw workflow/repository evidence.
        Projection and oracle scoring remain outside that callback.
        """
        self.verify_endpoint_binds_profile(profile)
        _require_bound_tokenizer(token_counter, profile)
        assert self.endpoint is not None and self.endpoint.base_url is not None
        if client.base_url != self.endpoint.base_url.rstrip("/"):
            raise LLMEvaluationError("workflow quality client base_url does not match the configured endpoint")
        if evaluation_binding.profile_digest != profile.profile_digest:
            raise LLMEvaluationError("workflow quality driver profile does not match the evaluation binding")
        if attestation is not None:
            require_attestation_binding(
                attestation,
                profile=profile,
                base_url=client.base_url,
                digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service,
            )
        planner = self.build_planner(
            profile=profile,
            policy=policy,
            client=client,
            token_counter=token_counter,
        )
        analyzer = self.build_analyzer(
            profile=profile,
            policy=policy,
            client=client,
            token_counter=token_counter,
        )
        executor = Phase1WorkflowRunExecutor(
            workflow=self.phase1.workflow,
            planner=planner,
            analyzer=analyzer,
            run_workflow=run_workflow,
        )
        return WorkflowBackedQualityDriver(
            client=client,
            attestation=attestation,
            evaluation_binding=evaluation_binding,
            executor=executor,
            token_counter=token_counter,
        )

    def build_isolated_workflow_quality_driver(
        self,
        *,
        profile: LocalLLMProfile,
        policy: LLMRequestBudgetPolicy,
        client: VLLMChatClient,
        token_counter: TokenCounter,
        evaluation_binding: EvaluationBinding,
        capability_results: tuple[LLMSchemaCapabilityResult, ...],
        attestation: ServerAttestation | None = None,
        max_parallel_runs: int = 1,
    ) -> WorkflowBackedQualityDriver:
        """Build the only workflow driver eligible for formal D11 evidence.

        Every call creates a fresh in-memory product kernel and a side-effect-free
        adapter whose mode is taken from the expectation-free environment input.
        """
        self.verify_endpoint_binds_profile(profile)
        _require_bound_tokenizer(token_counter, profile)
        assert self.endpoint is not None and self.endpoint.base_url is not None
        if client.base_url != self.endpoint.base_url.rstrip("/"):
            raise LLMEvaluationError("workflow quality client base_url does not match the configured endpoint")
        if evaluation_binding.profile_digest != profile.profile_digest:
            raise LLMEvaluationError("workflow quality driver profile does not match the evaluation binding")
        if attestation is not None:
            require_attestation_binding(
                attestation,
                profile=profile,
                base_url=client.base_url,
                digest_service=self.phase1.phase0c.phase0b.phase0a.digest_service,
            )

        def kernel_factory(run_input):  # type: ignore[no-untyped-def]
            adapter = MockExecutionAdapter(
                adapter_id="quality-isolated-adapter",
                result_delivery_mode="provider_task",
                reconcile_status="FOUND_TERMINAL",
                reconcile_provider_status="succeeded",
                stdout_chunks=(
                    b'{"host":"127.0.0.1","status":"observed","port":0}',
                ),
                clock_value=self.phase1.phase0c.phase0b.phase0a.clock.now(),
            )
            isolated = build_phase2_kernel(
                endpoint=self.endpoint,
                _scenario_mock_adapter=adapter,
            )
            a = isolated.phase1.phase0c.phase0b.phase0a
            a.profile_repository.save(profile)
            for result in capability_results:
                isolated.capability_repository.save(result)
            return isolated.phase1

        def planner_factory(phase1: Phase1Kernel) -> LocalLLMPlanner:
            return LocalLLMPlanner(
                profile=profile,
                policy=policy,
                client=client,
                token_counter=token_counter,
                clock=phase1.phase0c.monotonic_clock,
                digest_service=phase1.phase0c.phase0b.phase0a.digest_service,
            )

        def analyzer_factory(phase1: Phase1Kernel) -> LocalLLMAnalyzer:
            return LocalLLMAnalyzer(
                profile=profile,
                policy=policy,
                client=client,
                token_counter=token_counter,
                clock=phase1.phase0c.monotonic_clock,
                digest_service=phase1.phase0c.phase0b.phase0a.digest_service,
            )

        scenario_runner = IsolatedPhase1ScenarioRunner(
            kernel_factory=kernel_factory,
            planner_factory=planner_factory,
            analyzer_factory=analyzer_factory,
            profile=profile,
            client=client,
            token_counter=token_counter,
        )
        executor = IsolatedPhase1WorkflowRunExecutor(
            workflow=self.phase1.workflow,
            planner=self.build_planner(
                profile=profile,
                policy=policy,
                client=client,
                token_counter=token_counter,
            ),
            analyzer=self.build_analyzer(
                profile=profile,
                policy=policy,
                client=client,
                token_counter=token_counter,
            ),
            run_workflow=scenario_runner,
        )
        return WorkflowBackedQualityDriver(
            client=client,
            attestation=attestation,
            evaluation_binding=evaluation_binding,
            executor=executor,
            token_counter=token_counter,
            max_parallel_runs=max_parallel_runs,
        )

    def verify_endpoint_binds_profile(self, profile: LocalLLMProfile) -> None:
        """Fail closed unless the configured endpoint serves the profile's model."""
        if self.endpoint is None:
            raise LLMCapabilityError("no local vLLM endpoint is configured")
        assert_endpoint_matches_profile(self.endpoint, profile)

    def qualify_real_local_llm(
        self,
        *,
        profile: LocalLLMProfile,
        driver: RunDriver,
        evaluation_binding: EvaluationBinding,
        capability_results: tuple[LLMSchemaCapabilityResult, ...],
        evaluation_id: str | None = None,
        attestation: ServerAttestation | None = None,
    ) -> QualityReport:
        """The real 300-run qualification entry point.

        Every attempted run and the aggregate report are appended to the durable
        evidence sink under ``evaluation_id`` (default: the binding digest); a real
        ``PASS`` is impossible without that complete durable record.

        This is the reachable formal path, not a permanent ``NOT_RUN`` stub: given a real
        workflow-derived :class:`RunDriver`, a valid :class:`EvaluationBinding`, a
        configured endpoint that serves the mission-fixed profile, and passed real
        capability results, it verifies those bindings and runs the fixed 300-run gate.

        Only the concrete product quality driver over a direct network transport can
        supply real evidence; a test-double driver (or one relabelled
        ``real_local_llm``) is rejected. On this host no vLLM endpoint is configured, so it returns
        ``NOT_RUN`` — never a fabricated ``PASS``.
        """
        if self.endpoint is None or not self.endpoint.endpoint_available:
            return self.quality_gate_not_run(reason="no local vLLM endpoint configured for a real qualification")
        if self.qualification_commit_id is None or self.dependency_lock_digest is None:
            return self.quality_gate_not_run(
                reason="qualification commit and dependency-lock identity are not configured"
            )
        self.verify_endpoint_binds_profile(profile)
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        self._verify_real_capability_results(profile, capability_results, attestation)
        # Binding-field mismatches (tampered seeds, wrong digests) are blocked before any
        # driver / network activity, independent of the driver's provenance.
        expected_fields = self._expected_binding_fields(profile, capability_results, attestation)
        bound = evaluation_binding.model_dump(mode="python")
        mismatched = tuple(
            f"evaluation binding {name} does not match the trusted input"
            for name, value in expected_fields.items()
            if bound.get(name) != value
        )
        if mismatched:
            return blocked_report(
                corpus=self.quality_corpus,
                digest_service=ds,
                reasons=mismatched,
                evaluation_binding_digest=evaluation_binding.binding_digest,
            )
        self._require_persisted_attestation(attestation, profile)
        if derive_driver_evidence_kind(driver) != "real_local_llm":
            raise LLMEvaluationError(
                "a real qualification requires a real workflow-derived run driver, not a test double"
            )
        return run_agent_quality_gate(
            corpus=self.quality_corpus,
            digest_service=ds,
            driver=driver,
            external_prerequisites=REAL_LLM_PREREQUISITES,
            evaluation_binding=evaluation_binding,
            expected_capability_result_digests=tuple(r.result_digest for r in capability_results),
            expected_binding_fields=expected_fields,
            evidence_sink=self.quality_evidence_repository(),
            evaluation_id=evaluation_id or f"qualification:{evaluation_binding.binding_digest}",
        )

    def _expected_binding_fields(
        self,
        profile: LocalLLMProfile,
        capability_results: tuple[LLMSchemaCapabilityResult, ...],
        attestation: ServerAttestation | None = None,
    ) -> dict[str, object]:
        if self.qualification_commit_id is None or self.dependency_lock_digest is None:
            raise LLMEvaluationError("qualification build identity is not configured")
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        contracts = self.phase1.phase0c.phase0b.phase0a.contract_catalog.all()
        contract_digest = ds.compute(
            "llm_schema_digest",
            {
                "schema_name": "action_contract_catalog",
                "schema": {"definition_digests": tuple(item.definition_digest for item in contracts)},
            },
        )
        return {
            "commit_id": self.qualification_commit_id,
            "profile_digest": profile.profile_digest,
            "model_hash": profile.model_hash,
            "tokenizer_revision": profile.tokenizer_revision,
            "chat_template_digest": profile.chat_template_digest,
            "runtime_version": profile.runtime_version,
            "output_mode": profile.structured_output_mode,
            "schema_capability_corpus_version": self.schema_corpus.corpus_version,
            "schema_capability_corpus_digest": self.schema_corpus.corpus_digest(ds),
            "agent_quality_corpus_version": self.quality_corpus.corpus_version,
            "agent_quality_corpus_digest": self.quality_corpus.corpus_digest(ds),
            "schema_digests": tuple((str(name), compute_schema_digest(name, ds)) for name in ACTUAL_SCHEMA_NAMES),
            "prompt_set_digests": tuple(
                (str(name), self.schema_corpus.prompt_set_digest(name, ds)) for name in ACTUAL_SCHEMA_NAMES
            ) + quality_prompt_set_digests(ds),
            "contract_digest": contract_digest,
            "catalog_digest": ds.catalog.catalog_digest,
            "gateway_budget_policy_digest": self.request_budget_policy(profile).policy_digest,
            "dependency_lock_digest": self.dependency_lock_digest,
            "capability_result_digests": tuple(result.result_digest for result in capability_results),
            "server_attestation_digest": (attestation.attestation_digest if attestation is not None else None),
            "run_seeds": build_run_seeds(self.quality_corpus),
        }

    def _verify_real_capability_results(
        self,
        profile: LocalLLMProfile,
        results: tuple[LLMSchemaCapabilityResult, ...],
        attestation: ServerAttestation | None = None,
    ) -> None:
        ds = self.phase1.phase0c.phase0b.phase0a.digest_service
        verify_profile_digest(profile, ds)
        current_corpus_digest = self.schema_corpus.corpus_digest(ds)
        covered: set[str] = set()
        for result in results:
            ds.verify(
                "llm_schema_capability_result_digest",
                {k: v for k, v in result.model_dump(mode="python").items() if k != "result_digest"},
                result.result_digest,
            )
            if result.evidence_kind != "real_local_llm":
                raise LLMEvaluationError("a real qualification requires real_local_llm capability results")
            if not result.passed:
                raise LLMEvaluationError(f"capability result for {result.schema_name} did not pass")
            if result.profile_digest != profile.profile_digest:
                raise LLMEvaluationError("capability result is not bound to the qualifying profile")
            expected_schema_digest = compute_schema_digest(result.schema_name, ds)
            expected_prompt_digest = self.schema_corpus.prompt_set_digest(result.schema_name, ds)
            if (
                result.schema_digest != expected_schema_digest
                or result.corpus_version != self.schema_corpus.corpus_version
                or result.corpus_digest != current_corpus_digest
                or result.prompt_set_digest != expected_prompt_digest
                or result.structured_output_mode != profile.structured_output_mode
            ):
                raise LLMEvaluationError(
                    "capability result is stale for the current schema, corpus, prompt, or output mode"
                )
            if result.server_attestation_digest is None or (
                attestation is not None and result.server_attestation_digest != attestation.attestation_digest
            ):
                raise LLMEvaluationError("capability result is not bound to the attested server")
            if result.unsafe_boundary_acceptances != 0 or result.cancellation_failures != 0:
                raise LLMEvaluationError("capability result has non-zero safety counters")
            if result.valid_within_retry_budget / result.sample_count < MIN_VALID_RATIO:
                raise LLMEvaluationError("capability result valid ratio below threshold")
            stored = self.capability_repository.get(
                profile_digest=result.profile_digest,
                model_hash=result.model_hash,
                runtime_version=result.runtime_version,
                tokenizer_revision=result.tokenizer_revision,
                chat_template_digest=result.chat_template_digest,
                schema_name=result.schema_name,
                schema_digest=result.schema_digest,
                corpus_version=result.corpus_version,
                corpus_digest=result.corpus_digest,
                prompt_set_digest=result.prompt_set_digest,
                structured_output_mode=result.structured_output_mode,
            )
            if stored is None or stored.result_digest != result.result_digest:
                raise LLMEvaluationError("capability result is not the persisted result for this binding")
            covered.add(result.schema_name)
        expected = {str(name) for name in ACTUAL_SCHEMA_NAMES}
        if covered != expected or len(results) != len(expected):
            raise LLMEvaluationError("capability results must cover each actual schema exactly once")


def build_phase2_kernel(
    *,
    endpoint: LocalLLMEndpointConfig | None = None,
    qualification_commit_id: str | None = None,
    dependency_lock_digest: str | None = None,
    db_path: str = ":memory:",
    _scenario_mock_adapter: MockExecutionAdapter | None = None,
) -> Phase2Kernel:
    if qualification_commit_id is not None and (
        len(qualification_commit_id) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in qualification_commit_id.lower())
    ):
        raise LLMEvaluationError("qualification commit id must be a full hexadecimal object id")
    if dependency_lock_digest is not None and (
        len(dependency_lock_digest) != 64
        or any(character not in "0123456789abcdef" for character in dependency_lock_digest.lower())
    ):
        raise LLMEvaluationError("dependency lock digest must be a SHA-256 hexadecimal digest")
    lazy_verifier: _LazyMissionCapabilityVerifier = _LazyMissionCapabilityVerifier()
    verifier_ref: LLMCapabilityVerifier = lazy_verifier
    phase0a = build_test_kernel(
        db_path=db_path,
        allowed_profile_types=frozenset({"vllm"}),
        capability_verifier=verifier_ref,
    )
    phase0b = build_phase0b_kernel(
        phase0a=phase0a,
        mock_adapter=_scenario_mock_adapter,
        result_delivery_mode=(
            _scenario_mock_adapter.identity().result_delivery_mode
            if _scenario_mock_adapter is not None
            else "provider_task"
        ),
        adapter_id=(_scenario_mock_adapter.identity().adapter_id if _scenario_mock_adapter is not None else "c2-main"),
    )
    phase0c = build_phase0c_kernel(phase0b=phase0b)
    phase1 = build_phase1_kernel(phase0c=phase0c)
    ds = phase0a.digest_service
    schema_corpus = build_schema_capability_corpus()
    quality_corpus = build_agent_quality_corpus(ds)
    capability_repository = CapabilityRepository(database=phase0a.database, digest_service=ds)
    capability_evaluator = CapabilityEvaluator(digest_service=ds)
    capability_verifier = MissionCapabilityVerifier(
        repository=capability_repository, digest_service=ds, corpus=schema_corpus
    )
    lazy_verifier.bind(capability_verifier)
    evaluation_harness = LocalEvaluationHarness(digest_service=ds, corpus=schema_corpus)
    return Phase2Kernel(
        phase1=phase1,
        schema_corpus=schema_corpus,
        quality_corpus=quality_corpus,
        capability_repository=capability_repository,
        capability_evaluator=capability_evaluator,
        capability_verifier=capability_verifier,
        evaluation_harness=evaluation_harness,
        endpoint=endpoint,
        qualification_commit_id=qualification_commit_id,
        dependency_lock_digest=dependency_lock_digest,
    )


# Re-exported for tests/composition consumers that assemble a real capability probe.
__all__ = [
    "Phase2Kernel",
    "build_phase2_kernel",
    "evaluate_all_schemas",
]
