"""Read-only AD assessment catalog, Planner guard, and verifier tests."""

from __future__ import annotations

import json
from ipaddress import IPv4Address
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from pydantic import ValidationError

import support
from redteam_agent.ad_assessment import collector as collector_module
from redteam_agent.ad_assessment.catalog import (
    AD_ASSESSMENT_OPERATIONS,
    AD_ASSESSMENT_PARAMETER_SCHEMA,
    build_ad_assessment_tool_definitions,
    catalog_view,
)
from redteam_agent.ad_assessment.collector import (
    ADCollectorCredential,
    ADCollectorError,
    ADCollectorSettings,
    CertipyADCSAssessmentSource,
    DirectoryEvidence,
    VerifiedADCollector,
)
from redteam_agent.ad_assessment.consensus import ADAssessmentLLMConsensusEvaluator
from redteam_agent.ad_assessment.models import (
    ADAssessmentConsensusResult,
    ADAssessmentSnapshot,
    ADCSEvidence,
    ADCSExposureCount,
    DelegationEvidence,
    KerberosPreauthEvidence,
    KerberosServiceAccountEvidence,
    PrivilegedAccessEvidence,
)
from redteam_agent.ad_assessment.planner import (
    build_ad_assessment_candidate_seeds,
    validate_ad_assessment_planner_selection,
)
from redteam_agent.ad_assessment.reasoning import ADAssessmentReasoner
from redteam_agent.ad_assessment.service import ADAssessmentVerifier
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.contracts.catalog import (
    ActionContractCatalog,
    ActionContractDefinition,
    RuleCatalog,
    parameter_schema_digest,
)
from redteam_agent.errors import PlannerCandidateError, PydanticBoundaryValidationError
from redteam_agent.models.common import ToolRef
from redteam_agent.plan.models import ExecutionPlanProposal, PlannerActionOutput
from redteam_agent.policy.scope_models import HostTargetReference
from redteam_agent.runtime.clock import ManualClock
from redteam_agent.tools.registry import build_tool_registry


def _snapshot() -> ADAssessmentSnapshot:
    return ADAssessmentSnapshot(
        snapshot_id="snapshot-1",
        domain_ref="domain:intern.local",
        source_type="simulator",
        source_artifact_ids=("artifact-directory-1",),
        collected_at=support.T0,
        privileged_access=PrivilegedAccessEvidence(
            unexpected_tier_zero_membership_count=1,
            stale_privileged_account_count=2,
            excessive_delegated_admin_count=0,
        ),
        kerberos_service_accounts=KerberosServiceAccountEvidence(
            service_account_with_spn_count=4,
            weak_encryption_service_account_count=1,
            stale_password_service_account_count=2,
            unmanaged_service_account_count=3,
        ),
        kerberos_preauth=KerberosPreauthEvidence(
            preauthentication_disabled_account_count=1,
        ),
        adcs=ADCSEvidence(
            exposure_counts=(
                ADCSExposureCount(esc_id="ESC1", affected_object_count=1),
                ADCSExposureCount(esc_id="ESC2", affected_object_count=0),
                ADCSExposureCount(esc_id="ESC8", affected_object_count=2),
            )
        ),
        delegation=DelegationEvidence(
            unconstrained_delegation_account_count=1,
            broad_constrained_delegation_account_count=0,
            protocol_transition_account_count=2,
            risky_rbcd_acl_count=1,
        ),
    )


def _collector_settings(tmp_path: Path) -> ADCollectorSettings:
    return ADCollectorSettings(
        server_ip=IPv4Address("10.0.10.10"),
        port=636,
        domain="intern.local",
        credential_file=tmp_path / "ad-credential.json",
        tls_ca_file=None,
        certipy_python=Path("/usr/bin/python3"),
        timeout_seconds=5,
    )


def _all_esc_evidence() -> ADCSEvidence:
    return ADCSEvidence(
        exposure_counts=tuple(
            ADCSExposureCount(esc_id=esc_id, affected_object_count=1 if esc_id == "ESC1" else 0)
            for esc_id in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8")
        )
    )


def test_verifier_detects_all_supported_configuration_categories() -> None:
    result = ADAssessmentVerifier(clock=lambda: support.T0).evaluate(_snapshot())

    assert result.decision_authority == "deterministic_verifier"
    assert result.evidence_source_type == "simulator"
    assert len(result.checks) == 5
    assert all(check.status == "misconfiguration_detected" for check in result.checks)
    assert {finding.rule_id for finding in result.findings} == {
        "AD-PRIV-TIER0",
        "AD-PRIV-STALE",
        "AD-KRB-WEAK-ENC",
        "AD-KRB-STALE-PWD",
        "AD-KRB-UNMANAGED",
        "AD-KRB-PREAUTH",
        "AD-ADCS-ESC1",
        "AD-ADCS-ESC8",
        "AD-DELEG-UNCONSTRAINED",
        "AD-DELEG-PROTOCOL",
        "AD-DELEG-RBCD",
    }
    assert all(finding.evidence_artifact_ids == ("artifact-directory-1",) for finding in result.findings)


def test_missing_evidence_is_indeterminate_and_zero_counts_are_not_findings() -> None:
    source = _snapshot()
    snapshot = source.model_copy(
        update={
            "privileged_access": PrivilegedAccessEvidence(
                unexpected_tier_zero_membership_count=0,
                stale_privileged_account_count=0,
                excessive_delegated_admin_count=0,
            ),
            "kerberos_service_accounts": None,
            "kerberos_preauth": None,
            "adcs": None,
            "delegation": None,
        }
    )

    result = ADAssessmentVerifier(clock=lambda: support.T0).evaluate(snapshot)

    assert result.checks[0].status == "no_misconfiguration_detected"
    assert result.checks[0].reason_codes == ("NO_RULE_MATCH",)
    assert all(check.status == "indeterminate" for check in result.checks[1:])
    assert result.findings == ()


def test_evidence_boundary_rejects_secret_fields_and_inconsistent_counts() -> None:
    raw = _snapshot().model_dump(mode="json")
    kerberos = raw["kerberos_service_accounts"]
    assert isinstance(kerberos, dict)
    kerberos["ticket_hash"] = "must-not-cross-boundary"
    with pytest.raises(PydanticBoundaryValidationError):
        ADAssessmentSnapshot.from_untrusted_json(json.dumps(raw))

    with pytest.raises(ValidationError, match="exceeds"):
        KerberosServiceAccountEvidence(
            service_account_with_spn_count=1,
            weak_encryption_service_account_count=2,
            stale_password_service_account_count=0,
            unmanaged_service_account_count=0,
        )


def test_llm_planner_can_only_select_an_exact_read_only_candidate() -> None:
    target = HostTargetReference(type="host", host_id="dc-01")
    candidates = build_ad_assessment_candidate_seeds(
        host_target=target,
        registry_revision=4,
        completed_operation_ids=frozenset({"ad.audit.privileged_access"}),
    )
    selected = candidates[0]
    output = PlannerActionOutput(
        proposal=ExecutionPlanProposal(
            objective="Inspect the next incomplete AD configuration category",
            phase="DISCOVERY",
            tool_ref=selected.tool_ref,
            requested_targets=selected.canonical_target_binding,
            session_id=None,
            arguments=selected.suggested_arguments,
        ),
        working_state_update=None,
        next_iteration_hints=(),
    )

    assert validate_ad_assessment_planner_selection(output, candidates=candidates) == selected.tool_ref.tool_id

    unregistered = output.model_copy(
        update={
            "proposal": output.proposal.model_copy(
                update={"tool_ref": ToolRef(tool_id="ad.audit.request_tickets", registry_revision=4)}
            )
        }
    )
    with pytest.raises(PlannerCandidateError, match="exact current candidate"):
        validate_ad_assessment_planner_selection(unregistered, candidates=candidates)

    modified_arguments = output.model_copy(
        update={
            "proposal": output.proposal.model_copy(update={"arguments": {"host_ids": ["dc-02"], "timeout_seconds": 30}})
        }
    )
    with pytest.raises(PlannerCandidateError, match="exact current candidate"):
        validate_ad_assessment_planner_selection(modified_arguments, candidates=candidates)


def test_catalog_tools_validate_in_the_existing_registry_contract() -> None:
    digest_service = DigestService()
    registry_revision = 9
    evidence_rules = ("ad-assessment-evidence-v1",)
    publication_rule = "ad-assessment-redacted-v1"
    definitions = tuple(
        ActionContractDefinition(
            contract_id=f"contract-{item.operation_id}",
            revision="1",
            tool_id=item.operation_id,
            registry_revision=registry_revision,
            parameter_schema_digest=parameter_schema_digest(AD_ASSESSMENT_PARAMETER_SCHEMA),
            target_extractor_id="host_target_v1",
            evidence_rule_ids=evidence_rules,
            output_publication_rule_id=publication_rule,
            minimum_risk_level="read",
            side_effect="read_only",
        )
        for item in AD_ASSESSMENT_OPERATIONS
    )
    contracts = ActionContractCatalog(definitions)
    tools = build_ad_assessment_tool_definitions(
        registry_revision=registry_revision,
        action_contract_refs={item.tool_id: item.reference() for item in definitions},
        output_publication_rule_id=publication_rule,
        evidence_rule_ids=evidence_rules,
        digest_service=digest_service,
    )
    rules = RuleCatalog(
        publication_rule_ids=frozenset({publication_rule}),
        evidence_rule_ids=frozenset(evidence_rules),
    )

    registry = build_tool_registry(
        registry_revision=registry_revision,
        tools=tools,
        digest_service=digest_service,
        contract_catalog=contracts,
        rule_catalog=rules,
    )

    assert len(registry.tools) == 5
    assert all(tool.side_effect == "read_only" for tool in registry.tools)
    assert all(tool.secret_argument_paths == () for tool in registry.tools)
    assert all(tool.required_target_binding_modes == frozenset({"provider_attested"}) for tool in registry.tools)


def test_public_catalog_makes_simulator_and_live_gap_explicit() -> None:
    view = catalog_view()
    assert view["simulatorStatus"] == "ready"
    assert view["liveCollectorStatus"] == "not_attached"
    assert view["decisionAuthority"] == "deterministic_verifier"
    assert len(view["operations"]) == 5


def test_reasoner_reduces_local_planner_output_to_trusted_catalog_metadata() -> None:
    class Invocation:
        def before_attempt(self, _attempt: int) -> dict[str, object]:
            return {}

        def __call__(self, envelope):
            candidate = envelope.action_candidate_projection.candidates[2]
            return PlannerActionOutput(
                proposal=ExecutionPlanProposal(
                    objective="model-authored text is not returned to the UI",
                    phase="DISCOVERY",
                    tool_ref=candidate.tool_ref,
                    requested_targets=candidate.canonical_target_binding,
                    session_id=None,
                    arguments=candidate.suggested_arguments,
                ),
                working_state_update=None,
                next_iteration_hints=(),
            )

    class Planner:
        def build_invocation(self, *_args, **_kwargs):
            return Invocation()

    capability_checks = 0

    def check_capability() -> None:
        nonlocal capability_checks
        capability_checks += 1

    recommendation = ADAssessmentReasoner(
        planner=Planner(),  # type: ignore[arg-type]
        capability_checker=check_capability,
        clock=ManualClock(support.T0),
        digest_service=DigestService(),
    ).recommend()

    assert capability_checks == 1
    assert recommendation.operation_id == "ad.audit.kerberos_preauth"
    assert recommendation.authority == "recommendation_only"
    assert recommendation.output_schema == "planner_output"
    assert "model-authored" not in recommendation.model_dump_json()


class _ClassificationPlanner:
    def __init__(self, *, disagree_operation: str | None = None, unknown: bool = False) -> None:
        self.disagree_operation = disagree_operation
        self.unknown = unknown
        self.calls = 0
        self.attempts = 0

    def build_invocation(self, *_args, **_kwargs):
        owner = self

        class Invocation:
            def before_attempt(self, _attempt: int) -> dict[str, object]:
                owner.attempts += 1
                return {}

            def __call__(self, envelope):
                owner.calls += 1
                evidence = envelope.authorized_context["normalized_evidence"]
                operation_id = envelope.authorized_context["operation_id"]
                if not evidence["present"]:
                    desired = "indeterminate"
                elif evidence["risk_signal_count"] > 0:
                    desired = "misconfiguration_detected"
                else:
                    desired = "no_misconfiguration_detected"
                if operation_id == owner.disagree_operation:
                    desired = "no_misconfiguration_detected"
                candidate = next(
                    item
                    for item in envelope.action_candidate_projection.candidates
                    if item.suggested_arguments["classification"] == desired
                )
                tool_ref = (
                    ToolRef(tool_id="ad.classify.unregistered", registry_revision=1)
                    if owner.unknown
                    else candidate.tool_ref
                )
                return PlannerActionOutput(
                    proposal=ExecutionPlanProposal(
                        objective="model prose must not cross the result boundary",
                        phase="DISCOVERY",
                        tool_ref=tool_ref,
                        requested_targets=candidate.canonical_target_binding,
                        session_id=None,
                        arguments=candidate.suggested_arguments,
                    ),
                    working_state_update=None,
                    next_iteration_hints=(),
                )

        return Invocation()


def test_local_llm_consensus_evaluates_every_category_and_keeps_verifier_authority() -> None:
    planner = _ClassificationPlanner()
    capability_checks = 0

    def check_capability() -> None:
        nonlocal capability_checks
        capability_checks += 1

    result = ADAssessmentLLMConsensusEvaluator(
        planner=planner,  # type: ignore[arg-type]
        capability_checker=check_capability,
        clock=ManualClock(support.T0),
        digest_service=DigestService(),
    ).evaluate(_snapshot())

    assert result.status == "completed"
    assert result.decision_authority == "deterministic_verifier"
    assert result.output_schema == "planner_output"
    assert len(result.category_results) == 5
    assert all(item.consensus == "agreed" for item in result.category_results)
    assert planner.calls == 5
    assert capability_checks == 1
    assert "model prose" not in result.model_dump_json()


def test_local_llm_disagreement_blocks_result_but_cannot_change_findings() -> None:
    planner = _ClassificationPlanner(disagree_operation="ad.audit.privileged_access")
    result = ADAssessmentLLMConsensusEvaluator(
        planner=planner,  # type: ignore[arg-type]
        capability_checker=lambda: None,
        clock=ManualClock(support.T0),
        digest_service=DigestService(),
    ).evaluate(_snapshot())

    assert result.status == "blocked"
    assert result.category_results[0].consensus == "disagreed"
    assert result.category_results[0].llm_status == "no_misconfiguration_detected"
    assert result.category_results[0].verifier_status == "misconfiguration_detected"
    assert "AD-PRIV-TIER0" in {item.rule_id for item in result.findings}


def test_local_llm_unknown_candidate_retries_then_fails_closed() -> None:
    planner = _ClassificationPlanner(unknown=True)
    with pytest.raises(PlannerCandidateError, match="no exact AD assessment classification"):
        ADAssessmentLLMConsensusEvaluator(
            planner=planner,  # type: ignore[arg-type]
            capability_checker=lambda: None,
            clock=ManualClock(support.T0),
            digest_service=DigestService(),
        ).evaluate(_snapshot())

    assert planner.calls == 4
    assert planner.attempts == 4


def test_consensus_cannot_complete_when_evidence_is_indeterminate() -> None:
    snapshot = _snapshot().model_copy(update={"adcs": None})
    result = ADAssessmentLLMConsensusEvaluator(
        planner=_ClassificationPlanner(),  # type: ignore[arg-type]
        capability_checker=lambda: None,
        clock=ManualClock(support.T0),
        digest_service=DigestService(),
    ).evaluate(snapshot)
    assert result.status == "blocked"
    assert result.category_results[3].consensus == "agreed"
    assert result.category_results[3].verifier_status == "indeterminate"

    invalid = result.model_dump(mode="python")
    invalid["status"] = "completed"
    with pytest.raises(ValidationError, match="evidence completeness"):
        ADAssessmentConsensusResult.model_validate(invalid)


def test_verified_collector_normalizes_all_sources_without_returning_credentials(tmp_path) -> None:
    settings = _collector_settings(tmp_path)
    settings.credential_file.write_text(
        json.dumps({"domain": "intern.local", "username": "private-principal", "password": "secret-value"}),
        encoding="utf-8",
    )
    settings.credential_file.chmod(0o600)
    directory = DirectoryEvidence(
        privileged_access=PrivilegedAccessEvidence(
            unexpected_tier_zero_membership_count=1,
            stale_privileged_account_count=0,
            excessive_delegated_admin_count=0,
        ),
        kerberos_service_accounts=KerberosServiceAccountEvidence(
            service_account_with_spn_count=1,
            weak_encryption_service_account_count=1,
            stale_password_service_account_count=0,
            unmanaged_service_account_count=1,
        ),
        kerberos_preauth=KerberosPreauthEvidence(preauthentication_disabled_account_count=0),
        delegation=DelegationEvidence(
            unconstrained_delegation_account_count=0,
            broad_constrained_delegation_account_count=0,
            protocol_transition_account_count=0,
            risky_rbcd_acl_count=0,
        ),
    )

    class DirectorySource:
        def collect(self, credential: ADCollectorCredential) -> DirectoryEvidence:
            assert credential.username == "private-principal"
            return directory

    class ADCSSource:
        def collect(self, credential: ADCollectorCredential) -> ADCSEvidence:
            assert credential.domain == "intern.local"
            return _all_esc_evidence()

    snapshot = VerifiedADCollector(
        settings=settings,
        directory_source=DirectorySource(),
        adcs_source=ADCSSource(),
        digest_service=DigestService(),
        clock=lambda: support.T0,
    ).collect()

    assert snapshot.source_type == "verified_ldap_snapshot"
    assert snapshot.domain_ref == "domain:intern.local"
    assert len(snapshot.adcs.exposure_counts) == 8  # type: ignore[union-attr]
    serialized = snapshot.model_dump_json()
    assert "secret-value" not in serialized
    assert "private-principal" not in serialized
    assert snapshot.source_artifact_ids[0].startswith("collector-evidence:")


def test_verified_collector_rejects_permissive_secret_file(tmp_path) -> None:
    settings = _collector_settings(tmp_path)
    settings.credential_file.write_text(
        json.dumps({"domain": "intern.local", "username": "collector", "password": "secret-value"}),
        encoding="utf-8",
    )
    settings.credential_file.chmod(0o644)

    class UnusedSource:
        def collect(self, _credential: ADCollectorCredential):
            raise AssertionError("source must not be called")

    collector = VerifiedADCollector(
        settings=settings,
        directory_source=UnusedSource(),  # type: ignore[arg-type]
        adcs_source=UnusedSource(),  # type: ignore[arg-type]
        digest_service=DigestService(),
        clock=lambda: support.T0,
    )
    with pytest.raises(ADCollectorError) as caught:
        collector.collect()
    assert caught.value.code == "AD_COLLECTOR_SECRET_PERMISSIONS"


def test_certipy_source_accepts_only_complete_esc_coverage(tmp_path, monkeypatch) -> None:
    settings = _collector_settings(tmp_path)
    credential = ADCollectorCredential(domain="intern.local", username="collector", password="secret")
    complete = {
        "coverage_complete": True,
        "exposure_counts": {f"ESC{index}": index for index in range(1, 9)},
    }
    monkeypatch.setattr(
        collector_module.subprocess,
        "run",
        lambda *_args, **_kwargs: CompletedProcess([], 0, stdout=json.dumps(complete), stderr=""),
    )

    evidence = CertipyADCSAssessmentSource(settings).collect(credential)
    assert [item.affected_object_count for item in evidence.exposure_counts] == list(range(1, 9))

    incomplete = {"coverage_complete": False, "exposure_counts": complete["exposure_counts"]}
    monkeypatch.setattr(
        collector_module.subprocess,
        "run",
        lambda *_args, **_kwargs: CompletedProcess([], 0, stdout=json.dumps(incomplete), stderr=""),
    )
    with pytest.raises(ADCollectorError) as caught:
        CertipyADCSAssessmentSource(settings).collect(credential)
    assert caught.value.code == "AD_COLLECTOR_ADCS_INCOMPLETE"


def test_verified_snapshot_requires_all_eight_adcs_checks() -> None:
    raw = _snapshot().model_dump(mode="python")
    raw["source_type"] = "verified_ldap_snapshot"
    with pytest.raises(ValidationError, match="complete ESC1-ESC8"):
        ADAssessmentSnapshot.model_validate(raw)
