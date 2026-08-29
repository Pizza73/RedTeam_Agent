from __future__ import annotations

import inspect
import sqlite3
from datetime import timedelta

import pytest

from redteam_agent.canonical import CanonicalJsonObject, digest_model, stable_id
from redteam_agent.errors import (
    BoundaryJsonParseError,
    DigestIntegrityError,
    PolicyDecisionProvenanceError,
    PydanticBoundaryValidationError,
)
from redteam_agent.executor import authorize_execution
from redteam_agent.models.capabilities import SandboxCapabilities
from redteam_agent.models.common import OperationalPhase, RiskLevel
from redteam_agent.models.llm import LLMCapabilityResult
from redteam_agent.models.plans import ExecutionPlanProposal
from redteam_agent.models.scope import NetworkScopeRule, SessionScopeRule
from redteam_agent.models.tools import SandboxRequirement, ToolDefinition
from redteam_agent.policy.digests import authorization_digest_from_decision
from redteam_agent.policy.engine import PolicyEngine
from redteam_agent.policy.issuance import _POLICY_ENGINE_ISSUER_TOKEN
from redteam_agent.policy.plans import create_execution_plan
from redteam_agent.repositories import (
    AdapterCapabilitySnapshotRepository,
    AvailableToolSnapshotRepository,
    LLMProfileRepository,
    MissionRevisionRepository,
    PlanRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
)
from redteam_agent.repositories.base import model_json
from redteam_agent.seeds import (
    FIXED_TIME,
    mock_capability_snapshots,
    mock_mission,
    mock_network_tool,
    mock_profile,
)
from redteam_agent.storage import Database
from redteam_agent.storage.migrations import MIGRATIONS
from redteam_agent.tools import (
    ToolAvailabilityResolver,
    TrustedTargetExtractorRegistry,
    build_registry_revision,
)
from redteam_agent.tools.capability_snapshots import build_sandbox_snapshot
from redteam_agent.validation import parse_boundary_json
from tests.helpers import build_environment, persist_environment, persisted_gate_kwargs


def _endpoint_tool(*, requires_session: bool = False) -> ToolDefinition:
    data = mock_network_tool().model_dump(mode="python")
    data.update(
        {
            "requires_session": requires_session,
            "required_session_capabilities": frozenset({"shell"})
            if requires_session
            else frozenset(),
            "parameter_schema": CanonicalJsonObject(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "port": {"type": "integer"},
                        "protocol": {"type": "string", "enum": ["tcp", "udp"]},
                    },
                    "required": ["target", "port", "protocol"],
                    "additionalProperties": False,
                    "x-redteam-target-fields": ["target"],
                    "x-redteam-port-field": "port",
                    "x-redteam-protocol-field": "protocol",
                    "x-redteam-requires-port": True,
                    "x-redteam-requires-protocol": True,
                }
            ),
        }
    )
    return ToolDefinition.model_validate(data)


def _endpoint_decision(
    *,
    mission,
    tool: ToolDefinition,
    port: int,
    protocol: str,
    session_id: str | None = None,
):
    extractors = TrustedTargetExtractorRegistry()
    registry = build_registry_revision(
        registry_revision=1, tools=(tool,), created_at=FIXED_TIME, extractors=extractors
    )
    session, adapter, sandbox, remote = mock_capability_snapshots(mission.mission_id)
    resolver = ToolAvailabilityResolver(extractors)
    calculation = resolver.calculate(
        mission=mission,
        registry=registry,
        session_snapshot=session,
        adapter_snapshot=adapter,
        sandbox_snapshot=sandbox,
        remote_trust_snapshot=remote,
        policy_version="policy-v1",
    )
    if not calculation.tools:
        return None
    snapshot = resolver.persistable_snapshot(
        calculation,
        created_at=FIXED_TIME,
        expires_at=FIXED_TIME + timedelta(hours=1),
        mission_valid_until=mission.valid_until,
    )
    proposal = ExecutionPlanProposal(
        objective="endpoint scope regression",
        phase=OperationalPhase.DISCOVERY,
        tool_ref=tool.tool_ref,
        requested_targets=(),
        session_id=session_id,
        arguments=CanonicalJsonObject({"target": "10.0.0.10", "port": port, "protocol": protocol}),
    )
    plan = create_execution_plan(
        mission=mission, proposal=proposal, snapshot=snapshot, created_at=FIXED_TIME
    )
    return PolicyEngine(policy_version="policy-v1", extractors=extractors).authorize(
        mission=mission,
        plan=plan,
        snapshot=snapshot,
        registry=registry,
        issued_at=FIXED_TIME + timedelta(minutes=1),
        expires_at=FIXED_TIME + timedelta(minutes=30),
    )


@pytest.mark.parametrize(
    ("allowed_rule", "port", "protocol", "expected"),
    [
        (
            NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",), ports=(443,)),
            443,
            "tcp",
            "ALLOW",
        ),
        (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",), ports=(443,)), 22, "tcp", "DENY"),
        (
            NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",), protocols=("tcp",)),
            443,
            "tcp",
            "ALLOW",
        ),
        (
            NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",), protocols=("tcp",)),
            443,
            "udp",
            "DENY",
        ),
    ],
)
def test_network_endpoint_scope_is_enforced(allowed_rule, port, protocol, expected) -> None:
    mission = mock_mission().model_copy(
        update={
            "allowed_execution_scope": (
                allowed_rule,
                SessionScopeRule(type="session", session_id="session-1"),
            )
        }
    )
    decision = _endpoint_decision(
        mission=mission, tool=_endpoint_tool(), port=port, protocol=protocol
    )
    assert decision is not None and decision.decision == expected


def test_prohibited_port_wins() -> None:
    mission = mock_mission().model_copy(
        update={
            "allowed_execution_scope": (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),),
            "prohibited_execution_scope": (
                NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",), ports=(443,)),
            ),
        }
    )
    decision = _endpoint_decision(mission=mission, tool=_endpoint_tool(), port=443, protocol="tcp")
    assert decision is not None and decision.decision == "DENY"


def test_prohibited_endpoint_rule_does_not_match_an_unrelated_network() -> None:
    mission = mock_mission().model_copy(
        update={
            "allowed_execution_scope": (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),),
            "prohibited_execution_scope": (
                NetworkScopeRule(type="network", cidrs=("192.0.2.0/24",), ports=(443,)),
            ),
        }
    )
    decision = _endpoint_decision(mission=mission, tool=_endpoint_tool(), port=443, protocol="tcp")
    assert decision is not None and decision.decision == "ALLOW"


def test_execution_session_scope_present_allows_and_absent_removes_tool() -> None:
    tool = _endpoint_tool(requires_session=True)
    allowed = _endpoint_decision(
        mission=mock_mission(), tool=tool, port=443, protocol="tcp", session_id="session-1"
    )
    assert allowed is not None and allowed.decision == "ALLOW"
    assert any(target.type == "session" for target in allowed.normalized_targets)
    no_session_scope = mock_mission().model_copy(
        update={
            "allowed_execution_scope": (NetworkScopeRule(type="network", cidrs=("10.0.0.0/24",)),)
        }
    )
    assert (
        _endpoint_decision(
            mission=no_session_scope,
            tool=tool,
            port=443,
            protocol="tcp",
            session_id="session-1",
        )
        is None
    )


def test_duplicate_keys_rejected_at_boundary_top_level_and_nested() -> None:
    top = (
        '{"objective":"a","objective":"b","phase":"DISCOVERY",'
        '"tool_ref":{"tool_id":"t","registry_revision":1},'
        '"requested_targets":[],"session_id":null,"arguments":{}}'
    )
    nested = (
        '{"objective":"a","phase":"DISCOVERY",'
        '"tool_ref":{"tool_id":"a","tool_id":"b","registry_revision":1},'
        '"requested_targets":[],"session_id":null,"arguments":{}}'
    )
    for raw in (top, nested):
        with pytest.raises((BoundaryJsonParseError, PydanticBoundaryValidationError)):
            parse_boundary_json(raw, ExecutionPlanProposal)


def test_unrelated_sandbox_runtime_cannot_satisfy_tool() -> None:
    mission = mock_mission()
    requirement = SandboxRequirement(
        dedicated_os_user=False,
        process_isolation=True,
        container_or_namespace=False,
        filesystem_allowlist_required=False,
        network_egress_control_required=False,
        environment_allowlist_required=False,
        secret_injection_control_required=False,
        cpu_limit_required=False,
        memory_limit_required=False,
        process_limit_required=False,
    )
    tool = mock_network_tool().model_copy(
        update={"minimum_risk_level": RiskLevel.HIGH, "sandbox_requirement": requirement}
    )
    extractors = TrustedTargetExtractorRegistry()
    registry = build_registry_revision(
        registry_revision=1, tools=(tool,), created_at=FIXED_TIME, extractors=extractors
    )
    session, adapter, _, remote = mock_capability_snapshots(mission.mission_id)
    unrelated = build_sandbox_snapshot(
        sandboxes=(
            SandboxCapabilities(
                sandbox_id="safe-other-runtime",
                runtime_id="different-runtime",
                adapter_id=tool.adapter_id,
                execution_location="local_process",
                dedicated_os_user=True,
                process_isolation=True,
                container_or_namespace=True,
                filesystem_allowlist=True,
                network_egress_control=True,
                environment_allowlist=True,
                secret_injection_control=True,
                cpu_limit=True,
                memory_limit=True,
                process_limit=True,
            ),
        ),
        source="test",
        created_at=FIXED_TIME,
    )
    calculation = ToolAvailabilityResolver(extractors).calculate(
        mission=mission,
        registry=registry,
        session_snapshot=session,
        adapter_snapshot=adapter,
        sandbox_snapshot=unrelated,
        remote_trust_snapshot=remote,
        policy_version="policy-v1",
    )
    assert calculation.tools == ()


def _replace_decision(database: Database, decision) -> None:
    database.connection.execute(
        "DELETE FROM data_access_grants WHERE owner_type = 'policy' AND owner_id = ?",
        (decision.plan_id,),
    )
    database.connection.execute(
        "DELETE FROM policy_decisions WHERE plan_id = ?", (decision.plan_id,)
    )
    database.connection.execute(
        "INSERT INTO policy_decisions"
        "(decision_id, decision_digest, mission_id, plan_id, authorization_digest, decision, "
        "expires_at, payload_json, issuer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'policy_engine_v1')",
        (
            decision.decision_id,
            decision.decision_digest,
            decision.mission_id,
            decision.plan_id,
            decision.authorization_digest,
            decision.decision,
            decision.expires_at.isoformat(),
            model_json(decision),
        ),
    )


def _redigest_decision(original, **updates):
    changed = original.model_copy(update={**updates, "decision_digest": "pending"})
    changed = changed.model_copy(
        update={
            "decision_id": stable_id(
                "decision",
                {
                    "authorization_digest": changed.authorization_digest,
                    "decision": changed.decision,
                    "issued_at": changed.issued_at,
                    "expires_at": changed.expires_at,
                },
            )
        }
    )
    return changed.model_copy(
        update={"decision_digest": digest_model(changed, exclude={"decision_digest"})}
    )


def test_require_approval_cannot_be_rewritten_to_allow() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(approval_rule="always"))
        forged = _redigest_decision(
            kernel.decision, decision="ALLOW", reason_codes=("POLICY_ALLOW",)
        )
        _replace_decision(database, forged)
        kwargs = persisted_gate_kwargs(kernel)
        kwargs["policy_decision_id"] = forged.decision_id
        assert authorize_execution(**kwargs).status == "INVALID"


def test_decision_target_omission_is_rejected() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        partial = kernel.decision.model_copy(update={"normalized_targets": ()})
        auth = authorization_digest_from_decision(
            plan=kernel.environment.plan, tool=kernel.environment.tool, decision=partial
        )
        forged = _redigest_decision(partial, authorization_digest=auth)
        _replace_decision(database, forged)
        kwargs = persisted_gate_kwargs(kernel)
        kwargs["policy_decision_id"] = forged.decision_id
        assert authorize_execution(**kwargs).status == "INVALID"


def test_out_of_scope_target_cannot_be_deleted_to_create_allow() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment(target="10.0.0.200"))
        partial = kernel.decision.model_copy(
            update={
                "normalized_targets": (),
                "decision": "ALLOW",
                "reason_codes": ("POLICY_ALLOW",),
            }
        )
        auth = authorization_digest_from_decision(
            plan=kernel.environment.plan, tool=kernel.environment.tool, decision=partial
        )
        forged = _redigest_decision(partial, authorization_digest=auth)
        _replace_decision(database, forged)
        kwargs = persisted_gate_kwargs(kernel)
        kwargs["policy_decision_id"] = forged.decision_id
        assert authorize_execution(**kwargs).status == "INVALID"


def test_policy_repository_rejects_caller_issuance_and_invalid_digest() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        assert not hasattr(kernel.decisions, "add")
        invalid = kernel.decision.model_copy(update={"decision_digest": "sha256:invalid"})
        with pytest.raises(DigestIntegrityError):
            kernel.decisions._store_issued(invalid, issuer_token=_POLICY_ENGINE_ISSUER_TOKEN)
        with pytest.raises(PolicyDecisionProvenanceError):
            kernel.decisions._store_issued(kernel.decision, issuer_token=object())


def test_security_repositories_reject_invalid_digest_on_first_insert_and_read() -> None:
    environment = build_environment()
    with Database() as database:
        persist_environment(database, environment)
        repository = AvailableToolSnapshotRepository(database)
        invalid = environment.snapshot.model_copy(
            update={"snapshot_id": "new-id", "snapshot_digest": "bad"}
        )
        with pytest.raises(DigestIntegrityError):
            repository.add(invalid)
        database.connection.execute(
            "UPDATE available_tool_snapshots SET payload_json = ? WHERE snapshot_id = ?",
            (model_json(invalid), environment.snapshot.snapshot_id),
        )
        with pytest.raises(DigestIntegrityError):
            repository.get(environment.snapshot.snapshot_id)


def test_available_snapshot_read_revalidates_parent_capability_bindings() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        database.connection.execute("DELETE FROM sandbox_capability_snapshots")
        with pytest.raises(DigestIntegrityError):
            AvailableToolSnapshotRepository(database).get(kernel.environment.snapshot.snapshot_id)


def test_execution_plan_read_revalidates_persisted_proposal_binding() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        changed = kernel.environment.proposal.model_copy(update={"objective": "tampered"})
        database.connection.execute(
            "UPDATE execution_plan_proposals SET payload_json = ? WHERE proposal_digest = ?",
            (model_json(changed), kernel.environment.plan.proposal_digest),
        )
        with pytest.raises(DigestIntegrityError):
            PlanRepository(database).get(kernel.environment.plan.plan_id)


def test_plan_capability_and_profile_bad_digests_never_enter_source_of_truth() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        invalid_plan = kernel.environment.plan.model_copy(update={"plan_id": "forged-plan-id"})
        with pytest.raises(DigestIntegrityError):
            PlanRepository(database).add(invalid_plan)

        repositories_and_models = (
            (
                SessionSecurityContextSnapshotRepository(database),
                kernel.environment.session_snapshot,
            ),
            (AdapterCapabilitySnapshotRepository(database), kernel.environment.adapter_snapshot),
            (SandboxCapabilitySnapshotRepository(database), kernel.environment.sandbox_snapshot),
            (RemoteMCPTrustSnapshotRepository(database), kernel.environment.remote_snapshot),
        )
        for repository, snapshot in repositories_and_models:
            invalid = snapshot.model_copy(
                update={"snapshot_id": f"forged-{snapshot.snapshot_id}", "snapshot_digest": "bad"}
            )
            with pytest.raises(DigestIntegrityError):
                repository.add(invalid)

        profile = mock_profile().model_copy(
            update={"profile_revision": "forged-profile", "profile_digest": "bad"}
        )
        with pytest.raises(DigestIntegrityError):
            LLMProfileRepository(database).add(profile)


def _llm_capability_result(*, profile_revision: str, profile_digest: str):
    identity = {
        "profile_revision": profile_revision,
        "profile_digest": profile_digest,
        "status": "NOT_REQUIRED",
        "checked_at": FIXED_TIME,
    }
    provisional = LLMCapabilityResult(
        capability_result_id=stable_id("llmcap", identity),
        profile_revision=profile_revision,
        profile_digest=profile_digest,
        status="NOT_REQUIRED",
        result_digest="pending",
        checked_at=FIXED_TIME,
    )
    return provisional.model_copy(
        update={"result_digest": digest_model(provisional, exclude={"result_digest"})}
    )


def test_llm_capability_result_enforces_profile_binding_on_store_and_read() -> None:
    with Database() as database:
        repository = LLMProfileRepository(database)
        profile = mock_profile()
        repository.add(profile)

        wrong_binding = _llm_capability_result(
            profile_revision=profile.profile_revision,
            profile_digest="sha256:wrong-profile",
        )
        with pytest.raises(DigestIntegrityError):
            repository.add_capability_result(wrong_binding)

        valid = _llm_capability_result(
            profile_revision=profile.profile_revision,
            profile_digest=profile.profile_digest,
        )
        repository.add_capability_result(valid)
        corrupted = valid.model_copy(update={"profile_digest": "sha256:corrupted"})
        database.connection.execute(
            "UPDATE llm_capability_results SET payload_json = ? WHERE capability_result_id = ?",
            (model_json(corrupted), valid.capability_result_id),
        )
        with pytest.raises(DigestIntegrityError):
            repository.latest_capability_result(profile.profile_revision)


def test_mission_revision_repository_requires_composite_key() -> None:
    parameters = tuple(inspect.signature(MissionRevisionRepository.get).parameters)
    assert parameters == ("self", "mission_id", "mission_revision")


def test_old_runtime_binding_is_stale_after_new_mission_revision() -> None:
    with Database() as database:
        kernel = persist_environment(database, build_environment())
        revision = kernel.environment.mission.revision_record().model_copy(
            update={"mission_revision": 2, "description": "new authorization revision"}
        )
        MissionRevisionRepository(database).add(revision)
        assert authorize_execution(**persisted_gate_kwargs(kernel)).status == "STALE"


def test_existing_v1_database_is_upgraded_to_v2(tmp_path) -> None:
    path = tmp_path / "phase0a-v1.sqlite"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    for statement in MIGRATIONS[0][1]:
        connection.execute(statement)
    connection.execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (1, '2026-01-01T00:00:00Z')"
    )
    connection.commit()
    connection.close()
    with Database(path) as upgraded:
        versions = {
            row[0] for row in upgraded.connection.execute("SELECT version FROM schema_migrations")
        }
        assert versions == {1, 2}
        assert upgraded.connection.execute(
            "SELECT name FROM sqlite_master WHERE name='authorization_runtime_bindings'"
        ).fetchone()
