"""Regressions for the 25 independent-review probes (P01-P25).

Each probe exercised a scenario the independent review used to demonstrate a
bypass in the review candidate. These tests assert the *fixed*, fail-closed
behaviour, and - where the probe conflated a legitimate request with an attack -
add a positive counterpart proving the legitimate path still succeeds. The
probes are reproduced against the current public API (authenticated lifecycle
actors, grant-id based verification), not the pre-fix signatures.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

import support
from redteam_agent.composition.testing import build_test_kernel
from redteam_agent.context.models import ContextResourceIndexRecord
from redteam_agent.errors import (
    AuthorizationKernelError,
    DataAccessResourceError,
    MissionValidationError,
    PolicyEvaluationIndeterminateError,
    SessionContextGrantStaleError,
    ToolRegistryValidationError,
)
from redteam_agent.mission.models import FindingConfirmedCondition, SessionEstablishedCondition
from redteam_agent.plan.models import ExecutionPlan
from redteam_agent.policy.data_access import DataAccessPolicy, DataAccessRule
from redteam_agent.policy.scope_models import HostScopeRule, SessionScopeRule
from redteam_agent.runtime.clock import ManualClock

T0 = support.T0
MISSION_ID = support.MISSION_ID


def _kernel():
    return build_test_kernel(clock=ManualClock(T0))


def _redigest(kernel, revision, **changes):
    r = revision.model_copy(update=changes)
    fields = r.model_dump(mode="python")
    fields.pop("mission_revision_digest")
    digest = kernel.digest_service.compute("mission_revision_digest", fields)
    return r.model_copy(update={"mission_revision_digest": digest})


def _setup(*, tool=None, revision_transform=None, sessions=()):
    kernel = _kernel()
    revision = support.mission_revision(kernel.digest_service, profile=support.make_profile(kernel.digest_service))
    if revision_transform is not None:
        revision = revision_transform(kernel, revision)
    seeded = support.seed_running_mission(
        kernel, tool=tool or support.network_tool(), revision=revision, session_ids=sessions
    )
    return kernel, seeded


def _plan(kernel, seeded, args=None, **kwargs):
    proposal = support.make_proposal(
        tool=seeded.tool,
        arguments=args or {"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"},
        **kwargs,
    )
    return support.make_plan(kernel, seeded=seeded, proposal=proposal)


def _gate(kernel, plan, decision_id="decision-1"):
    decision = support.issue_decision(kernel, plan=plan, decision_id=decision_id)
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    return decision, result


def _assert_not_authorized(kernel, plan, decision_id="decision-1") -> None:
    """Fail closed either way: issuance raises, or a DENY decision is not executable."""
    try:
        decision = support.issue_decision(kernel, plan=plan, decision_id=decision_id)
    except AuthorizationKernelError:
        return
    assert decision.decision == "DENY"
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert not result.authorized


# --- P01: registered parameter schema is enforced ------------------------


def test_p01_registered_schema_is_enforced() -> None:
    restrictive = support.network_tool().model_copy(
        update={
            "parameter_schema": {
                "type": "object",
                "properties": {
                    "destinations": {"type": "array", "items": {"type": "string"}},
                    "port": {"type": "integer", "const": 8443},
                    "protocol": {"type": "string", "const": "tcp"},
                },
                "required": ["destinations", "port", "protocol"],
                "additionalProperties": False,
            }
        }
    )
    kernel, seeded = _setup(tool=restrictive)
    # Arguments that satisfy the extractor but violate the registered schema
    # (port 443 vs const 8443) must be rejected, not silently accepted.
    _assert_not_authorized(
        kernel, _plan(kernel, seeded, {"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp"})
    )


def test_p01_positive_schema_matching_arguments_allowed() -> None:
    kernel, seeded = _setup()
    _decision, result = _gate(kernel, _plan(kernel, seeded))
    assert result.authorized


# --- P02: data-access grant required for a resource tool -----------------


def test_p02_artifact_without_data_grant_denied() -> None:
    schema = {
        "type": "object",
        "properties": {"artifact_ids": {"type": "array", "items": {"type": "string"}}},
        "required": ["artifact_ids"],
        "additionalProperties": False,
    }
    tool = support.network_tool().model_copy(
        update={
            "target_mode": "none",
            "target_extractor_id": "artifact_target_v1",
            "required_target_binding_modes": frozenset({"none"}),
            "required_data_access_types": frozenset({"artifact"}),
            "parameter_schema": schema,
        }
    )
    kernel, seeded = _setup(tool=tool)
    decision, result = _gate(kernel, _plan(kernel, seeded, {"artifact_ids": ["not-authorized-artifact"]}))
    assert decision.decision == "DENY"
    assert not result.authorized


def test_p02_positive_artifact_is_bound_to_data_grant() -> None:
    from redteam_agent.resources.resource_metadata import ResourceMetadata

    schema = {
        "type": "object",
        "properties": {"artifact_ids": {"type": "array", "items": {"type": "string"}}},
        "required": ["artifact_ids"],
        "additionalProperties": False,
    }
    tool = support.network_tool().model_copy(
        update={
            "target_mode": "none",
            "target_extractor_id": "artifact_target_v1",
            "required_target_binding_modes": frozenset({"none"}),
            "required_data_access_types": frozenset({"artifact"}),
            "parameter_schema": schema,
        }
    )
    policy = DataAccessPolicy(
        allowed=(
            DataAccessRule(
                resource_type="artifact",
                resource_pattern="exact:a1",
                operations=frozenset({"read"}),
            ),
        ),
        prohibited=(),
    )
    kernel, seeded = _setup(
        tool=tool,
        revision_transform=lambda k, r: _redigest(k, r, data_access_policy=policy),
    )
    kernel.resource_metadata_store.put(
        ResourceMetadata(
            resource_id="a1",
            resource_type="artifact",
            version="1",
            metadata_digest="artifact-1",
            classification="redacted",
        )
    )
    decision, result = _gate(kernel, _plan(kernel, seeded, {"artifact_ids": ["a1"]}))
    assert decision.decision == "ALLOW"
    assert result.authorized
    assert [grant.resource.resource_id for grant in decision.authorized_data_access] == ["a1"]


# --- P03: target_mode none with no extractor still resolves no targets ---


def test_p03_target_none_without_extractor_rejects_smuggled_destination() -> None:
    # Preserve the original network schema and remove only the extractor.  The
    # registry must reject this inconsistent authority declaration.
    tool = support.network_tool().model_copy(
        update={
            "target_mode": "none",
            "target_extractor_id": None,
            "required_target_binding_modes": frozenset({"none"}),
        }
    )
    with pytest.raises(ToolRegistryValidationError):
        _setup(tool=tool)


# --- P04: snapshot cannot cross missions ---------------------------------


def test_p04_cross_mission_snapshot_rejected() -> None:
    kernel, seeded = _setup()
    rev2 = _redigest(kernel, seeded.revision, mission_id="mission-2")
    support.provision_lifecycle_roles(kernel, mission_id="mission-2")
    kernel.mission_manager.create_mission(rev2, actor_token=support.ADMIN_ACTOR_TOKEN)
    kernel.mission_manager.validate_mission("mission-2", 0, actor_token=support.OPERATOR_ACTOR_TOKEN)
    kernel.mission_manager.start_mission("mission-2", 1, actor_token=support.OPERATOR_ACTOR_TOKEN)
    plan = _plan(kernel, seeded).model_copy(update={"mission_id": "mission-2"})
    with pytest.raises(AuthorizationKernelError):
        support.issue_decision(kernel, plan=plan)


# --- P05: empty execution-precondition digest rejected -------------------


def test_p05_empty_precondition_digest_denied() -> None:
    kernel, seeded = _setup()
    plan = _plan(kernel, seeded).model_copy(update={"execution_precondition_digest": ""})
    plan = ExecutionPlan.from_untrusted_json(plan.model_dump_json())
    with pytest.raises(PolicyEvaluationIndeterminateError):
        support.issue_decision(kernel, plan=plan)


# --- P06: forged context grant model is not trusted ----------------------


def test_p06_forged_context_grant_not_trusted() -> None:
    kernel, _seeded = _setup()
    kernel.context_authorization_service.issue_grant(
        grant_id="g", mission_id=MISSION_ID, service_identity="planner_context",
        candidate_resource_ids=(), session_ids=(), ttl_seconds=300,
    )
    # A caller cannot verify a grant id that was never persisted.
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.verify_grant(grant_id="not-stored", mission_id=MISSION_ID)


# --- P07: context grant refused while mission paused + TTL honored -------


def test_p07_context_issue_denied_when_paused() -> None:
    kernel, _seeded = _setup()
    kernel.mission_manager.pause_mission(MISSION_ID, 2, actor_token=support.OPERATOR_ACTOR_TOKEN)
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.issue_grant(
            grant_id="paused", mission_id=MISSION_ID, service_identity="planner_context",
            candidate_resource_ids=(), session_ids=(), ttl_seconds=1,
        )


def test_p07_positive_context_ttl_is_honored_not_extended() -> None:
    kernel, _seeded = _setup()
    grant = kernel.context_authorization_service.issue_grant(
        grant_id="ttl", mission_id=MISSION_ID, service_identity="planner_context",
        candidate_resource_ids=(), session_ids=(), ttl_seconds=1,
    )
    assert (grant.expires_at - grant.issued_at).total_seconds() == 1


# --- P08: out-of-scope / expired session rejected ------------------------


def test_p08_expired_session_rejected() -> None:
    kernel, _seeded = _setup()
    kernel.session_repository.save(
        support.session_snapshot(session_id="out-of-scope", fresh_delta_hours=-1, security_status="lost")
    )
    with pytest.raises(SessionContextGrantStaleError):
        kernel.context_authorization_service.issue_grant(
            grant_id="stale-session", mission_id=MISSION_ID, service_identity="planner_context",
            candidate_resource_ids=(), session_ids=("out-of-scope",), ttl_seconds=300,
        )


# --- P09: index alias to a prohibited origin rejected --------------------


def test_p09_context_origin_alias_rejected() -> None:
    policy = DataAccessPolicy(
        allowed=(DataAccessRule(resource_type="artifact", resource_pattern="exact:allowed-index-id", operations=frozenset({"read"})),),
        prohibited=(),
    )
    kernel, _seeded = _setup(revision_transform=lambda k, r: _redigest(k, r, data_access_policy=policy))
    # The index aliases an allowed-looking id to a prohibited origin record; the
    # origin is what is registered in the source of truth. Policy is keyed off
    # the origin, so the alias cannot borrow the allowed id's permission (R08).
    kernel.index_repository.save(
        ContextResourceIndexRecord(
            resource_id="allowed-index-id", resource_type="artifact", mission_id=MISSION_ID,
            target_references=(), verification_state="unverified", observed_at=T0, classification="secret",
            summary_metadata={}, origin_record_id="prohibited-origin", origin_record_version="999",
            origin_record_digest="unverified-origin-hash",
        )
    )
    from redteam_agent.resources.resource_metadata import ResourceMetadata

    kernel.resource_metadata_store.put(
        ResourceMetadata(
            resource_id="prohibited-origin", resource_type="artifact", version="999",
            metadata_digest="unverified-origin-hash", classification="secret",
        )
    )
    with pytest.raises(DataAccessResourceError):
        kernel.context_authorization_service.issue_grant(
            grant_id="alias", mission_id=MISSION_ID, service_identity="planner_context",
            candidate_resource_ids=("allowed-index-id",), session_ids=(), ttl_seconds=300,
        )


# --- P10: unsupported / uninterpretable goal condition rejected ----------


def test_p10_unsupported_goal_condition_rejected() -> None:
    conditions = (
        FindingConfirmedCondition(
            condition_id="c", description="forbidden outcome condition", fact_type="execution_outcome",
            canonical_entity_ref="nonexistent-entity",
        ),
        SessionEstablishedCondition(
            condition_id="s", description="no host selector", selector_type="active_session", selector_value="any"
        ),
    )
    kernel = _kernel()
    profile = support.make_profile(kernel.digest_service)
    kernel.profile_repository.save(profile)
    revision = _redigest(
        kernel, support.mission_revision(kernel.digest_service, profile=profile), success_conditions=conditions
    )
    support.provision_lifecycle_roles(kernel)
    kernel.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    with pytest.raises(MissionValidationError):
        kernel.mission_manager.validate_mission(MISSION_ID, 0, actor_token=support.OPERATOR_ACTOR_TOKEN)


# --- P11: approval TTL bounded by mission approval_ttl_seconds ------------


def test_p11_approval_ttl_bounded_and_expires() -> None:
    tool = support.network_tool(approval_rule="always")
    kernel, seeded = _setup(
        tool=tool,
        revision_transform=lambda k, r: _redigest(
            k, r, approval_policy=r.approval_policy.model_copy(update={"approval_ttl_seconds": 1})
        ),
    )
    plan = _plan(kernel, seeded)
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "REQUIRE_APPROVAL"
    request = kernel.approval_service.issue_request(
        approval_request_id="r", decision_id=decision.decision_id, plan=plan
    )
    # Request TTL is derived from trusted bounds; the 1s mission TTL is the tightest bound.
    assert (request.expires_at - request.issued_at).total_seconds() == 1
    support.register_approver(kernel)
    record = kernel.approval_service.submit_decision(
        approval_id="a", approval_request_id="r", actor_token="tok-approver", verdict="APPROVED"
    )
    assert (record.expires_at - record.issued_at).total_seconds() <= 1
    # Two seconds later the approval is expired and the gate denies.
    kernel.clock.set(T0 + timedelta(seconds=2))
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert not result.authorized


# --- P12: raw-SQL state corruption is caught by row integrity ------------


def test_p12_state_row_corruption_detected() -> None:
    import json

    kernel, seeded = _setup()
    plan = _plan(kernel, seeded)
    decision = support.issue_decision(kernel, plan=plan)
    kernel.mission_manager.pause_mission(MISSION_ID, 2, actor_token=support.OPERATOR_ACTOR_TOKEN)
    conn = kernel.database.connection
    raw = conn.execute(
        "SELECT json FROM kv_store WHERE namespace='mission_states' AND key=?", (MISSION_ID,)
    ).fetchone()[0]
    state = json.loads(raw)
    state["state"] = "RUNNING"
    state["mission_state_version"] = 2
    state["authorization_epoch"] = 0
    conn.execute(
        "UPDATE kv_store SET json=? WHERE namespace='mission_states' AND key=?", (json.dumps(state), MISSION_ID)
    )
    # The row-integrity digest is over the stored bytes, so a raw edit fails
    # closed on read rather than resurrecting a RUNNING state.
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert not result.authorized
    assert result.reason_code == "INTEGRITY_ERROR"


# --- P13: prohibited host scope denies a session-bound action ------------


def test_p13_prohibited_execution_host_denied() -> None:
    kernel, seeded = _setup(
        tool=support.network_tool(requires_session=True),
        sessions=("sess-1",),
        revision_transform=lambda k, r: _redigest(
            k, r,
            allowed_execution_scope=(*support.default_scope(), SessionScopeRule(type="session", session_id="sess-1")),
            prohibited_execution_scope=(HostScopeRule(type="host", host_id="host-1"),),
        ),
    )
    decision, result = _gate(kernel, _plan(kernel, seeded, session_id="sess-1"))
    assert decision.decision == "DENY"
    assert not result.authorized


# --- P14: stale snapshot cannot yield a decision at issue ----------------


def test_p14_stale_snapshot_rejected_at_issue() -> None:
    kernel, seeded = _setup()
    kernel.clock.set(T0 + timedelta(minutes=16))  # snapshot TTL is 15 minutes
    with pytest.raises(AuthorizationKernelError):
        support.issue_decision(kernel, plan=_plan(kernel, seeded))


# --- P15: publishing with an expired session yields non-positive TTL -----


def test_p15_expired_session_excluded_from_publication() -> None:
    tool = support.network_tool(requires_session=True)
    kernel, seeded = _setup(tool=tool, sessions=("sess-1",))
    kernel.clock.set(T0 + timedelta(hours=7))  # past session freshness bound
    snap = kernel.tool_availability_service.publish(snapshot_id="expired-publication", mission_id=MISSION_ID)
    # The session-required tool has no fresh session, so it is excluded rather
    # than published bound to an expired session (R15).
    assert seeded.tool.tool_ref.tool_id not in {v.tool_ref.tool_id for v in snap.tools}
    assert snap.created_at < snap.expires_at  # never a non-positive lifetime


# --- P16: secret reference argument shape is enforced --------------------


def test_p16_malformed_secret_reference_rejected() -> None:
    from support import confirmed_secret_metadata, secret_data_access_policy

    kernel = _kernel()
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service),
        data_access_policy=secret_data_access_policy(),
    )
    seeded = support.seed_running_mission(
        kernel, tool=support.network_tool(secret_paths=("/credential",)), revision=revision
    )
    kernel.secret_metadata_store.put(confirmed_secret_metadata(kernel.digest_service))
    # A credential object with an unknown field / wrong-typed version violates
    # the closed schema and must be rejected.
    _assert_not_authorized(
        kernel,
        _plan(
            kernel, seeded,
            {
                "destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp",
                "credential": {"secret_version_id": "sv-1", "secret_version": 999, "unknown_field": "x"},
            },
        ),
    )


# --- P17: a constructed plan with an invalid field type is rejected ------


def test_p17_constructed_plan_invalid_type_rejected() -> None:
    kernel, seeded = _setup()
    plan = _plan(kernel, seeded).model_copy(update={"mission_revision": True})
    _assert_not_authorized(kernel, plan)


# --- P18: sandbox execution location must match the adapter --------------


def test_p18_sandbox_location_mismatch_excludes_tool() -> None:
    from redteam_agent.sandbox.models import SandboxRequirement, build_sandbox_capabilities

    req = SandboxRequirement(**dict.fromkeys(SandboxRequirement.model_fields, True))
    kernel, seeded = _setup(tool=support.network_tool().model_copy(update={"sandbox_requirement": req}))
    kernel.sandbox_repository.save(
        build_sandbox_capabilities(
            sandbox_id="wrong-location", adapter_id=seeded.tool.adapter_id,
            execution_location="untrusted_remote", digest_service=kernel.digest_service, all_enabled=True,
        )
    )
    snap = kernel.tool_availability_service.publish(snapshot_id="untrusted-location", mission_id=MISSION_ID)
    # An untrusted-remote sandbox cannot borrow local capabilities: the tool is
    # excluded from the availability snapshot entirely (H-04).
    assert seeded.tool.tool_ref.tool_id not in {v.tool_ref.tool_id for v in snap.tools}


# --- P19: raw registry save is fully re-validated ------------------------


def test_p19_registry_loader_revalidates() -> None:
    from redteam_agent.models.common import ActionContractReference
    from redteam_agent.tools.registry import ToolRegistryRevision

    kernel = _kernel()
    tool = support.network_tool().model_copy(
        update={
            "default_timeout_seconds": 9999,
            "action_contract_ref": ActionContractReference(contract_id="not-registered", revision="1", digest="unverified"),
        }
    )
    fields = {"registry_revision": 1, "tools": [tool.model_dump(mode="python")]}
    reg = ToolRegistryRevision(
        registry_revision=1, tools=(tool,), registry_digest=kernel.digest_service.compute("registry_digest", fields)
    )
    # A self-consistent but invalid registry (timeout floor violated, contract
    # not registered) cannot be persisted via the raw repository path (R13).
    with pytest.raises(ToolRegistryValidationError):
        kernel.registry_repository.save(reg)


# --- P20: unregistered rule ids are rejected -----------------------------


def test_p20_unregistered_rule_ids_rejected() -> None:
    from redteam_agent.canonical.digest_service import DigestService
    from redteam_agent.contracts.catalog import RuleCatalog
    from redteam_agent.tools.registry import build_tool_registry

    ds = DigestService()
    tool = support.rebind_contract(
        support.network_tool().model_copy(
            update={"evidence_rule_ids": ("absent-rule",), "output_publication_rule_id": "absent-publication"}
        )
    )
    # A rule catalog that does not register the tool's referenced rule ids must
    # reject the registry (rules are Root-provisioned, not tool-declared) (R20).
    with pytest.raises(ToolRegistryValidationError):
        build_tool_registry(
            registry_revision=1, tools=(tool,), digest_service=ds,
            contract_catalog=support.contract_catalog_for((tool,)), rule_catalog=RuleCatalog(),
        )


# --- P21: a self-attesting local LLM profile cannot start a mission ------


def test_p21_local_profile_self_attestation_rejected() -> None:
    from redteam_agent.llm.profile import build_agent_profile

    kernel = _kernel()
    profile = build_agent_profile(
        profile_revision="local-not-verified", profile_kind="local_llm", capability_check_passed=True,
        digest_service=kernel.digest_service,
    )
    kernel.profile_repository.save(profile)
    revision = support.mission_revision(kernel.digest_service, profile=profile)
    support.provision_lifecycle_roles(kernel)
    kernel.mission_manager.create_mission(revision, actor_token=support.ADMIN_ACTOR_TOKEN)
    with pytest.raises(MissionValidationError):
        kernel.mission_manager.validate_mission(MISSION_ID, 0, actor_token=support.OPERATOR_ACTOR_TOKEN)


# --- P22: mission lifecycle requires an authenticated actor --------------


def test_p22_mission_requires_authenticated_actor() -> None:
    from redteam_agent.errors import MissionAuthorizationError

    kernel = _kernel()
    profile = support.make_profile(kernel.digest_service)
    kernel.profile_repository.save(profile)
    revision = support.mission_revision(kernel.digest_service, profile=profile)
    # No role assignments provisioned: an unknown/unauthorized actor token
    # cannot create a mission, and the audit actor is never a bare caller string.
    with pytest.raises(MissionAuthorizationError):
        kernel.mission_manager.create_mission(revision, actor_token="token:unknown")


def test_p22_positive_authenticated_actor_recorded_in_audit() -> None:
    kernel, _seeded = _setup()
    actors = [e.actor for e in kernel.event_repository.events_for(MISSION_ID)]
    assert actors  # events exist
    assert all(a.startswith("principal:") for a in actors)


# --- P23: non-ASCII pointer digit is not an array index alias ------------


def test_p23_unicode_pointer_not_array_index() -> None:
    from redteam_agent.tools.secret_argument_path import validate_secret_argument_paths

    args = {"items": [{}, support.secret_reference()]}
    # '/items/1' is a valid array index; an ARABIC-INDIC DIGIT ONE (U+0661) is
    # not and must not alias to index 1 (R21).
    arabic_indic_one = "١"  # noqa: RUF001 - literal ARABIC-INDIC DIGIT ONE under test
    with pytest.raises(AuthorizationKernelError):
        validate_secret_argument_paths((f"/items/{arabic_indic_one}",), args)


def test_p23_positive_ascii_array_index_accepted() -> None:
    from redteam_agent.tools.secret_argument_path import validate_secret_argument_paths

    args = {"items": [{}, support.secret_reference()]}
    validate_secret_argument_paths(("/items/1",), args)


# --- P24: a valid array-index secret pointer supports approval -----------


def test_p24_valid_array_pointer_approval_succeeds() -> None:
    from support import confirmed_secret_metadata, secret_data_access_policy, secret_reference

    kernel = _kernel()
    revision = support.mission_revision(
        kernel.digest_service, profile=support.make_profile(kernel.digest_service),
        data_access_policy=secret_data_access_policy(),
    )
    secret_ref_schema = {
        "type": "object",
        "properties": {
            "credential_type": {"type": "string"},
            "secret_version_id": {"type": "string"},
            "secret_version": {"type": "string"},
            "principal_ref": {"type": "string"},
        },
        "required": ["credential_type", "secret_version_id", "secret_version", "principal_ref"],
        "additionalProperties": False,
    }
    schema = {
        "type": "object",
        "properties": {
            "destinations": {"type": "array", "items": {"type": "string"}},
            "port": {"type": "integer"},
            "protocol": {"type": "string"},
            "credential": {
                "type": "object",
                "properties": {"entries": {"type": "array", "items": secret_ref_schema}},
                "required": ["entries"],
                "additionalProperties": False,
            },
        },
        "required": ["destinations"],
        "additionalProperties": False,
    }
    tool = support.network_tool(secret_paths=("/credential/entries/0",), approval_rule="always").model_copy(
        update={"parameter_schema": schema}
    )
    seeded = support.seed_running_mission(kernel, tool=tool, revision=revision)
    kernel.secret_metadata_store.put(confirmed_secret_metadata(kernel.digest_service))
    plan = _plan(
        kernel, seeded,
        {"destinations": ["10.1.2.3"], "port": 443, "protocol": "tcp", "credential": {"entries": [secret_reference()]}},
    )
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "REQUIRE_APPROVAL"
    request = kernel.approval_service.issue_request(
        approval_request_id="array", decision_id=decision.decision_id, plan=plan
    )
    assert request.approval_request_id == "array"


# --- P25: decision adapter-field tamper is caught ------------------------


def test_p25_decision_adapter_field_tamper_denied() -> None:
    kernel, seeded = _setup()
    plan = _plan(kernel, seeded)
    decision = support.issue_decision(kernel, plan=plan)
    altered = decision.model_copy(update={"resolved_adapter": "local", "resolved_adapter_id": "different-runtime"})
    fields = altered.model_dump(mode="python")
    fields.pop("decision_digest")
    altered = altered.model_copy(update={"decision_digest": kernel.digest_service.compute("decision_digest", fields)})
    kernel.database.connection.execute(
        "UPDATE kv_store SET json=? WHERE namespace='policy_decisions' AND key=?",
        (altered.model_dump_json(), decision.decision_id),
    )
    # Even with a recomputed decision digest, the row-integrity digest and the
    # gate's adapter re-check against the registered tool deny the tamper (R23).
    result = kernel.authorization_gate.authorize_execution(decision_id=decision.decision_id, plan=plan)
    assert not result.authorized


def test_p17_nested_tool_ref_bool_revision_rejected() -> None:
    from redteam_agent.plan.models import compute_proposal_digest

    kernel, seeded = _setup()
    plan = _plan(kernel, seeded)
    ref = plan.proposal.tool_ref.model_copy(update={"registry_revision": True})
    proposal = plan.proposal.model_copy(update={"tool_ref": ref})
    plan = plan.model_copy(
        update={"proposal": proposal, "proposal_digest": compute_proposal_digest(proposal, kernel.digest_service)}
    )
    decision = support.issue_decision(kernel, plan=plan)
    assert decision.decision == "DENY"
    assert not kernel.authorization_gate.authorize_execution(
        decision_id=decision.decision_id, plan=plan
    ).authorized
