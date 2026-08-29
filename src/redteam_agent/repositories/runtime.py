"""Repositories for explicitly selected current authorization state."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical import digest_model, verify_model_digest
from redteam_agent.errors import CurrentAuthorizationStateError
from redteam_agent.models.runtime import AuthorizationRuntimeBinding, PolicyState

from .base import ImmutableJsonRepository, model_json


def policy_state_digest(state: PolicyState) -> str:
    return digest_model(state, exclude={"policy_digest"})


def runtime_binding_digest(binding: AuthorizationRuntimeBinding) -> str:
    return digest_model(binding, exclude={"binding_digest"})


def build_policy_state(
    *,
    mission_id: str,
    state_version: int,
    policy_version: str,
    updated_at: datetime,
) -> PolicyState:
    provisional = PolicyState(
        mission_id=mission_id,
        state_version=state_version,
        policy_version=policy_version,
        policy_digest="pending",
        updated_at=updated_at,
    )
    return provisional.model_copy(update={"policy_digest": policy_state_digest(provisional)})


def build_runtime_binding(
    *,
    mission_id: str,
    binding_version: int,
    mission_revision: int,
    authorization_epoch: int,
    policy_version: str,
    registry_revision: int,
    registry_digest: str,
    available_tool_snapshot_id: str,
    session_security_context_snapshot_id: str,
    adapter_capability_snapshot_id: str,
    sandbox_capability_snapshot_id: str,
    remote_mcp_trust_snapshot_id: str,
    updated_at: datetime,
) -> AuthorizationRuntimeBinding:
    provisional = AuthorizationRuntimeBinding(
        mission_id=mission_id,
        binding_version=binding_version,
        binding_digest="pending",
        mission_revision=mission_revision,
        authorization_epoch=authorization_epoch,
        policy_version=policy_version,
        registry_revision=registry_revision,
        registry_digest=registry_digest,
        available_tool_snapshot_id=available_tool_snapshot_id,
        session_security_context_snapshot_id=session_security_context_snapshot_id,
        adapter_capability_snapshot_id=adapter_capability_snapshot_id,
        sandbox_capability_snapshot_id=sandbox_capability_snapshot_id,
        remote_mcp_trust_snapshot_id=remote_mcp_trust_snapshot_id,
        updated_at=updated_at,
    )
    return provisional.model_copy(update={"binding_digest": runtime_binding_digest(provisional)})


class PolicyStateRepository(ImmutableJsonRepository[PolicyState]):
    table = "policy_states"
    id_column = "mission_id"
    model_type = PolicyState

    def set_current(self, state: PolicyState) -> PolicyState:
        verify_model_digest(state, state.policy_digest, exclude={"policy_digest"})
        row = self.database.connection.execute(
            "SELECT payload_json FROM policy_states WHERE mission_id = ?", (state.mission_id,)
        ).fetchone()
        if row is not None:
            current = self.get(state.mission_id)
            assert current is not None
            if state.state_version != current.state_version + 1:
                raise CurrentAuthorizationStateError("policy state version must increment by one")
            self.database.connection.execute(
                "UPDATE policy_states SET state_version = ?, policy_version = ?, "
                "policy_digest = ?, payload_json = ? WHERE mission_id = ?",
                (
                    state.state_version,
                    state.policy_version,
                    state.policy_digest,
                    model_json(state),
                    state.mission_id,
                ),
            )
        else:
            if state.state_version != 0:
                raise CurrentAuthorizationStateError("initial policy state version must be zero")
            self.database.connection.execute(
                "INSERT INTO policy_states"
                "(mission_id, state_version, policy_version, policy_digest, payload_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    state.mission_id,
                    state.state_version,
                    state.policy_version,
                    state.policy_digest,
                    model_json(state),
                ),
            )
        return state

    def verify_integrity(self, model: PolicyState) -> None:
        verify_model_digest(model, model.policy_digest, exclude={"policy_digest"})

    def verify_row_binding(self, identifier: str | int, model: PolicyState) -> None:
        row = self.database.connection.execute(
            "SELECT state_version, policy_version, policy_digest FROM policy_states "
            "WHERE mission_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            row["state_version"] == model.state_version
            and row["policy_version"] == model.policy_version
            and row["policy_digest"] == model.policy_digest
        ):
            raise CurrentAuthorizationStateError("policy state row binding mismatch")


class AuthorizationRuntimeBindingRepository(ImmutableJsonRepository[AuthorizationRuntimeBinding]):
    table = "authorization_runtime_bindings"
    id_column = "mission_id"
    model_type = AuthorizationRuntimeBinding

    def set_current(self, binding: AuthorizationRuntimeBinding) -> AuthorizationRuntimeBinding:
        verify_model_digest(binding, binding.binding_digest, exclude={"binding_digest"})
        row = self.database.connection.execute(
            "SELECT payload_json FROM authorization_runtime_bindings WHERE mission_id = ?",
            (binding.mission_id,),
        ).fetchone()
        if row is not None:
            current = self.get(binding.mission_id)
            assert current is not None
            if binding.binding_version != current.binding_version + 1:
                raise CurrentAuthorizationStateError(
                    "runtime binding version must increment by one"
                )
            self.database.connection.execute(
                "UPDATE authorization_runtime_bindings SET binding_version = ?, "
                "binding_digest = ?, payload_json = ? WHERE mission_id = ?",
                (
                    binding.binding_version,
                    binding.binding_digest,
                    model_json(binding),
                    binding.mission_id,
                ),
            )
        else:
            if binding.binding_version != 0:
                raise CurrentAuthorizationStateError("initial runtime binding version must be zero")
            self.database.connection.execute(
                "INSERT INTO authorization_runtime_bindings"
                "(mission_id, binding_version, binding_digest, payload_json) VALUES (?, ?, ?, ?)",
                (
                    binding.mission_id,
                    binding.binding_version,
                    binding.binding_digest,
                    model_json(binding),
                ),
            )
        return binding

    def verify_integrity(self, model: AuthorizationRuntimeBinding) -> None:
        verify_model_digest(model, model.binding_digest, exclude={"binding_digest"})

    def verify_row_binding(self, identifier: str | int, model: AuthorizationRuntimeBinding) -> None:
        row = self.database.connection.execute(
            "SELECT binding_version, binding_digest FROM authorization_runtime_bindings "
            "WHERE mission_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or not (
            row["binding_version"] == model.binding_version
            and row["binding_digest"] == model.binding_digest
        ):
            raise CurrentAuthorizationStateError("runtime binding row mismatch")
