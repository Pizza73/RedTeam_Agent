"""Separated mission root, immutable revision and lifecycle/OCC repositories."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical import digest_model, verify_model_digest
from redteam_agent.errors import (
    AuthorizationEpochMismatchError,
    MissionStateVersionConflictError,
)
from redteam_agent.models.mission import (
    Mission,
    MissionLifecycleState,
    MissionRevision,
    MissionRoot,
    MissionState,
)

from .base import ImmutableJsonRepository, model_json, parse_model_json


class MissionRepository(ImmutableJsonRepository[MissionRoot]):
    table = "missions"
    id_column = "mission_id"
    model_type = MissionRoot

    def add(self, root: MissionRoot) -> MissionRoot:
        payload = model_json(root)
        self._insert_or_same(
            "INSERT INTO missions(mission_id, payload_json, created_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            (root.mission_id, payload, root.created_at.isoformat(), root.created_by),
            payload,
        )
        return root


class MissionRevisionRepository(ImmutableJsonRepository[MissionRevision]):
    table = "mission_revisions"
    id_column = "mission_revision"
    model_type = MissionRevision

    def get(self, mission_id: str, mission_revision: int) -> MissionRevision | None:  # type: ignore[override]
        row = self.database.connection.execute(
            "SELECT payload_json FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (mission_id, mission_revision),
        ).fetchone()
        if row is None:
            return None
        revision = parse_model_json(MissionRevision, row["payload_json"])
        digest_row = self.database.connection.execute(
            "SELECT revision_digest FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (mission_id, mission_revision),
        ).fetchone()
        assert digest_row is not None
        verify_revision_integrity(revision, str(digest_row["revision_digest"]))
        return revision

    # Compatibility is intentionally explicit and still composite-keyed.
    get_for_mission = get

    def add(self, revision: MissionRevision) -> MissionRevision:
        payload = model_json(revision)
        revision_digest = digest_model(revision)
        existing_row = self.database.connection.execute(
            "SELECT payload_json, revision_digest FROM mission_revisions "
            "WHERE mission_id = ? AND mission_revision = ?",
            (revision.mission_id, revision.mission_revision),
        ).fetchone()
        if existing_row is not None:
            self.ensure_same_payload(existing_row["payload_json"], payload)
            return revision
        self.database.connection.execute(
            "INSERT INTO mission_revisions"
            "(mission_id, mission_revision, revision_digest, payload_json) VALUES (?, ?, ?, ?)",
            (revision.mission_id, revision.mission_revision, revision_digest, payload),
        )
        return revision

    def latest(self, mission_id: str) -> MissionRevision | None:
        row = self.database.connection.execute(
            "SELECT payload_json FROM mission_revisions WHERE mission_id = ? "
            "ORDER BY mission_revision DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
        if row is None:
            return None
        revision = parse_model_json(MissionRevision, row["payload_json"])
        return self.get(revision.mission_id, revision.mission_revision)


class MissionStateRepository(ImmutableJsonRepository[MissionState]):
    table = "mission_states"
    id_column = "mission_id"
    model_type = MissionState

    _allowed: dict[str, frozenset[str]] = {
        "DRAFT": frozenset({"VALIDATED", "ABORTED"}),
        "VALIDATED": frozenset({"RUNNING", "ABORTED"}),
        "RUNNING": frozenset({"PAUSED", "FINALIZING", "FAILED", "ABORTED"}),
        "PAUSED": frozenset({"RUNNING", "FINALIZING", "FAILED", "ABORTED"}),
        "FINALIZING": frozenset(
            {"COMPLETED", "WAITING_HUMAN_REVIEW", "FAILED", "ABORTED"}
        ),
        "WAITING_HUMAN_REVIEW": frozenset(
            {"COMPLETED_WITH_UNRESOLVED_EXECUTIONS", "FAILED", "ABORTED"}
        ),
        "COMPLETED": frozenset(),
        "COMPLETED_WITH_UNRESOLVED_EXECUTIONS": frozenset(),
        "FAILED": frozenset(),
        "ABORTED": frozenset(),
    }

    def get(self, identifier: str | int) -> MissionState | None:
        row = self.database.connection.execute(
            "SELECT mission_state_version, authorization_epoch, state, payload_json "
            "FROM mission_states WHERE mission_id = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return None
        state = parse_model_json(MissionState, row["payload_json"])
        if not (
            state.mission_id == identifier
            and state.mission_state_version == row["mission_state_version"]
            and state.authorization_epoch == row["authorization_epoch"]
            and state.state == row["state"]
        ):
            from redteam_agent.errors import DigestIntegrityError

            raise DigestIntegrityError("mission state payload/columns mismatch")
        return state

    def _initialize_draft(self, mission_id: str, *, updated_at: datetime) -> MissionState:
        state = MissionState(
            mission_id=mission_id,
            mission_state_version=0,
            authorization_epoch=0,
            state="DRAFT",
            updated_at=updated_at,
        )
        payload = model_json(state)
        self._insert_or_same(
            "INSERT INTO mission_states"
            "(mission_id, mission_state_version, authorization_epoch, state, payload_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                state.mission_id,
                state.mission_state_version,
                state.authorization_epoch,
                state.state,
                payload,
            ),
            payload,
        )
        return state

    def _transition(
        self,
        mission_id: str,
        *,
        expected_mission_state_version: int,
        expected_authorization_epoch: int,
        new_state: MissionLifecycleState,
        updated_at: datetime,
        invalidate_authorization: bool = False,
    ) -> MissionState:
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT payload_json FROM mission_states WHERE mission_id = ?", (mission_id,)
            ).fetchone()
            if row is None:
                raise MissionStateVersionConflictError("mission state does not exist")
            current = parse_model_json(MissionState, row["payload_json"])
            if current.mission_state_version != expected_mission_state_version:
                raise MissionStateVersionConflictError("mission state OCC version mismatch")
            if current.authorization_epoch != expected_authorization_epoch:
                raise AuthorizationEpochMismatchError("authorization epoch mismatch")
            if new_state not in self._allowed[current.state]:
                raise MissionStateVersionConflictError(
                    f"invalid mission transition: {current.state} -> {new_state}"
                )
            epoch_boundary = (current.state, new_state) in {
                ("RUNNING", "PAUSED"),
                ("PAUSED", "RUNNING"),
            }
            updated = MissionState(
                mission_id=mission_id,
                mission_state_version=current.mission_state_version + 1,
                authorization_epoch=current.authorization_epoch
                + int(epoch_boundary or invalidate_authorization),
                state=new_state,
                updated_at=updated_at,
            )
            connection.execute(
                "UPDATE mission_states SET mission_state_version = ?, authorization_epoch = ?, "
                "state = ?, payload_json = ? WHERE mission_id = ?",
                (
                    updated.mission_state_version,
                    updated.authorization_epoch,
                    updated.state,
                    model_json(updated),
                    mission_id,
                ),
            )
        return updated


def compose_mission(revision: MissionRevision, state: MissionState) -> Mission:
    if revision.mission_id != state.mission_id:
        raise ValueError("mission revision and state identity differ")
    return Mission.model_validate(
        {
            **revision.model_dump(mode="python"),
            "mission_state_version": state.mission_state_version,
            "authorization_epoch": state.authorization_epoch,
            "state": state.state,
        }
    )


def verify_revision_integrity(revision: MissionRevision, stored_digest: str) -> None:
    verify_model_digest(revision, stored_digest, exclude=())
