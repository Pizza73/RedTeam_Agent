"""Ordered, exactly-once accounting for logical execution outcomes (D10)."""

from __future__ import annotations

import json

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError
from redteam_agent.storage.database import Database, UnitOfWork
from redteam_agent.storage.execution_repositories import (
    ExecutionRecordRepository,
    ExecutionResultRepository,
)


class ExecutionOutcomeAccountingService:
    MAX_CONSECUTIVE_FAILURES = 5

    def __init__(
        self, *, database: Database, digest_service: DigestService,
        execution_repository: ExecutionRecordRepository,
        result_repository: ExecutionResultRepository,
    ) -> None:
        self._db, self._ds = database, digest_service
        self._executions, self._results = execution_repository, result_repository

    def reconcile(self, *, mission_id: str, mission_revision: int) -> int:
        state_key = f"{mission_id}:{mission_revision}"
        state_row = self._db.occ_get("execution_outcome_budget", state_key)
        if state_row is None:
            failures = 0
        else:
            state = json.loads(state_row[1])
            expected = state.pop("state_digest")
            self._ds.verify("execution_outcome_budget_digest", state, expected)
            if (
                state["mission_id"] != mission_id
                or state["mission_revision"] != mission_revision
                or state["budget_version"] != state_row[0]
            ):
                raise AgentLoopError("execution outcome budget identity or version mismatch")
            failures = int(state["consecutive_failures"])
        state_version = 0 if state_row is None else state_row[0]
        executions = sorted(
            self._executions.all_for_mission(mission_id),
            key=lambda item: (item.created_at, item.execution_id),
        )
        for sequence, execution in enumerate(executions, start=1):
            if execution.mission_revision != mission_revision:
                continue
            outcome_key = f"{state_key}:{execution.execution_id}"
            outcome_row = self._db.occ_get("execution_budget_outcome", outcome_key)
            if outcome_row is not None:
                recorded = json.loads(outcome_row[1])
                expected = recorded.pop("record_digest")
                self._ds.verify("execution_budget_outcome_digest", recorded, expected)
                if recorded["execution_id"] != execution.execution_id:
                    raise AgentLoopError("execution outcome identity mismatch")
                continue
            result = self._results.get(execution.execution_id)
            if result is None:
                if execution.provider_execution_state == "BLOCKED":
                    outcome = "neutral"
                    source_digest = execution.record_digest
                else:
                    break
            else:
                source_digest = self._ds.compute(
                    "execution_outcome_source_digest", result.model_dump(mode="python")
                )
                outcome = {
                    "SUCCEEDED": "success", "FAILED": "failure", "CANCELLED": "neutral",
                }[result.status]
            if outcome == "failure":
                failures += 1
            elif outcome == "success":
                failures = 0
            state_version += 1
            outcome_fields = {
                "mission_id": mission_id, "mission_revision": mission_revision,
                "execution_id": execution.execution_id, "sequence": sequence,
                "outcome": outcome, "source_digest": source_digest,
                "budget_version": state_version,
            }
            state_fields = {
                "mission_id": mission_id, "mission_revision": mission_revision,
                "budget_version": state_version, "consecutive_failures": failures,
            }
            with UnitOfWork(self._db):
                self._db.occ_insert(
                    "execution_budget_outcome", outcome_key, 1,
                    json.dumps({
                        **outcome_fields,
                        "record_digest": self._ds.compute(
                            "execution_budget_outcome_digest", outcome_fields
                        ),
                    }, sort_keys=True),
                )
                state_text = json.dumps({
                    **state_fields,
                    "state_digest": self._ds.compute("execution_outcome_budget_digest", state_fields),
                }, sort_keys=True)
                if state_row is None and state_version == 1:
                    self._db.occ_insert("execution_outcome_budget", state_key, 1, state_text)
                else:
                    self._db.occ_update(
                        "execution_outcome_budget", state_key,
                        expected_version=state_version - 1, new_version=state_version,
                        json_text=state_text,
                    )
            state_row = (state_version, state_text)
        if failures < 0:
            raise AgentLoopError("execution failure budget is invalid")
        return failures
