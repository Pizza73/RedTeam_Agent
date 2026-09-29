"""Application-owned OCC Plan Thread and unconfirmed hypothesis snapshots."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import AgentLoopError
from redteam_agent.models.base import StrictImmutableBoundaryModel
from redteam_agent.plan.models import PlanThreadUpdateProposal
from redteam_agent.runtime.authorization_context import AuthorizationContextResolver
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork


class WorkingHypothesisSnapshot(StrictImmutableBoundaryModel):
    hypothesis_id: str = Field(min_length=1)
    statement: str
    status: Literal["investigating", "supported", "refuted", "abandoned"]
    basis_reference_ids: tuple[str, ...]
    next_verification_objective: str | None
    hypothesis_version: int = Field(ge=1)
    hypothesis_digest: str = Field(min_length=1)


class PlanThreadSnapshot(StrictImmutableBoundaryModel):
    plan_thread_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    mission_revision: int = Field(ge=1)
    authorization_epoch: int = Field(ge=0)
    objective: str
    status: Literal["active", "abandoned", "superseded"]
    hypotheses: tuple[WorkingHypothesisSnapshot, ...] = Field(max_length=20)
    thread_version: int = Field(ge=1)
    updated_at: datetime
    thread_digest: str = Field(min_length=1)


class PlannerStateManager:
    def __init__(self, *, database: Database, digest_service: DigestService,
                 context_resolver: AuthorizationContextResolver, clock: Clock) -> None:
        self._db, self._ds, self._resolver, self._clock = database, digest_service, context_resolver, clock

    def apply(
        self, *, mission_id: str, proposal: PlanThreadUpdateProposal,
        allowed_reference_ids: frozenset[str] = frozenset(),
        use_existing_transaction: bool = False,
    ) -> PlanThreadSnapshot:
        mission = self._resolver.resolve(mission_id, now=self._clock.now()).mission
        row = self._db.occ_get("plan_thread", mission_id)
        current = None if row is None else PlanThreadSnapshot.model_validate_json(row[1])
        if current is not None:
            assert row is not None
            payload = current.model_dump(mode="python")
            expected_digest = payload.pop("thread_digest")
            self._ds.verify("plan_thread_digest", payload, expected_digest)
            if current.mission_id != mission_id or current.thread_version != row[0]:
                raise AgentLoopError("Plan Thread identity or version mismatch")
            for hypothesis in current.hypotheses:
                hypothesis_payload = hypothesis.model_dump(mode="python")
                hypothesis_digest = hypothesis_payload.pop("hypothesis_digest")
                self._ds.verify(
                    "working_hypothesis_digest", hypothesis_payload, hypothesis_digest
                )
        if current is not None and (
            current.mission_revision != mission.mission_revision
            or current.authorization_epoch != mission.authorization_epoch
        ):
            raise AgentLoopError("Plan Thread is stale for the current mission")
        expected = proposal.expected_thread_version
        if current is None and proposal.operation != "replace":
            raise AgentLoopError("a new Plan Thread must use replace")
        if current is not None and expected != current.thread_version:
            raise AgentLoopError("Plan Thread OCC version conflict")
        if current is None and expected is not None:
            raise AgentLoopError("new Plan Thread cannot claim an existing version")
        if current is not None and current.status != "active" and proposal.operation != "replace":
            raise AgentLoopError("a closed Plan Thread cannot continue")
        if proposal.operation == "replace":
            if any(item.operation != "create" for item in proposal.hypothesis_updates):
                raise AgentLoopError("replace accepts only new hypotheses")
            hypotheses: dict[str, WorkingHypothesisSnapshot] = {}
        else:
            hypotheses = {
                item.hypothesis_id: item for item in (() if current is None else current.hypotheses)
            }
        for item in proposal.hypothesis_updates:
            if not set(item.basis_reference_ids) <= allowed_reference_ids:
                raise AgentLoopError("hypothesis contains an unavailable basis reference")
            if item.operation == "create":
                identity = self._ds.compute("security_projection_digest", {
                    "mission_id": mission_id, "statement": item.statement,
                    "basis_reference_ids": sorted(set(item.basis_reference_ids)),
                })
                hypothesis_id = f"hypothesis-{identity[:24]}"
                if hypothesis_id in hypotheses:
                    raise AgentLoopError("duplicate hypothesis creation")
                hypothesis_fields = {
                    "hypothesis_id": hypothesis_id,
                    "statement": item.statement,
                    "status": "investigating",
                    "basis_reference_ids": tuple(sorted(set(item.basis_reference_ids))),
                    "next_verification_objective": item.next_verification_objective,
                    "hypothesis_version": 1,
                }
                hypotheses[hypothesis_id] = WorkingHypothesisSnapshot.model_validate({
                    **hypothesis_fields,
                    "hypothesis_digest": self._ds.compute(
                        "working_hypothesis_digest", hypothesis_fields
                    ),
                })
            else:
                existing = hypotheses.get(item.hypothesis_id)
                if existing is None or existing.hypothesis_version != item.expected_hypothesis_version:
                    raise AgentLoopError("hypothesis OCC version conflict")
                if existing.status in {"refuted", "abandoned"}:
                    raise AgentLoopError("closed hypothesis cannot be changed")
                if item.operation == "update":
                    hypothesis_fields = {
                        "hypothesis_id": existing.hypothesis_id,
                        "statement": item.statement, "status": item.proposed_status,
                        "basis_reference_ids": tuple(sorted(set(item.basis_reference_ids))),
                        "next_verification_objective": item.next_verification_objective,
                        "hypothesis_version": existing.hypothesis_version + 1,
                    }
                else:
                    hypothesis_fields = {
                        "hypothesis_id": existing.hypothesis_id,
                        "statement": existing.statement,
                        "status": item.proposed_status,
                        "basis_reference_ids": tuple(sorted(set(item.basis_reference_ids))),
                        "next_verification_objective": None,
                        "hypothesis_version": existing.hypothesis_version + 1,
                    }
                hypotheses[item.hypothesis_id] = WorkingHypothesisSnapshot.model_validate({
                    **hypothesis_fields,
                    "hypothesis_digest": self._ds.compute(
                        "working_hypothesis_digest", hypothesis_fields
                    ),
                })
        if len(hypotheses) > 20:
            raise AgentLoopError("Plan Thread hypothesis limit exceeded")
        version = 1 if current is None else current.thread_version + 1
        if current is None or proposal.operation == "replace":
            plan_thread_id = f"plan-thread-{mission_id}-{version}"
        else:
            plan_thread_id = current.plan_thread_id
        fields = {
            "plan_thread_id": plan_thread_id, "mission_id": mission_id,
            "mission_revision": mission.mission_revision, "authorization_epoch": mission.authorization_epoch,
            "objective": proposal.objective,
            "status": "abandoned" if proposal.operation == "abandon" else "active",
            "hypotheses": tuple(
                hypotheses[key].model_dump(mode="python") for key in sorted(hypotheses)
            ),
            "thread_version": version, "updated_at": self._clock.now(),
        }
        snapshot = PlanThreadSnapshot.model_validate({
            **fields, "thread_digest": self._ds.compute("plan_thread_digest", fields)
        })
        text = json.dumps(snapshot.model_dump(mode="json"), sort_keys=True)
        def persist() -> None:
            if row is None:
                self._db.occ_insert("plan_thread", mission_id, 1, text)
            else:
                self._db.occ_update(
                    "plan_thread", mission_id, expected_version=row[0],
                    new_version=version, json_text=text,
                )
            self._db.occ_insert(
                "plan_thread_snapshot", f"{mission_id}:{version}", version, text
            )
        if use_existing_transaction:
            if not self._db.in_transaction:
                raise AgentLoopError("Plan Thread joined write requires an active transaction")
            persist()
        else:
            with UnitOfWork(self._db):
                persist()
        return snapshot
