"""Application-owned workflow run and checkpoint identity bindings."""

from __future__ import annotations

from datetime import datetime

from redteam_agent.canonical import digest_model, stable_id
from redteam_agent.errors import WorkflowRunBindingError
from redteam_agent.models.execution import WorkflowRunBinding
from redteam_agent.repositories.execution import WorkflowRunRepository


def create_workflow_run(
    *,
    mission_id: str,
    mission_revision: int,
    run_seed: str,
    created_at: datetime,
) -> WorkflowRunBinding:
    """Issue a run identifier outside LLM-controlled data."""

    if ":" in mission_id or not run_seed:
        raise WorkflowRunBindingError("mission ID and run seed must be canonical")
    identity = {
        "schema_version": "workflow-run-v1",
        "mission_id": mission_id,
        "mission_revision": mission_revision,
        "run_seed": run_seed,
    }
    run_id = stable_id("run", identity)
    provisional = WorkflowRunBinding(
        run_id=run_id,
        run_digest="pending",
        mission_id=mission_id,
        mission_revision=mission_revision,
        thread_id=f"{mission_id}:{mission_revision}:{run_id}",
        created_at=created_at,
    )
    return provisional.model_copy(
        update={"run_digest": digest_model(provisional, exclude={"run_digest"})}
    )


def load_checkpoint_run(
    repository: WorkflowRunRepository,
    *,
    thread_id: str,
    mission_id: str,
    mission_revision: int,
) -> WorkflowRunBinding:
    run = repository.get_by_thread_id(thread_id)
    if run is None or not (
        run.mission_id == mission_id
        and run.mission_revision == mission_revision
        and run.thread_id == thread_id
    ):
        raise WorkflowRunBindingError("checkpoint thread does not match current mission revision")
    return run
