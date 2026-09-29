"""Persistent provider-job ledger and bounded subprocess lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import uuid
from contextlib import suppress
from pathlib import Path

from ad_mcp.audit import AuditLog
from ad_mcp.command import BuiltCommand
from ad_mcp.errors import AuthorizationError, ValidationError
from ad_mcp.models import (
    JobState,
    JobView,
    ProjectAuthorization,
    PublicResult,
    ToolDefinition,
    utc_now,
)
from ad_mcp.parsers import parse_public_result
from ad_mcp.storage import RawExecution, RawStorage


class _OutputLimit(Exception):
    pass


class JobStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL UNIQUE,
                    actor_id TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    raw_ref TEXT NOT NULL,
                    exit_code INTEGER,
                    result_json TEXT,
                    error_code TEXT
                )"""
            )
            now = utc_now().isoformat()
            connection.execute(
                "UPDATE jobs SET state=?, updated_at=?, error_code=? WHERE state IN (?, ?)",
                (
                    JobState.OUTCOME_UNKNOWN.value,
                    now,
                    "SERVER_RESTARTED_DURING_EXECUTION",
                    JobState.QUEUED.value,
                    JobState.RUNNING.value,
                ),
            )
        os.chmod(self._path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def create(
        self,
        *,
        job_id: str,
        auth: ProjectAuthorization,
        operation_id: str,
        request_digest: str,
        raw_ref: str,
    ) -> JobView:
        now = utc_now()
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
                    (
                        job_id,
                        auth.execution_id,
                        auth.actor_id,
                        auth.mission_id,
                        operation_id,
                        request_digest,
                        JobState.QUEUED.value,
                        now.isoformat(),
                        now.isoformat(),
                        raw_ref,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValidationError("EXECUTION_ALREADY_SUBMITTED") from exc
        return JobView(
            job_id=job_id,
            execution_id=auth.execution_id,
            operation_id=operation_id,
            state=JobState.QUEUED,
            created_at=now,
            updated_at=now,
        )

    def update(
        self,
        job_id: str,
        state: JobState,
        *,
        result: PublicResult | None = None,
        exit_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        encoded = result.model_dump_json() if result is not None else None
        with self._connect() as connection:
            connection.execute(
                """UPDATE jobs
                   SET state=?, updated_at=?, exit_code=?, result_json=?, error_code=?
                   WHERE job_id=?""",
                (state.value, utc_now().isoformat(), exit_code, encoded, error_code, job_id),
            )

    def get(self, job_id: str, auth: ProjectAuthorization) -> JobView:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise ValidationError("JOB_NOT_FOUND")
        if (
            row["execution_id"] != auth.execution_id
            or row["actor_id"] != auth.actor_id
            or row["mission_id"] != auth.mission_id
        ):
            raise AuthorizationError("JOB_BINDING_MISMATCH")
        result = (
            PublicResult.model_validate_json(row["result_json"])
            if row["result_json"]
            else None
        )
        return JobView(
            job_id=row["job_id"],
            execution_id=row["execution_id"],
            operation_id=row["operation_id"],
            state=JobState(row["state"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            result=result,
            error_code=row["error_code"],
        )


class JobManager:
    def __init__(
        self,
        store: JobStore,
        storage: RawStorage,
        audit: AuditLog,
        *,
        max_concurrent: int,
    ) -> None:
        self._store = store
        self._storage = storage
        self._audit = audit
        self._max_concurrent = max_concurrent
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._cancelled: set[str] = set()

    async def start(
        self,
        tool: ToolDefinition,
        command: BuiltCommand,
        auth: ProjectAuthorization,
    ) -> JobView:
        if len(self._processes) >= self._max_concurrent:
            raise ValidationError("JOB_CAPACITY_EXHAUSTED")
        job_id = str(uuid.uuid4())
        raw = self._storage.create(job_id)
        request_digest = hashlib.sha256(
            json.dumps(
                {
                    "operation": tool.operation_id,
                    "argv": command.plan.redacted_argv,
                    "targets": command.plan.targets,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        self._store.create(
            job_id=job_id,
            auth=auth,
            operation_id=tool.operation_id,
            request_digest=request_digest,
            raw_ref=job_id,
        )
        await self._audit.write(
            "job_started",
            auth,
            operation_id=tool.operation_id,
            job_id=job_id,
            details={"command": command.plan.redacted_argv, "targets": command.plan.targets},
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command.argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=raw.directory,
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                start_new_session=True,
            )
        except OSError:
            self._store.update(job_id, JobState.FAILED, error_code="PROCESS_START_FAILED")
            self._storage.commit(raw, state=JobState.FAILED, exit_code=None, complete=False)
            await self._audit.write(
                "job_failed", auth, operation_id=tool.operation_id, job_id=job_id,
                details={"error_code": "PROCESS_START_FAILED", "raw_result_ref": job_id},
            )
            return self._store.get(job_id, auth)
        self._processes[job_id] = process
        self._store.update(job_id, JobState.RUNNING)
        task = asyncio.create_task(
            self._monitor(job_id, tool, process, raw, auth, command.plan.timeout_seconds)
        )
        self._tasks[job_id] = task
        return self._store.get(job_id, auth)

    def get(self, job_id: str, auth: ProjectAuthorization) -> JobView:
        return self._store.get(job_id, auth)

    async def cancel(self, job_id: str, auth: ProjectAuthorization) -> JobView:
        current = self._store.get(job_id, auth)
        if current.state not in {JobState.QUEUED, JobState.RUNNING}:
            return current
        process = self._processes.get(job_id)
        if process is None:
            self._store.update(job_id, JobState.OUTCOME_UNKNOWN, error_code="PROCESS_NOT_OWNED")
            return self._store.get(job_id, auth)
        self._cancelled.add(job_id)
        _terminate(process)
        await self._audit.write(
            "job_cancel_requested", auth, operation_id=current.operation_id, job_id=job_id
        )
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(self._tasks[job_id]), timeout=5)
        return self._store.get(job_id, auth)

    async def _monitor(
        self,
        job_id: str,
        tool: ToolDefinition,
        process: asyncio.subprocess.Process,
        raw: RawExecution,
        auth: ProjectAuthorization,
        timeout_seconds: int,
    ) -> None:
        state = JobState.FAILED
        exit_code: int | None = None
        error_code: str | None = None
        limit = {"bytes": 0}
        lock = asyncio.Lock()
        try:
            assert process.stdout is not None and process.stderr is not None
            readers = asyncio.gather(
                _copy_stream(process.stdout, raw.stdout, tool.max_output_bytes, limit, lock),
                _copy_stream(process.stderr, raw.stderr, tool.max_output_bytes, limit, lock),
            )
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
                await readers
                exit_code = process.returncode
                if job_id in self._cancelled:
                    state = JobState.CANCELLED
                    error_code = "CANCELLED_BY_CALLER"
                elif exit_code == 0:
                    state = JobState.SUCCEEDED
                else:
                    state = JobState.FAILED
                    error_code = "PROCESS_EXIT_NONZERO"
            except TimeoutError:
                state = JobState.TIMED_OUT
                error_code = "PROCESS_TIMEOUT"
                _terminate(process)
                await process.wait()
                readers.cancel()
                with suppress(asyncio.CancelledError, _OutputLimit):
                    await readers
            except _OutputLimit:
                state = JobState.FAILED
                error_code = "OUTPUT_LIMIT_EXCEEDED"
                _terminate(process)
                await process.wait()
        except Exception:
            state = JobState.OUTCOME_UNKNOWN
            error_code = "MONITOR_FAILURE"
            _terminate(process)
            with suppress(Exception):
                await process.wait()
        finally:
            self._processes.pop(job_id, None)
            self._tasks.pop(job_id, None)
            self._cancelled.discard(job_id)
        complete = state in {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED}
        self._storage.commit(raw, state=state, exit_code=exit_code, complete=complete)
        result = parse_public_result(
            tool,
            state=state,
            exit_code=exit_code,
            stdout_path=raw.stdout,
            stderr_path=raw.stderr,
            raw_result_ref=job_id,
        )
        self._store.update(
            job_id, state, result=result, exit_code=exit_code, error_code=error_code
        )
        await self._audit.write(
            "job_completed",
            auth,
            operation_id=tool.operation_id,
            job_id=job_id,
            details={
                "state": state.value,
                "exit_code": exit_code,
                "error_code": error_code,
                "raw_result_ref": job_id,
            },
        )


async def _copy_stream(
    reader: asyncio.StreamReader,
    path: Path,
    maximum: int,
    counter: dict[str, int],
    lock: asyncio.Lock,
) -> None:
    with path.open("ab", buffering=0) as stream:
        while chunk := await reader.read(64 * 1024):
            async with lock:
                counter["bytes"] += len(chunk)
                if counter["bytes"] > maximum:
                    raise _OutputLimit
            stream.write(chunk)


def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
