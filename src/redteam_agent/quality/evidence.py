"""Append-only durable evidence sink for the D11 quality gate (SystemDesign §36.E1 / §37.1).

Every *attempted* run of a qualification is appended as a :class:`QualityRunRecord`
under ``<evaluation_id>/<run_index>``, and the aggregate :class:`QualityReport` under
``<evaluation_id>``. Rows are written through the shared repository conventions
(strict re-validation, catalog digest verification, duplicate-key-rejecting load,
row-key / payload identity check, ``put_idempotent``): an identical re-write is a
no-op and a conflicting re-write is rejected, so a stored run can never be silently
replaced by a better attempt. Failed runs and driver exceptions are recorded like any
other run (the failure classification is content-free).
"""

from __future__ import annotations

from redteam_agent.errors import RepositoryIntegrityError
from redteam_agent.quality.models import TOTAL_RUNS, QualityReport, QualityRunRecord
from redteam_agent.storage.repositories import _BaseRepository

_RUN_NS = "agent_quality_run"
_REPORT_NS = "agent_quality_report"


def run_row_key(evaluation_id: str, run_index: int) -> str:
    return f"{evaluation_id}/{run_index:03d}"


class QualityEvidenceRepository(_BaseRepository):
    """Repository-backed, append-only evidence store for quality runs and reports."""

    def append_run(self, record: QualityRunRecord) -> None:
        key = run_row_key(record.evaluation_id, record.run_index)
        self._db.put_idempotent(_RUN_NS, key, self._dump(record))

    def runs(self, evaluation_id: str) -> tuple[QualityRunRecord, ...]:
        prefix = f"{evaluation_id}/"
        records: list[QualityRunRecord] = []
        for row_key, json_text in self._db.get_all(_RUN_NS):
            if not row_key.startswith(prefix):
                continue
            record = self._load(QualityRunRecord, json_text, row_key=row_key, payload_key=row_key)
            if run_row_key(record.evaluation_id, record.run_index) != row_key:
                raise RepositoryIntegrityError("stored row key does not match payload identity")
            records.append(record)
        return tuple(sorted(records, key=lambda record: record.run_index))

    def append_report(self, report: QualityReport) -> None:
        if report.evaluation_id is None:
            raise RepositoryIntegrityError("a persisted report must carry its evaluation id")
        self._db.put_idempotent(_REPORT_NS, report.evaluation_id, self._dump(report))

    def report(self, evaluation_id: str) -> QualityReport | None:
        raw = self._db.get(_REPORT_NS, evaluation_id)
        if raw is None:
            return None
        report = self._load(QualityReport, raw, row_key=evaluation_id, payload_key=evaluation_id)
        if report.evaluation_id != evaluation_id:
            raise RepositoryIntegrityError("stored row key does not match payload identity")
        return report

    def verify_complete(self, evaluation_id: str) -> tuple[QualityRunRecord, ...]:
        """Load and integrity-check the full run set; fail closed unless it is exactly 300 rows."""
        records = self.runs(evaluation_id)
        if len(records) != TOTAL_RUNS:
            raise RepositoryIntegrityError("durable quality evidence does not hold exactly 300 runs")
        if [record.run_index for record in records] != list(range(TOTAL_RUNS)):
            raise RepositoryIntegrityError("durable quality evidence run indexes are not contiguous")
        return records


__all__ = ["QualityEvidenceRepository", "run_row_key"]
