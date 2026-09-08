"""The application-owned evaluation Gateway (SystemDesign §6.3).

Startup schema-capability evaluation must reach a real model only through the same
gateway boundary as production Planner / Analyzer requests, but with a *finite,
application-owned* evaluation run budget instead of a normal mission authorization,
and with no route to a production execution adapter or mission operation port.

For every actual model request — including each output-validation retry, the timeout
probe and the in-flight cancellation probe — this gateway:

* reserves one durable attempt record *before* the token preflight;
* runs the mandatory preflight through the reused :class:`AttemptBinding`, which
  measures the actual :class:`ChatCompletionRequest` with a required real
  :class:`TokenCounter` bound to ``profile.tokenizer_revision`` (no heuristic
  production fallback) and enforces ``rendered_input + reserved_output + margin <=
  max_context`` before any network I/O;
* enforces a finite evaluation run call / token budget and an absolute deadline;
* performs zero network calls when the preflight, budget or deadline rejects;
* updates the same attempt record with a safe outcome, re-verifying the record's
  integrity before mutating it;
* records only safe failure metadata — never a raw secret, unvalidated body or raw
  validation error.

It adds no workflow state and reuses the shared attempt-row semantics.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.errors import LLMEvaluationError, LLMRequestBudgetError, LLMTransportError
from redteam_agent.llm.adapters import AttemptBinding
from redteam_agent.llm.client import CancellationToken, ChatCompletionResult, VLLMChatClient
from redteam_agent.runtime.clock import Clock
from redteam_agent.storage.database import Database, UnitOfWork

_NS = "llm_eval_attempt"

EvalAttemptOutcome = Literal[
    "reserved",
    "budget_rejected",
    "deadline_reached",
    "preflight_rejected",
    "completed",
    "timeout",
    "cancelled",
    "transport_unknown",
]


class EvaluationRunBudget:
    """A finite, application-owned evaluation run budget: bounded calls, bounded total
    tokens and an absolute deadline. It replaces the normal mission authorization for the
    isolated evaluation entry point; exhausting any bound fails closed with zero network."""

    def __init__(
        self,
        *,
        max_calls: int,
        max_total_tokens: int,
        deadline: datetime,
        clock: Clock,
    ) -> None:
        if max_calls <= 0 or max_total_tokens <= 0:
            raise LLMEvaluationError("evaluation run budget must be finite and positive")
        self._max_calls = max_calls
        self._max_total_tokens = max_total_tokens
        self._deadline = deadline
        self._clock = clock
        self._calls_used = 0
        self._tokens_used = 0

    @property
    def deadline(self) -> datetime:
        return self._deadline

    def reserve_call(self) -> None:
        if self._clock.now() >= self._deadline:
            raise _DeadlineReached("evaluation run deadline reached")
        if self._calls_used >= self._max_calls:
            raise LLMRequestBudgetError("evaluation run call budget exhausted")
        self._calls_used += 1

    def reserve_tokens(self, tokens: int) -> None:
        if self._tokens_used + tokens > self._max_total_tokens:
            raise LLMRequestBudgetError("evaluation run token budget exhausted")
        self._tokens_used += tokens


class _DeadlineReached(LLMRequestBudgetError):
    """The evaluation run's absolute deadline was reached before a call (fail closed)."""


class EvaluationGateway:
    """Isolated evaluation-only gateway with the shared attempt semantics.

    It never receives a production adapter, mission manager or dispatch port; it owns only
    the durable attempt store, the digest service and the clock.
    """

    def __init__(
        self, *, database: Database, digest_service: DigestService, clock: Clock, run_id: str
    ) -> None:
        if not run_id:
            raise LLMEvaluationError("evaluation gateway requires a run id")
        self._db = database
        self._ds = digest_service
        self._clock = clock
        self._run_id = run_id
        self._seq = 0

    @property
    def digest_service(self) -> DigestService:
        """The canonical service used to bind safe request metadata."""
        return self._ds

    def execute(
        self,
        *,
        binding: AttemptBinding,
        client: VLLMChatClient,
        run_budget: EvaluationRunBudget,
        cancel_token: CancellationToken | None = None,
    ) -> ChatCompletionResult:
        attempt_index = self._seq
        self._seq += 1
        attempt_key = f"{self._run_id}:{attempt_index}"
        self._reserve_attempt(attempt_key, binding.schema_name, attempt_index)

        # 1) Finite run budget + absolute deadline (zero network on rejection).
        try:
            run_budget.reserve_call()
        except _DeadlineReached:
            self._update_attempt(attempt_key, "deadline_reached")
            raise
        except LLMRequestBudgetError:
            self._update_attempt(attempt_key, "budget_rejected")
            raise

        # 2) Mandatory token preflight through the reused AttemptBinding (zero network).
        try:
            metadata = binding.before_attempt(attempt_index)
        except LLMRequestBudgetError:
            self._update_attempt(attempt_key, "preflight_rejected")
            raise
        except Exception:
            self._update_attempt(attempt_key, "preflight_rejected")
            raise

        # 3) Reserve the measured tokens against the run budget (zero network).
        total = metadata.get("total_budgeted_tokens")
        if not isinstance(total, int):
            self._update_attempt(attempt_key, "preflight_rejected")
            raise LLMRequestBudgetError("evaluation preflight produced no measured token total")
        try:
            run_budget.reserve_tokens(total)
        except LLMRequestBudgetError:
            self._update_attempt(attempt_key, "budget_rejected")
            raise

        if binding.remaining_timeout() <= 0:
            self._update_attempt(attempt_key, "deadline_reached", metadata=metadata)
            raise _DeadlineReached("evaluation request deadline reached before send")

        # 4) The single bounded network call.
        try:
            result = client.complete(
                binding.request, timeout_seconds=binding.remaining_timeout(),
                cancel_token=cancel_token if cancel_token is not None else CancellationToken(),
            )
        except LLMTransportError as exc:
            self._update_attempt(
                attempt_key, _transport_outcome(exc.reason), metadata=metadata
            )
            raise
        except Exception:
            self._update_attempt(attempt_key, "transport_unknown", metadata=metadata)
            raise
        self._update_attempt(attempt_key, "completed", metadata=metadata)
        return result

    # --- durable attempt record ------------------------------------------

    def _reserve_attempt(self, attempt_key: str, schema_name: str, attempt_index: int) -> None:
        record: dict[str, Any] = {
            "run_id": self._run_id, "attempt_index": attempt_index, "schema_name": schema_name,
            "attempted_at": self._clock.now().isoformat(), "outcome": "reserved",
            "attempt_metadata": None,
        }
        record["attempt_digest"] = self._ds.compute("llm_eval_attempt_digest", {
            k: v for k, v in record.items() if k != "attempt_digest"
        })
        with UnitOfWork(self._db):
            self._db.occ_insert(_NS, attempt_key, 1, json.dumps(record, sort_keys=True))

    def _update_attempt(
        self, attempt_key: str, outcome: EvalAttemptOutcome,
        *, metadata: object | None = None,
    ) -> None:
        row = self._db.occ_get(_NS, attempt_key)
        if row is None:
            raise LLMEvaluationError("evaluation attempt row missing before outcome update")
        version, payload = row
        record = json.loads(payload)
        stored_digest = record.pop("attempt_digest", None)
        if not isinstance(stored_digest, str):
            raise LLMEvaluationError("evaluation attempt row is missing its integrity digest")
        # Verify the stored record's integrity BEFORE mutating its outcome (fail closed).
        self._ds.verify("llm_eval_attempt_digest", record, stored_digest)
        record["outcome"] = outcome
        if metadata is not None:
            # Persist only the safe, redacted preflight metadata (never a raw body).
            record["attempt_metadata"] = dict(metadata) if isinstance(metadata, dict) else None
        record["attempt_digest"] = self._ds.compute("llm_eval_attempt_digest", {
            k: v for k, v in record.items() if k != "attempt_digest"
        })
        with UnitOfWork(self._db):
            self._db.occ_update(
                _NS, attempt_key, expected_version=version, new_version=version + 1,
                json_text=json.dumps(record, sort_keys=True),
            )


def _transport_outcome(reason: str) -> EvalAttemptOutcome:
    if reason == "timeout":
        return "timeout"
    if reason == "cancelled_in_flight":
        return "cancelled"
    return "transport_unknown"


__all__ = [
    "EvalAttemptOutcome",
    "EvaluationGateway",
    "EvaluationRunBudget",
]
