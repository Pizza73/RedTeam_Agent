from __future__ import annotations

import time

from redteam_agent.llm.evaluation import TimedInFlightCancellation


def test_timed_cancellation_arms_only_after_request_starts() -> None:
    token = TimedInFlightCancellation(delay_seconds=0.01).new_token()
    time.sleep(0.02)
    assert token.cancelled is False
    token.request_started()
    time.sleep(0.03)
    assert token.cancelled is True
    token.request_finished()
