"""Verify Pydantic v2 / stdlib JSON contracts relied on by the authorization kernel.

Run with the project virtual environment:

    .venv/bin/python scripts/verify_pydantic_contract.py

Exits non-zero if any relied-upon contract does not hold, so failures are not
silently swallowed. This is a developer verification aid, not a product module.
"""

from __future__ import annotations

import json
import sys

from pydantic import BaseModel, ConfigDict, ValidationError


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    a: int
    b: tuple[int, ...]


def main() -> int:
    failures: list[str] = []

    def expect_reject(payload: dict[str, object], label: str) -> None:
        try:
            _Model(**payload)  # type: ignore[arg-type]
        except ValidationError:
            return
        failures.append(f"expected rejection but accepted: {label}")

    expect_reject({"a": "3", "b": ()}, "str->int coercion")
    expect_reject({"a": True, "b": ()}, "bool->int coercion")
    expect_reject({"a": 3.0, "b": ()}, "float->int coercion")
    expect_reject({"a": 3, "b": (1,), "c": 9}, "unknown field")

    model = _Model(a=3, b=(1, 2))
    try:
        model.a = 5  # type: ignore[misc]
        failures.append("frozen model allowed mutation")
    except ValidationError:
        pass

    # stdlib json collapses duplicate keys, taking the last value.
    if json.loads('{"x": 1, "x": 2}') != {"x": 2}:
        failures.append("unexpected stdlib duplicate-key behaviour")

    if failures:
        for line in failures:
            print(f"FAIL: {line}")
        return 1

    print("OK: all pydantic/json boundary contracts hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
