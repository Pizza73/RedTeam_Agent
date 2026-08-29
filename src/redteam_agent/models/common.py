"""Common enums, literals and UTC validation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware UTC")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError("datetime offset must be UTC")
    return value


UtcDatetime = Annotated[datetime, AfterValidator(require_utc)]


class OperationalPhase(StrEnum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DOMAIN_CONTROL = "DOMAIN_CONTROL"
    LINUX_PRIVILEGE_ESCALATION = "LINUX_PRIVILEGE_ESCALATION"
    OBJECTIVE = "OBJECTIVE"


class RiskLevel(StrEnum):
    READ = "read"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SideEffect(StrEnum):
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    DESTRUCTIVE = "destructive"

