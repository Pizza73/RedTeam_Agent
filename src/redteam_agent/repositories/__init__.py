"""Repository interfaces backed by SQLite for Phase 0A."""

from .approval import ApprovalRecordRepository, ApprovalRequestRepository
from .capabilities import (
    AdapterCapabilitySnapshotRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
)
from .context import ContextAuthorizationRepository, ContextResourceIndexRepository
from .llm import LLMProfileRepository
from .mission import MissionRepository, MissionRevisionRepository, MissionStateRepository
from .plans import PlanProposalRepository, PlanRepository
from .policy import PolicyDecisionRepository
from .runtime import AuthorizationRuntimeBindingRepository, PolicyStateRepository
from .tools import AvailableToolSnapshotRepository, ToolRegistryRepository

__all__ = [
    "AdapterCapabilitySnapshotRepository",
    "ApprovalRecordRepository",
    "ApprovalRequestRepository",
    "AvailableToolSnapshotRepository",
    "AuthorizationRuntimeBindingRepository",
    "ContextAuthorizationRepository",
    "ContextResourceIndexRepository",
    "LLMProfileRepository",
    "MissionRepository",
    "MissionRevisionRepository",
    "MissionStateRepository",
    "PlanProposalRepository",
    "PlanRepository",
    "PolicyDecisionRepository",
    "PolicyStateRepository",
    "RemoteMCPTrustSnapshotRepository",
    "SandboxCapabilitySnapshotRepository",
    "SessionSecurityContextSnapshotRepository",
    "ToolRegistryRepository",
]
