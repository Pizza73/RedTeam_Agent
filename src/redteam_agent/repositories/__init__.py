"""Repository interfaces backed by SQLite for implemented phases."""

from .approval import ApprovalRecordRepository, ApprovalRequestRepository
from .capabilities import (
    AdapterCapabilitySnapshotRepository,
    RemoteMCPTrustSnapshotRepository,
    SandboxCapabilitySnapshotRepository,
    SessionSecurityContextSnapshotRepository,
)
from .context import ContextAuthorizationRepository, ContextResourceIndexRepository
from .execution import (
    ExecutionRepository,
    ExecutionResultRepository,
    RawResultReceiptRepository,
    RawResultRecoveryRepository,
    ResultIngestionRepository,
    WorkflowRunRepository,
)
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
    "ExecutionRepository",
    "ExecutionResultRepository",
    "LLMProfileRepository",
    "MissionRepository",
    "MissionRevisionRepository",
    "MissionStateRepository",
    "PlanProposalRepository",
    "PlanRepository",
    "PolicyDecisionRepository",
    "PolicyStateRepository",
    "RawResultReceiptRepository",
    "RawResultRecoveryRepository",
    "RemoteMCPTrustSnapshotRepository",
    "SandboxCapabilitySnapshotRepository",
    "SessionSecurityContextSnapshotRepository",
    "ToolRegistryRepository",
    "ResultIngestionRepository",
    "WorkflowRunRepository",
]
