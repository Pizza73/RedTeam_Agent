"""Authorization and mock-only Phase 0B execution boundaries."""

from .adapter import (
    ExecutionAdapter,
    ExecutionAdapterRegistration,
    MockArtifact,
    MockExecutionAdapter,
    TrustedExecutionAdapterRegistry,
)
from .authorization_gate import AuthorizationGateResult, authorize_execution
from .finalization import FinalizationCoordinator
from .ingestion import MockSecureResultIngester, SecureResultIngester
from .raw_results import (
    MockQuarantineStore,
    MockRawResultSink,
    MockRawResultSinkFactory,
    RawResultSink,
    RawResultSinkFactory,
)
from .service import (
    Executor,
    PreDispatchCapabilityProbe,
    StaticPreDispatchCapabilityProbe,
    require_known_outcome,
)
from .workflow import create_workflow_run, load_checkpoint_run

__all__ = [
    "AuthorizationGateResult",
    "ExecutionAdapter",
    "ExecutionAdapterRegistration",
    "Executor",
    "FinalizationCoordinator",
    "MockArtifact",
    "MockExecutionAdapter",
    "MockQuarantineStore",
    "MockRawResultSink",
    "MockRawResultSinkFactory",
    "MockSecureResultIngester",
    "PreDispatchCapabilityProbe",
    "RawResultSink",
    "RawResultSinkFactory",
    "SecureResultIngester",
    "StaticPreDispatchCapabilityProbe",
    "TrustedExecutionAdapterRegistry",
    "authorize_execution",
    "create_workflow_run",
    "load_checkpoint_run",
    "require_known_outcome",
]
