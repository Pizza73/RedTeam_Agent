"""Execution / collection / ingestion state machines (SystemDesign §10-§10.4).

The legal edges are stated here once so the executor, coordinators and the
repositories all reject an illegal transition. These tables are the *product*
definition; the property/state-machine tests use an independent oracle so the
comparison is not tautological.
"""

from __future__ import annotations

from redteam_agent.execution.models import (
    ProviderExecutionState,
    ResultCollectionStatus,
    ResultIngestionStatus,
)

# Provider execution state machine (SystemDesign §10.1). ``AUTHORIZED -> BLOCKED``
# (pre-dispatch) and ``DISPATCH_CLAIMED -> BLOCKED`` (secret revocation) are the
# only two provider-never-called terminal blocks.
PROVIDER_EXECUTION_EDGES: frozenset[tuple[ProviderExecutionState, ProviderExecutionState]] = frozenset(
    {
        ("PLANNED", "AUTHORIZED"),
        ("AUTHORIZED", "BLOCKED"),
        ("AUTHORIZED", "DISPATCH_CLAIMED"),
        ("DISPATCH_CLAIMED", "BLOCKED"),
        ("DISPATCH_CLAIMED", "DISPATCHED"),
        ("DISPATCH_CLAIMED", "SUCCEEDED"),
        ("DISPATCH_CLAIMED", "FAILED"),
        ("DISPATCH_CLAIMED", "CANCELLED"),
        ("DISPATCH_CLAIMED", "RECONCILING"),
        ("DISPATCHED", "RUNNING"),
        ("DISPATCHED", "CANCEL_REQUESTED"),
        ("DISPATCHED", "RECONCILING"),
        ("RUNNING", "SUCCEEDED"),
        ("RUNNING", "FAILED"),
        ("RUNNING", "CANCEL_REQUESTED"),
        ("RUNNING", "CANCELLED"),
        ("RUNNING", "OUTCOME_UNKNOWN"),
        ("RUNNING", "RECONCILING"),
        ("CANCEL_REQUESTED", "CANCELLED"),
        ("CANCEL_REQUESTED", "RUNNING"),
        ("CANCEL_REQUESTED", "OUTCOME_UNKNOWN"),
        ("CANCEL_REQUESTED", "RECONCILING"),
        ("RECONCILING", "DISPATCHED"),
        ("RECONCILING", "RUNNING"),
        ("RECONCILING", "SUCCEEDED"),
        ("RECONCILING", "FAILED"),
        ("RECONCILING", "CANCELLED"),
        ("RECONCILING", "OUTCOME_UNKNOWN"),
        ("OUTCOME_UNKNOWN", "RECONCILING"),
    }
)

PROVIDER_TERMINAL_STATES: frozenset[ProviderExecutionState] = frozenset(
    {"SUCCEEDED", "FAILED", "BLOCKED", "CANCELLED", "OUTCOME_UNKNOWN"}
)

# Result collection state machine (SystemDesign §10).
RESULT_COLLECTION_EDGES: frozenset[tuple[ResultCollectionStatus, ResultCollectionStatus]] = frozenset(
    {
        ("NOT_STARTED", "STREAMING"),
        ("NOT_STARTED", "ABANDONED"),
        ("STREAMING", "COMMITTED_METADATA_PENDING"),
        ("STREAMING", "ABANDONED"),
        ("COMMITTED_METADATA_PENDING", "COMPLETE"),
        ("COMMITTED_METADATA_PENDING", "ABANDONED"),
    }
)

RESULT_COLLECTION_TERMINAL: frozenset[ResultCollectionStatus] = frozenset({"COMPLETE", "ABANDONED"})

# Result ingestion state machine (SystemDesign §10).
RESULT_INGESTION_EDGES: frozenset[tuple[ResultIngestionStatus, ResultIngestionStatus]] = frozenset(
    {
        ("NOT_AVAILABLE", "PENDING"),
        ("PENDING", "INGESTING"),
        ("PENDING", "EVIDENCE_RETENTION_EXPIRED"),
        ("INGESTING", "DELETE_PENDING"),
        ("INGESTING", "FAILED"),
        ("INGESTING", "EVIDENCE_RETENTION_EXPIRED"),
        ("FAILED", "PENDING"),
        ("FAILED", "QUARANTINED"),
        ("FAILED", "EVIDENCE_RETENTION_EXPIRED"),
        ("QUARANTINED", "EVIDENCE_RETENTION_EXPIRED"),
        ("EVIDENCE_RETENTION_EXPIRED", "DELETE_PENDING"),
        ("DELETE_PENDING", "ERASURE_CLAIMED"),
        ("ERASURE_CLAIMED", "QUARANTINE_ERASED"),
        ("QUARANTINE_ERASED", "SUCCEEDED"),
        ("QUARANTINE_ERASED", "ERASURE_COMPLETED_UNRESOLVED"),
    }
)


def is_legal_provider_edge(current: ProviderExecutionState, target: ProviderExecutionState) -> bool:
    return (current, target) in PROVIDER_EXECUTION_EDGES


def is_legal_collection_edge(current: ResultCollectionStatus, target: ResultCollectionStatus) -> bool:
    return (current, target) in RESULT_COLLECTION_EDGES


def is_legal_ingestion_edge(current: ResultIngestionStatus, target: ResultIngestionStatus) -> bool:
    return (current, target) in RESULT_INGESTION_EDGES
