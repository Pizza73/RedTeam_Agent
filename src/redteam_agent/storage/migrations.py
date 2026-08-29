"""Append-only Phase 0A schema migrations."""

from __future__ import annotations

MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        1,
        (
            """
            CREATE TABLE missions (
                mission_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE mission_revisions (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                mission_revision INTEGER NOT NULL CHECK (mission_revision >= 1),
                revision_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (mission_id, mission_revision)
            )
            """,
            """
            CREATE TABLE mission_states (
                mission_id TEXT PRIMARY KEY REFERENCES missions(mission_id),
                mission_state_version INTEGER NOT NULL CHECK (mission_state_version >= 0),
                authorization_epoch INTEGER NOT NULL CHECK (authorization_epoch >= 0),
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE context_resource_index (
                index_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                resource_id TEXT NOT NULL,
                resource_version TEXT NOT NULL,
                resource_digest TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE (mission_id, resource_id, resource_version)
            )
            """,
            """
            CREATE TABLE context_data_access_grants (
                grant_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                mission_revision INTEGER NOT NULL,
                authorization_epoch INTEGER NOT NULL,
                grant_digest TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY (mission_id, mission_revision)
                    REFERENCES mission_revisions(mission_id, mission_revision)
            )
            """,
            """
            CREATE TABLE data_access_grants (
                owner_type TEXT NOT NULL CHECK (owner_type IN ('context', 'policy')),
                owner_id TEXT NOT NULL,
                entry_index INTEGER NOT NULL CHECK (entry_index >= 0),
                resource_id TEXT NOT NULL,
                resource_version TEXT NOT NULL,
                resource_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (owner_type, owner_id, entry_index)
            )
            """,
            """
            CREATE TABLE tool_registry_revisions (
                registry_revision INTEGER PRIMARY KEY CHECK (registry_revision >= 1),
                registry_digest TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE available_tool_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                snapshot_digest TEXT NOT NULL,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                mission_revision INTEGER NOT NULL,
                authorization_epoch INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY (mission_id, mission_revision)
                    REFERENCES mission_revisions(mission_id, mission_revision)
            )
            """,
            """
            CREATE TABLE session_security_context_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                snapshot_digest TEXT NOT NULL,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE adapter_capability_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                snapshot_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE sandbox_capability_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                snapshot_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE remote_mcp_trust_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                snapshot_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE execution_plan_proposals (
                proposal_digest TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE execution_plans (
                plan_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                mission_revision INTEGER NOT NULL,
                authorization_epoch INTEGER NOT NULL,
                proposal_digest TEXT NOT NULL REFERENCES execution_plan_proposals(proposal_digest),
                payload_json TEXT NOT NULL,
                FOREIGN KEY (mission_id, mission_revision)
                    REFERENCES mission_revisions(mission_id, mission_revision)
            )
            """,
            """
            CREATE TABLE policy_decisions (
                decision_id TEXT PRIMARY KEY,
                decision_digest TEXT NOT NULL,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                plan_id TEXT NOT NULL REFERENCES execution_plans(plan_id),
                authorization_digest TEXT NOT NULL,
                decision TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE approval_requests (
                approval_request_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
                expires_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE approvals (
                approval_id TEXT PRIMARY KEY,
                approval_request_id TEXT NOT NULL REFERENCES approval_requests(approval_request_id),
                policy_decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
                record_digest TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE llm_profiles (
                profile_revision TEXT PRIMARY KEY,
                profile_digest TEXT NOT NULL,
                profile_type TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE llm_capability_results (
                capability_result_id TEXT PRIMARY KEY,
                profile_revision TEXT NOT NULL REFERENCES llm_profiles(profile_revision),
                result_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE audit_logs (
                event_id TEXT PRIMARY KEY,
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                sequence_number INTEGER NOT NULL CHECK (sequence_number >= 1),
                event_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE (mission_id, sequence_number)
            )
            """,
        ),
    ),
    (
        2,
        (
            """
            CREATE TABLE policy_states (
                mission_id TEXT PRIMARY KEY REFERENCES missions(mission_id),
                state_version INTEGER NOT NULL CHECK (state_version >= 0),
                policy_version TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE authorization_runtime_bindings (
                mission_id TEXT PRIMARY KEY REFERENCES missions(mission_id),
                binding_version INTEGER NOT NULL CHECK (binding_version >= 0),
                binding_digest TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """,
            "ALTER TABLE policy_decisions ADD COLUMN issuer TEXT NOT NULL "
            "DEFAULT 'legacy_unverified'",
            "CREATE UNIQUE INDEX policy_decisions_one_per_plan ON policy_decisions(plan_id)",
        ),
    ),
)
