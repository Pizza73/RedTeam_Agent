"""Agent profile and capability-result repository."""

from __future__ import annotations

from redteam_agent.canonical import stable_id, verify_model_digest
from redteam_agent.errors import DigestIntegrityError
from redteam_agent.models.llm import LLMCapabilityResult, LocalLLMProfile, MockAgentProfile
from redteam_agent.storage import Database

from .base import model_json, parse_model_json

AgentProfile = LocalLLMProfile | MockAgentProfile


class LLMProfileRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def add(self, profile: AgentProfile) -> AgentProfile:
        verify_model_digest(profile, profile.profile_digest, exclude={"profile_digest"})
        payload = model_json(profile)
        connection = self.database.connection
        existing = connection.execute(
            "SELECT payload_json FROM llm_profiles WHERE profile_revision = ?",
            (profile.profile_revision,),
        ).fetchone()
        if existing is not None:
            if existing["payload_json"] != payload:
                from redteam_agent.errors import DigestIntegrityError

                raise DigestIntegrityError("profile revision reused with different payload")
            return profile
        connection.execute(
            "INSERT INTO llm_profiles"
            "(profile_revision, profile_digest, profile_type, payload_json) VALUES (?, ?, ?, ?)",
            (profile.profile_revision, profile.profile_digest, profile.profile_type, payload),
        )
        return profile

    def get(self, profile_revision: str) -> AgentProfile | None:
        row = self.database.connection.execute(
            "SELECT profile_type, profile_digest, payload_json FROM llm_profiles "
            "WHERE profile_revision = ?",
            (profile_revision,),
        ).fetchone()
        if row is None:
            return None
        if row["profile_type"] == "mock":
            profile: AgentProfile = parse_model_json(MockAgentProfile, row["payload_json"])
        elif row["profile_type"] == "local_llm":
            profile = parse_model_json(LocalLLMProfile, row["payload_json"])
        else:
            raise DigestIntegrityError("unknown persisted LLM profile type")
        verify_model_digest(profile, profile.profile_digest, exclude={"profile_digest"})
        if (
            row["profile_type"] != profile.profile_type
            or row["profile_digest"] != profile.profile_digest
        ):
            raise DigestIntegrityError("LLM profile row binding mismatch")
        return profile

    def add_capability_result(self, result: LLMCapabilityResult) -> LLMCapabilityResult:
        verify_model_digest(result, result.result_digest, exclude={"result_digest"})
        expected_id = stable_id(
            "llmcap",
            {
                "profile_revision": result.profile_revision,
                "profile_digest": result.profile_digest,
                "status": result.status,
                "checked_at": result.checked_at,
            },
        )
        if result.capability_result_id != expected_id:
            raise DigestIntegrityError("LLM capability result ID mismatch")
        profile = self.get(result.profile_revision)
        if profile is None or profile.profile_digest != result.profile_digest:
            raise DigestIntegrityError("LLM capability result/profile binding mismatch")
        payload = model_json(result)
        existing = self.database.connection.execute(
            "SELECT profile_revision, result_digest, payload_json "
            "FROM llm_capability_results WHERE capability_result_id = ?",
            (result.capability_result_id,),
        ).fetchone()
        if existing is not None:
            if not (
                existing["profile_revision"] == result.profile_revision
                and existing["result_digest"] == result.result_digest
                and existing["payload_json"] == payload
            ):
                raise DigestIntegrityError("LLM capability result ID reused with different payload")
            return result
        self.database.connection.execute(
            "INSERT INTO llm_capability_results"
            "(capability_result_id, profile_revision, result_digest, payload_json) "
            "VALUES (?, ?, ?, ?)",
            (
                result.capability_result_id,
                result.profile_revision,
                result.result_digest,
                payload,
            ),
        )
        return result

    def latest_capability_result(self, profile_revision: str) -> LLMCapabilityResult | None:
        row = self.database.connection.execute(
            "SELECT capability_result_id, profile_revision, result_digest, payload_json "
            "FROM llm_capability_results "
            "WHERE profile_revision = ? ORDER BY rowid DESC LIMIT 1",
            (profile_revision,),
        ).fetchone()
        if row is None:
            return None
        result = parse_model_json(LLMCapabilityResult, row["payload_json"])
        verify_model_digest(result, result.result_digest, exclude={"result_digest"})
        profile = self.get(result.profile_revision)
        if not (
            row["capability_result_id"] == result.capability_result_id
            and row["profile_revision"] == result.profile_revision
            and row["result_digest"] == result.result_digest
            and result.profile_revision == profile_revision
            and profile is not None
            and profile.profile_digest == result.profile_digest
        ):
            raise DigestIntegrityError("LLM capability row binding mismatch")
        return result
