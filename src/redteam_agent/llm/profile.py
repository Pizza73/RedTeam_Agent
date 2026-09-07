"""Agent model profile record (SystemDesign §21).

Phase 0A registers an explicit Mock profile whose digest is computed over its
own fields (not an arbitrary non-empty string), so a forged profile fails
integrity verification on load. A local LLM profile additionally requires a
passed capability-check result; the real local LLM is a later phase and can be
rejected explicitly here.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.models.base import StrictImmutableBoundaryModel


class AgentModelProfile(StrictImmutableBoundaryModel):
    profile_revision: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    profile_kind: Literal["mock", "local_llm"]
    capability_check_passed: bool

    def is_usable(self) -> bool:
        """Mock profiles are usable; local LLM profiles need a passed check."""
        if self.profile_kind == "mock":
            return True
        return self.capability_check_passed


def _profile_payload(profile_revision: str, profile_kind: str, capability_check_passed: bool) -> dict[str, object]:
    return {
        "profile_revision": profile_revision,
        "profile_kind": profile_kind,
        "capability_check_passed": capability_check_passed,
    }


def build_agent_profile(
    *,
    profile_revision: str,
    profile_kind: Literal["mock", "local_llm"],
    capability_check_passed: bool,
    digest_service: DigestService,
) -> AgentModelProfile:
    digest = digest_service.compute(
        "profile_digest", _profile_payload(profile_revision, profile_kind, capability_check_passed)
    )
    return AgentModelProfile(
        profile_revision=profile_revision,
        profile_digest=digest,
        profile_kind=profile_kind,
        capability_check_passed=capability_check_passed,
    )


def mock_agent_profile(digest_service: DigestService, profile_revision: str = "mock-profile-v1") -> AgentModelProfile:
    return build_agent_profile(
        profile_revision=profile_revision,
        profile_kind="mock",
        capability_check_passed=True,
        digest_service=digest_service,
    )
