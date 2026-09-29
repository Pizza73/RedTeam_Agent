"""Read-model and draft boundary used by the local operator console.

This module never constructs execution authority.  Security-sensitive approval
decisions are delegated to an injected owner callback which must use the existing
ApprovalService and its authenticated actor binding.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel

from redteam_agent.ad_assessment.catalog import catalog_view as ad_assessment_catalog_view
from redteam_agent.ad_assessment.collector import ADCollectorError
from redteam_agent.ad_assessment.models import ADAssessmentSnapshot
from redteam_agent.ad_assessment.service import ADAssessmentVerifier
from redteam_agent.approval.models import ApprovalRecord, ApprovalRequest
from redteam_agent.canonical.digest_service import DigestService
from redteam_agent.canonical.immutable import thaw
from redteam_agent.canonical.json_boundary import load_model_from_json
from redteam_agent.errors import (
    LLMCapabilityError,
    LLMRequestBudgetError,
    LLMTransportError,
    MissionLifecycleError,
    MissionStateVersionConflictError,
    MissionValidationError,
    PlannerCandidateError,
)
from redteam_agent.execution.models import ExecutionRecord
from redteam_agent.ingestion.artifact_store import ArtifactReference
from redteam_agent.knowledge.entities import CanonicalEntityRecord
from redteam_agent.knowledge.models import KnowledgeObservation, VerifiedFinding
from redteam_agent.mission.models import MissionLifecycleEvent, MissionState
from redteam_agent.storage.database import Database
from redteam_agent.storage.integrity import verify_object_integrity
from redteam_agent.storage.repositories import (
    MissionLifecycleEventRepository,
    MissionRevisionRepository,
    MissionStateRepository,
    PolicyDecisionRepository,
)
from redteam_agent.ui.models import (
    MissionDraftInput,
    ProviderPolicyDraftInput,
    StoredDraft,
    VllmCandidateInput,
    VllmConfigInput,
)

_MISSION_DRAFT_NS = "ui_mission_draft"
_PROVIDER_DRAFT_NS = "ui_provider_policy_draft"


class UIControlPlaneError(RuntimeError):
    """Base class for content-free UI failures."""


class UIDataUnavailableError(UIControlPlaneError):
    """The configured application database is unavailable or unprovisioned."""


class UIConflictError(UIControlPlaneError):
    """The requested operator action is stale or unavailable."""


class UIActionBlockedError(UIConflictError):
    """A safe, operator-actionable explanation for a denied UI command."""

    def __init__(self, *, code: str, message: str, resolution: str) -> None:
        super().__init__(message)
        self.code = code
        self.user_message = message
        self.resolution = resolution


class ApprovalDecisionPort(Protocol):
    def __call__(self, approval_request_id: str, verdict: str) -> None: ...


class VllmCapabilityPort(Protocol):
    def __call__(self, config: VllmConfigInput) -> dict[str, object]: ...


class VllmSettingsPort(Protocol):
    def public_state(self) -> dict[str, object]: ...

    def stage(self, request: VllmCandidateInput) -> dict[str, object]: ...

    def test_candidate(self, *, expected_version: int) -> dict[str, object]: ...

    def activate_candidate(self, *, expected_version: int) -> dict[str, object]: ...


class ADAssessmentReasoningPort(Protocol):
    def __call__(self) -> dict[str, object]: ...


class ADAssessmentEvaluationPort(Protocol):
    def __call__(self, snapshot: ADAssessmentSnapshot) -> dict[str, object]: ...


class ADAssessmentCollectorPort(Protocol):
    def __call__(self) -> dict[str, object]: ...


class ProviderStatusPort(Protocol):
    def __call__(self) -> dict[str, object]: ...


class MissionCommandPort(Protocol):
    @property
    def execution_enabled(self) -> bool: ...

    def create_from_draft(self, *, draft_id: str, draft: MissionDraftInput) -> MissionState: ...

    def transition(self, *, mission_id: str, expected_version: int, action: str) -> MissionState: ...


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class UIControlPlane:
    """Same-host control-plane projection over a provisioned application DB."""

    def __init__(
        self,
        *,
        database_path: str,
        approval_decision_port: ApprovalDecisionPort | None = None,
        mission_command_port: MissionCommandPort | None = None,
        provider_status_port: ProviderStatusPort | None = None,
        approved_session_refs: frozenset[str] = frozenset(),
        ad_assessment_reasoning_port: ADAssessmentReasoningPort | None = None,
        ad_assessment_evaluation_port: ADAssessmentEvaluationPort | None = None,
        ad_assessment_collector_port: ADAssessmentCollectorPort | None = None,
        vllm_capability_port: VllmCapabilityPort | None = None,
        vllm_public_config: VllmConfigInput | None = None,
        vllm_settings_port: VllmSettingsPort | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if database_path == ":memory:":
            raise UIDataUnavailableError("UI requires a durable application database path")
        self._database_path = str(Path(database_path).expanduser().resolve())
        self._approval_decision_port = approval_decision_port
        self._mission_command_port = mission_command_port
        self._provider_status_port = provider_status_port
        self._approved_session_refs = approved_session_refs
        self._ad_assessment_reasoning_port = ad_assessment_reasoning_port
        self._ad_assessment_evaluation_port = ad_assessment_evaluation_port
        self._ad_assessment_collector_port = ad_assessment_collector_port
        self._vllm_capability_port = vllm_capability_port
        self._vllm_public_config = vllm_public_config
        self._vllm_settings_port = vllm_settings_port
        if (vllm_capability_port is None) != (vllm_public_config is None):
            raise ValueError("vLLM capability port and public configuration must be attached together")
        self._clock = clock
        self._digests = DigestService()

    def _open(self) -> Database:
        path = Path(self._database_path)
        if not path.is_file():
            raise UIDataUnavailableError("application database does not exist")
        database = Database(self._database_path, create_schema=False)
        if not database.has_table("kv_store") or not database.has_table("occ_store"):
            database.close()
            raise UIDataUnavailableError("application database schema is not provisioned")
        return database

    @staticmethod
    def _json(value: object) -> str:
        payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def health(self) -> dict[str, object]:
        database = self._open()
        try:
            return {
                "status": "healthy",
                "mode": "live",
                "database": "connected",
                "approvalActionsEnabled": self._approval_decision_port is not None,
                "missionActionsEnabled": self._mission_command_port is not None,
                "missionExecutionEnabled": (
                    self._mission_command_port is not None and self._mission_command_port.execution_enabled
                ),
                "vllmChecksEnabled": self._vllm_capability_port is not None,
                "adAssessmentReasoningEnabled": self._ad_assessment_reasoning_port is not None,
                "adAssessmentEvaluationEnabled": self._ad_assessment_evaluation_port is not None,
                "adAssessmentCollectorEnabled": self._ad_assessment_collector_port is not None,
            }
        finally:
            database.close()

    def vllm_configuration(self) -> dict[str, object]:
        if self._vllm_settings_port is not None:
            state = self._vllm_settings_port.public_state()
            active = state.get("active")
            if not isinstance(active, dict) or not isinstance(active.get("config"), dict):
                raise UIDataUnavailableError("managed vLLM settings state is invalid")
            return {"enabled": True, "config": active["config"]}
        if self._vllm_public_config is None:
            return {"enabled": False, "config": None}
        return {
            "enabled": True,
            "config": self._vllm_public_config.model_dump(mode="json"),
        }

    def vllm_settings(self) -> dict[str, object]:
        if self._vllm_settings_port is None:
            if self._vllm_public_config is None:
                raise UIActionBlockedError(
                    code="VLLM_SETTINGS_UNAVAILABLE",
                    message="Runtime LLM settings management is not attached.",
                    resolution="Start the Kali product composition with its managed settings directory.",
                )
            return {
                "enabled": True,
                "active": {
                    "version": 1,
                    "config": self._vllm_public_config.model_dump(mode="json"),
                    "apiKeyConfigured": True,
                    "activatedAt": None,
                    "transportSecurity": (
                        "encrypted"
                        if self._vllm_public_config.baseUrl.startswith("https://")
                        else "isolated_network_required"
                    ),
                },
                "candidate": None,
                "allowedCidrs": ["deployment-managed"],
                "settingsMutable": False,
                "modelMutable": False,
            }
        return self._vllm_settings_port.public_state()

    def stage_vllm_candidate(self, request: VllmCandidateInput) -> dict[str, object]:
        if self._vllm_settings_port is None:
            return self.vllm_settings()
        return self._vllm_settings_port.stage(request)

    def test_vllm_candidate(self, *, expected_version: int) -> dict[str, object]:
        if self._vllm_settings_port is None:
            return self.vllm_settings()
        return self._vllm_settings_port.test_candidate(expected_version=expected_version)

    def activate_vllm_candidate(self, *, expected_version: int) -> dict[str, object]:
        if self._vllm_settings_port is None:
            return self.vllm_settings()
        return self._vllm_settings_port.activate_candidate(expected_version=expected_version)

    def ad_assessment_catalog(self) -> dict[str, object]:
        """Expose the closed, non-authoritative AD assessment capability catalog."""

        return ad_assessment_catalog_view(live_collector_attached=self._ad_assessment_collector_port is not None)

    def evaluate_ad_assessment(self, snapshot: ADAssessmentSnapshot) -> dict[str, object]:
        """Evaluate normalized evidence without granting collection or execution authority."""

        if snapshot.source_type != "simulator":
            raise UIConflictError(
                "the UI endpoint accepts simulator evidence only; verified evidence requires a trusted collector"
            )
        result = ADAssessmentVerifier(clock=self._clock).evaluate(snapshot)
        return result.model_dump(mode="json")

    def recommend_ad_assessment(self) -> dict[str, object]:
        """Ask the qualified local Planner to select one advisory inspection."""

        if self._ad_assessment_reasoning_port is None:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_REASONING_UNAVAILABLE",
                message="Local LLM assessment reasoning is not attached.",
                resolution="Start the Kali product composition with its managed vLLM configuration.",
            )
        try:
            return self._ad_assessment_reasoning_port()
        except LLMCapabilityError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_CAPABILITY_REQUIRED",
                message="The local LLM has no current passing Planner capability evidence.",
                resolution="Run the VLLM capability check, then request the recommendation again.",
            ) from None

    def evaluate_ad_assessment_with_llm(
        self,
        snapshot: ADAssessmentSnapshot,
    ) -> dict[str, object]:
        """Require complete five-category LLM/verifier consensus for simulator evidence."""

        if snapshot.source_type != "simulator":
            raise UIConflictError(
                "the UI endpoint accepts simulator evidence only; verified evidence requires a trusted collector"
            )
        if self._ad_assessment_evaluation_port is None:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_EVALUATION_UNAVAILABLE",
                message="Complete local LLM assessment is not attached.",
                resolution="Start the Kali product composition with its managed vLLM configuration.",
            )
        try:
            return self._ad_assessment_evaluation_port(snapshot)
        except LLMCapabilityError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_CAPABILITY_REQUIRED",
                message="The local LLM has no current passing Planner capability evidence.",
                resolution="Run the VLLM capability check, then run the complete assessment again.",
            ) from None
        except PlannerCandidateError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_OUTPUT_REJECTED",
                message="The local LLM did not return an exact allowed classification.",
                resolution="Check the local model capability and retry; no assessment result was accepted.",
            ) from None
        except LLMTransportError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_UNREACHABLE",
                message="The local LLM server could not complete the assessment.",
                resolution="Verify the managed vLLM endpoint, then retry the complete assessment.",
            ) from None
        except LLMRequestBudgetError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_BUDGET_BLOCKED",
                message="The local LLM assessment exceeded its fixed request budget.",
                resolution="Run the capability check and verify the configured context limits before retrying.",
            ) from None

    def collect_and_evaluate_ad_assessment(self) -> dict[str, object]:
        """Collect trusted LDAPS evidence and pass it directly to LLM/verifier consensus."""

        if self._ad_assessment_collector_port is None:
            raise UIActionBlockedError(
                code="AD_COLLECTOR_NOT_ATTACHED",
                message="The live AD collector is not attached.",
                resolution="Enable the server-owned AD collector configuration and restart the product.",
            )
        try:
            return self._ad_assessment_collector_port()
        except ADCollectorError as exc:
            raise UIActionBlockedError(
                code=exc.code,
                message=exc.user_message,
                resolution=exc.resolution,
            ) from None
        except LLMCapabilityError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_CAPABILITY_REQUIRED",
                message="The local LLM has no current passing Planner capability evidence.",
                resolution="Run the VLLM capability check, then run live AD assessment again.",
            ) from None
        except PlannerCandidateError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_OUTPUT_REJECTED",
                message="The local LLM did not return an exact allowed classification.",
                resolution="Check the local model capability and retry; no assessment result was accepted.",
            ) from None
        except LLMTransportError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_UNREACHABLE",
                message="The local LLM server could not complete live AD assessment.",
                resolution="Verify the managed vLLM endpoint, then retry live AD assessment.",
            ) from None
        except LLMRequestBudgetError:
            raise UIActionBlockedError(
                code="AD_ASSESSMENT_LLM_BUDGET_BLOCKED",
                message="Live AD assessment exceeded its fixed local-LLM request budget.",
                resolution="Verify the configured context limits and rerun the capability check.",
            ) from None

    def save_mission_draft(self, draft: MissionDraftInput) -> dict[str, object]:
        return self._save_draft(namespace=_MISSION_DRAFT_NS, prefix="mission-draft", draft=draft)

    def save_provider_policy_draft(self, draft: ProviderPolicyDraftInput) -> dict[str, object]:
        return self._save_draft(namespace=_PROVIDER_DRAFT_NS, prefix="provider-draft", draft=draft)

    def create_mission(self, *, draft_id: str) -> dict[str, object]:
        if self._mission_command_port is None:
            raise UIConflictError("trusted mission owner service is not attached")
        database = self._open()
        try:
            raw = database.get(_MISSION_DRAFT_NS, draft_id)
        finally:
            database.close()
        if raw is None:
            raise UIConflictError("mission draft is unavailable")
        stored = StoredDraft.from_untrusted_json(raw)
        if stored.draftId != draft_id:
            raise UIDataUnavailableError("mission draft identity is invalid")
        draft = MissionDraftInput.from_untrusted_json(json.dumps(thaw(stored.draft), sort_keys=True).encode("utf-8"))
        try:
            state = self._mission_command_port.create_from_draft(draft_id=draft_id, draft=draft)
        except MissionValidationError:
            raise UIActionBlockedError(
                code="MISSION_DRAFT_NOT_ACTIVATABLE",
                message="The saved Mission draft cannot become an authoritative Mission.",
                resolution="Resolve every item in Execution readiness, save the draft again, then create the Mission.",
            ) from None
        return self._mission_state_view(state)

    def transition_mission(self, *, mission_id: str, expected_version: int, action: str) -> dict[str, object]:
        if self._mission_command_port is None:
            raise UIConflictError("trusted mission owner service is not attached")
        try:
            state = self._mission_command_port.transition(
                mission_id=mission_id,
                expected_version=expected_version,
                action=action,
            )
        except MissionStateVersionConflictError:
            raise UIActionBlockedError(
                code="MISSION_STATE_STALE",
                message="The Mission changed after this page was loaded.",
                resolution="Reload the current Mission state before trying the transition again.",
            ) from None
        except LLMCapabilityError:
            raise UIActionBlockedError(
                code="LLM_CAPABILITY_REQUIRED",
                message="The fixed LLM profile has no current passing capability evidence.",
                resolution="Run the VLLM capability check, then validate the Mission again.",
            ) from None
        except MissionValidationError:
            raise UIActionBlockedError(
                code="MISSION_VALIDATION_BLOCKED",
                message="Mission validation is blocked by an unresolved scope, session, or capability requirement.",
                resolution="Review Execution readiness and resolve its blocking items before retrying.",
            ) from None
        except MissionLifecycleError:
            raise UIActionBlockedError(
                code="MISSION_TRANSITION_INVALID",
                message="The requested transition is not valid from the current Mission state.",
                resolution="Reload the Mission and use the action shown for its current state.",
            ) from None
        return self._mission_state_view(state)

    def readiness(self) -> dict[str, object]:
        """Explain why Mission execution cannot currently advance."""
        database = self._open()
        try:
            mission_rows = database.get_all(_MISSION_DRAFT_NS)
            provider_rows = database.get_all(_PROVIDER_DRAFT_NS)
            draft: MissionDraftInput | None = None
            if mission_rows:
                stored_drafts = [StoredDraft.from_untrusted_json(raw) for _key, raw in mission_rows]
                latest = max(stored_drafts, key=lambda item: item.savedAt)
                draft = MissionDraftInput.from_untrusted_json(
                    json.dumps(thaw(latest.draft), sort_keys=True).encode("utf-8")
                )
            state = self._selected_mission_state(database)
            capability_count = int(
                database.connection.execute(
                    "SELECT COUNT(*) FROM occ_store WHERE namespace = ?",
                    ("llm_capability_results",),
                ).fetchone()[0]
            )
        finally:
            database.close()

        provider_status = (
            self._provider_status_port() if self._provider_status_port is not None else self._default_provider_status()
        )
        blockers: list[dict[str, str]] = []
        checks: list[dict[str, str]] = []

        def block(identifier: str, category: str, title: str, detail: str, resolution: str) -> None:
            blockers.append(
                {
                    "id": identifier,
                    "category": category,
                    "title": title,
                    "detail": detail,
                    "resolution": resolution,
                }
            )

        def passed(identifier: str, title: str, detail: str) -> None:
            checks.append({"id": identifier, "title": title, "detail": detail})

        if draft is None:
            block(
                "MISSION_DRAFT_MISSING",
                "mission",
                "Mission draft has not been saved",
                "There is no reviewed Mission boundary in the control-plane database.",
                "Open New Mission, complete every step, and save the draft.",
            )
        else:
            passed("MISSION_DRAFT_SAVED", "Mission draft saved", "A reviewed draft exists in the durable database.")
            if draft.successType != "session_exists":
                block(
                    "SUCCESS_CONDITION_UNSUPPORTED",
                    "mission",
                    "Success condition cannot be verified",
                    f"The selected '{draft.successType}' condition has no authoritative evaluator in this runtime.",
                    "Select Active session exists and provide an approved live session reference.",
                )
            elif draft.successValue not in self._approved_session_refs:
                block(
                    "SESSION_REFERENCE_UNAPPROVED",
                    "session",
                    "Session reference is not approved",
                    "The success condition does not reference a session registered by live C2 inventory.",
                    "Create or verify the authorized Beacon, then add its exact reference to "
                    "approvedSessionRefs and restart.",
                )
            else:
                passed(
                    "SESSION_REFERENCE_APPROVED",
                    "Session reference approved",
                    "The exact success-session reference is registered by the composition root.",
                )
            unsupported = sorted(
                {target.type for target in draft.targets if target.type in {"remote_filesystem", "other"}}
            )
            if unsupported:
                block(
                    "TARGET_TYPE_UNSUPPORTED",
                    "scope",
                    "One or more target types cannot be activated",
                    f"Unsupported target types: {', '.join(unsupported)}.",
                    "Use a registered network, host, session, hostname, domain, or URL target.",
                )
            else:
                passed("TARGET_SCOPE_TYPED", "Target scope is typed", "Every target uses a registered scope type.")

        if state is None:
            block(
                "MISSION_NOT_CREATED",
                "mission",
                "Authoritative Mission has not been created",
                "Saving a draft does not create execution authority.",
                "Resolve the draft blockers, then select Create Mission.",
            )
            stage = "mission_configuration"
        else:
            passed("MISSION_CREATED", "Authoritative Mission exists", f"Current lifecycle state: {state.state}.")
            stage = state.state.lower()
            if state.state == "DRAFT":
                block(
                    "MISSION_NOT_VALIDATED",
                    "mission",
                    "Mission has not passed validation",
                    "The owner service has created the Mission, but its immutable requirements are not validated.",
                    "Resolve the remaining blockers and select Validate.",
                )

        if not provider_rows:
            block(
                "PROVIDER_POLICY_DRAFT_MISSING",
                "provider",
                "C2 and tool policy has not been saved",
                "No reviewed Sliver/Impacket selection is stored in the control-plane database.",
                "Open C2 & Tools, review the fixed operation allowlist, and save the policy draft.",
            )
        else:
            passed("PROVIDER_POLICY_SAVED", "Provider policy draft saved", "A reviewed provider selection exists.")

        if self._vllm_capability_port is None:
            block(
                "LLM_GATEWAY_UNAVAILABLE",
                "llm",
                "Trusted VLLM gateway is not attached",
                "The UI cannot produce Phase 2 capability evidence.",
                "Start the authenticated Kali product composition with its fixed VLLM artifacts and credential.",
            )
        elif capability_count == 0:
            block(
                "LLM_CAPABILITY_NOT_RUN",
                "llm",
                "LLM capability check has not passed in this database",
                "No direct-network schema capability evidence is available for Mission validation.",
                "Open VLLM Settings and run Test connection & capabilities.",
            )
        else:
            passed(
                "LLM_CAPABILITY_PRESENT",
                "LLM capability evidence present",
                f"Stored result records: {capability_count}.",
            )

        sliver = provider_status.get("sliver")
        if isinstance(sliver, dict):
            if sliver.get("credentialPresent") is False:
                block(
                    "SLIVER_CREDENTIAL_MISSING",
                    "provider",
                    "Sliver operator credential is not provisioned",
                    "The runtime systemd credential path is unavailable.",
                    "Encrypt and install joe.cfg through the configured systemd LoadCredentialEncrypted entry.",
                )
            if sliver.get("identityAttested") is False:
                block(
                    "SLIVER_IDENTITY_UNATTESTED",
                    "provider",
                    "Sliver operator identity is not attested",
                    "A credential file alone does not prove a live gRPC/mTLS connection to the approved server.",
                    "Connect with the approved operator configuration and record the live Sliver "
                    "server identity attestation.",
                )
            if sliver.get("beaconPresent") is False:
                block(
                    "SLIVER_BEACON_MISSING",
                    "provider",
                    "No approved live HTTP Beacon is present",
                    "Sliver inventory cannot bind the Mission to a current target session.",
                    "Establish and attest the authorized HTTP Beacon outside this application, "
                    "then register its session reference.",
                )
        impacket = provider_status.get("impacket")
        if isinstance(impacket, dict):
            if impacket.get("installed") is False:
                block(
                    "IMPACKET_MCP_UNAVAILABLE",
                    "tool",
                    "Impacket MCP runtime is unavailable",
                    "The fixed one-shot MCP executable or package is missing.",
                    "Install the pinned impacket-mcp optional dependencies in the product venv.",
                )
            elif impacket.get("sandboxAttested") is False:
                block(
                    "IMPACKET_SANDBOX_UNATTESTED",
                    "tool",
                    "Impacket worker isolation is not attested",
                    "The executable exists, but OS-level target/port egress enforcement is not proven.",
                    "Run the dedicated worker under the approved egress sandbox and record its "
                    "Phase 5 live attestation.",
                )

        runtime = provider_status.get("runtime")
        if isinstance(runtime, dict) and runtime.get("tpmKeyProviderAttested") is False:
            block(
                "TPM_KEY_PROVIDER_UNAVAILABLE",
                "runtime",
                "TPM-backed persistent key provider is unavailable",
                "This Kali host cannot yet provide the hardware-backed persistent signing "
                "boundary required for production execution.",
                "Attach and attest the approved TPM-backed key provider before enabling the production composition.",
            )

        if self._mission_command_port is not None and not self._mission_command_port.execution_enabled:
            block(
                "EXECUTION_RUNTIME_DISABLED",
                "runtime",
                "Mission execution worker is disabled",
                "The control plane may create and validate records but cannot dispatch actions.",
                "Attach the production-qualified execution composition after all live provider and TPM gates pass.",
            )

        return {
            "status": "ready" if not blockers else "blocked",
            "stage": stage,
            "summary": (
                "Mission execution prerequisites are satisfied."
                if not blockers
                else f"Mission execution is blocked by {len(blockers)} unresolved item(s)."
            ),
            "blockerCount": len(blockers),
            "blockers": blockers,
            "checks": checks,
        }

    @staticmethod
    def _mission_state_view(state: MissionState) -> dict[str, object]:
        return {
            "missionId": state.mission_id,
            "missionRevision": state.mission_revision,
            "missionStateVersion": state.mission_state_version,
            "authorizationEpoch": state.authorization_epoch,
            "state": state.state,
        }

    def _save_draft(
        self, *, namespace: str, prefix: str, draft: MissionDraftInput | ProviderPolicyDraftInput
    ) -> dict[str, object]:
        now = self._clock().astimezone(UTC)
        draft_id = f"{prefix}-{uuid4()}"
        stored = StoredDraft(
            draftId=draft_id,
            savedAt=now,
            draft=draft.model_dump(mode="json"),
        )
        database = self._open()
        try:
            database.put_idempotent(namespace, draft_id, self._json(stored))
        finally:
            database.close()
        return {"draftId": draft_id, "savedAt": now.isoformat()}

    def dashboard(self) -> dict[str, object]:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return {
                    "mission": None,
                    "metrics": {"confirmedFindings": 0, "mappedEntities": 0, "pendingDecisions": 0},
                    "timeline": [],
                }
            revision = MissionRevisionRepository(database, self._digests).get(state.mission_id, state.mission_revision)
            if revision is None:
                raise UIDataUnavailableError("current mission revision is missing")
            findings = self._verified_findings(database, state.mission_id)
            entities = self._entities(database, state.mission_id)
            pending = sum(
                1
                for item in self._interventions(database)
                if item["missionId"] == state.mission_id and item["state"] == "pending"
            )
            events = MissionLifecycleEventRepository(database, self._digests).events_for(state.mission_id)
            scopes = [self._scope_label(rule.model_dump(mode="json")) for rule in revision.allowed_execution_scope]
            return {
                "mission": {
                    "id": state.mission_id,
                    "title": revision.description or state.mission_id,
                    "state": state.state.lower(),
                    "revision": state.mission_revision,
                    "authorizationEpoch": state.authorization_epoch,
                    "authorizationReference": revision.authorization_reference,
                    "validUntil": revision.valid_until.isoformat(),
                    "objectives": list(revision.objectives),
                    "scopes": scopes,
                },
                "metrics": {
                    "confirmedFindings": len(findings),
                    "mappedEntities": len(entities),
                    "pendingDecisions": pending,
                },
                "timeline": [self._event_view(event) for event in events[-6:]],
            }
        finally:
            database.close()

    def phases(self) -> list[dict[str, object]]:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return []
            status = {
                "DRAFT": "not_started",
                "VALIDATED": "not_started",
                "RUNNING": "current",
                "PAUSED": "blocked",
                "FINALIZING": "current",
                "WAITING_HUMAN_REVIEW": "approval_required",
                "COMPLETED": "completed",
                "COMPLETED_WITH_UNRESOLVED_ITEMS": "completed",
                "FAILED": "failed",
                "ABORTED": "failed",
            }[state.state]
            return [
                {
                    "phase": "OBJECTIVE",
                    "label": "Mission objective",
                    "status": status,
                    "detail": f"Lifecycle state: {state.state}",
                }
            ]
        finally:
            database.close()

    def activity(self) -> dict[str, object] | None:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return None
            rows = database.connection.execute(
                "SELECT json FROM executions WHERE mission_id = ? "
                "ORDER BY json_extract(json, '$.updated_at') DESC, execution_id DESC LIMIT 1",
                (state.mission_id,),
            ).fetchone()
            if rows is None:
                return None
            execution = load_model_from_json(ExecutionRecord, str(rows[0]))
            verify_object_integrity(execution, self._digests)
            terminal = execution.provider_execution_state not in {
                "PLANNED",
                "AUTHORIZED",
                "DISPATCH_CLAIMED",
                "DISPATCHED",
                "RUNNING",
                "CANCEL_REQUESTED",
                "RECONCILING",
            }
            elapsed = max(0, int((execution.updated_at - execution.created_at).total_seconds()))
            return {
                "id": f"activity-{execution.execution_id}",
                "executionId": execution.execution_id,
                "status": self._activity_status(execution.provider_execution_state),
                "title": execution.tool_ref.tool_id,
                "toolDisplayName": execution.tool_ref.tool_id,
                "operation": execution.tool_ref.tool_id,
                "adapterId": execution.resolved_adapter_id,
                "references": [
                    {"name": "mission_ref", "type": "mission", "id": execution.mission_id},
                    {"name": "execution_ref", "type": "execution", "id": execution.execution_id},
                ],
                "startedAt": execution.created_at.isoformat(),
                "completedAt": execution.updated_at.isoformat() if terminal else None,
                "elapsedSeconds": elapsed,
                "rawOutputAvailable": False,
                "summary": f"Sanitized execution state: {execution.provider_execution_state}",
            }
        finally:
            database.close()

    def interventions(self) -> list[dict[str, object]]:
        database = self._open()
        try:
            return self._interventions(database)
        finally:
            database.close()

    def _interventions(self, database: Database) -> list[dict[str, object]]:
        records = self._approval_records(database)
        decision_repository = PolicyDecisionRepository(database, self._digests)
        now = self._clock().astimezone(UTC)
        views: list[dict[str, object]] = []
        for row_key, raw in database.get_all("approval_requests"):
            request = load_model_from_json(ApprovalRequest, raw)
            verify_object_integrity(request, self._digests)
            if row_key != request.approval_request_id:
                raise UIDataUnavailableError("approval request identity is invalid")
            record = records.get(request.approval_request_id)
            if record is not None:
                state = "approved" if record.decision == "APPROVED" else "rejected"
            elif now >= request.expires_at:
                state = "expired"
            else:
                state = "pending"
            decision = decision_repository.get(request.policy_decision_id)
            if decision is None:
                raise UIDataUnavailableError("approval policy decision is missing")
            presentation = request.presentation
            actionable = state == "pending" and self._approval_decision_port is not None
            views.append(
                {
                    "id": request.approval_request_id,
                    "kind": "approval",
                    "missionId": request.mission_id,
                    "missionRevision": request.mission_revision,
                    "authorizationEpoch": request.authorization_epoch,
                    "title": presentation.tool_display_name,
                    "summary": "Bound execution intent awaiting an immutable operator decision.",
                    "createdAt": request.issued_at.isoformat(),
                    "expiresAt": request.expires_at.isoformat(),
                    "state": state,
                    "actionable": actionable,
                    "disabledReason": (
                        None if actionable else "Trusted approval service is not attached or request is closed."
                    ),
                    "presentationDigest": presentation.presentation_digest,
                    "toolDisplayName": presentation.tool_display_name,
                    "targets": [
                        self._target_label(target.model_dump(mode="json")) for target in presentation.normalized_targets
                    ],
                    "redactedArguments": presentation.redacted_arguments,
                    "risk": presentation.effective_risk,
                    "sideEffect": presentation.side_effect,
                    "adapterId": decision.resolved_adapter_id,
                }
            )
        return sorted(views, key=lambda item: (item["state"] != "pending", str(item["createdAt"])), reverse=False)

    def submit_approval(self, *, approval_request_id: str, presentation_digest: str, verdict: str) -> dict[str, object]:
        if self._approval_decision_port is None:
            raise UIConflictError("trusted approval service is not attached")
        current = next((item for item in self.interventions() if item["id"] == approval_request_id), None)
        if current is None or current["state"] != "pending" or current["presentationDigest"] != presentation_digest:
            raise UIConflictError("approval request is unavailable, stale, or binding-mismatched")
        self._approval_decision_port(approval_request_id, verdict.upper())
        updated = next((item for item in self.interventions() if item["id"] == approval_request_id), None)
        if updated is None:
            raise UIConflictError("approval decision outcome is unavailable")
        return updated

    def knowledge(self) -> dict[str, object]:
        database = self._open()
        try:
            state = self._selected_mission_state(database)
            if state is None:
                return {"nodes": [], "edges": [], "findings": [], "artifacts": []}
            entities = self._entities(database, state.mission_id)
            observations = self._observations(database, state.mission_id)
            findings = self._verified_findings(database, state.mission_id)
            artifacts = self._artifacts(database, state.mission_id)
            node_ids = {entity.entity_id for entity in entities}
            nodes = [self._entity_view(entity) for entity in entities]
            edges = [
                {
                    "id": observation.observation_id,
                    "source": observation.subject_ref,
                    "target": observation.object_ref,
                    "label": observation.predicate,
                }
                for observation in observations
                if observation.object_ref is not None
                and observation.subject_ref in node_ids
                and observation.object_ref in node_ids
            ]
            artifact_views = [self._artifact_view(artifact) for artifact in artifacts]
            return {
                "nodes": nodes,
                "edges": edges,
                "findings": [self._finding_view(finding) for finding in findings],
                "artifacts": artifact_views,
            }
        finally:
            database.close()

    def provider_status(self) -> dict[str, object]:
        database = self._open()
        try:
            rows = database.get_all(_PROVIDER_DRAFT_NS)
            latest = None
            if rows:
                drafts = [StoredDraft.from_untrusted_json(raw) for _key, raw in rows]
                selected = max(drafts, key=lambda draft: draft.savedAt)
                validated = ProviderPolicyDraftInput.from_untrusted_json(
                    json.dumps(thaw(selected.draft), sort_keys=True).encode("utf-8")
                )
                latest = {
                    "draftId": selected.draftId,
                    "savedAt": selected.savedAt.isoformat(),
                    "draft": validated.model_dump(mode="json"),
                }
            status = (
                self._provider_status_port()
                if self._provider_status_port is not None
                else self._default_provider_status()
            )
            if "latestDraft" in status:
                raise UIDataUnavailableError("provider status port cannot own draft state")
            return {**status, "latestDraft": latest}
        finally:
            database.close()

    @staticmethod
    def _default_provider_status() -> dict[str, object]:
        try:
            from importlib.metadata import version

            impacket_version = version("impacket")
        except Exception:  # pragma: no cover - environment dependent, result is intentionally coarse
            impacket_version = None
        return {
            "mode": "live",
            "runtime": {
                "productionEligible": False,
                "missionExecutionEnabled": False,
                "tpmKeyProviderAttested": False,
                "blockers": ["Production runtime attestations are not configured."],
            },
            "tuoni": {"edition": "commercial", "version": "latest", "access": "unconfigured"},
            "sliver": {
                "version": "1.7.7",
                "operator": "joe",
                "operatorConfigLocation": "downloads",
                "operatorAccess": "unconfigured",
                "implantTransport": "http",
                "beaconPresent": False,
                "identityAttested": False,
            },
            "impacket": {
                "installed": impacket_version is not None,
                "version": impacket_version,
                "server": "redteam-impacket-mcp",
                "operations": [
                    "impacket.smb.negotiate",
                    "impacket.smb.authenticate",
                    "impacket.smb.list_shares",
                    "impacket.rpc.endpoint_map",
                ],
                "sandboxAttested": False,
            },
        }

    def check_vllm(self, config: VllmConfigInput) -> dict[str, object]:
        if self._vllm_capability_port is None:
            return {
                "status": "failed",
                "summary": "The trusted Phase 2 capability gateway is not attached; no network request was sent.",
                "latencyMs": 0,
                "checkedAt": self._clock().astimezone(UTC).isoformat(),
                "checks": [
                    {
                        "name": "Trusted gateway",
                        "status": "failed",
                        "detail": "Start the UI from the production composition root with a capability port.",
                    }
                ],
            }
        return self._vllm_capability_port(config)

    def _selected_mission_state(self, database: Database) -> MissionState | None:
        states = MissionStateRepository(database, self._digests).all_states()
        if not states:
            return None
        priority = {
            "RUNNING": 0,
            "WAITING_HUMAN_REVIEW": 1,
            "FINALIZING": 2,
            "PAUSED": 3,
            "VALIDATED": 4,
            "DRAFT": 5,
            "FAILED": 6,
            "ABORTED": 7,
            "COMPLETED_WITH_UNRESOLVED_ITEMS": 8,
            "COMPLETED": 9,
        }
        return sorted(states, key=lambda item: (priority[item.state], item.mission_id))[0]

    def _approval_records(self, database: Database) -> dict[str, ApprovalRecord]:
        records: dict[str, ApprovalRecord] = {}
        for row_key, raw in database.get_all("approvals"):
            record = load_model_from_json(ApprovalRecord, raw)
            verify_object_integrity(record, self._digests)
            if row_key != record.approval_id or record.approval_request_id in records:
                raise UIDataUnavailableError("approval record identity is invalid")
            records[record.approval_request_id] = record
        return records

    def _entities(self, database: Database, mission_id: str) -> tuple[CanonicalEntityRecord, ...]:
        result: list[CanonicalEntityRecord] = []
        for row_key, version, raw in database.occ_get_all("canonical_entity"):
            entity = load_model_from_json(CanonicalEntityRecord, raw)
            if row_key != entity.entity_id or version != entity.entity_version:
                raise UIDataUnavailableError("knowledge entity identity is invalid")
            payload = entity.model_dump(mode="python")
            digest = str(payload.pop("record_digest"))
            self._digests.verify("canonical_entity_digest", payload, digest)
            if entity.mission_id == mission_id:
                result.append(entity)
        return tuple(result)

    def _observations(self, database: Database, mission_id: str) -> tuple[KnowledgeObservation, ...]:
        result: list[KnowledgeObservation] = []
        for row_key, _version, raw in database.occ_get_all("knowledge_observation"):
            observation = load_model_from_json(KnowledgeObservation, raw)
            if row_key != observation.observation_id:
                raise UIDataUnavailableError("knowledge observation identity is invalid")
            payload = observation.model_dump(mode="python")
            digest = str(payload.pop("observation_digest"))
            self._digests.verify("knowledge_observation_digest", payload, digest)
            if observation.mission_id == mission_id:
                result.append(observation)
        return tuple(result)

    def _verified_findings(self, database: Database, mission_id: str) -> tuple[VerifiedFinding, ...]:
        result: list[VerifiedFinding] = []
        for row_key, version, raw in database.occ_get_all("verified_finding"):
            finding = load_model_from_json(VerifiedFinding, raw)
            if row_key != finding.finding_id or version != finding.finding_version:
                raise UIDataUnavailableError("verified finding identity is invalid")
            payload = finding.model_dump(mode="python")
            digest = str(payload.pop("finding_digest"))
            self._digests.verify("verified_finding_digest", payload, digest)
            if finding.mission_id == mission_id:
                result.append(finding)
        return tuple(result)

    def _artifacts(self, database: Database, mission_id: str) -> tuple[ArtifactReference, ...]:
        result: list[ArtifactReference] = []
        for row_key, _version, raw in database.occ_get_all("artifact"):
            artifact = load_model_from_json(ArtifactReference, raw)
            if row_key != artifact.artifact_id:
                raise UIDataUnavailableError("artifact identity is invalid")
            payload = artifact.model_dump(mode="python")
            digest = str(payload.pop("artifact_digest"))
            self._digests.verify("artifact_digest", payload, digest)
            if artifact.mission_id == mission_id and artifact.variant == "redacted":
                result.append(artifact)
        return tuple(result)

    @staticmethod
    def _scope_label(scope: dict[str, Any]) -> str:
        kind = str(scope.get("type", "scope"))
        if kind == "network":
            return f"network:{','.join(str(item) for item in scope.get('cidrs', []))}"
        for field in ("host_id", "session_id", "hostname", "domain", "path_prefix"):
            if scope.get(field):
                return f"{kind}:{scope[field]}"
        return kind

    @staticmethod
    def _target_label(target: dict[str, Any]) -> str:
        suffix = ""
        if target.get("port") is not None:
            suffix = f":{target['port']}/{target.get('protocol') or 'unknown'}"
        return f"{target.get('type', 'target')}:{target.get('canonical_value', 'unknown')}{suffix}"

    @staticmethod
    def _event_view(event: MissionLifecycleEvent) -> dict[str, object]:
        return {
            "id": f"{event.mission_id}-{event.sequence_number}",
            "title": f"{event.from_state} → {event.to_state}",
            "detail": event.reason,
            "timestamp": event.occurred_at.isoformat(),
        }

    @staticmethod
    def _activity_status(state: str) -> str:
        if state in {
            "PLANNED",
            "AUTHORIZED",
            "DISPATCH_CLAIMED",
            "DISPATCHED",
            "RUNNING",
            "CANCEL_REQUESTED",
            "RECONCILING",
        }:
            return "running"
        if state == "SUCCEEDED":
            return "completed"
        if state == "BLOCKED":
            return "blocked"
        return "failed"

    @staticmethod
    def _entity_view(entity: CanonicalEntityRecord) -> dict[str, object]:
        category = {
            "host": "asset",
            "network_asset": "asset",
            "ad_principal": "account",
            "windows_local_principal": "account",
            "linux_principal": "account",
            "domain": "domain",
            "session": "session",
        }[entity.entity_type]
        return {
            "id": entity.entity_id,
            "label": entity.strong_key_value,
            "category": category,
            "verification": "confirmed",
            "detail": f"{entity.entity_type} · {entity.strong_key_type} · version {entity.entity_version}",
        }

    @staticmethod
    def _finding_view(finding: VerifiedFinding) -> dict[str, object]:
        return {
            "id": finding.finding_id,
            "title": finding.predicate.replace("_", " "),
            "target": finding.subject_ref,
            "verification": finding.verification_state,
            "confidence": 1.0,
            "sourceExecutionId": finding.source_execution_id,
            "artifactId": None,
            "timestamp": finding.recorded_at.isoformat(),
            "summary": "Deterministically verified execution outcome.",
        }

    @staticmethod
    def _artifact_view(artifact: ArtifactReference) -> dict[str, object]:
        classification = {
            "normal": "normal",
            "sensitive": "sensitive",
            "secret": "secret_reference",
        }[artifact.classification]
        return {
            "id": artifact.artifact_id,
            "mediaType": artifact.media_type,
            "sizeBytes": artifact.size_bytes,
            "classification": classification,
            "variant": "redacted",
            "createdAt": artifact.created_at.isoformat(),
        }
