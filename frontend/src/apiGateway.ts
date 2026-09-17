import { z } from "zod";
import {
  adAssessmentCatalogSchema,
  adAssessmentConsensusResultSchema,
  adAssessmentRecommendationSchema,
  adAssessmentResultSchema,
  agentActivitySchema,
  attackPhaseProgressSchema,
  dashboardSchema,
  executionReadinessSchema,
  healthSchema,
  interventionSchema,
  knowledgeGraphSchema,
  managedVllmConfigSchema,
  missionStateSchema,
  operatorSessionSchema,
  providerStatusSchema,
  timestampSchema,
  vllmCapabilityResultSchema,
  vllmCandidateActivationResultSchema,
  vllmCandidateTestResultSchema,
  vllmSettingsSchema,
  type FrontendGateway,
  type MissionDraft,
  type ProviderPolicyDraft,
  type VllmConfig,
} from "./types";

const savedDraftSchema = z.object({ draftId: z.string().min(1), savedAt: timestampSchema }).strict();
const errorSchema = z.object({
  error: z.string(),
  code: z.string(),
  resolution: z.string().optional(),
}).strict();

function buildADAssessmentSimulationSnapshot() {
  const snapshotId = `ui-simulator-${Date.now()}`;
  return {
    snapshot_id: snapshotId,
    domain_ref: "domain:simulated.local",
    source_type: "simulator",
    source_artifact_ids: [`artifact-${snapshotId}`],
    collected_at: new Date().toISOString(),
    privileged_access: { unexpected_tier_zero_membership_count: 1, stale_privileged_account_count: 0, excessive_delegated_admin_count: 0 },
    kerberos_service_accounts: { service_account_with_spn_count: 2, weak_encryption_service_account_count: 1, stale_password_service_account_count: 0, unmanaged_service_account_count: 1 },
    kerberos_preauth: { preauthentication_disabled_account_count: 1 },
    adcs: { exposure_counts: [{ esc_id: "ESC1", affected_object_count: 1 }] },
    delegation: { unconstrained_delegation_account_count: 0, broad_constrained_delegation_account_count: 1, protocol_transition_account_count: 0, risky_rbcd_acl_count: 0 },
  };
}

async function request(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json", "X-RedTeam-UI": "1" } : {}),
      ...init?.headers,
    },
    credentials: "same-origin",
  });
  const value: unknown = await response.json();
  if (!response.ok) {
    const parsed = errorSchema.safeParse(value);
    throw new Error(parsed.success
      ? `${parsed.data.error} (${parsed.data.code})${parsed.data.resolution ? ` ${parsed.data.resolution}` : ""}`
      : `Request failed (${response.status})`);
  }
  return value;
}

function zonedUtc(value: string): string {
  if (/Z$|[+-]\d{2}:\d{2}$/.test(value)) return value;
  return `${value.length === 16 ? `${value}:00` : value}Z`;
}

export const apiGateway: FrontendGateway = {
  async getOperatorSession() {
    return operatorSessionSchema.parse(await request("/api/v1/session"));
  },
  async loginOperator(token: string) {
    return operatorSessionSchema.parse(await request("/api/v1/session", {
      method: "POST",
      body: JSON.stringify({ token }),
    }));
  },
  async logoutOperator() {
    return operatorSessionSchema.parse(await request("/api/v1/session", {
      method: "DELETE",
      headers: { "X-RedTeam-UI": "1" },
    }));
  },
  async getVllmConfiguration() {
    return managedVllmConfigSchema.parse(await request("/api/v1/vllm/config"));
  },
  async getVllmSettings() {
    return vllmSettingsSchema.parse(await request("/api/v1/vllm/settings"));
  },
  async stageVllmCandidate(baseUrl: string, apiKey: string) {
    return vllmSettingsSchema.parse(await request("/api/v1/vllm/candidate", {
      method: "POST",
      body: JSON.stringify({ baseUrl, apiKey }),
    }));
  },
  async testVllmCandidate(version: number) {
    return vllmCandidateTestResultSchema.parse(await request("/api/v1/vllm/candidate/test", {
      method: "POST",
      body: JSON.stringify({ version }),
    }));
  },
  async activateVllmCandidate(version: number) {
    return vllmCandidateActivationResultSchema.parse(await request("/api/v1/vllm/candidate/activate", {
      method: "POST",
      body: JSON.stringify({ version }),
    }));
  },
  async getHealth() {
    return healthSchema.parse(await request("/api/v1/health"));
  },
  async getDashboard() {
    return dashboardSchema.parse(await request("/api/v1/dashboard"));
  },
  async getProviderStatus() {
    return providerStatusSchema.parse(await request("/api/v1/providers"));
  },
  async getADAssessmentCatalog() {
    return adAssessmentCatalogSchema.parse(await request("/api/v1/ad-assessment/catalog"));
  },
  async runADAssessmentSimulation() {
    return adAssessmentResultSchema.parse(await request("/api/v1/ad-assessment/evaluate", {
      method: "POST",
      body: JSON.stringify(buildADAssessmentSimulationSnapshot()),
    }));
  },
  async runCompleteADAssessment() {
    return adAssessmentConsensusResultSchema.parse(await request("/api/v1/ad-assessment/evaluate-with-llm", {
      method: "POST",
      body: JSON.stringify(buildADAssessmentSimulationSnapshot()),
    }));
  },
  async runLiveADAssessment() {
    return adAssessmentConsensusResultSchema.parse(await request("/api/v1/ad-assessment/collect-and-evaluate", {
      method: "POST",
      body: JSON.stringify({}),
    }));
  },
  async recommendADAssessment() {
    return adAssessmentRecommendationSchema.parse(await request("/api/v1/ad-assessment/recommendation", {
      method: "POST",
      body: JSON.stringify({}),
    }));
  },
  async getExecutionReadiness() {
    return executionReadinessSchema.parse(await request("/api/v1/readiness"));
  },
  async testVllmConnection(config: VllmConfig) {
    return vllmCapabilityResultSchema.parse(await request("/api/v1/vllm/capability", {
      method: "POST",
      body: JSON.stringify(config),
    }));
  },
  async getInterventions() {
    return z.array(interventionSchema).parse(await request("/api/v1/interventions"));
  },
  async resolveApproval(id, decision, presentationDigest) {
    return interventionSchema.parse(await request(`/api/v1/interventions/${encodeURIComponent(id)}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, presentationDigest }),
    }));
  },
  async selectCandidate(id, candidateId) {
    return interventionSchema.parse(await request(`/api/v1/interventions/${encodeURIComponent(id)}/selection`, {
      method: "POST",
      body: JSON.stringify({ candidateId }),
    }));
  },
  async saveMissionDraft(draft: MissionDraft) {
    return savedDraftSchema.parse(await request("/api/v1/mission-drafts", {
      method: "POST",
      body: JSON.stringify({ ...draft, validUntil: zonedUtc(draft.validUntil) }),
    }));
  },
  async createMission(draftId: string) {
    return missionStateSchema.parse(await request("/api/v1/missions", {
      method: "POST",
      body: JSON.stringify({ draftId }),
    }));
  },
  async transitionMission(missionId, expectedVersion, action) {
    return missionStateSchema.parse(await request(`/api/v1/missions/${encodeURIComponent(missionId)}/transitions`, {
      method: "POST",
      body: JSON.stringify({ expectedVersion, action }),
    }));
  },
  async getKnowledgeGraph() {
    return knowledgeGraphSchema.parse(await request("/api/v1/knowledge"));
  },
  async getPhaseProgress() {
    return z.array(attackPhaseProgressSchema).parse(await request("/api/v1/phases"));
  },
  async getAgentActivity() {
    return agentActivitySchema.nullable().parse(await request("/api/v1/activity"));
  },
  async saveProviderPolicyDraft(draft: ProviderPolicyDraft) {
    return savedDraftSchema.parse(await request("/api/v1/provider-policy-drafts", {
      method: "POST",
      body: JSON.stringify(draft),
    }));
  },
};
