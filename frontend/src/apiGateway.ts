import { z } from "zod";
import {
  agentActivitySchema,
  attackPhaseProgressSchema,
  dashboardSchema,
  healthSchema,
  interventionSchema,
  knowledgeGraphSchema,
  managedVllmConfigSchema,
  providerStatusSchema,
  timestampSchema,
  vllmCapabilityResultSchema,
  type FrontendGateway,
  type MissionDraft,
  type ProviderPolicyDraft,
  type VllmConfig,
} from "./types";

const savedDraftSchema = z.object({ draftId: z.string().min(1), savedAt: timestampSchema }).strict();
const errorSchema = z.object({ error: z.string(), code: z.string() }).strict();

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
    throw new Error(parsed.success ? `${parsed.data.error} (${parsed.data.code})` : `Request failed (${response.status})`);
  }
  return value;
}

function zonedUtc(value: string): string {
  if (/Z$|[+-]\d{2}:\d{2}$/.test(value)) return value;
  return `${value.length === 16 ? `${value}:00` : value}Z`;
}

export const apiGateway: FrontendGateway = {
  async getVllmConfiguration() {
    return managedVllmConfigSchema.parse(await request("/api/v1/vllm/config"));
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
