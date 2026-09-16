import { z } from "zod";

export const timestampSchema = z.string().datetime({ offset: true });

export const phaseNames = [
  "INITIAL_ACCESS",
  "DISCOVERY",
  "PRIVILEGE_ESCALATION",
  "CREDENTIAL_ACCESS",
  "LATERAL_MOVEMENT",
  "DOMAIN_CONTROL",
  "LINUX_PRIVILEGE_ESCALATION",
  "OBJECTIVE",
] as const;

export const phaseStatusSchema = z.enum([
  "not_started",
  "current",
  "completed",
  "blocked",
  "approval_required",
  "failed",
  "not_applicable",
]);

export const attackPhaseProgressSchema = z.object({
  phase: z.enum(phaseNames),
  label: z.string().min(1),
  status: phaseStatusSchema,
  detail: z.string().min(1),
}).strict();
export type AttackPhaseProgress = z.infer<typeof attackPhaseProgressSchema>;

export const agentActivityReferenceSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]*$/),
  type: z.enum(["mission", "execution", "session", "host", "account", "group", "artifact"]),
  id: z.string().min(1).max(100),
}).strict();

export const agentActivitySchema = z.object({
  id: z.string().min(1),
  executionId: z.string().min(1),
  status: z.enum(["running", "completed", "blocked", "failed"]),
  title: z.string().min(1),
  toolDisplayName: z.string().min(1),
  operation: z.string().regex(/^[a-z][a-z0-9_.-]*$/),
  adapterId: z.string().min(1),
  references: z.array(agentActivityReferenceSchema).max(6),
  startedAt: timestampSchema,
  completedAt: timestampSchema.nullable(),
  elapsedSeconds: z.number().int().nonnegative(),
  rawOutputAvailable: z.literal(false),
  summary: z.string().min(1),
}).strict().superRefine((activity, context) => {
  if (activity.status === "running" && activity.completedAt !== null) {
    context.addIssue({ code: "custom", path: ["completedAt"], message: "Running activity cannot have a completion timestamp" });
  }
  if (activity.status !== "running" && activity.completedAt === null) {
    context.addIssue({ code: "custom", path: ["completedAt"], message: "Terminal activity requires a completion timestamp" });
  }
});
export type AgentActivity = z.infer<typeof agentActivitySchema>;

export const vllmConfigSchema = z.object({
  baseUrl: z.string().url().refine((value) => value.startsWith("http://") || value.startsWith("https://"), "Use an HTTP or HTTPS URL"),
  modelName: z.string().trim().min(1, "Model name is required"),
  wireApi: z.literal("chat_completions"),
  structuredOutputMode: z.enum(["native", "tool_output"]),
});
export type VllmConfig = z.infer<typeof vllmConfigSchema>;

export const capabilityCheckSchema = z.object({
  name: z.string(),
  status: z.enum(["passed", "failed", "not_run"]),
  detail: z.string(),
}).strict();
export const vllmCapabilityResultSchema = z.object({
  status: z.enum(["passed", "failed", "timeout"]),
  summary: z.string(),
  latencyMs: z.number().nonnegative(),
  checkedAt: timestampSchema,
  checks: z.array(capabilityCheckSchema),
}).strict();
export type VllmCapabilityResult = z.infer<typeof vllmCapabilityResultSchema>;
export type VllmScenario = "success" | "incompatible" | "unreachable" | "timeout";

export const c2ProviderIdSchema = z.enum(["none", "tuoni"]);
export const mcpServerIdSchema = z.enum(["impacket_mcp"]);
export const toolPolicyStateSchema = z.enum(["allowed", "approval_required", "disabled"]);
export const impacketOperationIds = [
  "impacket.smb.negotiate",
  "impacket.smb.authenticate",
  "impacket.smb.list_shares",
  "impacket.rpc.endpoint_map",
] as const;

export const providerPolicyDraftSchema = z.object({
  missionRevision: z.number().int().positive(),
  c2: z.object({
    providerId: c2ProviderIdSchema,
    registryReference: z.string().min(1).nullable(),
  }).strict(),
  enabledMcpServers: z.array(mcpServerIdSchema).min(1).refine((items) => new Set(items).size === items.length, "MCP server IDs must be unique"),
  operations: z.array(z.object({
    id: z.string().regex(/^[a-z][a-z0-9_.-]*$/),
    source: z.enum(["impacket_mcp", "offline_analysis"]),
    state: toolPolicyStateSchema,
    arbitraryArguments: z.literal(false),
  }).strict()).min(1),
}).strict().superRefine((draft, context) => {
  if (!draft.enabledMcpServers.includes("impacket_mcp")) {
    context.addIssue({ code: "custom", path: ["enabledMcpServers"], message: "Impacket MCP is required by Phase 5" });
  }
  if (draft.c2.providerId === "none" && draft.c2.registryReference !== null) {
    context.addIssue({ code: "custom", path: ["c2", "registryReference"], message: "No C2 selection cannot include a registry reference" });
  }
  if (draft.c2.providerId !== "none" && draft.c2.registryReference === null) {
    context.addIssue({ code: "custom", path: ["c2", "registryReference"], message: "A selected C2 adapter requires a registry reference" });
  }
  const operationIds = draft.operations.map((operation) => operation.id);
  if (
    operationIds.length !== impacketOperationIds.length
    || new Set(operationIds).size !== operationIds.length
    || impacketOperationIds.some((id) => !operationIds.includes(id))
    || draft.operations.some((operation) => operation.source !== "impacket_mcp")
  ) {
    context.addIssue({ code: "custom", path: ["operations"], message: "Use the exact registered Impacket operation set" });
  }
});
export type C2ProviderId = z.infer<typeof c2ProviderIdSchema>;
export type McpServerId = z.infer<typeof mcpServerIdSchema>;
export type ToolPolicyState = z.infer<typeof toolPolicyStateSchema>;
export type ProviderPolicyDraft = z.infer<typeof providerPolicyDraftSchema>;

const interventionBaseSchema = z.object({
  id: z.string().min(1),
  missionId: z.string().min(1),
  missionRevision: z.number().int().positive(),
  authorizationEpoch: z.number().int().nonnegative(),
  title: z.string().min(1),
  summary: z.string().min(1),
  createdAt: timestampSchema,
  expiresAt: timestampSchema,
  state: z.enum(["pending", "approved", "rejected", "selected", "stale", "expired"]),
  actionable: z.boolean().optional(),
  disabledReason: z.string().nullable().optional(),
}).strict();

const approvalInterventionSchema = interventionBaseSchema.extend({
  kind: z.literal("approval"),
  presentationDigest: z.string().min(1),
  toolDisplayName: z.string().min(1),
  targets: z.array(z.string()).min(1),
  redactedArguments: z.record(z.string(), z.unknown()),
  risk: z.enum(["read", "low", "medium", "high"]),
  sideEffect: z.enum(["read_only", "state_change", "destructive"]),
  adapterId: z.string().min(1),
});

const choiceInterventionSchema = interventionBaseSchema.extend({
  kind: z.literal("choice"),
  candidates: z.array(z.object({
    id: z.string().min(1),
    label: z.string().min(1),
    description: z.string().min(1),
    estimatedRisk: z.enum(["read", "low", "medium", "high"]),
  })).min(2),
  selectedCandidateId: z.string().nullable(),
});

export const interventionSchema = z.discriminatedUnion("kind", [approvalInterventionSchema, choiceInterventionSchema]);
export type Intervention = z.infer<typeof interventionSchema>;
export type ApprovalIntervention = Extract<Intervention, { kind: "approval" }>;
export type ChoiceIntervention = Extract<Intervention, { kind: "choice" }>;

export const targetScopeSchema = z.object({
  id: z.string(),
  type: z.enum(["network", "host", "session", "hostname", "domain", "url", "remote_filesystem", "other"]),
  value: z.string().trim().min(1, "Target value is required"),
  port: z.number().int().min(1).max(65535).nullable(),
  protocol: z.enum(["tcp", "udp"]).nullable(),
}).strict();

export const missionDraftSchema = z.object({
  name: z.string().trim().min(3),
  description: z.string().trim().min(10),
  authorizationReference: z.string().trim().min(1),
  validUntil: z.string().min(1),
  targets: z.array(targetScopeSchema).min(1),
  successType: z.enum(["session_exists", "windows_privilege", "ad_membership", "linux_root", "evidence", "artifact", "other"]),
  successValue: z.string().trim().min(1),
  maxIterations: z.number().int().positive(),
  maxRuntimeMinutes: z.number().int().positive(),
  approvalRisk: z.enum(["low", "medium", "high"]),
}).strict();
export type MissionDraft = z.infer<typeof missionDraftSchema>;

export const knowledgeNodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  category: z.enum(["asset", "account", "session", "group", "domain"]),
  verification: z.enum(["inferred", "confirmed", "contradicted"]),
  detail: z.string(),
}).strict();
export const knowledgeEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  label: z.string(),
}).strict();
export const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  target: z.string(),
  verification: z.enum(["inferred", "confirmed", "contradicted"]),
  confidence: z.number().min(0).max(1),
  sourceExecutionId: z.string(),
  artifactId: z.string().nullable(),
  timestamp: timestampSchema,
  summary: z.string(),
}).strict();
export const artifactSchema = z.object({
  id: z.string(),
  mediaType: z.string(),
  sizeBytes: z.number().nonnegative(),
  classification: z.enum(["normal", "sensitive", "secret_reference"]),
  variant: z.literal("redacted"),
  createdAt: timestampSchema,
}).strict();
export const knowledgeGraphSchema = z.object({
  nodes: z.array(knowledgeNodeSchema),
  edges: z.array(knowledgeEdgeSchema),
  findings: z.array(findingSchema),
  artifacts: z.array(artifactSchema),
}).strict();
export type KnowledgeNode = z.infer<typeof knowledgeNodeSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type KnowledgeGraph = z.infer<typeof knowledgeGraphSchema>;

export const dashboardSchema = z.object({
  mission: z.object({
    id: z.string(),
    title: z.string(),
    state: z.string(),
    revision: z.number().int().positive(),
    authorizationEpoch: z.number().int().nonnegative(),
    authorizationReference: z.string(),
    validUntil: timestampSchema,
    objectives: z.array(z.string()),
    scopes: z.array(z.string()),
  }).strict().nullable(),
  metrics: z.object({
    confirmedFindings: z.number().int().nonnegative(),
    mappedEntities: z.number().int().nonnegative(),
    pendingDecisions: z.number().int().nonnegative(),
  }).strict(),
  timeline: z.array(z.object({
    id: z.string(),
    title: z.string(),
    detail: z.string(),
    timestamp: timestampSchema,
  }).strict()),
}).strict();
export type Dashboard = z.infer<typeof dashboardSchema>;

export const providerStatusSchema = z.object({
  mode: z.literal("live"),
  tuoni: z.object({ edition: z.literal("commercial"), version: z.string(), access: z.string() }).strict(),
  impacket: z.object({
    installed: z.boolean(),
    version: z.string().nullable(),
    server: z.string(),
    operations: z.array(z.string()),
  }).strict(),
  latestDraft: z.object({
    draftId: z.string().min(1),
    savedAt: timestampSchema,
    draft: providerPolicyDraftSchema,
  }).strict().nullable(),
}).strict();
export type ProviderStatus = z.infer<typeof providerStatusSchema>;

export const healthSchema = z.object({
  status: z.literal("healthy"),
  mode: z.literal("live"),
  database: z.literal("connected"),
  approvalActionsEnabled: z.boolean(),
  vllmChecksEnabled: z.boolean(),
}).strict();
export type Health = z.infer<typeof healthSchema>;

export interface FrontendGateway {
  testVllmConnection(config: VllmConfig, scenario?: VllmScenario): Promise<VllmCapabilityResult>;
  getHealth(): Promise<Health>;
  getDashboard(): Promise<Dashboard>;
  getProviderStatus(): Promise<ProviderStatus>;
  getInterventions(): Promise<Intervention[]>;
  resolveApproval(id: string, decision: "approved" | "rejected", presentationDigest: string): Promise<Intervention>;
  selectCandidate(id: string, candidateId: string): Promise<Intervention>;
  saveMissionDraft(draft: MissionDraft): Promise<{ draftId: string; savedAt: string }>;
  getKnowledgeGraph(): Promise<KnowledgeGraph>;
  getPhaseProgress(): Promise<AttackPhaseProgress[]>;
  getAgentActivity(): Promise<AgentActivity | null>;
  saveProviderPolicyDraft(draft: ProviderPolicyDraft): Promise<{ draftId: string; savedAt: string }>;
}
