import {
  agentActivitySchema,
  attackPhaseProgressSchema,
  dashboardSchema,
  healthSchema,
  interventionSchema,
  knowledgeGraphSchema,
  missionDraftSchema,
  providerPolicyDraftSchema,
  providerStatusSchema,
  vllmCapabilityResultSchema,
  vllmConfigSchema,
  type AgentActivity,
  type AttackPhaseProgress,
  type FrontendGateway,
  type Intervention,
  type KnowledgeGraph,
  type MissionDraft,
  type ProviderPolicyDraft,
  type VllmCapabilityResult,
  type VllmConfig,
  type VllmScenario,
} from "./types";

const pause = (duration = 350) => new Promise((resolve) => setTimeout(resolve, duration));
const future = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString();
const past = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
const pastSeconds = (seconds: number) => new Date(Date.now() - seconds * 1_000).toISOString();

let interventions: Intervention[] = [
  {
    id: "approval-domain-control-021",
    kind: "approval",
    missionId: "mission-domain-admin-lab-09",
    missionRevision: 9,
    authorizationEpoch: 16,
    title: "Controlled administrative group transition",
    summary: "The final state-changing transition from the validated operator principal to the Domain Admins group requires explicit approval.",
    createdAt: past(2),
    expiresAt: future(8),
    state: "pending",
    presentationDigest: "sha256:da8f7c14ab90e211",
    toolDisplayName: "Directory Membership Change (Training Adapter)",
    targets: ["group:LAB.EXAMPLE/Domain Admins", "principal:LAB\\ops-automation"],
    redactedArguments: { member_reference: "LAB\\ops-automation", target_group: "Domain Admins", authorization_reference: "LAB-AUTH-2026-091", credential_reference: "[REFERENCE REDACTED]" },
    risk: "high",
    sideEffect: "state_change",
    adapterId: "mock-directory-training-adapter-v1",
  },
  {
    id: "choice-006",
    kind: "choice",
    missionId: "mission-domain-admin-lab-09",
    missionRevision: 9,
    authorizationEpoch: 16,
    title: "Choose the final evidence refresh",
    summary: "Two read-only confirmation paths can reduce uncertainty before the high-risk approval. Selection does not authorize execution.",
    createdAt: past(1),
    expiresAt: future(25),
    state: "pending",
    selectedCandidateId: null,
    candidates: [
      { id: "candidate-a", label: "Refresh delegated group relationships", description: "Reconfirm the complete group-control chain from the starting user to the operator principal.", estimatedRisk: "read" },
      { id: "candidate-b", label: "Refresh administrative session context", description: "Reconfirm the current principal and session bindings on APP-01.", estimatedRisk: "read" },
    ],
  },
  {
    id: "approval-expired-004",
    kind: "approval",
    missionId: "mission-domain-admin-lab-09",
    missionRevision: 8,
    authorizationEpoch: 15,
    title: "Expired delegated group inspection",
    summary: "This previous-revision request is retained for audit visibility but can no longer be acted upon.",
    createdAt: past(35),
    expiresAt: past(20),
    state: "expired",
    presentationDigest: "sha256:expired0ca6b1",
    toolDisplayName: "Directory Relationship Inspector",
    targets: ["group:LAB.EXAMPLE/Server Operators"],
    redactedArguments: { principal: "LAB\\analyst01" },
    risk: "read",
    sideEffect: "read_only",
    adapterId: "mock-directory-read-adapter-v1",
  },
].map((item) => interventionSchema.parse(item));

const phases: AttackPhaseProgress[] = [
  { phase: "INITIAL_ACCESS", label: "Initial Access", status: "completed", detail: "LAB\\analyst01 on WKSTN-07" },
  { phase: "DISCOVERY", label: "Discovery", status: "completed", detail: "Delegated group path confirmed" },
  { phase: "PRIVILEGE_ESCALATION", label: "Privilege Escalation", status: "completed", detail: "Server operator context confirmed" },
  { phase: "CREDENTIAL_ACCESS", label: "Credential Access", status: "completed", detail: "Reference metadata verified" },
  { phase: "LATERAL_MOVEMENT", label: "Lateral Movement", status: "completed", detail: "Administrative session on APP-01" },
  { phase: "DOMAIN_CONTROL", label: "Domain Control", status: "approval_required", detail: "High-risk approval required" },
  { phase: "LINUX_PRIVILEGE_ESCALATION", label: "Linux Privilege Escalation", status: "not_applicable", detail: "Not applicable" },
  { phase: "OBJECTIVE", label: "Objective", status: "not_started", detail: "Not started" },
].map((item) => attackPhaseProgressSchema.parse(item));

const agentActivity: AgentActivity = agentActivitySchema.parse({
  id: "activity-session-refresh-0444",
  executionId: "exec-0444",
  status: "running",
  title: "Refresh administrative session context",
  toolDisplayName: "Session Context Inspector",
  operation: "session_context.refresh",
  adapterId: "mock-session-read-adapter-v1",
  references: [
    { name: "session_ref", type: "session", id: "WINRM-031" },
    { name: "host_ref", type: "host", id: "APP-01" },
  ],
  startedAt: pastSeconds(38),
  completedAt: null,
  elapsedSeconds: 38,
  rawOutputAvailable: false,
  summary: "Revalidating the current principal and authorization epoch before the next policy evaluation.",
});

const knowledge: KnowledgeGraph = knowledgeGraphSchema.parse({
  nodes: [
    { id: "domain-lab", label: "LAB.EXAMPLE", category: "domain", verification: "confirmed", detail: "Authorized training domain" },
    { id: "host-dc01", label: "DC-01", category: "asset", verification: "confirmed", detail: "Windows Server 2022 · 10.40.8.10" },
    { id: "host-wkstn07", label: "WKSTN-07", category: "asset", verification: "confirmed", detail: "Initial authorized workstation · 10.40.8.57" },
    { id: "host-app01", label: "APP-01", category: "asset", verification: "confirmed", detail: "Windows Server 2019 · 10.40.8.24" },
    { id: "account-analyst", label: "LAB\\analyst01", category: "account", verification: "confirmed", detail: "Starting principal · standard domain user" },
    { id: "group-helpdesk", label: "Helpdesk Tier 1", category: "group", verification: "confirmed", detail: "Delegated support group" },
    { id: "group-serverops", label: "Server Operators", category: "group", verification: "confirmed", detail: "Validated delegated relationship" },
    { id: "account-automation", label: "LAB\\ops-automation", category: "account", verification: "confirmed", detail: "Administrative automation principal · reference only" },
    { id: "session-app01", label: "WINRM-031", category: "session", verification: "confirmed", detail: "Administrative session confirmed on APP-01" },
    { id: "group-admin", label: "Domain Admins", category: "group", verification: "inferred", detail: "Final transition is pending explicit approval" },
  ],
  edges: [
    { id: "e1", source: "host-dc01", target: "domain-lab", label: "controls" },
    { id: "e2", source: "host-app01", target: "domain-lab", label: "joined to" },
    { id: "e3", source: "account-analyst", target: "host-wkstn07", label: "initial session" },
    { id: "e4", source: "account-analyst", target: "group-helpdesk", label: "member of" },
    { id: "e5", source: "group-helpdesk", target: "group-serverops", label: "delegated control" },
    { id: "e6", source: "group-serverops", target: "host-app01", label: "administers" },
    { id: "e7", source: "session-app01", target: "host-app01", label: "active on" },
    { id: "e8", source: "account-automation", target: "session-app01", label: "principal" },
    { id: "e9", source: "account-automation", target: "group-admin", label: "pending transition" },
    { id: "e10", source: "group-admin", target: "host-dc01", label: "administrative scope" },
  ],
  findings: [
    { id: "finding-131", title: "Standard user starting context confirmed", target: "LAB\\analyst01", verification: "confirmed", confidence: 1, sourceExecutionId: "exec-0412", artifactId: "artifact-redacted-112", timestamp: past(31), summary: "Trusted session refresh confirmed a standard domain-user context on the authorized workstation." },
    { id: "finding-136", title: "Delegated group-control path confirmed", target: "Helpdesk Tier 1 → Server Operators", verification: "confirmed", confidence: 1, sourceExecutionId: "exec-0421", artifactId: "artifact-redacted-118", timestamp: past(22), summary: "Deterministic directory metadata confirmed the delegated relationship used by the simulated escalation path." },
    { id: "finding-142", title: "Administrative session on APP-01 confirmed", target: "WINRM-031", verification: "confirmed", confidence: 1, sourceExecutionId: "exec-0433", artifactId: "artifact-redacted-124", timestamp: past(9), summary: "Trusted session refresh confirmed the administrative context used for the next policy evaluation." },
    { id: "finding-148", title: "Domain administrator transition available", target: "LAB\\ops-automation → Domain Admins", verification: "inferred", confidence: 0.91, sourceExecutionId: "exec-0440", artifactId: "artifact-redacted-129", timestamp: past(3), summary: "The final relationship is a proposal only. It remains non-executable until the bound high-risk approval succeeds." },
  ],
  artifacts: [
    { id: "artifact-redacted-112", mediaType: "application/json", sizeBytes: 742, classification: "normal", variant: "redacted", createdAt: past(31) },
    { id: "artifact-redacted-118", mediaType: "application/json", sizeBytes: 2280, classification: "sensitive", variant: "redacted", createdAt: past(22) },
    { id: "artifact-redacted-124", mediaType: "application/json", sizeBytes: 914, classification: "sensitive", variant: "redacted", createdAt: past(9) },
    { id: "secret-ref-021", mediaType: "application/vnd.redteam.secret-reference+json", sizeBytes: 204, classification: "secret_reference", variant: "redacted", createdAt: past(15) },
  ],
});

const checks = ["Transport", "Nested model", "Enums", "Optional fields", "Lists", "Discriminated union", "Unknown-field rejection", "Strict typing", "Timeout", "Cancellation"];

export const mockGateway: FrontendGateway = {
  async getHealth() {
    return healthSchema.parse({
      status: "healthy",
      mode: "live",
      database: "connected",
      approvalActionsEnabled: true,
      vllmChecksEnabled: true,
    });
  },
  async getDashboard() {
    return dashboardSchema.parse({
      mission: {
        id: "mission-domain-admin-lab-09",
        title: "Domain Administrator Escalation",
        state: "waiting_human_review",
        revision: 9,
        authorizationEpoch: 16,
        authorizationReference: "LAB-AUTH-2026-091",
        validUntil: future(120),
        objectives: ["Review the final transition to Domain Admin"],
        scopes: ["network:10.40.8.0/24", "host:APP-01", "host:DC-01"],
      },
      metrics: { confirmedFindings: 11, mappedEntities: 8, pendingDecisions: 2 },
      timeline: [
        { id: "event-1", title: "Delegated path confirmed", detail: "Relationship verified", timestamp: past(9) },
        { id: "event-2", title: "Policy requires approval", detail: "Final transition remains blocked", timestamp: past(3) },
      ],
    });
  },
  async getProviderStatus() {
    return providerStatusSchema.parse({
      mode: "live",
      tuoni: { edition: "commercial", version: "latest", access: "unconfigured" },
      sliver: {
        version: "1.7.3",
        operator: "joe",
        operatorConfigLocation: "downloads",
        operatorAccess: "unconfigured",
        implantTransport: "http",
        beaconPresent: false,
      },
      impacket: {
        installed: true,
        version: "0.13.1",
        server: "redteam-impacket-mcp",
        operations: ["impacket.smb.negotiate", "impacket.smb.authenticate", "impacket.smb.list_shares", "impacket.rpc.endpoint_map"],
      },
      latestDraft: null,
    });
  },
  async testVllmConnection(config: VllmConfig, scenario: VllmScenario = "success"): Promise<VllmCapabilityResult> {
    vllmConfigSchema.parse(config);
    await pause(scenario === "timeout" ? 900 : 500);
    const failedName = scenario === "incompatible" ? "Unknown-field rejection" : scenario === "unreachable" ? "Transport" : null;
    return vllmCapabilityResultSchema.parse({
      status: scenario === "success" ? "passed" : scenario === "timeout" ? "timeout" : "failed",
      summary: scenario === "success" ? "Profile meets the required capability contract." : scenario === "timeout" ? "The capability check exceeded its bounded timeout." : scenario === "unreachable" ? "The managed gateway could not reach the configured service." : "Transport succeeded, but strict structured output is incompatible.",
      latencyMs: scenario === "timeout" ? 10_000 : scenario === "unreachable" ? 0 : 428,
      checkedAt: new Date().toISOString(),
      checks: checks.map((name, index) => ({
        name,
        status: scenario === "success" ? "passed" : scenario === "timeout" ? (index < 2 ? "passed" : "not_run") : failedName === name ? "failed" : failedName === "Transport" ? "not_run" : "passed",
        detail: failedName === name ? "Required behavior was not observed." : scenario === "timeout" && index >= 2 ? "Not run after timeout." : "Capability confirmed by the mock canary.",
      })),
    });
  },
  async getInterventions() {
    await pause(120);
    return zodInterventions(interventions);
  },
  async resolveApproval(id, decision, presentationDigest) {
    await pause();
    const current = interventions.find((item) => item.id === id);
    if (!current || current.kind !== "approval") throw new Error("Approval request was not found.");
    if (current.state !== "pending" || new Date(current.expiresAt) <= new Date()) throw new Error("Approval request is no longer actionable.");
    if (current.presentationDigest !== presentationDigest) throw new Error("Approval presentation binding does not match.");
    interventions = interventions.map((item) => item.id === id ? { ...item, state: decision } : item) as Intervention[];
    return interventionSchema.parse(interventions.find((item) => item.id === id));
  },
  async selectCandidate(id, candidateId) {
    await pause();
    const current = interventions.find((item) => item.id === id);
    if (!current || current.kind !== "choice") throw new Error("Choice request was not found.");
    if (!current.candidates.some((candidate) => candidate.id === candidateId)) throw new Error("Candidate is not part of the bound request.");
    interventions = interventions.map((item) => item.id === id && item.kind === "choice" ? { ...item, selectedCandidateId: candidateId, state: "selected" } : item) as Intervention[];
    return interventionSchema.parse(interventions.find((item) => item.id === id));
  },
  async saveMissionDraft(draft: MissionDraft) {
    missionDraftSchema.parse(draft);
    await pause();
    return { draftId: "draft-mission-024", savedAt: new Date().toISOString() };
  },
  async getKnowledgeGraph() {
    await pause(180);
    return knowledgeGraphSchema.parse(knowledge);
  },
  async getPhaseProgress() {
    await pause(100);
    return phases.map((phase) => attackPhaseProgressSchema.parse(phase));
  },
  async getAgentActivity() {
    await pause(80);
    const elapsedSeconds = agentActivity.status === "running" ? Math.floor((Date.now() - new Date(agentActivity.startedAt).getTime()) / 1_000) : agentActivity.elapsedSeconds;
    return agentActivitySchema.parse({ ...agentActivity, elapsedSeconds });
  },
  async saveProviderPolicyDraft(draft: ProviderPolicyDraft) {
    providerPolicyDraftSchema.parse(draft);
    await pause();
    return { draftId: "provider-policy-draft-009", savedAt: new Date().toISOString() };
  },
};

function zodInterventions(items: Intervention[]) {
  return items.map((item) => interventionSchema.parse(item));
}
