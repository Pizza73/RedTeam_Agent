import {
  adAssessmentCatalogSchema,
  adAssessmentConsensusResultSchema,
  adAssessmentRecommendationSchema,
  adAssessmentResultSchema,
  agentActivitySchema,
  attackPhaseProgressSchema,
  dashboardSchema,
  healthSchema,
  interventionSchema,
  knowledgeGraphSchema,
  missionDraftSchema,
  providerPolicyDraftSchema,
  providerStatusSchema,
  executionReadinessSchema,
  vllmCapabilityResultSchema,
  vllmCandidateActivationResultSchema,
  vllmCandidateTestResultSchema,
  vllmConfigSchema,
  vllmSettingsSchema,
  type AgentActivity,
  type AttackPhaseProgress,
  type FrontendGateway,
  type Intervention,
  type KnowledgeGraph,
  type MissionDraft,
  type MissionState,
  type ProviderPolicyDraft,
  type VllmCapabilityResult,
  type VllmConfig,
  type VllmScenario,
  type VllmSettings,
} from "./types";

const pause = (duration = 350) => new Promise((resolve) => setTimeout(resolve, duration));
const future = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString();
const past = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
const pastSeconds = (seconds: number) => new Date(Date.now() - seconds * 1_000).toISOString();

let mockVllmSettings: VllmSettings = vllmSettingsSchema.parse({
  enabled: true,
  active: {
    version: 1,
    config: { baseUrl: "http://10.0.6.181:8100/v1", modelName: "gemma-4-31B-it", wireApi: "chat_completions", structuredOutputMode: "native" },
    apiKeyConfigured: true,
    activatedAt: null,
    transportSecurity: "isolated_network_required",
  },
  candidate: null,
  allowedCidrs: ["10.0.6.0/24"],
  settingsMutable: true,
  modelMutable: false,
});

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
let missionState: MissionState = {
  missionId: "mission-ui-demo",
  missionRevision: 1,
  missionStateVersion: 0,
  authorizationEpoch: 0,
  state: "DRAFT",
};

export const mockGateway: FrontendGateway = {
  async getOperatorSession() {
    return { authenticated: true as const, principalId: "redteam-operator", expiresAt: null };
  },
  async loginOperator() {
    return { authenticated: true as const, principalId: "redteam-operator", expiresAt: null };
  },
  async logoutOperator() {
    return { authenticated: false as const, principalId: null, expiresAt: null };
  },
  async getVllmConfiguration() {
    return {
      enabled: true as const,
      config: {
        baseUrl: "http://10.0.6.181:8100/v1",
        modelName: "gemma-4-31B-it",
        wireApi: "chat_completions" as const,
        structuredOutputMode: "native" as const,
      },
    };
  },
  async getVllmSettings() {
    return vllmSettingsSchema.parse(mockVllmSettings);
  },
  async stageVllmCandidate(baseUrl: string, apiKey: string) {
    if (!apiKey.trim()) throw new Error("API key is required.");
    mockVllmSettings = vllmSettingsSchema.parse({
      ...mockVllmSettings,
      candidate: {
        version: Math.max(mockVllmSettings.active.version, mockVllmSettings.candidate?.version ?? 0) + 1,
        config: { ...mockVllmSettings.active.config, baseUrl },
        apiKeyConfigured: true,
        testStatus: "not_run",
        testedAt: null,
        transportSecurity: baseUrl.startsWith("https://") ? "encrypted" : "isolated_network_required",
      },
    });
    return mockVllmSettings;
  },
  async testVllmCandidate(version: number, scenario: VllmScenario = "success") {
    if (mockVllmSettings.candidate?.version !== version) throw new Error("Candidate is stale.");
    const capability = await mockGateway.testVllmConnection(mockVllmSettings.candidate.config, scenario);
    mockVllmSettings = vllmSettingsSchema.parse({
      ...mockVllmSettings,
      candidate: { ...mockVllmSettings.candidate, testStatus: capability.status, testedAt: new Date().toISOString() },
    });
    return vllmCandidateTestResultSchema.parse({ settings: mockVllmSettings, capability });
  },
  async activateVllmCandidate(version: number) {
    const candidate = mockVllmSettings.candidate;
    if (candidate?.version !== version || candidate.testStatus !== "passed") throw new Error("A passing candidate test is required.");
    const capability = await mockGateway.testVllmConnection(candidate.config, "success");
    mockVllmSettings = vllmSettingsSchema.parse({
      ...mockVllmSettings,
      active: {
        version: candidate.version,
        config: candidate.config,
        apiKeyConfigured: true,
        activatedAt: new Date().toISOString(),
        transportSecurity: candidate.transportSecurity,
      },
      candidate: null,
    });
    return vllmCandidateActivationResultSchema.parse({ activated: true, settings: mockVllmSettings, capability });
  },
  async getHealth() {
    return healthSchema.parse({
      status: "healthy",
      mode: "live",
      database: "connected",
      approvalActionsEnabled: true,
      missionActionsEnabled: true,
      missionExecutionEnabled: false,
      vllmChecksEnabled: true,
      adAssessmentReasoningEnabled: true,
      adAssessmentEvaluationEnabled: true,
      adAssessmentCollectorEnabled: true,
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
      runtime: {
        productionEligible: false,
        missionExecutionEnabled: false,
        tpmKeyProviderAttested: false,
        blockers: ["Live provider attestations are not present in mock mode."],
      },
      tuoni: { edition: "commercial", version: "latest", access: "unconfigured" },
      sliver: {
        version: "1.7.7",
        operator: "joe",
        operatorConfigLocation: "downloads",
        operatorAccess: "unconfigured",
        implantTransport: "http",
        beaconPresent: false,
        identityAttested: false,
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
  async getADAssessmentCatalog() {
    return adAssessmentCatalogSchema.parse({
      catalogRevision: "ad-assessment-readonly-v1",
      mode: "read_only_configuration_assessment",
      plannerRole: "select_next_registered_inspection",
      evaluationRole: "classify_all_five_then_verify_consensus",
      decisionAuthority: "deterministic_verifier",
      liveCollectorStatus: "attached",
      simulatorStatus: "ready",
      prohibitedActions: [
        "Kerberos ticket acquisition or export",
        "password or hash cracking",
        "certificate enrollment or authentication",
        "delegation impersonation",
        "directory modification",
        "arbitrary command execution",
      ],
      operations: [
        { id: "ad.audit.privileged_access", category: "privileged_access_configuration", title: "Privileged access configuration", description: "Inspect tier-zero membership, stale privileged identities, and delegated administration metadata.", readOnly: true, llmSelectable: true, evidenceField: "privileged_access" },
        { id: "ad.audit.kerberos_service_accounts", category: "kerberos_service_account_configuration", title: "Kerberos service-account configuration", description: "Inspect SPN account encryption, password-age, and managed-identity metadata without requesting tickets.", readOnly: true, llmSelectable: true, evidenceField: "kerberos_service_accounts" },
        { id: "ad.audit.kerberos_preauth", category: "kerberos_preauth_configuration", title: "Kerberos preauthentication configuration", description: "Inspect the preauthentication-required account setting without requesting AS-REP material.", readOnly: true, llmSelectable: true, evidenceField: "kerberos_preauth" },
        { id: "ad.audit.adcs_esc", category: "adcs_esc_configuration", title: "AD CS ESC configuration", description: "Inspect normalized certificate-template, CA, ACL, and enrollment endpoint configuration for ESC1-ESC8.", readOnly: true, llmSelectable: true, evidenceField: "adcs" },
        { id: "ad.audit.delegation", category: "delegation_configuration", title: "Kerberos delegation configuration", description: "Inspect unconstrained, constrained, protocol-transition, and RBCD configuration metadata.", readOnly: true, llmSelectable: true, evidenceField: "delegation" },
      ],
    });
  },
  async runADAssessmentSimulation() {
    await pause();
    return adAssessmentResultSchema.parse({
      result_id: "ad-assessment-ui-simulator-1",
      snapshot_id: "ui-simulator-1",
      domain_ref: "domain:simulated.local",
      evidence_source_type: "simulator",
      decision_authority: "deterministic_verifier",
      evaluated_at: new Date().toISOString(),
      checks: [
        { operation_id: "ad.audit.privileged_access", category: "privileged_access_configuration", status: "misconfiguration_detected", reason_codes: ["DETERMINISTIC_RULE_MATCH"], finding_rule_ids: ["AD-PRIV-TIER0"] },
        { operation_id: "ad.audit.kerberos_service_accounts", category: "kerberos_service_account_configuration", status: "misconfiguration_detected", reason_codes: ["DETERMINISTIC_RULE_MATCH"], finding_rule_ids: ["AD-KRB-WEAK-ENC", "AD-KRB-UNMANAGED"] },
        { operation_id: "ad.audit.kerberos_preauth", category: "kerberos_preauth_configuration", status: "misconfiguration_detected", reason_codes: ["DETERMINISTIC_RULE_MATCH"], finding_rule_ids: ["AD-KRB-PREAUTH"] },
        { operation_id: "ad.audit.adcs_esc", category: "adcs_esc_configuration", status: "misconfiguration_detected", reason_codes: ["DETERMINISTIC_RULE_MATCH"], finding_rule_ids: ["AD-ADCS-ESC1"] },
        { operation_id: "ad.audit.delegation", category: "delegation_configuration", status: "misconfiguration_detected", reason_codes: ["DETERMINISTIC_RULE_MATCH"], finding_rule_ids: ["AD-DELEG-BROAD"] },
      ],
      findings: [
        { rule_id: "AD-PRIV-TIER0", category: "privileged_access_configuration", severity: "high", title: "Unexpected tier-zero membership", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-KRB-WEAK-ENC", category: "kerberos_service_account_configuration", severity: "high", title: "Service account permits weak Kerberos encryption", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-KRB-UNMANAGED", category: "kerberos_service_account_configuration", severity: "medium", title: "SPN account is not managed", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-KRB-PREAUTH", category: "kerberos_preauth_configuration", severity: "high", title: "Kerberos preauthentication is disabled", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-ADCS-ESC1", category: "adcs_esc_configuration", severity: "high", title: "AD CS ESC1 configuration exposure", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-DELEG-BROAD", category: "delegation_configuration", severity: "medium", title: "Constrained delegation scope is broad", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
      ],
    });
  },
  async recommendADAssessment() {
    await pause();
    return adAssessmentRecommendationSchema.parse({
      operation_id: "ad.audit.kerberos_preauth",
      category: "kerberos_preauth_configuration",
      title: "Kerberos preauthentication configuration",
      description: "Inspect the preauthentication-required account setting without requesting AS-REP material.",
      output_schema: "planner_output",
      authority: "recommendation_only",
      candidate_count: 5,
      generated_at: new Date().toISOString(),
    });
  },
  async runCompleteADAssessment() {
    await pause();
    return adAssessmentConsensusResultSchema.parse({
      result_id: "ad-assessment-consensus-ui-simulator-1",
      snapshot_id: "ui-simulator-1",
      domain_ref: "domain:simulated.local",
      evidence_source_type: "simulator",
      evaluation_mode: "local_llm_plus_deterministic_verifier",
      status: "completed",
      decision_authority: "deterministic_verifier",
      output_schema: "planner_output",
      evaluated_at: new Date().toISOString(),
      category_results: [
        { operation_id: "ad.audit.privileged_access", category: "privileged_access_configuration", llm_status: "misconfiguration_detected", verifier_status: "misconfiguration_detected", consensus: "agreed", verified_rule_ids: ["AD-PRIV-TIER0"] },
        { operation_id: "ad.audit.kerberos_service_accounts", category: "kerberos_service_account_configuration", llm_status: "misconfiguration_detected", verifier_status: "misconfiguration_detected", consensus: "agreed", verified_rule_ids: ["AD-KRB-WEAK-ENC", "AD-KRB-UNMANAGED"] },
        { operation_id: "ad.audit.kerberos_preauth", category: "kerberos_preauth_configuration", llm_status: "misconfiguration_detected", verifier_status: "misconfiguration_detected", consensus: "agreed", verified_rule_ids: ["AD-KRB-PREAUTH"] },
        { operation_id: "ad.audit.adcs_esc", category: "adcs_esc_configuration", llm_status: "misconfiguration_detected", verifier_status: "misconfiguration_detected", consensus: "agreed", verified_rule_ids: ["AD-ADCS-ESC1"] },
        { operation_id: "ad.audit.delegation", category: "delegation_configuration", llm_status: "misconfiguration_detected", verifier_status: "misconfiguration_detected", consensus: "agreed", verified_rule_ids: ["AD-DELEG-BROAD"] },
      ],
      findings: [
        { rule_id: "AD-PRIV-TIER0", category: "privileged_access_configuration", severity: "high", title: "Unexpected tier-zero membership", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-KRB-WEAK-ENC", category: "kerberos_service_account_configuration", severity: "high", title: "Service account permits weak Kerberos encryption", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-KRB-UNMANAGED", category: "kerberos_service_account_configuration", severity: "medium", title: "SPN account is not managed", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-KRB-PREAUTH", category: "kerberos_preauth_configuration", severity: "high", title: "Kerberos preauthentication is disabled", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-ADCS-ESC1", category: "adcs_esc_configuration", severity: "high", title: "AD CS ESC1 configuration exposure", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
        { rule_id: "AD-DELEG-BROAD", category: "delegation_configuration", severity: "medium", title: "Constrained delegation scope is broad", affected_object_count: 1, evidence_artifact_ids: ["artifact-ui-simulator-1"] },
      ],
    });
  },
  async runLiveADAssessment() {
    const result = await this.runCompleteADAssessment();
    return adAssessmentConsensusResultSchema.parse({
      ...result,
      result_id: "ad-assessment-consensus-live-1",
      snapshot_id: "verified-ldap-1",
      domain_ref: "domain:intern.local",
      evidence_source_type: "verified_ldap_snapshot",
      findings: result.findings.map((finding) => ({
        ...finding,
        evidence_artifact_ids: ["collector-evidence:mock-digest"],
      })),
    });
  },
  async getExecutionReadiness() {
    return executionReadinessSchema.parse({
      status: "blocked",
      stage: "mission_configuration",
      summary: "Mission execution is blocked by 3 unresolved item(s).",
      blockerCount: 3,
      blockers: [
        {
          id: "SESSION_REFERENCE_UNAPPROVED",
          category: "session",
          title: "Session reference is not approved",
          detail: "No session registered by live C2 inventory matches the Mission condition.",
          resolution: "Verify an authorized live Beacon and register its exact session reference.",
        },
        {
          id: "IMPACKET_SANDBOX_UNATTESTED",
          category: "tool",
          title: "Impacket worker isolation is not attested",
          detail: "OS-level target and port egress enforcement has not been proven.",
          resolution: "Run the worker under the approved egress sandbox and record live evidence.",
        },
        {
          id: "EXECUTION_RUNTIME_DISABLED",
          category: "runtime",
          title: "Mission execution worker is disabled",
          detail: "The control plane cannot dispatch actions.",
          resolution: "Attach the qualified execution composition after every live gate passes.",
        },
      ],
      checks: [
        { id: "MISSION_DRAFT_SAVED", title: "Mission draft saved", detail: "A reviewed draft exists." },
      ],
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
  async createMission() {
    missionState = { ...missionState, missionStateVersion: 0, authorizationEpoch: 0, state: "DRAFT" };
    return missionState;
  },
  async transitionMission(_missionId, expectedVersion, action) {
    if (expectedVersion !== missionState.missionStateVersion) throw new Error("Mission state is stale.");
    const next = action === "validate" ? "VALIDATED" : action === "start" || action === "resume" ? "RUNNING" : action === "pause" ? "PAUSED" : action === "finalize" ? "FINALIZING" : action === "complete" ? "COMPLETED" : "ABORTED";
    missionState = {
      ...missionState,
      missionStateVersion: missionState.missionStateVersion + 1,
      authorizationEpoch: missionState.authorizationEpoch + (["pause", "resume", "finalize"].includes(action) ? 1 : 0),
      state: next,
    };
    return missionState;
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
