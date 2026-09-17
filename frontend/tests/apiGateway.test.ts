import { afterEach, describe, expect, it, vi } from "vitest";
import { apiGateway } from "../src/apiGateway";

afterEach(() => vi.unstubAllGlobals());

describe("same-origin API gateway", () => {
  it("loads only a strict server-managed VLLM profile", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      enabled: true,
      config: {
        baseUrl: "http://10.0.6.181:8100/v1",
        modelName: "gemma-4-31B-it",
        wireApi: "chat_completions",
        structuredOutputMode: "native",
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const managed = await apiGateway.getVllmConfiguration();

    expect(managed.enabled).toBe(true);
    expect(managed.config?.modelName).toBe("gemma-4-31B-it");
  });

  it("submits an LLM key once and accepts only a redacted settings response", async () => {
    const response = {
      enabled: true,
      active: {
        version: 1,
        config: { baseUrl: "http://10.0.6.181:8100/v1", modelName: "gemma-4-31B-it", wireApi: "chat_completions", structuredOutputMode: "native" },
        apiKeyConfigured: true,
        activatedAt: null,
        transportSecurity: "isolated_network_required",
      },
      candidate: {
        version: 2,
        config: { baseUrl: "http://10.0.6.182:8100/v1", modelName: "gemma-4-31B-it", wireApi: "chat_completions", structuredOutputMode: "native" },
        apiKeyConfigured: true,
        testStatus: "not_run",
        testedAt: null,
        transportSecurity: "isolated_network_required",
      },
      allowedCidrs: ["10.0.6.0/24"],
      settingsMutable: true,
      modelMutable: false,
    };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(response), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiGateway.stageVllmCandidate("http://10.0.6.182:8100/v1", "one-shot-secret");

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/vllm/candidate");
    expect(JSON.parse(String(init.body))).toEqual({ baseUrl: "http://10.0.6.182:8100/v1", apiKey: "one-shot-secret" });
    expect(JSON.stringify(result)).not.toContain("one-shot-secret");
    expect(result.candidate?.apiKeyConfigured).toBe(true);
  });

  it("sends a zoned Mission draft with the UI mutation proof", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      draftId: "mission-draft-1",
      savedAt: "2026-09-15T01:00:00Z",
    }), { status: 201, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGateway.saveMissionDraft({
      name: "Lab Mission",
      description: "Authorized isolated lab mission.",
      authorizationReference: "AUTH-1",
      validUntil: "2026-12-01T00:00",
      targets: [{ id: "target-1", type: "network", value: "10.0.0.0/24", port: 445, protocol: "tcp" }],
      successType: "evidence",
      successValue: "Confirmed evidence exists",
      maxIterations: 10,
      maxRuntimeMinutes: 60,
      approvalRisk: "medium",
    });

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/mission-drafts");
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toMatchObject({ "Content-Type": "application/json", "X-RedTeam-UI": "1" });
    expect(JSON.parse(String(init.body)).validUntil).toBe("2026-12-01T00:00:00Z");
  });

  it("rejects unknown fields returned by the control plane", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: "healthy",
      mode: "live",
      database: "connected",
      approvalActionsEnabled: false,
      vllmChecksEnabled: false,
      implicitAuthority: true,
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    await expect(apiGateway.getHealth()).rejects.toThrow();
  });

  it("does not expose server error details as executable data", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: "operator action is stale or unavailable",
      code: "CONFLICT",
      resolution: "Reload the current Mission state.",
    }), { status: 409, headers: { "Content-Type": "application/json" } })));

    await expect(apiGateway.getInterventions()).rejects.toThrow(/Reload the current Mission state/);
  });

  it("labels AD verifier requests as simulator evidence", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      result_id: "ad-assessment-ui-simulator-1",
      snapshot_id: "ui-simulator-1",
      domain_ref: "domain:simulated.local",
      evidence_source_type: "simulator",
      decision_authority: "deterministic_verifier",
      evaluated_at: "2026-09-17T00:00:00Z",
      checks: [
        ["ad.audit.privileged_access", "privileged_access_configuration"],
        ["ad.audit.kerberos_service_accounts", "kerberos_service_account_configuration"],
        ["ad.audit.kerberos_preauth", "kerberos_preauth_configuration"],
        ["ad.audit.adcs_esc", "adcs_esc_configuration"],
        ["ad.audit.delegation", "delegation_configuration"],
      ].map(([operation_id, category]) => ({ operation_id, category, status: "no_misconfiguration_detected", reason_codes: ["NO_RULE_MATCH"], finding_rule_ids: [] })),
      findings: [],
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await apiGateway.runADAssessmentSimulation();

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/ad-assessment/evaluate");
    expect(init.headers).toMatchObject({ "X-RedTeam-UI": "1" });
    const body = JSON.parse(String(init.body));
    expect(body.source_type).toBe("simulator");
    expect(JSON.stringify(body)).not.toMatch(/ticket_hash|password_value|private_key/);
  });

  it("requests complete local-LLM assessment with normalized evidence only", async () => {
    const categories = [
      ["ad.audit.privileged_access", "privileged_access_configuration"],
      ["ad.audit.kerberos_service_accounts", "kerberos_service_account_configuration"],
      ["ad.audit.kerberos_preauth", "kerberos_preauth_configuration"],
      ["ad.audit.adcs_esc", "adcs_esc_configuration"],
      ["ad.audit.delegation", "delegation_configuration"],
    ];
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      result_id: "ad-assessment-consensus-ui-simulator-1",
      snapshot_id: "ui-simulator-1",
      domain_ref: "domain:simulated.local",
      evidence_source_type: "simulator",
      evaluation_mode: "local_llm_plus_deterministic_verifier",
      status: "completed",
      decision_authority: "deterministic_verifier",
      output_schema: "planner_output",
      evaluated_at: "2026-09-17T00:00:00Z",
      category_results: categories.map(([operation_id, category]) => ({
        operation_id,
        category,
        llm_status: "misconfiguration_detected",
        verifier_status: "misconfiguration_detected",
        consensus: "agreed",
        verified_rule_ids: [],
      })),
      findings: [],
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiGateway.runCompleteADAssessment();

    expect(result.status).toBe("completed");
    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/ad-assessment/evaluate-with-llm");
    const body = JSON.parse(String(init.body));
    expect(body.source_type).toBe("simulator");
    expect(JSON.stringify(body)).not.toMatch(/ticket_hash|password_value|private_key/);
  });

  it("keeps live AD target and credentials server-owned", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: "The configured domain controller LDAPS endpoint is unreachable or untrusted.",
      code: "AD_COLLECTOR_LDAPS_UNREACHABLE",
      resolution: "Provide the DC IP, allow TCP/636, and install its issuing CA certificate.",
    }), { status: 409, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiGateway.runLiveADAssessment()).rejects.toThrow(/AD_COLLECTOR_LDAPS_UNREACHABLE/);

    const [path, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(path).toBe("/api/v1/ad-assessment/collect-and-evaluate");
    expect(JSON.parse(String(init.body))).toEqual({});
  });
});
