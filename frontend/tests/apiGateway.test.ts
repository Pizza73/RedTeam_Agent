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
    }), { status: 409, headers: { "Content-Type": "application/json" } })));

    await expect(apiGateway.getInterventions()).rejects.toThrow(/CONFLICT/);
  });
});
