import { describe, expect, it } from "vitest";
import { agentActivitySchema, dashboardSchema, interventionSchema, missionDraftSchema, providerPolicyDraftSchema, vllmConfigSchema } from "../src/types";

const validDraft = {
  name: "Lab Mission",
  description: "Authorized assessment inside an isolated training environment.",
  authorizationReference: "LAB-AUTH-001",
  validUntil: "2026-09-01T18:00",
  targets: [{ id: "target-1", type: "network", value: "10.40.8.0/24", port: 443, protocol: "tcp" }],
  successType: "session_exists",
  successValue: "Confirmed active session on APP-01",
  maxIterations: 10,
  maxRuntimeMinutes: 60,
  approvalRisk: "medium",
} as const;

describe("frontend trust-boundary schemas", () => {
  it("accepts a typed Mission draft", () => {
    expect(missionDraftSchema.parse(validDraft).targets[0]?.port).toBe(443);
  });

  it("accepts offset-aware timestamps emitted by the Python API", () => {
    const dashboard = dashboardSchema.parse({
      mission: {
        id: "mission-1",
        title: "Lab Mission",
        state: "running",
        revision: 1,
        authorizationEpoch: 0,
        authorizationReference: "AUTH-1",
        validUntil: "2026-09-15T12:00:00+00:00",
        objectives: ["Enumerate"],
        scopes: ["network:10.0.0.0/24"],
      },
      metrics: { confirmedFindings: 0, mappedEntities: 0, pendingDecisions: 0 },
      timeline: [{
        id: "event-1",
        title: "VALIDATED → RUNNING",
        detail: "started",
        timestamp: "2026-09-15T12:00:00+00:00",
      }],
    });
    expect(dashboard.mission?.state).toBe("running");
  });

  it("rejects an out-of-range target port", () => {
    expect(() => missionDraftSchema.parse({ ...validDraft, targets: [{ ...validDraft.targets[0], port: 70000 }] })).toThrow();
  });

  it("rejects unknown gateway fields", () => {
    expect(() => vllmConfigSchema.strict().parse({ baseUrl: "http://127.0.0.1:8000/v1", modelName: "Qwen", wireApi: "chat_completions", structuredOutputMode: "native", implicitFallback: true })).toThrow();
  });

  it("rejects an approval request without normalized targets", () => {
    expect(() => interventionSchema.parse({ kind: "approval", id: "a", missionId: "m", missionRevision: 1, authorizationEpoch: 0, title: "Approval", summary: "Summary", createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 1000).toISOString(), state: "pending", presentationDigest: "digest", toolDisplayName: "Tool", targets: [], redactedArguments: {}, risk: "medium", sideEffect: "read_only", adapterId: "adapter" })).toThrow();
  });

  it("rejects inconsistent or untyped agent activity", () => {
    const activity = {
      id: "activity-1", executionId: "exec-1", status: "running", title: "Refresh context",
      toolDisplayName: "Context Inspector", operation: "session_context.refresh", adapterId: "mock-adapter",
      references: [{ name: "session_ref", type: "session", id: "WINRM-031" }],
      startedAt: new Date().toISOString(), completedAt: new Date().toISOString(), elapsedSeconds: 5,
      rawOutputAvailable: false, summary: "Refreshing a reference-only context.",
    };
    expect(() => agentActivitySchema.parse(activity)).toThrow(/completion timestamp/i);
    expect(() => agentActivitySchema.parse({ ...activity, completedAt: null, rawCommand: "untyped-command" })).toThrow();
  });

  it("accepts a registered C2 and typed tool operations", () => {
    const draft = providerPolicyDraftSchema.parse({
      missionRevision: 9,
      c2: { providerId: "tuoni", registryReference: "registry://c2/tuoni/v1" },
      enabledMcpServers: ["impacket_mcp"],
      operations: [
        { id: "impacket.smb.negotiate", source: "impacket_mcp", state: "allowed", arbitraryArguments: false },
        { id: "impacket.smb.authenticate", source: "impacket_mcp", state: "approval_required", arbitraryArguments: false },
        { id: "impacket.smb.list_shares", source: "impacket_mcp", state: "approval_required", arbitraryArguments: false },
        { id: "impacket.rpc.endpoint_map", source: "impacket_mcp", state: "allowed", arbitraryArguments: false },
      ],
    });
    expect(draft.c2.providerId).toBe("tuoni");
    const sliver = providerPolicyDraftSchema.parse({
      ...draft,
      c2: { providerId: "sliver", registryReference: "registry://c2/sliver/v1.7.3-read-control" },
    });
    expect(sliver.c2.providerId).toBe("sliver");
  });

  it("rejects arbitrary arguments and unregistered MCP servers", () => {
    const base = {
      missionRevision: 9,
      c2: { providerId: "none", registryReference: null },
      enabledMcpServers: ["impacket_mcp"],
      operations: [{ id: "impacket.execute", source: "impacket_mcp", state: "allowed", arbitraryArguments: true }],
    };
    expect(() => providerPolicyDraftSchema.parse(base)).toThrow();
    expect(() => providerPolicyDraftSchema.parse({ ...base, enabledMcpServers: ["impacket_mcp", "siem_mcp"], operations: [{ ...base.operations[0], arbitraryArguments: false }] })).toThrow();
  });

  it("rejects a selected C2 without a trusted registry reference", () => {
    expect(() => providerPolicyDraftSchema.parse({
      missionRevision: 9,
      c2: { providerId: "tuoni", registryReference: null },
      enabledMcpServers: ["impacket_mcp"],
      operations: [{ id: "offline.artifact.parse", source: "offline_analysis", state: "allowed", arbitraryArguments: false }],
    })).toThrow(/registry reference/i);
  });

  it("rejects a browser-supplied Human Gate status", () => {
    expect(() => providerPolicyDraftSchema.parse({
      missionRevision: 9,
      c2: { providerId: "tuoni", registryReference: "registry://c2/tuoni/latest", humanGateStatus: "approved" },
      enabledMcpServers: ["impacket_mcp"],
      operations: [{ id: "impacket.smb.negotiate", source: "impacket_mcp", state: "allowed", arbitraryArguments: false }],
    })).toThrow();
  });
});
