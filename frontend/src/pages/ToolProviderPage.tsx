import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, Database, LockKeyhole, RadioTower, Save, ShieldAlert, TerminalSquare } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Badge, Button, PageHeader } from "../components/ui";
import { gateway, gatewayMode } from "../gateway";
import { formatUtcTime } from "../lib/time";
import { providerPolicyDraftSchema, type C2ProviderId, type ProviderPolicyDraft, type ToolPolicyState } from "../types";

type PolicyTab = "c2" | "tools" | "review";

const c2Options: Record<C2ProviderId, { label: string; description: string; registryReference: string | null }> = {
  none: { label: "No C2 adapter", description: "C2 session and task routing is disabled for this Mission revision.", registryReference: null },
  tuoni: { label: "Tuoni Commercial", description: "Existing Tuoni deployment through the typed Phase 4 adapter.", registryReference: "registry://c2/tuoni/latest-commercial" },
  sliver: { label: "Sliver", description: "Pinned Sliver v1.7.7 inventory and existing Beacon Task control over operator gRPC/mTLS.", registryReference: "registry://c2/sliver/v1.7.7-read-control" },
};

const operations = [
  { id: "impacket.smb.negotiate", function: "SMB negotiation", inputs: "Approved target reference", output: "Dialect and signing observations", constraint: "TCP/445 only; no credential", state: "allowed" },
  { id: "impacket.smb.authenticate", function: "SMB authentication", inputs: "Target, principal, and secret references", output: "Typed authentication outcome", constraint: "Secret resolved just in time", state: "approval_required" },
  { id: "impacket.smb.list_shares", function: "SMB share listing", inputs: "Target, principal, and secret references", output: "Share-name observations", constraint: "List only; no upload or delete", state: "approval_required" },
  { id: "impacket.rpc.endpoint_map", function: "RPC endpoint map", inputs: "Approved target reference", output: "RPC endpoint observations", constraint: "TCP/135 only; bounded response", state: "allowed" },
] as const;

const initialDraft: ProviderPolicyDraft = providerPolicyDraftSchema.parse({
  missionRevision: 1,
  c2: { providerId: "sliver", registryReference: c2Options.sliver.registryReference },
  enabledMcpServers: ["impacket_mcp"],
  operations: operations.map(({ id, state }) => ({ id, source: "impacket_mcp", state, arbitraryArguments: false })),
});

export function ToolProviderPage() {
  const [tab, setTab] = useState<PolicyTab>("c2");
  const [draft, setDraft] = useState<ProviderPolicyDraft>(initialDraft);
  const [validationError, setValidationError] = useState("");
  const { data: status } = useQuery({ queryKey: ["provider-status"], queryFn: () => gateway.getProviderStatus() });
  const { data: dashboard } = useQuery({ queryKey: ["dashboard"], queryFn: () => gateway.getDashboard() });
  useEffect(() => {
    const loaded = status?.latestDraft?.draft ?? initialDraft;
    const missionRevision = dashboard?.mission?.revision ?? loaded.missionRevision;
    setDraft({ ...loaded, missionRevision });
  }, [dashboard?.mission?.revision, status?.latestDraft?.draft, status?.latestDraft?.draftId]);
  const saveMutation = useMutation({
    mutationFn: async () => {
      const parsed = providerPolicyDraftSchema.safeParse(draft);
      if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? "Provider policy draft is invalid.");
      return gateway.saveProviderPolicyDraft(parsed.data);
    },
    onMutate: () => setValidationError(""),
    onError: (error: Error) => setValidationError(error.message),
  });

  const selectedC2 = c2Options[draft.c2.providerId];
  const operationCounts = useMemo(() => ({
    allowed: draft.operations.filter((operation) => operation.state === "allowed").length,
    approval: draft.operations.filter((operation) => operation.state === "approval_required").length,
    disabled: draft.operations.filter((operation) => operation.state === "disabled").length,
  }), [draft.operations]);

  function selectC2(providerId: C2ProviderId) {
    setDraft((current) => ({
      ...current,
      c2: { providerId, registryReference: c2Options[providerId].registryReference },
    }));
  }

  function updateOperation(id: string, state: ToolPolicyState) {
    setDraft((current) => ({
      ...current,
      operations: current.operations.map((operation) => operation.id === id ? { ...operation, state } : operation),
    }));
  }

  return (
    <div className="page-content provider-policy-page">
      <PageHeader eyebrow={`MISSION POLICY · REVISION ${draft.missionRevision}`} title="C2 and tool access policy" description="Manage Tuoni, Sliver, and the Phase 5 Impacket MCP allowlist. Saving a draft never authorizes execution." actions={<Badge tone={gatewayMode === "live" ? "green" : "amber"}>{gatewayMode === "live" ? "LIVE CONTROL" : "MOCK MODE"}</Badge>} />
      <div className="inline-alert provider-principle"><ShieldAlert size={16}/><span><b>Provider access is not execution authorization.</b> Arbitrary commands, unrestricted arguments, payload generation, credential dumping, and native C2 commands remain unavailable.</span></div>

      <section className="panel provider-policy-shell">
        <div className="provider-tabs" role="tablist" aria-label="Provider policy sections">
          <button type="button" role="tab" aria-selected={tab === "c2"} onClick={() => setTab("c2")}>C2 Selection</button>
          <button type="button" role="tab" aria-selected={tab === "tools"} onClick={() => setTab("tools")}>Tools (MCP) Control</button>
          <button type="button" role="tab" aria-selected={tab === "review"} onClick={() => setTab("review")}>Review Policy</button>
        </div>

        {tab === "c2" && <div className="provider-tab-panel" role="tabpanel">
          <div className="provider-card-heading"><div className="provider-icon"><RadioTower size={18}/></div><div><p className="eyebrow">EXECUTION ADAPTER</p><h2>C2 Adapter</h2><p>Choose the typed C2 provider referenced by the current Mission draft.</p></div><Badge tone={draft.c2.providerId === "none" ? "neutral" : "amber"}>{draft.c2.providerId === "none" ? "NOT SELECTED" : "HUMAN GATE"}</Badge></div>
          <div className="c2-selection-grid">
            <label className="field"><span>Preferred C2</span><select aria-label="Preferred C2" value={draft.c2.providerId} onChange={(event) => selectC2(event.target.value as C2ProviderId)}>{Object.entries(c2Options).map(([id, option]) => <option key={id} value={id}>{option.label}</option>)}</select></label>
            {draft.c2.providerId === "sliver" ? <dl className="provider-facts"><div><dt>Version</dt><dd>{status?.sliver.version ?? "1.7.7"}</dd></div><div><dt>Operator</dt><dd>{status?.sliver.operator ?? "joe"}</dd></div><div><dt>Implant transport</dt><dd>{status?.sliver.implantTransport.toUpperCase() ?? "HTTP"}</dd></div><div><dt>Beacon</dt><dd>{status?.sliver.beaconPresent ? "present" : "not present"}</dd></div></dl> : <dl className="provider-facts"><div><dt>Edition</dt><dd>{status?.tuoni.edition ?? "commercial"}</dd></div><div><dt>Version</dt><dd>{status?.tuoni.version ?? "latest"}</dd></div><div><dt>Control VM access</dt><dd>{status?.tuoni.access ?? "unconfigured"}</dd></div><div><dt>External egress</dt><dd>Default deny</dd></div></dl>}
          </div>
          <div className="c2-selection-detail" aria-live="polite"><h3>{selectedC2.label}</h3><p>{selectedC2.description}</p><div className="capability-grid"><span><Check size={14}/>Session inventory</span><span><Check size={14}/>Typed task status</span><span className={draft.c2.providerId === "sliver" ? "unavailable" : undefined}>{draft.c2.providerId === "sliver" ? <LockKeyhole size={14}/> : <Check size={14}/>}Redacted results</span><span><Check size={14}/>Cancellation</span><span><Check size={14}/>Reconciliation</span><span className="unavailable"><LockKeyhole size={14}/>Payload generation</span></div>{draft.c2.providerId !== "none" && <div className="inline-alert"><AlertTriangle size={15}/><span>{draft.c2.providerId === "sliver" ? "Selection remains inactive until the exact operator config, gRPC/mTLS server identity, and a live HTTP Beacon pass the Provider Human Gate." : "Selection remains inactive until the real Control VM access, authentication, vCenter isolation, and exact capability mapping pass the Phase 4 Human Gate."}</span></div>}</div>
        </div>}

        {tab === "tools" && <div className="provider-tab-panel" role="tabpanel">
          <div className="provider-card-heading"><div className="provider-icon"><TerminalSquare size={18}/></div><div><p className="eyebrow">PRIMARY TOOL RUNTIME</p><h2>Impacket MCP</h2><p>Only four immutable, purpose-specific operations are exposed.</p></div><Badge tone={status?.impacket.installed ? "green" : "red"}>{status?.impacket.installed ? `INSTALLED ${status.impacket.version ?? ""}` : "UNAVAILABLE"}</Badge></div>
          <dl className="runtime-facts"><div><dt>Server</dt><dd>{status?.impacket.server ?? "redteam-impacket-mcp"}</dd></div><div><dt>Arbitrary command</dt><dd><LockKeyhole size={13}/>Disabled</dd></div><div><dt>Egress</dt><dd>TCP/445 and TCP/135 only</dd></div><div><dt>Raw result</dt><dd>Quarantine stream</dd></div></dl>

          <section className="registered-operations" aria-labelledby="operations-heading"><div className="section-title"><div><p className="eyebrow">TOOL REGISTRY</p><h2 id="operations-heading">Registered Impacket functions</h2></div><span className="operation-summary">{operationCounts.allowed} allowed · {operationCounts.approval} approval · {operationCounts.disabled} disabled</span></div><div className="tool-operation-list"><details className="tool-operation-group" data-tool="Impacket"><summary><div><h3>Impacket</h3><p>Purpose-specific SMB and RPC operations; the suite itself is never exposed.</p></div><span className="tool-summary-meta"><Badge tone="green">AVAILABLE</Badge><small>{operations.length} functions</small></span></summary><div>{operations.map((definition) => { const policy = draft.operations.find((operation) => operation.id === definition.id); return <article className="tool-function-row" key={definition.id}><div className="tool-function-title"><div><b>{definition.function}</b><span>via <code>{definition.id}</code></span></div><code>{definition.id}</code></div><div className="command-template"><span>MCP operation</span><code>{definition.id}(target_ref=&lt;approved-target-ref&gt;)</code><small>References are resolved by the trusted adapter; values are not free-form commands.</small></div><dl className="tool-function-details"><div><dt>Required inputs</dt><dd>{definition.inputs}</dd></div><div><dt>Produces</dt><dd>{definition.output}</dd></div><div><dt>Safety constraint</dt><dd>{definition.constraint}</dd></div></dl><label className="operation-policy-field"><span>Policy state</span><select aria-label={`Policy for ${definition.function}`} value={policy?.state} onChange={(event) => updateOperation(definition.id, event.target.value as ToolPolicyState)}><option value="allowed">Allowed</option><option value="approval_required">Approval required</option><option value="disabled">Disabled</option></select></label></article>; })}</div></details></div></section>
          <div className="offline-note"><Database size={17}/><div><b>Closed allowlist</b><p>secretsdump, service execution, arbitrary flags, uploads, and deletes are not registered and cannot be selected here.</p></div></div>
        </div>}

        {tab === "review" && <div className="provider-tab-panel" role="tabpanel">
          <div className="policy-review-grid"><div><span>Preferred C2</span><b>{selectedC2.label}</b><small>{draft.c2.providerId === "none" ? "No gate required" : "Human Gate required"}</small></div><div><span>Primary runtime</span><b>Impacket MCP</b><small>Arbitrary commands disabled</small></div><div><span>Version</span><b>{status?.impacket.version ?? "unavailable"}</b><small>Runtime package</small></div><div><span>Operation policy</span><b>{draft.operations.length} typed operations</b><small>{operationCounts.disabled} explicitly disabled</small></div></div>
          <ul className="policy-review-list"><li>C2 selection is an adapter preference, not authority to execute.</li><li>Sliver is limited to inventory and existing Beacon Task read/cancel operations.</li><li>Impacket is exposed only through four reviewed purpose-specific operations.</li><li>Secrets remain references and are resolved only at trusted dispatch.</li><li>Saving this record does not create a Policy Decision or activate a Mission.</li></ul>
          {validationError && <div className="inline-alert error" role="alert"><AlertTriangle size={15}/><span>{validationError}</span></div>}
          {saveMutation.isSuccess && <div className="inline-alert success"><Check size={15}/><span>Draft {saveMutation.data.draftId} saved at {formatUtcTime(saveMutation.data.savedAt)} UTC. No Mission was activated.</span></div>}
          <div className="provider-actions"><span>Saving does not create a Policy Decision.</span><Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}><Save size={15}/>{saveMutation.isPending ? "Saving draft" : "Save policy draft"}</Button></div>
        </div>}
      </section>
    </div>
  );
}
