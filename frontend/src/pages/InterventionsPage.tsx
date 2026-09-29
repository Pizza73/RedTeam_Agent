import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Check, ChevronRight, Clock3, FileCheck2, LoaderCircle, ShieldAlert, Split, X } from "lucide-react";
import { useMemo, useState } from "react";
import { gateway } from "../gateway";
import type { Intervention } from "../types";
import { Badge, Button, EmptyState, Modal, PageHeader } from "../components/ui";
import { formatUtcTime } from "../lib/time";

function stateTone(state: Intervention["state"]) {
  return state === "pending" ? "amber" : state === "approved" || state === "selected" ? "green" : state === "rejected" || state === "expired" ? "red" : "neutral";
}

export function InterventionsPage() {
  const queryClient = useQueryClient();
  const { data = [], isLoading } = useQuery({ queryKey: ["interventions"], queryFn: () => gateway.getInterventions() });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [candidateId, setCandidateId] = useState("");
  const selected = useMemo(() => data.find((item) => item.id === selectedId) ?? null, [data, selectedId]);
  const mutation = useMutation({
    mutationFn: async (input: { action: "approved" | "rejected" | "select"; candidateId?: string }) => {
      if (!selected) throw new Error("No intervention is selected.");
      if (selected.actionable === false) throw new Error(selected.disabledReason ?? "This intervention is read-only.");
      if (input.action === "select") return gateway.selectCandidate(selected.id, input.candidateId ?? "");
      if (selected.kind !== "approval") throw new Error("This intervention is not an approval request.");
      return gateway.resolveApproval(selected.id, input.action, selected.presentationDigest);
    },
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ["interventions"] }); setSelectedId(null); setCandidateId(""); },
  });
  const pending = data.filter((item) => item.state === "pending");
  return (
    <div className="page-content">
      <PageHeader eyebrow="OPERATOR QUEUE" title="Human interventions" description="Review bound execution intent and choose among safe planning candidates without conflating selection with authorization." actions={<Badge tone="amber">{pending.length} PENDING</Badge>} />
      <div className="intervention-layout">
        <section className="panel queue-panel">
          <div className="queue-tabs"><button className="active">Pending <span>{pending.length}</span></button><button>Resolved <span>{data.length - pending.length}</span></button></div>
          {isLoading ? <div className="loading-row"><LoaderCircle className="spin" size={18}/> Loading intervention queue</div> : data.length === 0 ? <EmptyState icon={<FileCheck2/>} title="Queue is clear" description="No operator action is currently required."/> : <div className="intervention-list">{data.map((item) => <button key={item.id} className="intervention-card" onClick={() => { setSelectedId(item.id); setCandidateId(""); }}><span className={`intervention-icon ${item.kind}`}>{item.kind === "approval" ? <ShieldAlert size={17}/> : <Split size={17}/>}</span><div><span className="card-meta">{item.kind === "approval" ? "EXECUTION APPROVAL" : "PLANNING CHOICE"} · REV {item.missionRevision}</span><h3>{item.title}</h3><p>{item.summary}</p><small><Clock3 size={12}/>{item.state === "expired" ? "Expired" : `Expires ${new Date(item.expiresAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`}</small></div><Badge tone={stateTone(item.state)}>{item.state.replace("_", " ")}</Badge><ChevronRight size={15}/></button>)}</div>}
        </section>
        <aside className="panel queue-guidance"><p className="eyebrow">FAIL-CLOSED REVIEW</p><h2>Selection is not approval</h2><p>A planning choice only identifies the operator's preferred next proposal. The selected action must still pass current scope, policy, binding, and approval checks.</p><ul><li><Check size={13}/>Review the full normalized target</li><li><Check size={13}/>Confirm risk and side effect</li><li><Check size={13}/>Verify revision, epoch, and expiry</li><li><X size={13}/>Never approve stale requests</li></ul></aside>
      </div>

      <Modal open={Boolean(selected)} onOpenChange={(open) => !open && setSelectedId(null)} title={selected?.title ?? "Intervention"} description={selected?.summary}>
        {selected && <div className="intervention-detail">
          <div className="binding-strip"><span>Mission <b>{selected.missionId}</b></span><span>Revision <b>{selected.missionRevision}</b></span><span>Epoch <b>{selected.authorizationEpoch}</b></span><span>Expires <b>{formatUtcTime(selected.expiresAt)} UTC</b></span></div>
          {selected.kind === "approval" ? <>
            <div className="intent-grid"><div><span>Tool</span><b>{selected.toolDisplayName}</b></div><div><span>Adapter</span><b>{selected.adapterId}</b></div><div><span>Risk</span><Badge tone={selected.risk === "high" ? "red" : "amber"}>{selected.risk}</Badge></div><div><span>Side effect</span><Badge tone={selected.sideEffect === "read_only" ? "green" : "red"}>{selected.sideEffect.replace("_", " ")}</Badge></div></div>
            <div className="detail-block"><span>Normalized targets</span>{selected.targets.map((target) => <code key={target}>{target}</code>)}</div>
            <div className="detail-block"><span>Redacted arguments</span><pre>{JSON.stringify(selected.redactedArguments, null, 2)}</pre></div>
            <div className="digest-row"><span>Presentation digest</span><code>{selected.presentationDigest}</code></div>
            {selected.state === "pending" && selected.actionable !== false ? <div className="dialog-actions"><Button variant="danger" onClick={() => mutation.mutate({ action: "rejected" })} disabled={mutation.isPending}><X size={15}/> Reject</Button><Button onClick={() => mutation.mutate({ action: "approved" })} disabled={mutation.isPending}>{mutation.isPending ? <LoaderCircle className="spin" size={15}/> : <Check size={15}/>} Approve bound intent</Button></div> : <div className="inline-alert error"><AlertTriangle size={15}/>{selected.disabledReason ?? `This request is ${selected.state} and cannot be changed.`}</div>}
          </> : <>
            <div className="candidate-list">{selected.candidates.map((candidate) => <label className={candidateId === candidate.id ? "selected" : ""} key={candidate.id}><input type="radio" name="candidate" value={candidate.id} checked={candidateId === candidate.id} onChange={() => setCandidateId(candidate.id)}/><div><b>{candidate.label}</b><p>{candidate.description}</p></div><Badge tone={candidate.estimatedRisk === "read" ? "green" : "cyan"}>{candidate.estimatedRisk}</Badge></label>)}</div>
            <div className="inline-alert"><AlertTriangle size={15}/><span>Confirming this choice starts policy re-evaluation. It does not authorize execution.</span></div>
            {selected.state === "pending" ? <div className="dialog-actions"><Button variant="secondary" onClick={() => setSelectedId(null)}>Cancel</Button><Button onClick={() => mutation.mutate({ action: "select", candidateId })} disabled={!candidateId || mutation.isPending}>Confirm planning choice <ChevronRight size={15}/></Button></div> : <div className="inline-alert success"><Check size={15}/>Choice recorded. Awaiting policy re-evaluation.</div>}
          </>}
          {mutation.isError && <div className="inline-alert error"><AlertTriangle size={15}/>{mutation.error.message}</div>}
        </div>}
      </Modal>
    </div>
  );
}
