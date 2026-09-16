import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Check, ChevronLeft, ChevronRight, CircleCheck, Crosshair, FileText, Plus, Save, ShieldCheck, Target, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { gateway } from "../gateway";
import { missionDraftSchema, type MissionDraft } from "../types";
import { Badge, Button, Input, PageHeader } from "../components/ui";
import { formatUtcTime } from "../lib/time";

type DraftTarget = MissionDraft["targets"][number];
const unsupportedTypes = new Set<DraftTarget["type"]>(["hostname", "domain", "url", "remote_filesystem", "other"]);

const targetLabels: Record<DraftTarget["type"], string> = {
  network: "IP or CIDR", host: "Host ID", session: "Session ID", hostname: "Hostname", domain: "Domain", url: "URL", remote_filesystem: "Remote filesystem", other: "Other",
};

function defaultValidity(): string {
  const date = new Date(Date.now() + 24 * 60 * 60 * 1_000);
  return date.toISOString().slice(0, 16);
}

export function MissionBuilderPage() {
  const [step, setStep] = useState(0);
  const [errors, setErrors] = useState<string[]>([]);
  const [draft, setDraft] = useState<MissionDraft>({
    name: "AD privilege assessment",
    description: "Validate whether the authorized service principal can satisfy the defined lab objective.",
    authorizationReference: "LAB-AUTH-2026-084",
    validUntil: defaultValidity(),
    targets: [{ id: crypto.randomUUID(), type: "network", value: "10.40.8.0/24", port: 636, protocol: "tcp" }],
    successType: "ad_membership",
    successValue: "Principal svc-backup is a confirmed transitive member of Backup Operators",
    maxIterations: 20,
    maxRuntimeMinutes: 180,
    approvalRisk: "medium",
  });
  const saveMutation = useMutation({ mutationFn: () => gateway.saveMissionDraft(draft) });
  const unresolved = useMemo(() => draft.targets.some((target) => unsupportedTypes.has(target.type)) || draft.successType === "other", [draft]);

  function updateTarget(id: string, patch: Partial<DraftTarget>) {
    setDraft((current) => ({ ...current, targets: current.targets.map((target) => target.id === id ? { ...target, ...patch } : target) }));
  }
  function addTarget() {
    setDraft((current) => ({ ...current, targets: [...current.targets, { id: crypto.randomUUID(), type: "network", value: "", port: null, protocol: "tcp" }] }));
  }
  function validateStep() {
    const nextErrors: string[] = [];
    if (step === 0) {
      if (!draft.targets.length) nextErrors.push("At least one allowed execution scope is required.");
      if (draft.targets.some((target) => !target.value.trim())) nextErrors.push("Every target must include a value.");
      if (draft.targets.some((target) => target.port !== null && (target.port < 1 || target.port > 65535))) nextErrors.push("Ports must be between 1 and 65,535.");
    }
    if (step === 1 && !draft.successValue.trim()) nextErrors.push("A deterministic success condition is required.");
    if (step === 2) {
      if (draft.name.trim().length < 3) nextErrors.push("Mission name must contain at least three characters.");
      if (draft.description.trim().length < 10) nextErrors.push("Mission description must contain at least ten characters.");
      if (!draft.authorizationReference.trim()) nextErrors.push("Authorization reference is required.");
      if (!draft.validUntil) nextErrors.push("A validity end time is required.");
    }
    setErrors(nextErrors);
    if (!nextErrors.length) setStep((current) => Math.min(3, current + 1));
  }

  const steps = [["Targets", Target], ["Success condition", Crosshair], ["Controls", ShieldCheck], ["Review", FileText]] as const;
  return (
    <div className="page-content">
      <PageHeader eyebrow="MISSION CONFIGURATION" title="Create Mission draft" description="Define typed authorization boundaries and deterministic success conditions before validation." actions={<Badge tone="amber">DRAFT</Badge>} />
      <div className="builder-shell">
        <ol className="builder-steps">{steps.map(([label, Icon], index) => <li key={label} className={index === step ? "active" : index < step ? "complete" : ""}><span>{index < step ? <Check size={14}/> : <Icon size={14}/>}</span><div><small>STEP {index + 1}</small><b>{label}</b></div></li>)}</ol>
        <section className="panel builder-panel">
          {step === 0 && <><div className="builder-heading"><div><p className="eyebrow">ALLOWED EXECUTION SCOPE</p><h2>Where may this Mission operate?</h2><p>Unknown, incomplete, or unsupported target types remain fail-closed.</p></div><Button variant="secondary" onClick={addTarget}><Plus size={15}/> Add target</Button></div><div className="target-list">{draft.targets.map((target, index) => <div className="target-row" key={target.id}><div className="target-number">{index + 1}</div><label className="field"><span>Target type</span><select value={target.type} onChange={(event) => updateTarget(target.id, { type: event.target.value as DraftTarget["type"], value: "", port: null, protocol: event.target.value === "network" ? "tcp" : null })}>{Object.entries(targetLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label className="field field-grow"><span>{target.type === "other" ? "Describe the target" : targetLabels[target.type]}</span><Input value={target.value} placeholder={target.type === "network" ? "10.40.8.0/24" : target.type === "other" ? "Describe a target requiring contract review" : "Enter canonical reference"} onChange={(event) => updateTarget(target.id, { value: event.target.value })}/>{unsupportedTypes.has(target.type) && <small className="warning-text">This type is stored as an unresolved draft and cannot activate a Mission.</small>}</label>{target.type === "network" && <><label className="field compact"><span>Port</span><Input type="number" value={target.port ?? ""} min={1} max={65535} onChange={(event) => updateTarget(target.id, { port: event.target.value ? Number(event.target.value) : null })}/></label><label className="field compact"><span>Protocol</span><select value={target.protocol ?? "tcp"} onChange={(event) => updateTarget(target.id, { protocol: event.target.value as "tcp" | "udp" })}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label></>}<button className="icon-button danger" onClick={() => setDraft((current) => ({ ...current, targets: current.targets.filter((item) => item.id !== target.id) }))} aria-label={`Remove target ${index + 1}`}><Trash2 size={15}/></button></div>)}</div></>}
          {step === 1 && <><div className="builder-heading"><div><p className="eyebrow">DETERMINISTIC OUTCOME</p><h2>What confirms Mission success?</h2><p>Planner text alone cannot satisfy a success condition.</p></div></div><div className="condition-grid"><label className="field"><span>Condition type</span><select value={draft.successType} onChange={(event) => setDraft({ ...draft, successType: event.target.value as MissionDraft["successType"], successValue: "" })}><option value="session_exists">Active session exists</option><option value="windows_privilege">Windows privilege confirmed</option><option value="ad_membership">AD membership confirmed</option><option value="linux_root">Linux effective UID is root</option><option value="evidence">Confirmed evidence exists</option><option value="artifact">Verified artifact exists</option><option value="other">Other</option></select></label><label className="field field-wide"><span>{draft.successType === "other" ? "Describe the requested condition" : "Condition parameters"}</span><textarea value={draft.successValue} onChange={(event) => setDraft({ ...draft, successValue: event.target.value })} placeholder="Describe the typed identifiers and required confirmed state." />{draft.successType === "other" && <small className="warning-text">A backend-owned deterministic condition type is required before activation.</small>}</label></div></>}
          {step === 2 && <><div className="builder-heading"><div><p className="eyebrow">AUTHORIZATION & LIMITS</p><h2>Bind operator authority and execution limits</h2><p>These values become immutable when a Mission revision enters RUNNING.</p></div></div><div className="form-grid controls-grid"><label className="field"><span>Mission name</span><Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })}/></label><label className="field"><span>Authorization reference</span><Input value={draft.authorizationReference} onChange={(event) => setDraft({ ...draft, authorizationReference: event.target.value })}/></label><label className="field field-wide"><span>Description</span><textarea value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })}/></label><label className="field"><span>Valid until (UTC)</span><Input type="datetime-local" value={draft.validUntil} onChange={(event) => setDraft({ ...draft, validUntil: event.target.value })}/></label><label className="field"><span>Approval required from risk</span><select value={draft.approvalRisk} onChange={(event) => setDraft({ ...draft, approvalRisk: event.target.value as MissionDraft["approvalRisk"] })}><option value="low">Low and above</option><option value="medium">Medium and above</option><option value="high">High only</option></select></label><label className="field"><span>Maximum iterations</span><Input type="number" min={1} value={draft.maxIterations} onChange={(event) => setDraft({ ...draft, maxIterations: Number(event.target.value) })}/></label><label className="field"><span>Maximum runtime (minutes)</span><Input type="number" min={1} value={draft.maxRuntimeMinutes} onChange={(event) => setDraft({ ...draft, maxRuntimeMinutes: Number(event.target.value) })}/></label></div></>}
          {step === 3 && <><div className="builder-heading"><div><p className="eyebrow">REVIEW DRAFT</p><h2>Confirm the proposed Mission boundary</h2><p>Saving creates a frontend-only draft. No Mission lifecycle transition occurs.</p></div></div><div className="review-grid"><div><span>Mission</span><b>{draft.name}</b><p>{draft.description}</p></div><div><span>Authorization</span><b>{draft.authorizationReference}</b><p>Valid until {draft.validUntil} UTC</p></div><div><span>Allowed targets</span><b>{draft.targets.length} scope rule{draft.targets.length === 1 ? "" : "s"}</b><p>{draft.targets.map((target) => `${targetLabels[target.type]}: ${target.value}`).join(" · ")}</p></div><div><span>Success condition</span><b>{draft.successType.replaceAll("_", " ")}</b><p>{draft.successValue}</p></div><div><span>Limits</span><b>{draft.maxIterations} iterations · {draft.maxRuntimeMinutes} minutes</b><p>Approval from {draft.approvalRisk} risk</p></div></div>{unresolved && <div className="inline-alert error"><AlertTriangle size={16}/><span>This draft contains an unresolved “Other” or default-denied type. It can be saved, but Mission activation remains blocked.</span></div>}{saveMutation.isSuccess && <div className="inline-alert success"><CircleCheck size={16}/><span>Draft {saveMutation.data.draftId} saved at {formatUtcTime(saveMutation.data.savedAt)} UTC.</span></div>}</>}
          {errors.length > 0 && <div className="error-list" role="alert">{errors.map((error) => <p key={error}><AlertTriangle size={14}/>{error}</p>)}</div>}
          <div className="builder-footer"><Button variant="secondary" disabled={step === 0} onClick={() => { setErrors([]); setStep((current) => Math.max(0, current - 1)); }}><ChevronLeft size={15}/> Back</Button><span>Drafts do not authorize or dispatch actions.</span>{step < 3 ? <Button onClick={validateStep}>Continue <ChevronRight size={15}/></Button> : <Button onClick={() => { const parsed = missionDraftSchema.safeParse(draft); if (!parsed.success) setErrors(parsed.error.issues.map((issue) => issue.message)); else saveMutation.mutate(); }} disabled={saveMutation.isPending}><Save size={15}/> Save frontend draft</Button>}</div>
        </section>
      </div>
    </div>
  );
}
