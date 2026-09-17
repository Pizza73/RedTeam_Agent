import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Check, ChevronLeft, ChevronRight, CircleCheck, Crosshair, FileText, Plus, Save, ShieldCheck, Target, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { gateway } from "../gateway";
import { missionDraftSchema, type MissionDraft, type MissionState } from "../types";
import { Badge, Button, Input, PageHeader } from "../components/ui";
import { formatUtcTime } from "../lib/time";

type DraftTarget = MissionDraft["targets"][number];
const unsupportedTypes = new Set<DraftTarget["type"]>(["remote_filesystem", "other"]);

const targetLabels: Record<DraftTarget["type"], string> = {
  network: "IP or CIDR", host: "Host ID", session: "Session ID", hostname: "Hostname", domain: "Domain", url: "URL", remote_filesystem: "Remote filesystem", other: "Other",
};

function defaultValidity(): string {
  const date = new Date(Date.now() + 24 * 60 * 60 * 1_000);
  return date.toISOString().slice(0, 16);
}

export function MissionBuilderPage() {
  const queryClient = useQueryClient();
  const { data: health } = useQuery({ queryKey: ["health"], queryFn: () => gateway.getHealth() });
  const { data: readiness, isLoading: readinessLoading, isError: readinessError } = useQuery({ queryKey: ["execution-readiness"], queryFn: () => gateway.getExecutionReadiness(), refetchInterval: 5_000 });
  const [step, setStep] = useState(0);
  const [errors, setErrors] = useState<string[]>([]);
  const [draft, setDraft] = useState<MissionDraft>({
    name: "AD privilege assessment",
    description: "Validate whether the authorized service principal can satisfy the defined lab objective.",
    authorizationReference: "LAB-AUTH-2026-084",
    validUntil: defaultValidity(),
    targets: [{ id: crypto.randomUUID(), type: "network", value: "10.0.10.212/32", port: 445, protocol: "tcp" }],
    successType: "session_exists",
    successValue: "beacon:<approved-id>",
    maxIterations: 20,
    maxRuntimeMinutes: 180,
    approvalRisk: "medium",
  });
  const [savedDraftFingerprint, setSavedDraftFingerprint] = useState<string | null>(null);
  const currentDraftFingerprint = JSON.stringify(draft);
  const saveMutation = useMutation({
    mutationFn: () => gateway.saveMissionDraft(draft),
    onSuccess: () => {
      setSavedDraftFingerprint(currentDraftFingerprint);
      void queryClient.invalidateQueries({ queryKey: ["execution-readiness"] });
    },
  });
  const [mission, setMission] = useState<MissionState | null>(null);
  const createMutation = useMutation({
    mutationFn: (draftId: string) => gateway.createMission(draftId),
    onSuccess: (created) => {
      setMission(created);
      void queryClient.invalidateQueries({ queryKey: ["execution-readiness"] });
    },
  });
  const transitionMutation = useMutation({
    mutationFn: (action: "validate" | "start" | "pause" | "resume" | "finalize" | "complete" | "abort") => {
      if (mission === null) throw new Error("Mission has not been created.");
      return gateway.transitionMission(mission.missionId, mission.missionStateVersion, action);
    },
    onSuccess: (updated) => {
      setMission(updated);
      void queryClient.invalidateQueries({ queryKey: ["execution-readiness"] });
    },
  });
  const unresolved = useMemo(() => draft.targets.some((target) => unsupportedTypes.has(target.type)) || draft.successType !== "session_exists", [draft]);
  const draftSaved = saveMutation.isSuccess && savedDraftFingerprint === currentDraftFingerprint;

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
      <section className={`panel readiness-panel ${readinessError ? "error" : readiness?.status ?? "loading"}`} aria-labelledby="execution-readiness-heading" aria-live="polite">
        <div className="readiness-heading"><div><p className="eyebrow">EXECUTION GATE · SAVED CONTROL-PLANE STATE</p><h2 id="execution-readiness-heading">Execution readiness</h2><p>{readinessLoading ? "Checking every activation prerequisite…" : readinessError ? "The server could not determine execution readiness. Execution remains blocked until this status can be loaded." : readiness?.summary ?? "Readiness is unavailable."}</p></div><Badge tone={readiness?.status === "ready" && !readinessError ? "green" : "red"}>{readinessError ? "ERROR" : readiness?.status === "ready" ? "READY" : `${readiness?.blockerCount ?? "—"} BLOCKING`}</Badge></div>
        {readiness?.blockers.length ? <ol className="readiness-blockers">{readiness.blockers.map((blocker) => <li key={blocker.id}><span>{blocker.category}</span><div><b>{blocker.title}</b><p>{blocker.detail}</p><small>Next: {blocker.resolution}</small></div><code>{blocker.id}</code></li>)}</ol> : readiness?.status === "ready" ? <div className="inline-alert success"><CircleCheck size={16}/><span>All registered prerequisites are satisfied.</span></div> : null}
        {readiness?.checks.length ? <details className="readiness-checks"><summary>{readiness.checks.length} completed check{readiness.checks.length === 1 ? "" : "s"}</summary><ul>{readiness.checks.map((check) => <li key={check.id}><CircleCheck size={14}/><span><b>{check.title}</b>{check.detail}</span></li>)}</ul></details> : null}
      </section>
      <div className="builder-shell">
        <ol className="builder-steps">{steps.map(([label, Icon], index) => <li key={label} className={index === step ? "active" : index < step ? "complete" : ""}><span>{index < step ? <Check size={14}/> : <Icon size={14}/>}</span><div><small>STEP {index + 1}</small><b>{label}</b></div></li>)}</ol>
        <section className="panel builder-panel">
          {step === 0 && <><div className="builder-heading"><div><p className="eyebrow">ALLOWED EXECUTION SCOPE</p><h2>Where may this Mission operate?</h2><p>Unknown, incomplete, or unsupported target types remain fail-closed.</p></div><Button variant="secondary" onClick={addTarget}><Plus size={15}/> Add target</Button></div><div className="target-list">{draft.targets.map((target, index) => <div className="target-row" key={target.id}><div className="target-number">{index + 1}</div><label className="field"><span>Target type</span><select value={target.type} onChange={(event) => updateTarget(target.id, { type: event.target.value as DraftTarget["type"], value: "", port: null, protocol: event.target.value === "network" ? "tcp" : null })}>{Object.entries(targetLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label className="field field-grow"><span>{target.type === "other" ? "Describe the target" : targetLabels[target.type]}</span><Input value={target.value} placeholder={target.type === "network" ? "10.40.8.0/24" : target.type === "other" ? "Describe a target requiring contract review" : "Enter canonical reference"} onChange={(event) => updateTarget(target.id, { value: event.target.value })}/>{unsupportedTypes.has(target.type) && <small className="warning-text">This type is stored as an unresolved draft and cannot activate a Mission.</small>}</label>{target.type === "network" && <><label className="field compact"><span>Port</span><Input type="number" value={target.port ?? ""} min={1} max={65535} onChange={(event) => updateTarget(target.id, { port: event.target.value ? Number(event.target.value) : null })}/></label><label className="field compact"><span>Protocol</span><select value={target.protocol ?? "tcp"} onChange={(event) => updateTarget(target.id, { protocol: event.target.value as "tcp" | "udp" })}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label></>}<button className="icon-button danger" onClick={() => setDraft((current) => ({ ...current, targets: current.targets.filter((item) => item.id !== target.id) }))} aria-label={`Remove target ${index + 1}`}><Trash2 size={15}/></button></div>)}</div></>}
          {step === 1 && <><div className="builder-heading"><div><p className="eyebrow">DETERMINISTIC OUTCOME</p><h2>What confirms Mission success?</h2><p>Planner text alone cannot satisfy a success condition.</p></div></div><div className="condition-grid"><label className="field"><span>Condition type</span><select value={draft.successType} onChange={(event) => setDraft({ ...draft, successType: event.target.value as MissionDraft["successType"], successValue: "" })}><option value="session_exists">Active session exists</option><option value="windows_privilege">Windows privilege confirmed</option><option value="ad_membership">AD membership confirmed</option><option value="linux_root">Linux effective UID is root</option><option value="evidence">Confirmed evidence exists</option><option value="artifact">Verified artifact exists</option><option value="other">Other</option></select></label><label className="field field-wide"><span>{draft.successType === "other" ? "Describe the requested condition" : "Condition parameters"}</span><textarea value={draft.successValue} onChange={(event) => setDraft({ ...draft, successValue: event.target.value })} placeholder="Describe the typed identifiers and required confirmed state." />{draft.successType === "other" && <small className="warning-text">A backend-owned deterministic condition type is required before activation.</small>}</label></div></>}
          {step === 2 && <><div className="builder-heading"><div><p className="eyebrow">AUTHORIZATION & LIMITS</p><h2>Bind operator authority and execution limits</h2><p>These values become immutable when a Mission revision enters RUNNING.</p></div></div><div className="form-grid controls-grid"><label className="field"><span>Mission name</span><Input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })}/></label><label className="field"><span>Authorization reference</span><Input value={draft.authorizationReference} onChange={(event) => setDraft({ ...draft, authorizationReference: event.target.value })}/></label><label className="field field-wide"><span>Description</span><textarea value={draft.description} onChange={(event) => setDraft({ ...draft, description: event.target.value })}/></label><label className="field"><span>Valid until (UTC)</span><Input type="datetime-local" value={draft.validUntil} onChange={(event) => setDraft({ ...draft, validUntil: event.target.value })}/></label><label className="field"><span>Approval required from risk</span><select value={draft.approvalRisk} onChange={(event) => setDraft({ ...draft, approvalRisk: event.target.value as MissionDraft["approvalRisk"] })}><option value="low">Low and above</option><option value="medium">Medium and above</option><option value="high">High only</option></select></label><label className="field"><span>Maximum iterations</span><Input type="number" min={1} value={draft.maxIterations} onChange={(event) => setDraft({ ...draft, maxIterations: Number(event.target.value) })}/></label><label className="field"><span>Maximum runtime (minutes)</span><Input type="number" min={1} value={draft.maxRuntimeMinutes} onChange={(event) => setDraft({ ...draft, maxRuntimeMinutes: Number(event.target.value) })}/></label></div></>}
          {step === 3 && <><div className="builder-heading"><div><p className="eyebrow">REVIEW DRAFT</p><h2>Confirm the proposed Mission boundary</h2><p>Save the reviewable draft, then create and transition the authoritative Mission through the owner service.</p></div></div><div className="review-grid"><div><span>Mission</span><b>{draft.name}</b><p>{draft.description}</p></div><div><span>Authorization</span><b>{draft.authorizationReference}</b><p>Valid until {draft.validUntil} UTC</p></div><div><span>Allowed targets</span><b>{draft.targets.length} scope rule{draft.targets.length === 1 ? "" : "s"}</b><p>{draft.targets.map((target) => `${targetLabels[target.type]}: ${target.value}`).join(" · ")}</p></div><div><span>Success condition</span><b>{draft.successType.replaceAll("_", " ")}</b><p>{draft.successValue}</p></div><div><span>Limits</span><b>{draft.maxIterations} iterations · {draft.maxRuntimeMinutes} minutes</b><p>Approval from {draft.approvalRisk} risk</p></div></div>{unresolved && <div className="inline-alert error"><AlertTriangle size={16}/><span>This draft contains a type without a registered deterministic owner rule. It can be saved, but Mission activation remains blocked.</span></div>}{health && !health.missionExecutionEnabled && <div className="inline-alert"><AlertTriangle size={16}/><span>The execution worker is not attested. This Mission can be created and validated, but start and resume remain disabled.</span></div>}{draftSaved && <div className="inline-alert success"><CircleCheck size={16}/><span>Draft {saveMutation.data.draftId} saved at {formatUtcTime(saveMutation.data.savedAt)} UTC.</span></div>}{mission && <div className="inline-alert success"><CircleCheck size={16}/><span>Mission {mission.missionId} is {mission.state} at state version {mission.missionStateVersion}.</span></div>}{(createMutation.isError || transitionMutation.isError) && <div className="inline-alert error" role="alert"><AlertTriangle size={16}/><span>{createMutation.error?.message ?? transitionMutation.error?.message ?? "The trusted owner service rejected the operation."}</span></div>}</>}
          {errors.length > 0 && <div className="error-list" role="alert">{errors.map((error) => <p key={error}><AlertTriangle size={14}/>{error}</p>)}</div>}
          <div className="builder-footer"><Button variant="secondary" disabled={step === 0} onClick={() => { setErrors([]); setStep((current) => Math.max(0, current - 1)); }}><ChevronLeft size={15}/> Back</Button><span>Only owner-service transitions create authority.</span>{step < 3 ? <Button onClick={validateStep}>Continue <ChevronRight size={15}/></Button> : <>{!draftSaved && <Button onClick={() => { const parsed = missionDraftSchema.safeParse(draft); if (!parsed.success) setErrors(parsed.error.issues.map((issue) => issue.message)); else saveMutation.mutate(); }} disabled={saveMutation.isPending}><Save size={15}/> {savedDraftFingerprint === null ? "Save draft" : "Save updated draft"}</Button>}{draftSaved && mission === null && <Button onClick={() => createMutation.mutate(saveMutation.data.draftId)} disabled={unresolved || createMutation.isPending}><ShieldCheck size={15}/> Create Mission</Button>}{mission?.state === "DRAFT" && <Button onClick={() => transitionMutation.mutate("validate")} disabled={transitionMutation.isPending}><ShieldCheck size={15}/> Validate</Button>}{mission?.state === "VALIDATED" && <Button onClick={() => transitionMutation.mutate("start")} disabled={transitionMutation.isPending || !health?.missionExecutionEnabled}><CircleCheck size={15}/> Start</Button>}{mission?.state === "RUNNING" && <Button variant="secondary" onClick={() => transitionMutation.mutate("pause")} disabled={transitionMutation.isPending}>Pause</Button>}{mission?.state === "PAUSED" && <Button onClick={() => transitionMutation.mutate("resume")} disabled={transitionMutation.isPending || !health?.missionExecutionEnabled}>Resume</Button>}</>}</div>
        </section>
      </div>
    </div>
  );
}
