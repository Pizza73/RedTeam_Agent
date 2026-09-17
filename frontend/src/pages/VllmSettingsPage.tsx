import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Bot, Check, CheckCircle2, Clock3, KeyRound, LoaderCircle, Save, Server, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge, Button, Input, PageHeader } from "../components/ui";
import { gateway, gatewayMode } from "../gateway";
import { formatUtcTime } from "../lib/time";
import { vllmConfigSchema, type VllmCapabilityResult, type VllmScenario, type VllmSettings } from "../types";

export function VllmSettingsPage() {
  const queryClient = useQueryClient();
  const [baseUrl, setBaseUrl] = useState("http://10.0.6.181:8100/v1");
  const [apiKey, setApiKey] = useState("");
  const [scenario, setScenario] = useState<VllmScenario>("success");
  const [validationError, setValidationError] = useState("");
  const [result, setResult] = useState<VllmCapabilityResult | null>(null);
  const settingsQuery = useQuery({ queryKey: ["vllm-settings"], queryFn: () => gateway.getVllmSettings() });
  const settings = settingsQuery.data;

  useEffect(() => {
    if (settings) setBaseUrl(settings.candidate?.config.baseUrl ?? settings.active.config.baseUrl);
  }, [settings]);

  const updateSettings = (next: VllmSettings) => queryClient.setQueryData(["vllm-settings"], next);
  const stageMutation = useMutation<VllmSettings, Error>({
    mutationFn: async () => {
      const active = settings?.active.config;
      if (!active) throw new Error("The managed model profile is unavailable.");
      const parsed = vllmConfigSchema.safeParse({ ...active, baseUrl });
      if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? "Configuration is invalid.");
      if (!apiKey) throw new Error("Enter an API key to register or replace the candidate credential.");
      return gateway.stageVllmCandidate(parsed.data.baseUrl, apiKey);
    },
    onMutate: () => setValidationError(""),
    onSuccess: (next) => { updateSettings(next); setApiKey(""); setResult(null); },
    onError: (error) => setValidationError(error.message),
  });
  const testMutation = useMutation<VllmCapabilityResult, Error>({
    mutationFn: async () => {
      if (!settings) throw new Error("The managed model profile is unavailable.");
      if (settings.candidate) {
        const response = await gateway.testVllmCandidate(settings.candidate.version, scenario);
        updateSettings(response.settings);
        return response.capability;
      }
      return gateway.testVllmConnection(settings.active.config, scenario);
    },
    onMutate: () => setValidationError(""),
    onSuccess: setResult,
    onError: (error) => setValidationError(error.message),
  });
  const activateMutation = useMutation<VllmCapabilityResult, Error>({
    mutationFn: async () => {
      const candidate = settings?.candidate;
      if (!candidate) throw new Error("Register and test a candidate before activation.");
      const response = await gateway.activateVllmCandidate(candidate.version);
      updateSettings(response.settings);
      if (!response.activated) throw new Error("The activation check failed; the previous endpoint remains active.");
      return response.capability;
    },
    onMutate: () => setValidationError(""),
    onSuccess: (capability) => { setResult(capability); setApiKey(""); },
    onError: (error) => setValidationError(error.message),
  });

  const candidate = settings?.candidate;
  const busy = stageMutation.isPending || testMutation.isPending || activateMutation.isPending;
  return (
    <div className="page-content settings-page">
      <PageHeader eyebrow="MODEL PROFILE" title="VLLM connection and capability check" description="Register a server-owned credential, test a staged endpoint, and activate it only after the complete signed Phase 2 contract passes." actions={<Badge tone={gatewayMode === "live" ? "green" : "amber"}>{gatewayMode === "live" ? "LIVE GATEWAY" : "MOCK MODE"}</Badge>} />
      <div className="settings-layout">
        <section className="panel form-panel">
          <div className="section-title"><div><p className="eyebrow">MANAGED CONNECTION</p><h2>Profile configuration</h2></div><Server size={19}/></div>
          <div className="form-grid">
            <label className="field field-wide"><span>Base URL</span><Input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} aria-describedby="base-url-help" disabled={busy || settings?.settingsMutable === false}/><small id="base-url-help">{settings?.settingsMutable === false ? "This server uses a deployment-managed endpoint." : `Use an approved literal IPv4 address ending in /v1. Allowed network: ${settings?.allowedCidrs.join(", ") ?? "loading"}.`}</small></label>
            <label className="field field-wide"><span>API key</span><Input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} autoComplete="new-password" maxLength={4096} aria-describedby="api-key-help" disabled={busy || settings?.settingsMutable === false}/><small id="api-key-help">{settings?.settingsMutable === false ? "The credential is managed outside this UI." : "Submitted once to the local control plane, stored in a 0600 service file, never returned or prefilled."}</small></label>
            <label className="field"><span>Model name</span><Input value={settings?.active.config.modelName ?? "gemma-4-31B-it"} disabled /></label>
            <label className="field"><span>Wire API</span><Input value="chat_completions" disabled /></label>
            {gatewayMode === "mock" && <label className="field"><span>Mock scenario</span><select value={scenario} onChange={(event) => setScenario(event.target.value as VllmScenario)}><option value="success">Compatible profile</option><option value="incompatible">Structured output incompatible</option><option value="unreachable">Service unreachable</option><option value="timeout">Bounded timeout</option></select></label>}
          </div>
          {settingsQuery.isPending && <div className="inline-alert"><LoaderCircle className="spin" size={15}/><span>Loading server-managed LLM settings.</span></div>}
          {settingsQuery.isError && <div className="inline-alert error"><AlertTriangle size={15}/><span>Runtime LLM settings management is unavailable.</span></div>}
          {settings && <div className="llm-setting-status"><div><span>ACTIVE</span><b>{settings.active.config.baseUrl}</b><small>Key {settings.active.apiKeyConfigured ? "registered" : "missing"} · generation {settings.active.version}</small></div><div><span>CANDIDATE</span><b>{candidate?.config.baseUrl ?? "Not registered"}</b><small>{candidate ? `Key registered · test ${candidate.testStatus.replace("_", " ")}` : "Enter a URL and key to stage a replacement"}</small></div></div>}
          {candidate?.transportSecurity === "isolated_network_required" && <div className="inline-alert"><AlertTriangle size={15}/><span>This HTTP endpoint sends its API key without TLS. Use it only on the approved isolated network.</span></div>}
          {candidate?.testStatus === "passed" && <div className="inline-alert success"><CheckCircle2 size={15}/><span>The candidate passed. Activation reruns the contract and keeps the old endpoint if that final check fails.</span></div>}
          {validationError && <div className="inline-alert error"><AlertTriangle size={15}/><span>{validationError}</span></div>}
          <div className="form-footer"><div className="safety-note"><KeyRound size={16}/><span>Saved keys never enter SQLite, logs, or API responses.</span></div><div className="llm-setting-actions"><Button variant="secondary" onClick={() => stageMutation.mutate()} disabled={busy || !settings?.settingsMutable}>{stageMutation.isPending ? <LoaderCircle className="spin" size={16}/> : <Save size={16}/>} Register candidate</Button><Button onClick={() => testMutation.mutate()} disabled={busy || !settings}>{testMutation.isPending ? <><LoaderCircle className="spin" size={16}/> Testing capabilities</> : <><Check size={16}/> Test connection & capabilities</>}</Button><Button variant="secondary" onClick={() => activateMutation.mutate()} disabled={busy || !settings?.settingsMutable || candidate?.testStatus !== "passed"}>{activateMutation.isPending ? <LoaderCircle className="spin" size={16}/> : <CheckCircle2 size={16}/>} Activate candidate</Button></div></div>
        </section>

        <section className="panel result-panel" aria-live="polite">
          <div className="section-title"><div><p className="eyebrow">CAPABILITY CONTRACT</p><h2>Latest check</h2></div>{result ? <Badge tone={result.status === "passed" ? "green" : result.status === "timeout" ? "amber" : "red"}>{result.status.toUpperCase()}</Badge> : <Badge>NOT RUN</Badge>}</div>
          {!result && !testMutation.isPending && !activateMutation.isPending && <div className="result-placeholder"><Bot size={34}/><h3>No capability result</h3><p>Run the bounded canary to inspect model compatibility.</p></div>}
          {(testMutation.isPending || activateMutation.isPending) && <div className="result-placeholder"><LoaderCircle className="spin" size={34}/><h3>Checking profile</h3><p>Running transport and schema canaries with a finite timeout.</p></div>}
          {result && !testMutation.isPending && !activateMutation.isPending && <><div className={`result-summary ${result.status}`}>{result.status === "passed" ? <CheckCircle2 size={21}/> : result.status === "timeout" ? <Clock3 size={21}/> : <XCircle size={21}/>}<div><b>{result.summary}</b><span>{result.latencyMs.toLocaleString()} ms · {formatUtcTime(result.checkedAt)} UTC</span></div></div><div className="check-list">{result.checks.map((check) => <div key={check.name}><span className={`check-icon ${check.status}`}>{check.status === "passed" ? <Check size={13}/> : check.status === "failed" ? <XCircle size={13}/> : <Clock3 size={13}/>}</span><p><b>{check.name}</b><small>{check.detail}</small></p><Badge tone={check.status === "passed" ? "green" : check.status === "failed" ? "red" : "neutral"}>{check.status.replace("_", " ")}</Badge></div>)}</div></>}
        </section>
      </div>
    </div>
  );
}
