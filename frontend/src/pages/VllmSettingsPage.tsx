import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Bot, Check, CheckCircle2, Clock3, LoaderCircle, Server, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { gateway, gatewayMode } from "../gateway";
import { vllmConfigSchema, type VllmCapabilityResult, type VllmScenario } from "../types";
import { Badge, Button, Input, PageHeader } from "../components/ui";
import { formatUtcTime } from "../lib/time";

export function VllmSettingsPage() {
  const [baseUrl, setBaseUrl] = useState("http://10.0.6.181:8100/v1");
  const [modelName, setModelName] = useState("gemma-4-31B-it");
  const [structuredOutputMode, setStructuredOutputMode] = useState<"native" | "tool_output">("native");
  const [scenario, setScenario] = useState<VllmScenario>("success");
  const [validationError, setValidationError] = useState("");
  const managedQuery = useQuery({
    queryKey: ["vllm-configuration"],
    queryFn: () => gateway.getVllmConfiguration(),
  });
  const managed = managedQuery.data;
  const liveConfigurationReady = gatewayMode === "mock" || managed?.enabled === true;

  useEffect(() => {
    if (managed?.enabled) {
      setBaseUrl(managed.config.baseUrl);
      setModelName(managed.config.modelName);
      setStructuredOutputMode(managed.config.structuredOutputMode);
    }
  }, [managed]);

  const testMutation = useMutation<VllmCapabilityResult, Error>({
    mutationFn: async () => {
      const parsed = vllmConfigSchema.safeParse({ baseUrl, modelName, wireApi: "chat_completions", structuredOutputMode });
      if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? "Configuration is invalid.");
      return gateway.testVllmConnection(parsed.data, scenario);
    },
    onMutate: () => setValidationError(""),
    onError: (error) => setValidationError(error.message),
  });

  const result = testMutation.data;
  return (
    <div className="page-content settings-page">
      <PageHeader eyebrow="MODEL PROFILE" title="VLLM connection and capability check" description="Validate transport and strict structured-output behavior before a model profile can be bound to a Mission revision." actions={<Badge tone={gatewayMode === "live" ? "green" : "amber"}>{gatewayMode === "live" ? "LIVE GATEWAY" : "MOCK MODE"}</Badge>} />
      <div className="settings-layout">
        <section className="panel form-panel">
          <div className="section-title"><div><p className="eyebrow">MANAGED CONNECTION</p><h2>Profile configuration</h2></div><Server size={19}/></div>
          <div className="form-grid">
            <label className="field field-wide"><span>Base URL</span><Input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} aria-describedby="base-url-help" disabled={gatewayMode === "live"}/><small id="base-url-help">The trusted UI server fixes this destination; API credentials never enter the browser.</small></label>
            <label className="field"><span>Model name</span><Input value={modelName} onChange={(event) => setModelName(event.target.value)} disabled={gatewayMode === "live"} /></label>
            <label className="field"><span>Wire API</span><Input value="chat_completions" disabled /></label>
            <label className="field"><span>Structured output</span><select value={structuredOutputMode} onChange={(event) => setStructuredOutputMode(event.target.value as "native" | "tool_output")} disabled={gatewayMode === "live"}><option value="native">Native JSON schema</option><option value="tool_output">Tool output fallback</option></select></label>
            {gatewayMode === "mock" && <label className="field"><span>Mock scenario</span><select value={scenario} onChange={(event) => setScenario(event.target.value as VllmScenario)}><option value="success">Compatible profile</option><option value="incompatible">Structured output incompatible</option><option value="unreachable">Service unreachable</option><option value="timeout">Bounded timeout</option></select></label>}
          </div>
          {gatewayMode === "live" && managedQuery.isPending && <div className="inline-alert"><LoaderCircle className="spin" size={15}/><span>Loading the server-managed model profile.</span></div>}
          {gatewayMode === "live" && managed && !managed.enabled && <div className="inline-alert error"><AlertTriangle size={15}/><span>The UI server was started without the trusted Phase 2 VLLM configuration.</span></div>}
          {gatewayMode === "live" && managedQuery.isError && <div className="inline-alert error"><AlertTriangle size={15}/><span>The managed model profile is unavailable.</span></div>}
          {validationError && <div className="inline-alert error"><AlertTriangle size={15}/><span>{validationError}</span></div>}
          <div className="form-footer"><div className="safety-note"><Bot size={16}/><span>{gatewayMode === "live" ? "Requests use signed attestation and the bounded Phase 2 gateway only." : "This test performs no real network request."}</span></div><Button onClick={() => testMutation.mutate()} disabled={testMutation.isPending || !liveConfigurationReady}>{testMutation.isPending ? <><LoaderCircle className="spin" size={16}/> Testing capabilities</> : <><Check size={16}/> Test connection & capabilities</>}</Button></div>
        </section>

        <section className="panel result-panel" aria-live="polite">
          <div className="section-title"><div><p className="eyebrow">CAPABILITY CONTRACT</p><h2>Latest check</h2></div>{result ? <Badge tone={result.status === "passed" ? "green" : result.status === "timeout" ? "amber" : "red"}>{result.status.toUpperCase()}</Badge> : <Badge>NOT RUN</Badge>}</div>
          {!result && !testMutation.isPending && <div className="result-placeholder"><Bot size={34}/><h3>No capability result</h3><p>Run the bounded canary to inspect model compatibility.</p></div>}
          {testMutation.isPending && <div className="result-placeholder"><LoaderCircle className="spin" size={34}/><h3>Checking profile</h3><p>Running transport and schema canaries with a finite timeout.</p></div>}
          {result && !testMutation.isPending && <><div className={`result-summary ${result.status}`} >{result.status === "passed" ? <CheckCircle2 size={21}/> : result.status === "timeout" ? <Clock3 size={21}/> : <XCircle size={21}/>}<div><b>{result.summary}</b><span>{result.latencyMs.toLocaleString()} ms · {formatUtcTime(result.checkedAt)} UTC</span></div></div><div className="check-list">{result.checks.map((check) => <div key={check.name}><span className={`check-icon ${check.status}`}>{check.status === "passed" ? <Check size={13}/> : check.status === "failed" ? <XCircle size={13}/> : <Clock3 size={13}/>}</span><p><b>{check.name}</b><small>{check.detail}</small></p><Badge tone={check.status === "passed" ? "green" : check.status === "failed" ? "red" : "neutral"}>{check.status.replace("_", " ")}</Badge></div>)}</div></>}
        </section>
      </div>
    </div>
  );
}
