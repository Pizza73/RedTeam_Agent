import {
  Activity,
  Bot,
  Crosshair,
  LayoutDashboard,
  LoaderCircle,
  Menu,
  Network,
  Radio,
  ShieldCheck,
  ShieldEllipsis,
  TerminalSquare,
  Timer,
  UserRoundCheck,
  X,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useState } from "react";
import { gateway, gatewayMode } from "../gateway";
import type { AgentActivity } from "../types";

const routeTitles: Record<string, [string, string]> = {
  "/dashboard": ["MISSION CONTROL / ACTIVE MISSION", "Mission Dashboard"],
  "/missions/new": ["MISSION CONTROL / CONFIGURATION", "Create Mission Draft"],
  "/interventions": ["MISSION CONTROL / OPERATOR QUEUE", "Human Interventions"],
  "/knowledge": ["MISSION CONTROL / KNOWLEDGE BASE", "Collected Intelligence"],
  "/settings/providers": ["MISSION CONTROL / POLICY", "C2 & Tool Access"],
  "/settings/llm": ["MISSION CONTROL / MODEL PROFILE", "VLLM Settings"],
};

function AppNav() {
  const { data: interventions = [] } = useQuery({ queryKey: ["interventions"], queryFn: () => gateway.getInterventions() });
  const pendingCount = interventions.filter((item) => item.state === "pending").length;
  const items = [
    ["Dashboard", "/dashboard", LayoutDashboard],
    ["New Mission", "/missions/new", Crosshair],
    ["Interventions", "/interventions", UserRoundCheck],
    ["Knowledge", "/knowledge", Network],
    ["C2 & Tools", "/settings/providers", ShieldEllipsis],
    ["VLLM Settings", "/settings/llm", Bot],
  ] as const;
  return (
    <aside className="app-nav">
      <div className="brand-mark"><ShieldCheck size={21} /><span>REDTEAM <b>AGENT</b></span></div>
      <p className="eyebrow nav-label">OPERATIONS</p>
      <nav aria-label="Primary navigation">
        {items.map(([label, path, Icon]) => (
          <NavLink key={path} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`} to={path}>
            <Icon size={17} /><span>{label}</span>
            {label === "Interventions" && pendingCount > 0 && <span className="nav-count">{pendingCount}</span>}
          </NavLink>
        ))}
      </nav>
      <div className="mock-notice"><Radio size={14} /><div><b>{gatewayMode === "live" ? "Live control plane" : "Mock mode"}</b><span>{gatewayMode === "live" ? "Same-origin · fail closed" : "No external dispatch"}</span></div></div>
    </aside>
  );
}

function formatElapsed(seconds: number) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;
  return [hours, minutes, remainingSeconds].map((value) => value.toString().padStart(2, "0")).join(":");
}

function AgentActivityPanel({ activity, loading }: { activity?: AgentActivity | null; loading: boolean }) {
  const isRunning = activity?.status === "running";
  return <section className="agent-activity" aria-label="Agent activity" aria-live="polite">
    <div className="agent-activity-heading"><div><p className="eyebrow">AGENT ACTIVITY</p><h3>{isRunning ? "Currently executing" : "Last execution"}</h3></div>{activity && <span className={`activity-state ${activity.status}`}>{isRunning ? <LoaderCircle className="spin" size={12}/> : <Activity size={12}/>} {activity.status}</span>}</div>
    {loading ? <div className="agent-activity-loading"><LoaderCircle className="spin" size={14}/>Loading sanitized activity</div> : activity ? <>
      <div className="agent-activity-title"><TerminalSquare size={16}/><div><b>{activity.title}</b><small>{activity.toolDisplayName}</small></div></div>
      <div className="activity-command"><span>TOOL OPERATION</span><code>{activity.operation}</code></div>
      <div className="activity-references">{activity.references.map((reference) => <code key={`${reference.name}-${reference.id}`}><span>--{reference.name}</span> {reference.type}:{reference.id}</code>)}</div>
      <div className="activity-meta"><span>Execution <code>{activity.executionId}</code></span><span>{isRunning ? "Elapsed" : "Duration"} <b>{formatElapsed(activity.elapsedSeconds)}</b></span></div>
      <p>{activity.summary}</p>
      <small className="activity-safety">Reference-only display · raw output unavailable</small>
    </> : <p className="agent-activity-empty">No agent execution has been recorded for this mission.</p>}
  </section>;
}

function PhaseRail({ mobile = false, close }: { mobile?: boolean; close?: () => void }) {
  const { data = [] } = useQuery({ queryKey: ["phase-progress"], queryFn: () => gateway.getPhaseProgress() });
  const { data: agentActivity, isLoading: activityLoading } = useQuery({ queryKey: ["agent-activity"], queryFn: () => gateway.getAgentActivity(), refetchInterval: 1_000 });
  const { data: dashboard } = useQuery({ queryKey: ["dashboard"], queryFn: () => gateway.getDashboard() });
  const applicable = data.filter((phase) => phase.status !== "not_applicable");
  const progress = applicable.length ? Math.round((applicable.filter((phase) => phase.status === "completed").length / applicable.length) * 100) : 0;
  return (
    <aside className={mobile ? "phase-rail phase-rail-mobile" : "phase-rail"} aria-label="Attack phase progress">
      <div className="rail-title"><div><p className="eyebrow">MISSION FLOW</p><h2>{dashboard?.mission?.title ?? "No active Mission"}</h2></div>{mobile ? <button className="icon-button" onClick={close} aria-label="Close mission flow"><X size={17}/></button> : <span className="live-chip"><i /> LIVE</span>}</div>
      <div className="mission-progress"><span>Mission progress</span><b>{progress}%</b><div><i style={{ width: `${progress}%` }} /></div></div>
      <ol className="phase-list" tabIndex={0} aria-label="Mission phase progress">
        {data.map((phase, index) => (
          <li className={`phase ${phase.status}`} key={phase.phase}>
            <span className="phase-index">{phase.status === "completed" ? "✓" : index + 1}</span>
            <div><b>{phase.label}</b><small>{phase.detail}</small></div>
          </li>
        ))}
      </ol>
      <AgentActivityPanel activity={agentActivity} loading={activityLoading}/>
      <div className="runtime"><Timer size={15}/><span>Valid until</span><b>{dashboard?.mission ? new Date(dashboard.mission.validUntil).toLocaleTimeString() : "—"}</b></div>
    </aside>
  );
}

export function Layout() {
  const [mobileFlow, setMobileFlow] = useState(false);
  const { pathname } = useLocation();
  const [eyebrow, title] = routeTitles[pathname] ?? routeTitles["/dashboard"];
  const { data: health, isError: healthError } = useQuery({ queryKey: ["health"], queryFn: () => gateway.getHealth(), refetchInterval: 5_000 });
  const { data: readiness, isError: readinessError } = useQuery({ queryKey: ["execution-readiness"], queryFn: () => gateway.getExecutionReadiness(), refetchInterval: 5_000 });
  const { data: dashboard } = useQuery({ queryKey: ["dashboard"], queryFn: () => gateway.getDashboard() });
  const resolvedTitle = pathname === "/dashboard" ? dashboard?.mission?.title ?? title : title;
  return (
    <div className="app-shell">
      <AppNav />
      <main>
        <header className="topbar">
          <div><p className="eyebrow">{eyebrow}</p><h1>{resolvedTitle}</h1></div>
          <div className="topbar-actions"><NavLink className={`ghost-button ${readiness?.status === "blocked" || readinessError ? "blocked" : ""}`} to="/missions/new"><Activity size={15}/> {healthError ? "System unavailable" : readinessError ? "Readiness unavailable" : readiness?.status === "blocked" ? `Execution blocked · ${readiness.blockerCount}` : health && readiness ? "Execution ready" : "Checking system"}</NavLink><button className="flow-toggle" onClick={() => setMobileFlow(true)}><Menu size={16}/> Mission flow</button></div>
        </header>
        <Outlet />
      </main>
      <PhaseRail />
      {mobileFlow && <div className="mobile-flow-overlay" onClick={() => setMobileFlow(false)}><div onClick={(event) => event.stopPropagation()}><PhaseRail mobile close={() => setMobileFlow(false)} /></div></div>}
    </div>
  );
}
