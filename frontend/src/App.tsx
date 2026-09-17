import { Navigate, Route, Routes } from "react-router-dom";
import { lazy, Suspense, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Layout } from "./components/Layout";
import { Button, Input } from "./components/ui";
import { gateway } from "./gateway";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const InterventionsPage = lazy(() => import("./pages/InterventionsPage").then((module) => ({ default: module.InterventionsPage })));
const KnowledgePage = lazy(() => import("./pages/KnowledgePage").then((module) => ({ default: module.KnowledgePage })));
const MissionBuilderPage = lazy(() => import("./pages/MissionBuilderPage").then((module) => ({ default: module.MissionBuilderPage })));
const VllmSettingsPage = lazy(() => import("./pages/VllmSettingsPage").then((module) => ({ default: module.VllmSettingsPage })));
const ToolProviderPage = lazy(() => import("./pages/ToolProviderPage").then((module) => ({ default: module.ToolProviderPage })));

export function App() {
  const session = useQuery({
    queryKey: ["operator-session"],
    queryFn: () => gateway.getOperatorSession(),
    staleTime: 0,
  });
  if (session.isLoading) return <div className="route-loading" role="status">Checking operator session</div>;
  if (!session.data?.authenticated) return <OperatorLogin />;
  return <Suspense fallback={<div className="route-loading" role="status">Loading operator surface</div>}><Routes><Route element={<Layout/>}><Route index element={<Navigate to="/dashboard" replace/>}/><Route path="dashboard" element={<DashboardPage/>}/><Route path="missions/new" element={<MissionBuilderPage/>}/><Route path="interventions" element={<InterventionsPage/>}/><Route path="knowledge" element={<KnowledgePage/>}/><Route path="settings/providers" element={<ToolProviderPage/>}/><Route path="settings/llm" element={<VllmSettingsPage/>}/><Route path="*" element={<Navigate to="/dashboard" replace/>}/></Route></Routes></Suspense>;
}

function OperatorLogin() {
  const [token, setToken] = useState("");
  const queryClient = useQueryClient();
  const login = useMutation({
    mutationFn: () => gateway.loginOperator(token),
    onSuccess: async () => {
      setToken("");
      await queryClient.invalidateQueries({ queryKey: ["operator-session"] });
    },
  });
  return <main className="login-shell"><section className="panel login-panel"><p className="eyebrow">LOCAL OPERATOR AUTHENTICATION</p><h1>RedTeam Agent</h1><p>Enter the token provisioned for this Kali control VM. It is exchanged for a restart-ephemeral HttpOnly session and is not stored by the browser.</p><form onSubmit={(event) => { event.preventDefault(); login.mutate(); }}><label className="field"><span>Operator token</span><Input type="password" autoComplete="current-password" value={token} minLength={32} maxLength={4096} onChange={(event) => setToken(event.target.value)} required /></label>{login.isError && <p className="warning-text" role="alert">Authentication failed.</p>}<Button type="submit" disabled={login.isPending || token.length < 32}>{login.isPending ? "Authenticating…" : "Sign in"}</Button></form></section></main>;
}
