import { Navigate, Route, Routes } from "react-router-dom";
import { lazy, Suspense } from "react";
import { Layout } from "./components/Layout";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const InterventionsPage = lazy(() => import("./pages/InterventionsPage").then((module) => ({ default: module.InterventionsPage })));
const KnowledgePage = lazy(() => import("./pages/KnowledgePage").then((module) => ({ default: module.KnowledgePage })));
const MissionBuilderPage = lazy(() => import("./pages/MissionBuilderPage").then((module) => ({ default: module.MissionBuilderPage })));
const VllmSettingsPage = lazy(() => import("./pages/VllmSettingsPage").then((module) => ({ default: module.VllmSettingsPage })));
const ToolProviderPage = lazy(() => import("./pages/ToolProviderPage").then((module) => ({ default: module.ToolProviderPage })));

export function App() {
  return <Suspense fallback={<div className="route-loading" role="status">Loading operator surface</div>}><Routes><Route element={<Layout/>}><Route index element={<Navigate to="/dashboard" replace/>}/><Route path="dashboard" element={<DashboardPage/>}/><Route path="missions/new" element={<MissionBuilderPage/>}/><Route path="interventions" element={<InterventionsPage/>}/><Route path="knowledge" element={<KnowledgePage/>}/><Route path="settings/providers" element={<ToolProviderPage/>}/><Route path="settings/llm" element={<VllmSettingsPage/>}/><Route path="*" element={<Navigate to="/dashboard" replace/>}/></Route></Routes></Suspense>;
}
