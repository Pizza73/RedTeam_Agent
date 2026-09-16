import { useQuery } from "@tanstack/react-query";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { Box, Braces, CircleUserRound, Database, FileSearch, Filter, KeyRound, Network, Search, Server, Share2, ShieldAlert, X } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Badge, EmptyState, Input, Modal, PageHeader } from "../components/ui";
import { gateway } from "../gateway";
import type { Finding, KnowledgeGraph, KnowledgeNode } from "../types";

type GraphView = "escalation" | "identity" | "infrastructure" | "all";
type CollectionView = "graph" | "structured";
type GraphNodeData = { record: KnowledgeNode; dimmed: boolean; focused: boolean; onSelect: (id: string) => void };

const graphViews: Array<{ id: GraphView; label: string; description: string }> = [
  { id: "escalation", label: "Escalation path", description: "Privilege relationships and supporting system context" },
  { id: "identity", label: "Identity", description: "Accounts, groups, and membership relationships" },
  { id: "infrastructure", label: "Infrastructure", description: "Hosts, sessions, and domain relationships" },
  { id: "all", label: "All relationships", description: "Every validated relationship in the current knowledge snapshot" },
];

function visibleInView(view: GraphView, node: KnowledgeNode): boolean {
  if (view === "identity") return ["account", "group", "domain"].includes(node.category);
  if (view === "infrastructure") return ["asset", "session", "domain"].includes(node.category);
  return true;
}

function graphPosition(index: number): { x: number; y: number } {
  return { x: 20 + (index % 5) * 180, y: 55 + Math.floor(index / 5) * 220 };
}

function KnowledgeGraphNode({ data }: NodeProps<Node<GraphNodeData>>) {
  const icons = { asset: Server, account: CircleUserRound, session: KeyRound, group: ShieldAlert, domain: Network };
  const Icon = icons[data.record.category];
  return <div className={`knowledge-node ${data.record.verification}${data.dimmed ? " dimmed" : ""}${data.focused ? " focused" : ""}`}>
    <Handle type="target" position={Position.Left}/>
    <button type="button" onClick={() => data.onSelect(data.record.id)} aria-label={`Open details for ${data.record.label}`}>
      <span className="knowledge-node-icon"><Icon size={17}/></span>
      <span className="knowledge-node-copy"><small>{data.record.category}</small><b>{data.record.label}</b><em>{data.record.verification}</em></span>
    </button>
    <Handle type="source" position={Position.Right}/>
  </div>;
}

const nodeTypes = { knowledge: KnowledgeGraphNode };

function StructuredKnowledgeView({ data }: { data: KnowledgeGraph }) {
  const nodeLabels = new Map(data.nodes.map((node) => [node.id, node.label]));

  return <div className="structured-knowledge" role="region" aria-label="Structured knowledge inventory">
    <div className="structured-summary">
      <div><span>snapshot:</span><strong>current</strong></div>
      <div><span>entities:</span><strong>{data.nodes.length}</strong></div>
      <div><span>relationships:</span><strong>{data.edges.length}</strong></div>
      <div><span>artifact_refs:</span><strong>{data.artifacts.length}</strong></div>
    </div>

    <section className="structured-section" aria-labelledby="structured-entities-heading">
      <div className="structured-section-heading"><div><p className="eyebrow">ENTITIES</p><h3 id="structured-entities-heading">Validated knowledge records</h3></div><span>{data.nodes.length} records</span></div>
      <div className="structured-records">
        {data.nodes.map((node) => <article className="structured-record" key={node.id}>
          <header><code>- entity:</code><Badge tone={node.verification === "confirmed" ? "green" : node.verification === "inferred" ? "amber" : "red"}>{node.verification}</Badge></header>
          <dl>
            <div><dt>id:</dt><dd><code>{node.id}</code></dd></div>
            <div><dt>type:</dt><dd>{node.category}</dd></div>
            <div><dt>label:</dt><dd>{node.label}</dd></div>
            <div className="structured-wide"><dt>detail:</dt><dd>{node.detail}</dd></div>
          </dl>
        </article>)}
      </div>
    </section>

    <section className="structured-section" aria-labelledby="structured-relations-heading">
      <div className="structured-section-heading"><div><p className="eyebrow">RELATIONSHIPS</p><h3 id="structured-relations-heading">Bound entity links</h3></div><span>{data.edges.length} records</span></div>
      <div className="structured-relation-table" role="table" aria-label="Knowledge relationships">
        <div className="structured-relation-head" role="row"><span role="columnheader">Relation</span><span role="columnheader">From</span><span role="columnheader">To</span><span role="columnheader">ID</span></div>
        {data.edges.map((edge) => <div className="structured-relation-row" role="row" key={edge.id}><strong role="cell">{edge.label}</strong><code role="cell">{nodeLabels.get(edge.source) ?? edge.source}</code><code role="cell">{nodeLabels.get(edge.target) ?? edge.target}</code><small role="cell">{edge.id}</small></div>)}
      </div>
    </section>

    <section className="structured-section" aria-labelledby="structured-artifacts-heading">
      <div className="structured-section-heading"><div><p className="eyebrow">ARTIFACT REFERENCES</p><h3 id="structured-artifacts-heading">Redacted provenance inventory</h3></div><span>{data.artifacts.length} records</span></div>
      <div className="structured-records artifacts">
        {data.artifacts.map((artifact) => {
          const findings = data.findings.filter((finding) => finding.artifactId === artifact.id);
          return <article className="structured-record" key={artifact.id}>
            <header><code>- artifact:</code><Badge tone={artifact.classification === "secret_reference" ? "purple" : artifact.classification === "sensitive" ? "amber" : "green"}>{artifact.classification.replace("_", " ")}</Badge></header>
            <dl>
              <div className="structured-wide"><dt>id:</dt><dd><code>{artifact.id}</code></dd></div>
              <div><dt>media_type:</dt><dd><code>{artifact.mediaType}</code></dd></div>
              <div><dt>variant:</dt><dd>{artifact.variant}</dd></div>
              <div><dt>size_bytes:</dt><dd>{artifact.sizeBytes.toLocaleString()}</dd></div>
              <div><dt>observed_at:</dt><dd><time>{new Date(artifact.createdAt).toLocaleString("en-US")}</time></dd></div>
              <div className="structured-wide"><dt>derived_findings:</dt><dd>{findings.length ? findings.map((finding) => <code key={finding.id}>{finding.id}</code>) : <span>none</span>}</dd></div>
            </dl>
          </article>;
        })}
      </div>
      <div className="inline-alert structured-safety"><ShieldAlert size={15}/>Metadata and redacted references only. Raw tool output and secret values remain unavailable.</div>
    </section>
  </div>;
}

export function KnowledgePage() {
  const { data, isLoading, isError } = useQuery({ queryKey: ["knowledge"], queryFn: () => gateway.getKnowledgeGraph() });
  const [search, setSearch] = useState("");
  const [verification, setVerification] = useState("all");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [graphView, setGraphView] = useState<GraphView>("escalation");
  const [collectionView, setCollectionView] = useState<CollectionView>("graph");
  const [tab, setTab] = useState<"findings" | "artifacts">("findings");

  const selectNode = useCallback((id: string) => setSelectedNodeId(id), []);
  const visibleRecords = useMemo(() => data?.nodes.filter((node) => visibleInView(graphView, node)) ?? [], [data, graphView]);
  const visibleNodeIds = useMemo(() => new Set(visibleRecords.map((node) => node.id)), [visibleRecords]);
  const visibleEdges = useMemo(() => data?.edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)) ?? [], [data, visibleNodeIds]);
  const focusedNodeIds = useMemo(() => {
    if (!selectedNodeId) return null;
    const ids = new Set([selectedNodeId]);
    visibleEdges.forEach((edge) => { if (edge.source === selectedNodeId || edge.target === selectedNodeId) { ids.add(edge.source); ids.add(edge.target); } });
    return ids;
  }, [selectedNodeId, visibleEdges]);
  const nodes: Node<GraphNodeData>[] = useMemo(() => visibleRecords.map((record, index) => ({
    id: record.id, type: "knowledge", position: graphPosition(index),
    data: { record, dimmed: Boolean(focusedNodeIds && !focusedNodeIds.has(record.id)), focused: selectedNodeId === record.id, onSelect: selectNode },
  })), [focusedNodeIds, selectNode, selectedNodeId, visibleRecords]);
  const edges: Edge[] = useMemo(() => visibleEdges.map((edge) => {
    const pending = edge.label === "pending transition";
    const connectedToSelection = !selectedNodeId || edge.source === selectedNodeId || edge.target === selectedNodeId;
    const primary = graphView === "escalation";
    const stroke = pending ? "#fbbf24" : primary ? "#fb7185" : "#5e4650";
    return { ...edge, type: "smoothstep", animated: pending, markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
      style: { stroke, strokeWidth: primary ? 2.1 : 1.4, strokeDasharray: pending ? "7 5" : undefined, opacity: connectedToSelection ? 1 : 0.12 },
      labelStyle: { fill: pending ? "#f4c95d" : "#a6bac4", fontSize: 11, fontWeight: 650 },
      labelBgStyle: { fill: "#0b151c", fillOpacity: 0.94, stroke: pending ? "#6e5519" : "#263b47" },
      labelBgPadding: [6, 4] as [number, number], labelBgBorderRadius: 4 };
  }), [graphView, selectedNodeId, visibleEdges]);

  const selectedNode = data?.nodes.find((node) => node.id === selectedNodeId) ?? null;
  const selectedRelations = selectedNode ? data?.edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id) ?? [] : [];
  const activeView = graphViews.find((view) => view.id === graphView) ?? graphViews[0];
  const filteredFindings = data?.findings.filter((finding) => (verification === "all" || finding.verification === verification) && `${finding.title} ${finding.target}`.toLowerCase().includes(search.toLowerCase())) ?? [];

  function changeGraphView(view: GraphView) {
    setGraphView(view);
    const selected = data?.nodes.find((node) => node.id === selectedNodeId);
    if (selected && !visibleInView(view, selected)) setSelectedNodeId(null);
  }

  return <div className="page-content knowledge-page">
    <PageHeader eyebrow="KNOWLEDGE BASE" title="Collected intelligence" description="Switch between relationship context and a structured, provenance-bound inventory without exposing raw output or secret values." actions={<div className="knowledge-stats"><Badge tone="green">{data?.nodes.filter((node) => node.verification === "confirmed").length ?? 0} CONFIRMED</Badge><Badge tone="amber">{data?.nodes.filter((node) => node.verification === "inferred").length ?? 0} INFERRED</Badge><Badge tone="red">{data?.nodes.filter((node) => node.verification === "contradicted").length ?? 0} CONTRADICTED</Badge></div>}/>
    {isLoading ? <div className="panel graph-loading"><Database className="pulse" size={28}/><span>Loading redacted knowledge view</span></div> : isError || !data ? <div className="panel"><EmptyState icon={<X/>} title="Knowledge view unavailable" description="The live control plane could not produce a validated knowledge response."/></div> : <>
      <section className="panel graph-panel">
        <div className="collection-view-toolbar"><div><p className="eyebrow">KNOWLEDGE SNAPSHOT</p><h2>{collectionView === "graph" ? "Relationship graph" : "Structured inventory"}</h2><p>{collectionView === "graph" ? "Trace how validated entities connect across the mission." : "Inspect the same snapshot as YAML-inspired, readable records."}</p></div><div className="collection-view-toggle" role="group" aria-label="Knowledge presentation"><button type="button" className={collectionView === "graph" ? "active" : ""} aria-pressed={collectionView === "graph"} onClick={() => setCollectionView("graph")}><Share2 size={14}/>Graph view</button><button type="button" className={collectionView === "structured" ? "active" : ""} aria-pressed={collectionView === "structured"} onClick={() => setCollectionView("structured")}><Braces size={14}/>Structured view</button></div></div>
        {collectionView === "graph" ? <>
          <div className="graph-toolbar"><div><p className="eyebrow">RELATIONSHIP MAP</p><h2>{activeView.label}</h2><p>{activeView.description}</p></div><div className="graph-view-tabs" aria-label="Knowledge graph view">{graphViews.map((view) => <button type="button" key={view.id} className={graphView === view.id ? "active" : ""} aria-pressed={graphView === view.id} onClick={() => changeGraphView(view.id)}>{view.label}</button>)}</div></div>
          <div className="graph-legend" aria-label="Graph legend"><span><i className="primary"/>Primary relationship</span><span><i className="confirmed"/>Confirmed</span><span><i className="inferred"/>Inferred / pending</span><span><i className="contradicted"/>Contradicted</span></div>
          <div className="graph-workspace">
          <div className="graph-lane-labels" aria-hidden="true"><span>IDENTITY &amp; PRIVILEGE</span><span>SYSTEM CONTEXT</span></div>
          <div className="graph-canvas"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.14 }} minZoom={0.7} maxZoom={1.5} nodesDraggable={false} nodesConnectable={false} edgesFocusable={false} elementsSelectable><Background color="#19313d" gap={24}/><Controls showInteractive={false} position="bottom-right"/></ReactFlow></div>
          <ol className="knowledge-mobile-path" aria-label={`${activeView.label} relationships`}>{nodes.map((node, index) => <li key={node.id}><span className="mobile-path-index">{index + 1}</span><button type="button" onClick={() => selectNode(node.id)} aria-label={`Open details for ${node.data.record.label}`}><small>{node.data.record.category}</small><b>{node.data.record.label}</b><span className={node.data.record.verification}>{node.data.record.verification}</span></button></li>)}</ol>
          {selectedNode && <aside className="graph-detail-drawer" aria-label="Selected knowledge node details"><button type="button" className="graph-detail-close" onClick={() => setSelectedNodeId(null)} aria-label="Close node details"><X size={15}/></button><p className="eyebrow">SELECTED NODE</p><div className="graph-detail-title"><span className={`node-category-icon ${selectedNode.verification}`}>{selectedNode.category === "asset" ? <Server size={17}/> : selectedNode.category === "account" ? <CircleUserRound size={17}/> : selectedNode.category === "session" ? <KeyRound size={17}/> : selectedNode.category === "group" ? <ShieldAlert size={17}/> : <Network size={17}/>}</span><div><small>{selectedNode.category}</small><h3>{selectedNode.label}</h3></div></div><Badge tone={selectedNode.verification === "confirmed" ? "green" : selectedNode.verification === "inferred" ? "amber" : "red"}>{selectedNode.verification}</Badge><p className="graph-detail-description">{selectedNode.detail}</p><div className="graph-relation-list"><span>BOUND RELATIONSHIPS</span>{selectedRelations.length ? selectedRelations.map((relation) => { const outgoing = relation.source === selectedNode.id; const peerId = outgoing ? relation.target : relation.source; const peer = data.nodes.find((node) => node.id === peerId); return <div key={relation.id}><small>{outgoing ? "OUTGOING" : "INCOMING"}</small><b>{relation.label}</b><code>{peer?.label ?? peerId}</code></div>; }) : <p>No relationships in this snapshot.</p>}</div><div className="inline-alert"><ShieldAlert size={15}/>Validated metadata only. Raw output and secret values remain unavailable.</div></aside>}
          </div>
        </> : <StructuredKnowledgeView data={data}/>}
      </section>
      <section className="panel intelligence-table"><div className="table-toolbar"><div className="table-tabs"><button className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}><FileSearch size={14}/> Findings <span>{data.findings.length}</span></button><button className={tab === "artifacts" ? "active" : ""} onClick={() => setTab("artifacts")}><Box size={14}/> Redacted artifacts <span>{data.artifacts.length}</span></button></div><div className="table-filters"><label className="search-field"><Search size={14}/><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search findings" aria-label="Search findings"/></label><label className="filter-select"><Filter size={14}/><select value={verification} onChange={(event) => setVerification(event.target.value)} aria-label="Filter verification state"><option value="all">All states</option><option value="confirmed">Confirmed</option><option value="inferred">Inferred</option><option value="contradicted">Contradicted</option></select></label></div></div>
        {tab === "findings" ? <div className="data-table"><div className="table-head"><span>Finding</span><span>Target</span><span>Verification</span><span>Confidence</span><span>Observed</span></div>{filteredFindings.length ? filteredFindings.map((finding) => <button className="table-row" key={finding.id} onClick={() => setSelectedFinding(finding)}><span><b>{finding.title}</b><small>{finding.id}</small></span><code>{finding.target}</code><Badge tone={finding.verification === "confirmed" ? "green" : finding.verification === "inferred" ? "amber" : "red"}>{finding.verification}</Badge><span>{Math.round(finding.confidence * 100)}%</span><time>{new Date(finding.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}</time></button>) : <EmptyState icon={<Search/>} title="No matching findings" description="Adjust search text or verification filters."/>}</div> : <div className="data-table artifact-table"><div className="table-head"><span>Artifact reference</span><span>Media type</span><span>Classification</span><span>Variant</span><span>Size</span></div>{data.artifacts.map((artifact) => <div className="table-row static" key={artifact.id}><span><b>{artifact.id}</b><small>{new Date(artifact.createdAt).toLocaleString("en-US")}</small></span><code>{artifact.mediaType}</code><Badge tone={artifact.classification === "secret_reference" ? "purple" : artifact.classification === "sensitive" ? "amber" : "green"}>{artifact.classification.replace("_", " ")}</Badge><span>{artifact.variant}</span><span>{artifact.sizeBytes.toLocaleString()} B</span></div>)}</div>}
      </section>
    </>}
    <Modal open={Boolean(selectedFinding)} onOpenChange={(open) => !open && setSelectedFinding(null)} title={selectedFinding?.title ?? "Finding detail"} description="Validated metadata and provenance only">{selectedFinding && <div className="finding-detail"><div className="finding-summary"><Badge tone={selectedFinding.verification === "confirmed" ? "green" : selectedFinding.verification === "inferred" ? "amber" : "red"}>{selectedFinding.verification}</Badge><strong>{Math.round(selectedFinding.confidence * 100)}% confidence</strong></div><p>{selectedFinding.summary}</p><dl><div><dt>Target</dt><dd>{selectedFinding.target}</dd></div><div><dt>Finding ID</dt><dd>{selectedFinding.id}</dd></div><div><dt>Source execution</dt><dd>{selectedFinding.sourceExecutionId}</dd></div><div><dt>Redacted artifact</dt><dd>{selectedFinding.artifactId ?? "Not directly linked"}</dd></div><div><dt>Observed</dt><dd>{new Date(selectedFinding.timestamp).toLocaleString("en-US")}</dd></div></dl><div className="inline-alert"><ShieldAlert size={15}/>Raw result content and secret values are intentionally unavailable in this view.</div></div>}</Modal>
  </div>;
}
