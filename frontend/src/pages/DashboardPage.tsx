import { useQuery } from "@tanstack/react-query";
import { ChevronRight, CircleAlert, Database, LoaderCircle, Network, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { EmptyState } from "../components/ui";
import { gateway } from "../gateway";

export function DashboardPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => gateway.getDashboard(),
    refetchInterval: 5_000,
  });

  if (isLoading) {
    return <div className="page-content panel graph-loading"><LoaderCircle className="spin" size={28}/>Loading live control plane</div>;
  }
  if (isError || !data) {
    return <div className="page-content panel"><EmptyState icon={<CircleAlert/>} title="Control plane unavailable" description="Verify the local UI API and application database."/></div>;
  }
  if (!data.mission) {
    return <div className="page-content panel"><EmptyState icon={<ShieldCheck/>} title="No Mission configured" description="Create a non-authoritative draft, then validate it through the trusted Mission workflow."/></div>;
  }

  const mission = data.mission;
  const objective = mission.objectives[0] ?? mission.title;
  return (
    <section className="dashboard-grid page-content">
      <article className="hero-panel panel">
        <div className="hero-copy">
          <span className="status-chip amber"><i/> {mission.state.replaceAll("_", " ").toUpperCase()}</span>
          <p className="eyebrow">CURRENT OBJECTIVE</p>
          <h2>{objective}</h2>
          <p>{mission.title}</p>
          <div className="hero-actions">
            <Link className="primary-button link-button" to="/interventions">Review interventions <ChevronRight size={16}/></Link>
            <Link className="secondary-button link-button" to="/knowledge">Inspect verified knowledge</Link>
          </div>
        </div>
        <div className="signal-orbit" aria-hidden="true"><div className="orbit orbit-1"/><div className="orbit orbit-2"/><div className="core"><ShieldCheck size={28}/></div><span className="signal-dot one"/><span className="signal-dot two"/><span className="signal-dot three"/></div>
      </article>

      <div className="metric-row">
        <article className="metric panel"><div className="metric-icon cyan"><Database size={18}/></div><span>Confirmed findings</span><strong>{data.metrics.confirmedFindings}</strong><small>Verified records only</small></article>
        <article className="metric panel"><div className="metric-icon purple"><Network size={18}/></div><span>Mapped entities</span><strong>{data.metrics.mappedEntities}</strong><small>Current Mission snapshot</small></article>
        <article className="metric panel"><div className="metric-icon amber"><CircleAlert size={18}/></div><span>Pending decisions</span><strong>{data.metrics.pendingDecisions}</strong><small>Immutable bound requests</small></article>
      </div>

      <article className="panel attack-path-panel">
        <div className="section-title"><div><p className="eyebrow">MISSION STATE</p><h2>Authorization boundary</h2></div><span className="status-chip green">LIVE DATA</span></div>
        <dl className="provider-facts">
          <div><dt>Mission</dt><dd>{mission.id}</dd></div>
          <div><dt>Revision / Epoch</dt><dd>{mission.revision} / {mission.authorizationEpoch}</dd></div>
          <div><dt>Authorization</dt><dd>{mission.authorizationReference}</dd></div>
          <div><dt>Valid until</dt><dd>{new Date(mission.validUntil).toLocaleString()}</dd></div>
        </dl>
        <div className="detail-block"><span>Allowed scopes</span>{mission.scopes.map((scope) => <code key={scope}>{scope}</code>)}</div>
      </article>

      <article className="panel activity-panel">
        <div className="section-title"><div><p className="eyebrow">RECENT ACTIVITY</p><h2>Mission lifecycle</h2></div></div>
        {data.timeline.length ? <div className="timeline">{data.timeline.map((event) => <div key={event.id}><span className="event-dot success"/><time>{new Date(event.timestamp).toLocaleTimeString()}</time><p><b>{event.title}</b><small>{event.detail}</small></p></div>)}</div> : <p>No lifecycle event has been recorded.</p>}
      </article>
    </section>
  );
}
