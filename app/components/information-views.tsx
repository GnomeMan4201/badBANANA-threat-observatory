import type { FreshnessSummary, HistoryHealth, IngestionHealth, ObservatoryAnalytics, SourceHealth } from "../../lib/threat-types";
import { formatTimestamp } from "./observatory-format";

export function SourcesView({ sources, history, freshness, ingestion }: { sources: SourceHealth[]; history: HistoryHealth; freshness: FreshnessSummary; ingestion: IngestionHealth }) {
  const healthy = sources.filter((source) => source.status === "healthy").length;
  return (
    <section className="dataSection sources">
      <div className="sectionHead"><div><p>OPERATIONAL STATE</p><h1>Source operations</h1></div><span className="scopeNote">FALLBACK DATA: DISABLED</span></div>
      <div className="observatoryHealth">
        <span><small>OBSERVATORY STATE</small><b>{freshness.state.toUpperCase()}</b></span>
        <span><small>INGESTION MODE</small><b>{ingestion.mode.toUpperCase()}</b></span>
        <span><small>INGESTION STATUS</small><b>{ingestion.status.toUpperCase()}</b></span>
        <span><small>COLLECTION TRIGGER</small><b>{ingestion.schedulerSupported ? "SCHEDULED" : "DEMAND-DRIVEN"}</b></span>
        <span><small>LAST CYCLE</small><b>{formatTimestamp(ingestion.lastCycleCompleted)}</b></span>
        <span><small>LAST SUCCESSFUL CYCLE</small><b>{formatTimestamp(ingestion.lastSuccessfulCycle)}</b></span>
        <span><small>SOURCES ELIGIBLE</small><b>{ingestion.sourcesEligible} / {ingestion.totalSources}</b></span>
        <span><small>REFRESH LEASE</small><b>{ingestion.leaseBackend === "d1" ? "D1 / DISTRIBUTED" : "ISOLATE MEMORY"}</b></span>
        <span><small>CURRENT STATE</small><b>{history.mode === "persistent" ? "D1 / HEALTHY" : "SNAPSHOT ONLY"}</b></span>
        <span><small>EVENT RETENTION</small><b>{history.retentionDays}D</b></span>
        <span><small>CURRENT OBSERVATIONS</small><b>{numberOrUnavailable(history.observationsStored)}</b></span>
        <span><small>FIRST OBSERVATORY INGEST</small><b>{formatTimestamp(history.oldestObservation)}</b></span>
        <span><small>LATEST SOURCE SIGHTING</small><b>{formatTimestamp(history.newestObservation)}</b></span>
        <span><small>SOURCES</small><b>{healthy} HEALTHY / {sources.length - healthy} DEGRADED</b></span>
      </div>
      {!ingestion.schedulerSupported && <div className="historyWarning"><b>DEMAND-DRIVEN COLLECTION</b><span>Continuous scheduled collection is unavailable in this deployment. An explicit Observatory maintenance request refreshes only eligible sources; ordinary reads remain local.</span></div>}
      {history.mode === "snapshot-only" && <div className="historyWarning"><b>PERSISTENT HISTORY UNAVAILABLE</b><span>{history.reason ?? "Current source snapshots remain usable, but historical coverage may be incomplete."}</span></div>}
      <div className="sourceCards">
        {sources.map((source) => {
          const cycle = ingestion.latestSourceCycles.find((item) => item.source === source.id);
          return <article key={source.id}>
          <header><b>{source.name}</b><em className={source.status}>{source.status.toUpperCase()}</em></header>
          <dl>
            <dt>CONFIGURED</dt><dd>{source.configured ? "YES" : "NO"}</dd>
            <dt>OPERATOR INTERPRETATION</dt><dd>{operatorState(source)}</dd>
            <dt>LAST ATTEMPT</dt><dd>{formatTimestamp(source.lastAttempt)}</dd>
            <dt>LAST SUCCESS</dt><dd>{formatTimestamp(source.lastSuccess)}</dd>
            <dt>DATA AGE BASIS</dt><dd>{source.lastSuccess ? `SINCE ${formatTimestamp(source.lastSuccess)}` : "NOT AVAILABLE"}</dd>
            <dt>CACHE CREATED</dt><dd>{formatTimestamp(source.fetchedAt)}</dd>
            <dt>CACHE EXPIRES</dt><dd>{formatTimestamp(source.expiresAt)}</dd>
            <dt>FAILURES</dt><dd>{source.consecutiveFailures ?? "NOT AVAILABLE"}</dd>
            <dt>NEXT RETRY</dt><dd>{formatTimestamp(source.nextRetryAt)}</dd>
            <dt>LATENCY</dt><dd>{source.latencyMs !== undefined ? `${source.latencyMs}ms` : "NOT AVAILABLE"}</dd>
            <dt>LATEST FETCH RECORDS</dt><dd>{numberOrUnavailable(source.recordCount)}</dd>
            <dt>HISTORY RECORDS</dt><dd>{numberOrUnavailable(source.historyRecordCount)}</dd>
            <dt>COVERAGE</dt><dd>{source.coverage}</dd>
            <dt>COVERAGE MODE</dt><dd>{source.coverageMode.toUpperCase()}</dd>
            <dt>UPSTREAM DATA DATE</dt><dd>{source.upstreamDataDate ?? "NOT AVAILABLE"}</dd>
            <dt>REFRESH POLICY</dt><dd>{source.refreshPolicy}</dd>
            <dt>AUTH MODE</dt><dd>{source.authMode}</dd>
            <dt>ERROR</dt><dd>{source.error ?? source.reason ?? "NONE"}</dd>
            <dt>DATA USED</dt><dd>{source.dataUsed}</dd>
            <dt>LAST CYCLE FETCHED</dt><dd>{cycle ? cycle.upstreamRecords : "NOT AVAILABLE"}</dd>
            <dt>VALID / REJECTED</dt><dd>{cycle ? `${cycle.validRecords} / ${cycle.rejectedRecords}` : "NOT AVAILABLE"}</dd>
            <dt>REJECTION DIAGNOSTICS</dt><dd>{cycle?.validationDiagnostics?.length ? cycle.validationDiagnostics.map((item) => `${item.field}:${item.reason} ×${item.count}`).join(" · ") : cycle?.rejectedRecords ? "BOUNDED BREAKDOWN UNAVAILABLE FOR THIS CYCLE" : "NONE"}</dd>
            <dt>NEW / UPDATED</dt><dd>{cycle ? `${cycle.newRecords} / ${cycle.updatedRecords}` : "NOT AVAILABLE"}</dd>
            <dt>UNCHANGED / REMOVED</dt><dd>{cycle ? `${cycle.unchangedRecords} / ${cycle.removedRecords}` : "NOT AVAILABLE"}</dd>
          </dl>
          <a href={source.upstreamUrl} target="_blank" rel="noreferrer">UPSTREAM DOCUMENTATION ↗</a>
        </article>; })}
      </div>
    </section>
  );
}

export function HistoryAnalytics({ analytics, history }: { analytics: ObservatoryAnalytics; history: HistoryHealth }) {
  const cells = [
    ["TOP SOURCE", analytics.bySource[0] ? `${analytics.bySource[0].label} / ${analytics.bySource[0].count}` : "NOT AVAILABLE"],
    ["TOP TYPE", analytics.byKind[0] ? `${analytics.byKind[0].label} / ${analytics.byKind[0].count}` : "NOT AVAILABLE"],
    ["TOP FAMILY", analytics.topMalwareFamilies[0] ? `${analytics.topMalwareFamilies[0].label} / ${analytics.topMalwareFamilies[0].count}` : "NOT AVAILABLE"],
    ["TIME BUCKETS", history.mode === "persistent" ? String(analytics.overTime.length) : "HISTORY DEGRADED"],
  ];
  return <section className="historyAnalytics" aria-label="History analytics">{cells.map(([label, value]) => <span key={label}><small>{label}</small><b>{value}</b></span>)}</section>;
}

export function MethodView() {
  const sections = [
    ["CURRENT STATE", "The current-state table answers what each source says now. Full-catalog and bounded recent feeds retain different coverage semantics, which are shown per source."],
    ["CHANGE LEDGER", "Seven-day events record meaningful NEW, UPDATED, and defensible REMOVED transitions. Unchanged sightings update current state without creating duplicate revisions."],
    ["TIME BASIS", "Threat views use source observation time. Observatory Events use badBANANA detection time. Those clocks are never presented as equivalent."],
    ["INGESTION", "This deployment is demand-driven because Sites exposes no scheduled-trigger configuration. Explicit maintenance and ordinary D1 reads are separate paths."],
    ["IDENTITY", "Stable source identity deduplicates repeated fetches. Records from different sources remain independent even when their indicators match."],
    ["ATTRIBUTION", "Infrastructure geography is not attacker attribution. No actor, nationality, ownership, or intent is inferred."],
    ["CORRELATION", "Cross-source equality is correlation, not campaign membership or attribution. Original evidence records remain distinct."],
    ["FAILURE", "Persistent-history failure is reported as snapshot-only. Stale, offline, backoff, and disabled states remain visible without synthetic fallback."],
    ["RATE LIMIT", "API throttling is a best-effort in-memory fixed-window counter scoped to each Worker isolate. It is not described as a global distributed control."],
  ];
  return <section className="method"><div className="methodIntro"><p>DOCUMENTATION</p><h1>Method and claim boundaries</h1></div><div className="methodGrid">{sections.map(([title, copy]) => <article key={title}><b>{title}</b><p>{copy}</p></article>)}</div></section>;
}

function numberOrUnavailable(value?: number): string { return value === undefined ? "NOT AVAILABLE" : String(value); }

function operatorState(source: SourceHealth): string {
  if (!source.configured || source.status === "disabled") return "NOT CONFIGURED — NO SOURCE READ ATTEMPTED";
  if (source.status === "stale") return source.recordCount > 0 ? "LAST COLLECTION FAILED — STALE VALIDATED DATA RETAINED" : "LAST COLLECTION FAILED — NO VALIDATED RECORDS AVAILABLE";
  if (source.status === "offline") return "SOURCE UNAVAILABLE — ZERO RESULTS NOT ASSUMED";
  if (source.status === "healthy" && source.recordCount === 0) return "SUCCESSFUL READ — SOURCE RETURNED ZERO VALIDATED RECORDS";
  if (source.status === "healthy") return "REACHABLE — VALIDATED RECORDS AVAILABLE";
  return "STATE UNRESOLVED";
}
