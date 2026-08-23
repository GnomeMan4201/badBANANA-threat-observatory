"use client";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { EventPayload, HistoryHealth, NormalizedObservation, ObservationScope, ObservatoryPayload, SearchPayload, TimeWindow } from "../lib/threat-types";
import { HistoryAnalytics, MethodView, SourcesView } from "./components/information-views";
import { ObservationGraphPanel, KevWorkspace, ObservationTable, ObservatoryEventTable, PaginationControls, PulsePanel, RecordDrawer } from "./components/observation-views";
import { Topbar } from "./components/topbar";
import { AnalystBriefing, ExportWorkbench } from "./components/analyst-workbench";
import { ObservatoryReplay } from "./components/observatory-replay";
import { eventRequestPath } from "../lib/event-view";
import { formatCorrelationCount } from "../lib/analysis";

type View = "briefing" | "pulse" | "replay" | "infrastructure" | "exploited" | "urls" | "malware" | "events" | "export" | "sources" | "method";
type SearchStatus = "idle" | "loading" | "ready" | "error";
type EventReadStatus = "loading" | "ready" | "error";

const navigation: { id: View; label: string }[] = [
  { id: "briefing", label: "Briefing" }, { id: "pulse", label: "Pulse" }, { id: "replay", label: "Replay" }, { id: "infrastructure", label: "Infrastructure" },
  { id: "exploited", label: "Exploited" }, { id: "urls", label: "URLs" },
  { id: "malware", label: "Malware" }, { id: "events", label: "Recent Events" },
  { id: "export", label: "Export" }, { id: "sources", label: "Sources" }, { id: "method", label: "About / Method" },
];
const windows: TimeWindow[] = ["15m", "1h", "6h", "24h", "7d"];
const scopedViews = new Set<View>(["pulse", "infrastructure", "urls", "malware", "export"]);

export default function Observatory() {
  const [payload, setPayload] = useState<ObservatoryPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [maintenanceError, setMaintenanceError] = useState(false);
  const [maintenanceRevision, setMaintenanceRevision] = useState(0);
  const [view, setView] = useState<View>("briefing");
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<NormalizedObservation[] | null>(null);
  const [searchHistory, setSearchHistory] = useState<HistoryHealth | null>(null);
  const [searchNextCursor, setSearchNextCursor] = useState<string | undefined>();
  const [searchCursor, setSearchCursor] = useState<string | null>(null);
  const [searchStatus, setSearchStatus] = useState<SearchStatus>("idle");
  const [briefingPayload, setBriefingPayload] = useState<EventPayload | null>(null);
  const [replayPayload, setReplayPayload] = useState<EventPayload | null>(null);
  const [recentEventsPayload, setRecentEventsPayload] = useState<EventPayload | null>(null);
  const [briefingStatus, setBriefingStatus] = useState<EventReadStatus>("loading");
  const [replayStatus, setReplayStatus] = useState<EventReadStatus>("loading");
  const [recentEventsStatus, setRecentEventsStatus] = useState<EventReadStatus>("loading");
  const [recentEventsCursor, setRecentEventsCursor] = useState<string | null>(null);
  const [recentEventsCursorTrail, setRecentEventsCursorTrail] = useState<string[]>([]);
  const [selected, setSelected] = useState<NormalizedObservation | null>(null);
  const [feedCollapsed, setFeedCollapsed] = useStoredBoolean("badbanana:v2:records-collapsed", true);
  const [overviewCollapsed, setOverviewCollapsed] = useStoredBoolean("badbanana:v2:overview-collapsed", true);
  const [now, setNow] = useState(() => new Date(0));
  const [window, setWindow] = useState<TimeWindow>("24h");
  const [cursor, setCursor] = useState<string | null>(null);
  const [cursorTrail, setCursorTrail] = useState<string[]>([]);
  const [searchCursorTrail, setSearchCursorTrail] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [headerCompact, setHeaderCompact] = useState(false);
  const [lastDataScope, setLastDataScope] = useState<ObservationScope>("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [kindFilter, setKindFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState<"any" | "supplied" | "missing">("any");
  const [correlationFilter, setCorrelationFilter] = useState<"any" | "cross-source">("any");
  const dataScope = view === "export" ? lastDataScope : scopeForView(view);

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const update = () => setHeaderCompact(globalThis.window.scrollY > 72);
    update();
    globalThis.window.addEventListener("scroll", update, { passive: true });
    return () => globalThis.window.removeEventListener("scroll", update);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const maintain = () => fetch("/api/ingest", { method: "POST", signal: controller.signal })
      .then((response) => { if (!response.ok) throw new Error("Maintenance unavailable"); setMaintenanceError(false); setMaintenanceRevision((value) => value + 1); })
      .catch((reason) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setMaintenanceError(true); });
    maintain();
    const timer = setInterval(maintain, 5 * 60_000);
    return () => { controller.abort(); clearInterval(timer); };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const refresh = () => loadObservatory(window, cursor, dataScope, controller.signal)
      .then((data) => { setPayload(data); setError(null); })
      .catch((reason) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Observatory read failed"); })
      .finally(() => setLoading(false));
    refresh();
    const poll = setInterval(refresh, 120_000);
    return () => { controller.abort(); clearInterval(poll); };
  }, [cursor, dataScope, maintenanceRevision, window]);

  useEffect(() => {
    if (view !== "events" && view !== "briefing" && view !== "replay") return;
    const controller = new AbortController();
    const requestPath = eventRequestPath(view, { recentEventsCursor });
    queueMicrotask(() => {
      if (controller.signal.aborted) return;
      if (view === "briefing") setBriefingStatus("loading");
      else if (view === "replay") setReplayStatus("loading");
      else setRecentEventsStatus("loading");
    });
    fetch(requestPath, { signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error("Event ledger unavailable"); return response.json() as Promise<EventPayload>; })
      .then((data) => {
        if (view === "briefing") { setBriefingPayload(data); setBriefingStatus("ready"); }
        else if (view === "replay") { setReplayPayload(data); setReplayStatus("ready"); }
        else { setRecentEventsPayload(data); setRecentEventsStatus("ready"); }
      })
      .catch(() => {
        if (controller.signal.aborted) return;
        if (view === "briefing") { setBriefingPayload(null); setBriefingStatus("error"); }
        else if (view === "replay") { setReplayPayload(null); setReplayStatus("error"); }
        else { setRecentEventsPayload(null); setRecentEventsStatus("error"); }
      });
    return () => controller.abort();
  }, [maintenanceRevision, recentEventsCursor, view]);

  useEffect(() => {
    if (query.trim().length < 2) return;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (controller.signal.aborted) return;
      setSearchStatus("loading");
      setSearchResults(null);
      setSearchHistory(null);
      setSearchNextCursor(undefined);
    });
    const timer = setTimeout(() => {
      const params = new URLSearchParams({ q: query.trim(), window, limit: "100" });
      params.set("scope", dataScope);
      if (searchCursor) params.set("cursor", searchCursor);
      fetch(`/api/search?${params}`, { signal: controller.signal })
        .then(async (response) => { if (!response.ok) throw new Error("Search unavailable"); return response.json() as Promise<SearchPayload>; })
        .then((data) => { setSearchResults(data.records); setSearchHistory(data.history); setSearchNextCursor(data.pagination.nextCursor); setSearchStatus("ready"); })
        .catch((reason) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) { setSearchResults(null); setSearchHistory(null); setSearchStatus("error"); } });
    }, 300);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [dataScope, query, searchCursor, window]);

  const searching = query.trim().length >= 2;
  const viewRecords = useMemo(() => {
    if (!searching) return payload?.records ?? [];
    return searchStatus === "ready" ? searchResults ?? [] : [];
  }, [payload, searchResults, searchStatus, searching]);
  const correlatedIndicators = useMemo(() => new Set((payload?.correlations ?? []).map((item) => item.indicator.toLowerCase())), [payload?.correlations]);
  const filteredRecords = useMemo(() => viewRecords.filter((record) =>
    (sourceFilter === "all" || record.source === sourceFilter) &&
    (kindFilter === "all" || record.kind === kindFilter) &&
    (confidenceFilter === "any" || (confidenceFilter === "supplied" ? record.confidence !== undefined : record.confidence === undefined)) &&
    (correlationFilter === "any" || Boolean(record.indicator && correlatedIndicators.has(record.indicator.toLowerCase())))
  ), [confidenceFilter, correlatedIndicators, correlationFilter, kindFilter, sourceFilter, viewRecords]);
  const filtersActive = sourceFilter !== "all" || kindFilter !== "all" || confidenceFilter !== "any" || correlationFilter !== "any";

  const correlated = useMemo(() => selected && payload ? payload.records.filter((record) => record.id !== selected.id && record.indicator && record.indicator.toLowerCase() === selected.indicator?.toLowerCase()) : [], [payload, selected]);
  const healthy = payload?.sources.filter((source) => source.status === "healthy").length ?? 0;
  const displayError = searchStatus === "error" ? "Search unavailable. This is not a zero-result response" : error;
  const sourceReadState: "loading" | "error" | "ready" = loading ? "loading" : error ? "error" : payload ? "ready" : "loading";
  const ordinaryPage = !["briefing", "replay", "exploited", "events", "export", "sources", "method"].includes(view);
  const fieldView = view === "pulse" || view === "infrastructure";
  const scopedView = scopedViews.has(view);
  const openPanelCount = fieldView ? Number(!overviewCollapsed) + Number(!feedCollapsed) : 0;

  const changeQuery = (value: string) => {
    setQuery(value); setSearchCursor(null); setSearchCursorTrail([]); setSearchResults(null); setSearchHistory(null); setSearchNextCursor(undefined);
    setSearchStatus(value.trim().length >= 2 ? "loading" : "idle");
  };
  const changeWindow = (value: TimeWindow) => { setLoading(true); setCursor(null); setCursorTrail([]); setSearchCursor(null); setSearchCursorTrail([]); if (searching) { setSearchResults(null); setSearchStatus("loading"); } setWindow(value); };
  const changeView = (nextView: View) => {
    if (["pulse", "infrastructure", "urls", "malware"].includes(nextView)) setLastDataScope(scopeForView(nextView));
    if (!scopedViews.has(nextView) && query) changeQuery("");
    if (scopeForView(nextView) !== dataScope && nextView !== "export") { setLoading(true); setPayload(null); setCursor(null); setCursorTrail([]); setSearchCursor(null); setSearchCursorTrail([]); setSourceFilter("all"); setKindFilter("all"); setConfidenceFilter("any"); setCorrelationFilter("any"); }
    setView(nextView);
  };
  const nextPage = (nextCursor: string | undefined, activeCursor: string | null, setTrail: Dispatch<SetStateAction<string[]>>, setActive: Dispatch<SetStateAction<string | null>>) => {
    if (!nextCursor) return;
    setTrail((trail) => [...trail, activeCursor ?? ""]);
    setActive(nextCursor);
  };
  const previousPage = (trail: string[], setTrail: Dispatch<SetStateAction<string[]>>, setActive: Dispatch<SetStateAction<string | null>>) => {
    const previous = trail.at(-1);
    if (previous === undefined) return;
    setTrail((current) => current.slice(0, -1));
    setActive(previous || null);
  };

  return (
    <main className={`shell workspaceIntensity intensity-${openPanelCount}`} data-open-panels={openPanelCount}>
      <Topbar now={now} query={query} dataState={payload?.freshness.state} compact={headerCompact} searchEnabled={scopedView} onHome={() => changeView("briefing")} onQueryChange={changeQuery} />
      <nav className="nav" aria-label="Primary views">
        {navigation.map((item) => <button className={view === item.id ? "active" : ""} aria-current={view === item.id ? "page" : undefined} onPointerUp={(event) => event.currentTarget.blur()} onClick={() => changeView(item.id)} key={item.id}>{item.label}</button>)}
      </nav>
      {scopedView && <section className={`analytics ${overviewCollapsed ? "collapsed" : ""}`} aria-label="Observatory window and overview">
        <div className="windowControls" aria-label="Active time window">{windows.map((value) => <button className={window === value ? "active" : ""} onClick={() => changeWindow(value)} key={value}>{value.toUpperCase()}</button>)}</div>
        {sourceReadState === "ready" && payload ? <>
          <span>PAGE OBS <b>{payload.records.length} SHOWN</b></span><span>SOURCES <b>{healthy}/{payload.sources.length} HEALTHY</b></span>
          <span>CURRENT STATE <b>{payload.history.mode === "persistent" ? "D1" : "SNAPSHOT ONLY"}</b></span><span>INGESTION <b>{payload.ingestion.mode.toUpperCase()}</b></span>
          <span>LATEST SUCCESS <b>{age(payload.freshness.latestSourceSuccess, now)}</b></span>
          <span>SNAPSHOT GENERATED <b>{age(payload.freshness.snapshotGenerated, now)}</b></span><span>CORRELATED <b>{formatCorrelationCount(payload.correlations.length, payload.correlationCoverage.truncated)}</b></span>
        </> : <span>READ STATE <b>{sourceReadState === "error" ? "FAILED — COUNTS UNRESOLVED" : "LOADING — COUNTS UNRESOLVED"}</b></span>}
        <button className="stripToggle" onClick={() => setOverviewCollapsed((value) => !value)} aria-label={overviewCollapsed ? "Expand overview metrics" : "Minimize overview metrics"} aria-expanded={!overviewCollapsed}>{overviewCollapsed ? "+" : "−"}</button>
      </section>}
      {searching && <div className={`searchState ${searchStatus}`}><b>SEARCH SCOPE // {window.toUpperCase()}</b><span>{searchStatus === "loading" ? "QUERYING LOCAL CURRENT STATE" : searchStatus === "error" ? "SEARCH UNAVAILABLE — NO-MATCH STATE NOT ASSUMED" : searchHistory?.mode === "snapshot-only" ? `${searchResults?.length ?? 0} MATCHES IN AVAILABLE SNAPSHOT // HISTORY DEGRADED` : `${searchResults?.length ?? 0} MATCHES ON THIS PAGE`}</span></div>}
      {scopedView && sourceReadState === "ready" && (!searching || searchStatus === "ready") && <InvestigationFilters records={viewRecords} filteredCount={filteredRecords.length} source={sourceFilter} kind={kindFilter} confidence={confidenceFilter} correlation={correlationFilter} correlationBounded={payload?.correlationCoverage.truncated ?? false} onSource={setSourceFilter} onKind={setKindFilter} onConfidence={setConfidenceFilter} onCorrelation={setCorrelationFilter} />}
      {maintenanceError && <div className="historyWarning compact"><b>INGEST MAINTENANCE DEGRADED</b><span>Local reads remain available; no upstream success is being claimed.</span></div>}
      {payload?.history.mode === "snapshot-only" && <div className="historyWarning compact"><b>PERSISTENT STATE UNAVAILABLE</b><span>Current snapshots remain usable; change-ledger coverage may be incomplete.</span></div>}
      {view === "briefing" && payload && (briefingStatus === "ready" && briefingPayload ? <AnalystBriefing events={briefingPayload.events} ledgerHasMore={briefingPayload.pagination.hasMore} ledger={briefingPayload.ledger} records={payload.records} datasetRevision={`${payload.generatedAt}:${payload.records.length}`} onSelect={setSelected} /> : <><EventReadNotice status={briefingStatus === "ready" ? "error" : briefingStatus} label="BRIEFING LEDGER" fallback={briefingStatus === "error" && payload.recentEvents.length > 0} />{briefingStatus === "error" && payload.recentEvents.length > 0 && <><div className="eventReadState loading"><b>PAGE-BOUNDED FALLBACK // OBSERVATIONAL ONLY</b><span>These recent events are displayed for reference only. They are not used to determine acknowledgement delta, no-change state, or ledger-gap state.</span></div><ObservatoryEventTable events={payload.recentEvents} selectedId={selected?.id} onSelect={setSelected} /></>}</>)}
      {view === "replay" && (replayStatus === "ready" ? <ObservatoryReplay events={replayPayload?.events ?? []} pageBounded={replayPayload?.pagination.hasMore ?? false} onSelect={setSelected} /> : <EventReadNotice status={replayStatus} label="REPLAY LEDGER" fallback={false} />)}
      {view === "pulse" && payload && !overviewCollapsed && <HistoryAnalytics analytics={payload.analytics} history={payload.history} />}
      {view === "infrastructure" && <div className="activeFilter"><b>ACTIVE FILTER</b><span>PUBLIC IP · DOMAIN · INFRASTRUCTURE RECORDS ONLY</span></div>}
      {(view === "pulse" || view === "infrastructure") && <section className={`heroGrid ${feedCollapsed ? "feedCollapsed" : ""}`}><ObservationGraphPanel records={filteredRecords} window={window} onSelect={setSelected} /><PulsePanel records={filteredRecords} loading={loading || searchStatus === "loading"} error={displayError} collapsed={feedCollapsed} onToggle={() => setFeedCollapsed((value) => !value)} onSelect={setSelected} /></section>}
      {view === "exploited" && <KevWorkspace onSelect={setSelected} />}
      {view === "urls" && (sourceReadState !== "ready" ? <SourceReadState source="URLHAUS" status={sourceReadState} /> : searching && searchStatus !== "ready" ? <SearchReadState status={searchStatus} /> : <ObservationTable title="Malicious URL observations" label="URLHAUS / DEFANGED BY DEFAULT" records={filteredRecords} onSelect={setSelected} />)}
      {view === "malware" && (sourceReadState !== "ready" ? <SourceReadState source="MALWAREBAZAAR" status={sourceReadState} /> : searching && searchStatus !== "ready" ? <SearchReadState status={searchStatus} /> : <ObservationTable title="Malware sample metadata" label="MALWAREBAZAAR / METADATA ONLY" records={filteredRecords} onSelect={setSelected} />)}
      {view === "events" && (recentEventsStatus === "ready" ? <><ObservatoryEventTable events={recentEventsPayload?.events ?? []} selectedId={selected?.id} onSelect={setSelected} /><PaginationControls page={recentEventsCursorTrail.length + 1} canPrevious={recentEventsCursorTrail.length > 0} nextCursor={recentEventsPayload?.pagination.nextCursor} onPrevious={() => previousPage(recentEventsCursorTrail, setRecentEventsCursorTrail, setRecentEventsCursor)} onNext={() => nextPage(recentEventsPayload?.pagination.nextCursor, recentEventsCursor, setRecentEventsCursorTrail, setRecentEventsCursor)} /></> : <EventReadNotice status={recentEventsStatus} label="RECENT EVENTS" fallback={false} />)}
      {view === "export" && payload && (searching && searchStatus !== "ready" ? <SearchExportState status={searchStatus} /> : <ExportWorkbench records={filteredRecords} allSources={payload.sources.map((source) => source.id)} window={window} scope={searching ? "SEARCH RESULTS ON THIS PAGE" : filtersActive ? "FILTERED VISIBLE PAGE" : "VISIBLE PAGE"} />)}
      {view === "sources" && payload && <SourcesView sources={payload.sources} history={payload.history} freshness={payload.freshness} ingestion={payload.ingestion} />}
      {view === "method" && <MethodView />}
      {ordinaryPage && <PaginationControls page={(searching ? searchCursorTrail : cursorTrail).length + 1} canPrevious={(searching ? searchCursorTrail : cursorTrail).length > 0} nextCursor={searching ? searchNextCursor : payload?.pagination.nextCursor} onPrevious={() => searching ? previousPage(searchCursorTrail, setSearchCursorTrail, setSearchCursor) : previousPage(cursorTrail, setCursorTrail, setCursor)} onNext={() => searching ? nextPage(searchNextCursor, searchCursor, setSearchCursorTrail, setSearchCursor) : nextPage(payload?.pagination.nextCursor, cursor, setCursorTrail, setCursor)} />}
      <footer><span>badBANANA // THREAT OBSERVATORY</span><b>CISA KEV · THREATFOX · URLHAUS · MALWAREBAZAAR</b></footer>
      {selected && <RecordDrawer key={selected.id} record={selected} correlated={correlated} onClose={() => setSelected(null)} />}
    </main>
  );
}


function SearchReadState({ status }: { status: Exclude<SearchStatus, "ready"> }) {
  return <section className={`dataSection sourceReadState ${status}`} aria-live="polite"><div className="sectionHead"><div><p>SEARCH / READ STATE</p><h1>{status === "error" ? "Search read failed" : "Resolving search results"}</h1></div><span className="scopeNote">COUNTS UNRESOLVED</span></div><div className="empty"><b>{status === "error" ? "SEARCH FAILED — ZERO RESULTS NOT ASSUMED" : "SEARCH IN PROGRESS — ZERO RESULTS NOT ASSUMED"}</b><span>{status === "error" ? "The active search could not be read. Ordinary observation records are not substituted." : "Waiting for a validated search response before displaying result records."}</span></div></section>;
}

function SearchExportState({ status }: { status: Exclude<SearchStatus, "ready"> }) {
  return <section className={`dataSection sourceReadState ${status}`} aria-live="polite"><div className="sectionHead"><div><p>EXPORT / SEARCH STATE</p><h1>{status === "error" ? "Search export unavailable" : "Resolving search results"}</h1></div><span className="scopeNote">EXPORT WITHHELD</span></div><div className="empty"><b>{status === "error" ? "SEARCH READ FAILED — FALLBACK RECORDS NOT EXPORTED" : "SEARCH IN PROGRESS — EXPORT SCOPE UNRESOLVED"}</b><span>{status === "error" ? "Retry the search before exporting. The ordinary observation page is not substituted for failed search results." : "Export becomes available only after the active search returns a validated result set."}</span></div></section>;
}

function SourceReadState({ source, status }: { source: "URLHAUS" | "MALWAREBAZAAR"; status: "loading" | "error" }) {
  return <section className={`dataSection sourceReadState ${status}`} aria-live="polite"><div className="sectionHead"><div><p>{source} / READ STATE</p><h1>{status === "error" ? "Source read failed" : "Loading source observations"}</h1></div><span className="scopeNote">COUNTS UNRESOLVED</span></div><div className="empty"><b>{status === "error" ? "READ FAILED — ZERO RESULTS NOT ASSUMED" : "READ IN PROGRESS — ZERO RESULTS NOT ASSUMED"}</b><span>{status === "error" ? "The selected source could not be read. Retry before treating this as an empty result." : "Waiting for a validated response from the selected source scope."}</span></div></section>;
}

function EventReadNotice({ status, label, fallback }: { status: Exclude<EventReadStatus, "ready">; label: string; fallback: boolean }) {
  return <div className={`eventReadState ${status}`} role={status === "error" ? "alert" : "status"}><b>{label} {"//"} {status === "loading" ? "LOADING NEWEST REQUESTED PAGE" : "READ FAILED"}</b><span>{status === "loading" ? "Counts and event content remain unresolved until the ledger responds." : fallback ? "A page-bounded fallback from the observation response is shown below; completeness is not claimed." : "No event list is displayed because a failed read is not an empty result."}</span></div>;
}

function InvestigationFilters({ records, filteredCount, source, kind, confidence, correlation, correlationBounded, onSource, onKind, onConfidence, onCorrelation }: { records: NormalizedObservation[]; filteredCount: number; source: string; kind: string; confidence: "any" | "supplied" | "missing"; correlation: "any" | "cross-source"; correlationBounded: boolean; onSource(value: string): void; onKind(value: string): void; onConfidence(value: "any" | "supplied" | "missing"): void; onCorrelation(value: "any" | "cross-source"): void }) {
  const sources = [...new Set(records.map((record) => record.source))].sort();
  const kinds = [...new Set(records.map((record) => record.kind))].sort();
  return <section className="investigationFilters" aria-label="Current-page investigation filters"><div><b>FILTER CURRENT PAGE</b><span>{filteredCount} / {records.length} SHOWN{correlationBounded ? " · CORRELATION SET BOUNDED" : ""}</span></div><label>SOURCE<select value={source} onChange={(event) => onSource(event.target.value)}><option value="all">ALL LOADED SOURCES</option>{sources.map((value) => <option value={value} key={value}>{value}</option>)}</select></label><label>RECORD TYPE<select value={kind} onChange={(event) => onKind(event.target.value)}><option value="all">ALL LOADED TYPES</option>{kinds.map((value) => <option value={value} key={value}>{value}</option>)}</select></label><label>CONFIDENCE<select value={confidence} onChange={(event) => onConfidence(event.target.value as "any" | "supplied" | "missing")}><option value="any">ANY / INCLUDING ABSENT</option><option value="supplied">SOURCE-SUPPLIED ONLY</option><option value="missing">NOT SUPPLIED</option></select></label><label>CORRELATION<select value={correlation} onChange={(event) => onCorrelation(event.target.value as "any" | "cross-source")}><option value="any">ANY LOADED RECORD</option><option value="cross-source">CROSS-SOURCE PEER IN CURRENT WINDOW</option></select></label></section>;
}

async function loadObservatory(window: TimeWindow, cursor: string | null, scope: ObservationScope, signal: AbortSignal): Promise<ObservatoryPayload> {
  const params = new URLSearchParams({ window, limit: "100", scope });
  if (cursor) params.set("cursor", cursor);
  const response = await fetch(`/api/observations?${params}`, { signal });
  if (!response.ok) throw new Error("Observatory read path failed");
  return response.json();
}

function scopeForView(view: View): ObservationScope {
  if (view === "urls") return "urlhaus";
  if (view === "malware") return "malwarebazaar";
  if (view === "infrastructure") return "infrastructure";
  return "all";
}

function age(value: string | undefined, now: Date): string {
  if (!value) return "NOT AVAILABLE";
  const seconds = Math.max(0, Math.floor((now.getTime() - new Date(value).getTime()) / 1_000));
  if (seconds < 60) return `${seconds}s AGO`;
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m AGO` : `${Math.floor(minutes / 60)}h ${minutes % 60}m AGO`;
}

function useStoredBoolean(key: string, initial: boolean) {
  const eventName = `badbanana-preference:${key}`;
  const subscribe = (notify: () => void) => {
    const onStorage = (event: StorageEvent) => { if (event.key === key) notify(); };
    window.addEventListener("storage", onStorage);
    window.addEventListener(eventName, notify);
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener(eventName, notify); };
  };
  const read = () => {
    try { const stored = window.localStorage.getItem(key); return stored === null ? initial : stored === "true"; }
    catch { return initial; }
  };
  const value = useSyncExternalStore(subscribe, read, () => initial);
  const update = (next: boolean | ((current: boolean) => boolean)) => {
    const resolved = typeof next === "function" ? next(value) : next;
    try { window.localStorage.setItem(key, String(resolved)); } catch { /* Device storage is optional. */ }
    window.dispatchEvent(new Event(eventName));
  };
  return [value, update] as const;
}
