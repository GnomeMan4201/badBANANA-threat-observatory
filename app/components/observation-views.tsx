"use client";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import type { GeoPayload, KevCatalogPayload, NormalizedObservation, ObservationEvent, RevisionPayload, TimeWindow } from "../../lib/threat-types";
import { defangUrl, referencePolicy } from "../../lib/normalize";
import { formatTimestamp } from "./observatory-format";
import { RelationshipField } from "./relationship-field";
import { GeoMap } from "./geo-map";
import { buildEvidenceTrace } from "../../lib/evidence-trace";
import { recentKevCutoffDate, recentKevRangeLabel, type KevRecentRange } from "../../lib/kev-time";

type PulseMode = "relationships" | "geography";

export function ObservationGraphPanel({ records, window, onSelect }: { records: NormalizedObservation[]; window: TimeWindow; onSelect(record: NormalizedObservation): void }) {
  const [mode, setMode] = useState<PulseMode>("relationships");
  const [geo, setGeo] = useState<GeoPayload | null>(null);
  const [geoStatus, setGeoStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");

  useEffect(() => {
    if (mode !== "geography") return;
    const controller = new AbortController();
    const load = async () => {
      setGeo(null);
      setGeoStatus("loading");
      try {
        for (let attempt = 0; attempt < 8; attempt += 1) {
          const response = await fetch(`/api/geo?window=${window}`, { signal: controller.signal });
          if (!response.ok) throw new Error(response.status === 429 ? "Enrichment rate limit reached" : "Geography read failed");
          const payload = await response.json() as GeoPayload;
          setGeo(payload);
          if (!payload.pending) break;
          await waitFor(1_200, controller.signal);
        }
        setGeoStatus("ready");
      } catch (error) {
        if (!(error instanceof DOMException && error.name === "AbortError")) setGeoStatus("error");
      }
    };
    load();
    return () => controller.abort();
  }, [mode, window]);

  return (
    <div className="mapPanel">
      <div className="eyebrow graphHead"><span>{mode === "relationships" ? "OBSERVATION RELATIONSHIPS" : "PUBLIC IP GEOGRAPHY"}</span><div className="graphModes" aria-label="Visualization mode"><button className={mode === "relationships" ? "active" : ""} onClick={() => setMode("relationships")}>RELATIONSHIPS</button><button className={mode === "geography" ? "active" : ""} onClick={() => setMode("geography")}>GEO</button></div></div>
      {mode === "relationships" ? <RelationshipField records={records} onSelect={onSelect}/> : <GeoMap payload={geo} loading={geoStatus === "loading"} error={geoStatus === "error" ? "Validated coordinates could not be loaded. No fallback points were generated." : null} records={records} onSelect={onSelect} />}
      <div className="mapFooter">{mode === "relationships" ? <><span>MODE <b>RELATIONSHIP</b></span><span>SIGNALS <b>{records.length}</b></span><span>DERIVATION <b>SOURCE FIELDS</b></span></> : geoStatus === "ready" && geo ? <><span>IP RECORDS <b>{geo.candidateRecords}{geo.candidateRecordsTruncated ? " · QUERY BOUNDED" : ""}</b></span><span>PUBLIC CANDIDATES <b>{geo.candidates}</b></span><span>GEOLOCATED <b>{geo.points.length}</b></span><span>EXCLUDED <b>{geo.excluded}</b></span><span>UNAVAILABLE <b>{geo.unavailable}</b></span><span>PENDING <b>{geo.pending}</b></span><span>PROVIDERS <b>{geo.provider.name}</b></span></> : <><span>IP RECORDS <b>UNRESOLVED</b></span><span>PUBLIC CANDIDATES <b>UNRESOLVED</b></span><span>GEOLOCATED <b>UNRESOLVED</b></span><span>EXCLUDED <b>UNRESOLVED</b></span><span>UNAVAILABLE <b>UNRESOLVED</b></span><span>PENDING <b>UNRESOLVED</b></span><span>PROVIDERS <b>UNRESOLVED</b></span></>}</div>
    </div>
  );
}

function waitFor(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); };
    const timer = setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, milliseconds);
    signal.addEventListener("abort", abort, { once: true });
  });
}

export function PulsePanel({ records, loading, error, collapsed, onToggle, onSelect }: { records: NormalizedObservation[]; loading: boolean; error: string | null; collapsed: boolean; onToggle(): void; onSelect(record: NormalizedObservation): void }) {
  return (
    <aside className={`pulsePanel ${collapsed ? "collapsed" : ""}`}>
      <div className="eyebrow"><span>RECENT SOURCE RECORDS</span><span>{records.length} VISIBLE</span><button className="panelToggle" onClick={onToggle} aria-label={collapsed ? "Expand recent records panel" : "Minimize recent records panel"} aria-expanded={!collapsed}>{collapsed ? "+" : "−"}</button></div>
      {!collapsed && <div className="feed">
        {loading && <div className="loading">READING LOCAL OBSERVATIONS<span /></div>}
        {error && <div className="empty"><b>READ PATH DEGRADED</b><span>{error}. No demo records substituted.</span></div>}
        {!loading && !error && !records.length && <div className="empty"><b>NO SIGNAL</b><span>No observations match this source-time window.</span></div>}
        {records.slice(0, 100).map((record) => (
          <button className="event" key={record.id} onClick={() => onSelect(record)}>
            <time>{record.observedAt.slice(11, 19)}</time><b>{record.source.toUpperCase()}</b><code>{displayIndicator(record)}</code>
            <span>{record.malwareFamily ?? record.title ?? record.threatType ?? record.kind}</span>
          </button>
        ))}
      </div>}
    </aside>
  );
}

export function ObservationTable({ title, label, records, onSelect }: { title: string; label: string; records: NormalizedObservation[]; onSelect(record: NormalizedObservation): void }) {
  return (
    <section className="dataSection">
      <div className="sectionHead"><div><p>{label}</p><h1>{title}</h1></div><span className="scopeNote">{records.length} ON THIS PAGE</span></div>
      <div className="table" role="table">
        <div className="tr obs th" role="row"><span>INDICATOR</span><span>SOURCE / TYPE</span><span>CONTEXT</span><span>FIRST SEEN</span><span>CONF.</span></div>
        {records.map((record) => (
          <div className="tr obs" role="row" key={record.id}>
            <button className="rowOpen" aria-label={`Inspect ${displayIndicator(record)}`} onClick={() => onSelect(record)} />
            <IndicatorCell record={record} /><span className="sourceCell" data-label="SOURCE / TYPE"><b>{record.source}</b><small>{record.indicatorType ?? record.kind}</small></span>
            <span className="contextCell" data-label="CONTEXT">{record.malwareFamily ?? record.title ?? record.threatType ?? "Not provided"}</span>
            <time data-label="FIRST SEEN">{record.firstSeen?.slice(0, 10) ?? "NOT PROVIDED"}</time><em data-label="CONFIDENCE">{record.confidence ?? "NOT PROVIDED"}</em>
          </div>
        ))}
        {!records.length && <div className="empty"><b>NO VALIDATED RESULTS IN THIS SCOPE</b><span>The read completed successfully and returned zero matching observations.</span></div>}
      </div>
    </section>
  );
}

export function ObservatoryEventTable({ events, selectedId, onSelect }: { events: ObservationEvent[]; selectedId?: string; onSelect(record: NormalizedObservation): void }) {
  return (
    <section className="dataSection">
      <div className="sectionHead"><div><p>CHANGE LEDGER / OBSERVATORY TIME</p><h1>Recent Observatory events</h1></div><span className="scopeNote">MATERIAL CHANGES · PAGE BOUNDED</span></div>
      <div className="table eventTable" role="table">
        <div className="tr eventRow th" role="row"><span>DETECTED</span><span>EVENT</span><span>SOURCE</span><span>CHANGED FIELDS</span><span>RECORD</span></div>
        {events.map((event) => {
          const record = event.current ?? event.previous;
          return record ? <button className={`tr eventRow ${selectedId === record.id ? "selected" : ""}`} role="row" aria-label={`${selectedId === record.id ? "Selected. " : ""}Inspect ${event.eventType} event ${displayIndicator(record)}`} key={event.eventId} onClick={() => onSelect(record)}>
            <time data-label="DETECTED">{formatTimestamp(event.detectedAt)}</time><em data-label="EVENT" className={event.eventType}>{event.eventType.toUpperCase()}</em><b data-label="SOURCE">{event.source}</b>
            <span className="changeCell" data-label="CHANGED FIELDS">{event.diff.length ? event.diff.map((item) => item.field).join(", ") : event.eventType === "new" ? "NEW SOURCE RECORD" : "NO LONGER PRESENT"}</span><code className="indicatorCell" data-label="RECORD">{displayIndicator(record)}</code>
          </button> : null;
        })}
        {!events.length && <div className="empty"><b>NO MATERIAL EVENTS</b><span>Unchanged source sightings are summarized in source-cycle statistics instead of being emitted individually.</span></div>}
      </div>
    </section>
  );
}

export function KevWorkspace({ onSelect }: { onSelect(record: NormalizedObservation): void }) {
  const [mode, setMode] = useState<"catalog" | "recent">("catalog");
  const [query, setQuery] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [ransomware, setRansomware] = useState(false);
  const [newlyAdded, setNewlyAdded] = useState(false);
  const [addedSince, setAddedSince] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [cursorTrail, setCursorTrail] = useState<string[]>([]);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [payload, setPayload] = useState<KevCatalogPayload | null>(null);
  const [recentPayload, setRecentPayload] = useState<KevCatalogPayload | null>(null);
  const [recentCursor, setRecentCursor] = useState<string | null>(null);
  const [recentCursorTrail, setRecentCursorTrail] = useState<string[]>([]);
  const [recentRange, setRecentRange] = useState<KevRecentRange>("today");
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [sevenDaysAgo] = useState(() => new Date(Date.now() - 7 * 24 * 60 * 60_000).toISOString().slice(0, 10));

  const params = useMemo(() => {
    const values = new URLSearchParams({ limit: "50" });
    if (query.trim().length >= 2) values.set("q", query.trim());
    if (vendor.trim()) values.set("vendor", vendor.trim());
    if (product.trim()) values.set("product", product.trim());
    if (ransomware) values.set("ransomware", "known");
    if (newlyAdded) values.set("addedSince", sevenDaysAgo);
    else if (addedSince) values.set("addedSince", addedSince);
    if (cursor) values.set("cursor", cursor);
    return values.toString();
  }, [addedSince, cursor, newlyAdded, product, query, ransomware, sevenDaysAgo, vendor]);

  useEffect(() => {
    if (mode !== "catalog") return;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setStatus("loading");
      fetch(`/api/kev?${params}`, { signal: controller.signal })
        .then(async (response) => { if (!response.ok) throw new Error("Catalog unavailable"); return response.json() as Promise<KevCatalogPayload>; })
        .then((data) => { setPayload(data); setStatus("ready"); })
        .catch((error) => { if (!(error instanceof DOMException && error.name === "AbortError")) setStatus("error"); });
    }, 250);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [mode, params]);

  useEffect(() => {
    if (mode !== "recent") return;
    const controller = new AbortController();
    const values = new URLSearchParams({ limit: "50", addedSince: recentKevCutoffDate(recentRange) });
    if (recentCursor) values.set("cursor", recentCursor);
    const timer = setTimeout(() => {
      setStatus("loading");
      fetch(`/api/kev?${values}`, { signal: controller.signal })
        .then(async (response) => { if (!response.ok) throw new Error("Recent catalog unavailable"); return response.json() as Promise<KevCatalogPayload>; })
        .then((data) => { setRecentPayload(data); setStatus("ready"); })
        .catch((error) => { if (!(error instanceof DOMException && error.name === "AbortError")) setStatus("error"); });
    }, 0);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [mode, recentCursor, recentRange]);

  const resetPage = () => { setCursor(null); setCursorTrail([]); };
  return (
    <section className="dataSection kevWorkspace">
      <div className="sectionHead"><div><p>CISA KNOWN EXPLOITED VULNERABILITIES</p><h1>Exploited analyst workspace</h1></div><span className="scopeNote">CVSS: SOURCE-SUPPLIED ONLY</span></div>
      <div className="workspaceTabs" role="tablist">
        <button className={mode === "catalog" ? "active" : ""} onClick={() => { setStatus("loading"); setMode("catalog"); }}>CURRENT KEV CATALOG</button>
        <button className={mode === "recent" ? "active" : ""} onClick={() => { setStatus("loading"); setMode("recent"); }}>RECENT KEV / DAY-GRANULAR</button>
      </div>
      {mode === "catalog" ? <>
        <button className="filterToggle" aria-expanded={filtersOpen} onClick={() => setFiltersOpen((open) => !open)}>FILTERS <span>{filtersOpen ? "−" : "+"}</span></button>
        <div className={`kevFilters ${filtersOpen ? "" : "collapsed"}`}>
          <label>SEARCH<input value={query} onChange={(event) => { setQuery(event.target.value.slice(0, 160)); resetPage(); }} placeholder="CVE, vendor, product, action" /></label>
          <label>VENDOR<input list="kev-vendors" value={vendor} onChange={(event) => { setVendor(event.target.value.slice(0, 160)); resetPage(); }} /><datalist id="kev-vendors">{payload?.vendors.map((value) => <option value={value} key={value} />)}</datalist></label>
          <label>PRODUCT<input list="kev-products" value={product} onChange={(event) => { setProduct(event.target.value.slice(0, 160)); resetPage(); }} /><datalist id="kev-products">{payload?.products.map((value) => <option value={value} key={value} />)}</datalist></label>
          <label>DATE ADDED ON/AFTER<input type="date" value={addedSince} disabled={newlyAdded} onChange={(event) => { setAddedSince(event.target.value); resetPage(); }} /></label>
          <label className="checkFilter"><input type="checkbox" checked={newlyAdded} onChange={(event) => { setNewlyAdded(event.target.checked); resetPage(); }} /> NEWLY ADDED / 7D</label>
          <label className="checkFilter"><input type="checkbox" checked={ransomware} onChange={(event) => { setRansomware(event.target.checked); resetPage(); }} /> RANSOMWARE ASSOCIATED</label>
        </div>
        <div className="catalogMeta"><span>CURRENT VALIDATED RECORDS <b>{payload?.total ?? "—"}</b></span><span>TIME BASIS <b>SOURCE DATE ADDED / NOT GLOBAL WINDOW</b></span><span>STATE <b>{status.toUpperCase()}</b></span></div>
        {status === "loading" ? <div className="empty"><b>CATALOG READ IN PROGRESS — COUNTS UNRESOLVED</b><span>No prior response is presented as the current filter result.</span></div> : status === "error" ? <div className="empty"><b>CATALOG UNAVAILABLE — ZERO RESULTS NOT ASSUMED</b><span>No snapshot records substituted without explicit degraded state.</span></div> : payload?.records.length ? <KevTable records={payload.records} onSelect={onSelect} /> : <div className="empty"><b>NO VALIDATED KEV RESULTS IN THIS SCOPE</b><span>The catalog read succeeded and returned zero matching records.</span></div>}
        {status === "ready" && <PaginationControls page={cursorTrail.length + 1} canPrevious={cursorTrail.length > 0} nextCursor={payload?.pagination.nextCursor} onPrevious={() => { const previous = cursorTrail.at(-1); if (previous === undefined) return; setStatus("loading"); setCursorTrail((trail) => trail.slice(0, -1)); setCursor(previous || null); }} onNext={() => { const next = payload?.pagination.nextCursor; if (!next) return; setStatus("loading"); setCursorTrail((trail) => [...trail, cursor ?? ""]); setCursor(next); }} />}
      </> : <>
        <div className="kevRecentRanges" aria-label="CISA day-granular time range">{(["today", "7d", "30d"] as KevRecentRange[]).map((range) => <button className={recentRange === range ? "active" : ""} key={range} onClick={() => { setStatus("loading"); setRecentRange(range); setRecentCursor(null); setRecentCursorTrail([]); }}>{recentKevRangeLabel(range)}</button>)}</div>
        <div className="catalogMeta"><span>SCOPE <b>{recentKevRangeLabel(recentRange)}</b></span><span>TIME BASIS <b>CISA DATE ADDED · DAY PRECISION</b></span><span>RECORDS <b>{status === "ready" && recentPayload ? `${recentPayload.records.length} ON PAGE · ${recentPayload.total} MATCHED` : "UNRESOLVED"}</b></span></div>
        {status === "loading" ? <div className="empty"><b>RECENT KEV READ IN PROGRESS — COUNTS UNRESOLVED</b><span>Waiting for a validated day-granular response.</span></div> : status === "error" ? <div className="empty"><b>RECENT KEV UNAVAILABLE — ZERO RESULTS NOT ASSUMED</b><span>No globally paginated observation page was substituted.</span></div> : recentPayload?.records.length ? <KevTable records={recentPayload.records} onSelect={onSelect} /> : <div className="empty"><b>NO VALIDATED KEV RESULTS IN THIS DAY-GRANULAR SCOPE</b><span>The recent KEV read succeeded and returned zero matching records.</span></div>}
        {status === "ready" && <PaginationControls page={recentCursorTrail.length + 1} canPrevious={recentCursorTrail.length > 0} nextCursor={recentPayload?.pagination.nextCursor} onPrevious={() => { const previous = recentCursorTrail.at(-1); if (previous === undefined) return; setStatus("loading"); setRecentCursorTrail((trail) => trail.slice(0, -1)); setRecentCursor(previous || null); }} onNext={() => { const next = recentPayload?.pagination.nextCursor; if (!next) return; setStatus("loading"); setRecentCursorTrail((trail) => [...trail, recentCursor ?? ""]); setRecentCursor(next); }} />}
      </>}
    </section>
  );
}

function KevTable({ records, onSelect }: { records: NormalizedObservation[]; onSelect(record: NormalizedObservation): void }) {
  return <div className="table kevTable" role="table">
    <div className="tr kevRow th" role="row"><span>CVE</span><span>VENDOR / PRODUCT</span><span>VULNERABILITY</span><span>DATE ADDED / DUE</span><span>RANSOMWARE</span><span>REQUIRED ACTION</span></div>
    {records.map((record) => <button className="tr kevRow" role="row" key={record.id} onClick={() => onSelect(record)}>
      <code>{record.indicator}</code><span><b>{String(record.metadata.vendor ?? "—")}</b><small>{String(record.metadata.product ?? "—")}</small></span>
      <span>{record.title ?? "—"}</span><time>{record.observedAt.slice(0, 10)}<small>DUE {String(record.metadata.dueDate ?? "—").slice(0, 10)}</small></time>
      <em className={String(record.metadata.knownRansomwareCampaignUse).toLowerCase() === "known" ? "yes" : "no"}>{String(record.metadata.knownRansomwareCampaignUse ?? "UNKNOWN")}</em>
      <span>{String(record.metadata.requiredAction ?? "—")}</span>
    </button>)}
  </div>;
}

export function PaginationControls({ page, canPrevious, nextCursor, onPrevious, onNext }: { page: number; canPrevious: boolean; nextCursor?: string; onPrevious(): void; onNext(): void }) {
  if (!canPrevious && !nextCursor) return null;
  return <div className="pagination"><button disabled={!canPrevious} onClick={onPrevious}>PREVIOUS</button><span>PAGE {page} · TOTAL PAGES UNKNOWN</span><button disabled={!nextCursor} onClick={onNext}>NEXT</button></div>;
}

function IndicatorCell({ record }: { record: NormalizedObservation }) {
  const [expanded, setExpanded] = useState(false);
  const value = displayIndicator(record);
  const longHash = (record.kind === "hash" || /^[a-f0-9]{32,128}$/i.test(value)) && value.length > 32;
  const shown = longHash && !expanded ? `${value.slice(0, 14)}…${value.slice(-12)}` : value;
  return <div className={`indicatorCell ${longHash ? "longHash" : ""}`} data-label="INDICATOR"><code>{shown}</code>{longHash && <span className="indicatorActions"><button onClick={() => setExpanded((open) => !open)}>{expanded ? "COLLAPSE" : "EXPAND"}</button><button onClick={() => navigator.clipboard.writeText(value)}>COPY</button></span>}</div>;
}

export function RecordDrawer({ record, correlated, onClose }: { record: NormalizedObservation; correlated: NormalizedObservation[]; onClose(): void }) {
  const isUrl = record.kind === "url" && record.indicator;
  const reference = referencePolicy(record.reference, record.source);
  const [revisions, setRevisions] = useState<RevisionPayload | null>(null);
  const [revisionError, setRevisionError] = useState(false);
  const [peers, setPeers] = useState(correlated);
  const [correlationStatus, setCorrelationStatus] = useState<"loading" | "ready" | "error">("loading");
  const drawerRef = useRef<HTMLElement>(null);
  const closeRef = useRef(onClose);
  const trace = buildEvidenceTrace(record);
  const metadataEntries = useMemo(() => Object.entries(record.metadata).filter(([, value]) => value !== undefined).slice(0, 50), [record.metadata]);
  useEffect(() => { closeRef.current = onClose; }, [onClose]);
  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const drawer = drawerRef.current;
    const focusable = () => [...(drawer?.querySelectorAll<HTMLElement>('button:not([disabled]),a[href],input:not([disabled]),[tabindex]:not([tabindex="-1"])') ?? [])];
    focusable()[0]?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) return;
      const first = items[0], last = items.at(-1)!;
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", keydown);
    return () => { document.removeEventListener("keydown", keydown); previous?.focus(); };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/revisions?id=${encodeURIComponent(record.id)}&limit=50`, { signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error("Revision history unavailable"); return response.json() as Promise<RevisionPayload>; })
      .then((data) => { setRevisions(data); setRevisionError(false); })
      .catch((error) => { if (!(error instanceof DOMException && error.name === "AbortError")) setRevisionError(true); });
    return () => controller.abort();
  }, [record.id]);
  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/correlations?id=${encodeURIComponent(record.id)}`, { signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error("Correlation read failed"); return response.json() as Promise<{ records: NormalizedObservation[] }>; })
      .then((payload) => { setPeers(payload.records); setCorrelationStatus("ready"); })
      .catch((error) => { if (!(error instanceof DOMException && error.name === "AbortError")) setCorrelationStatus("error"); });
    return () => controller.abort();
  }, [record.id]);
  return (
    <div className="drawerWrap" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside ref={drawerRef} className="drawer" role="dialog" aria-modal="true" aria-label={`Observation ${record.id}`}>
        <button className="close" onClick={onClose}>CLOSE ×</button>
        <p className="drawerLabel">CURRENT SOURCE RECORD // OBSERVATORY PROVENANCE</p><h2>{displayIndicator(record)}</h2>
        <p className="drawerTitle">{record.title ?? record.malwareFamily ?? record.threatType ?? record.kind}</p>
        {isUrl && <div className="copyRow"><button onClick={() => navigator.clipboard.writeText(defangUrl(record.indicator!))}>COPY DEFANGED</button><button onClick={() => navigator.clipboard.writeText(record.indicator!)}>COPY RAW</button></div>}
        <section className="drawerEvidenceGroup"><header><b>SOURCE-SUPPLIED</b><span>RETAINED EVIDENCE</span></header><dl>
          <dt>SOURCE</dt><dd>{record.source}</dd><dt>SOURCE RECORD</dt><dd>{record.sourceRecordId ?? "NOT PROVIDED"}</dd>
          <dt>SOURCE TYPE</dt><dd>{record.indicatorType ?? "NOT PROVIDED"}</dd><dt>CONFIDENCE</dt><dd>{record.confidence ?? "NOT PROVIDED"}</dd>
          <dt>SOURCE FIRST SEEN</dt><dd>{formatTimestamp(record.firstSeen)}</dd><dt>SOURCE LAST SEEN</dt><dd>{formatTimestamp(record.lastSeen)}</dd>
          <dt>TAGS / CLASSIFICATION</dt><dd>{record.tags.join(", ") || "NOT PROVIDED"}</dd><dt>SOURCE REFERENCE</dt><dd>{reference.hostname ?? "NOT PROVIDED OR INVALID"}</dd>
        </dl></section>
        <section className="drawerEvidenceGroup"><header><b>NORMALIZED</b><span>OBSERVATORY MODEL</span></header><dl>
          <dt>INDICATOR</dt><dd className="hashValue">{record.indicator ?? "NOT PROVIDED"}</dd><dt>NORMALIZED KIND</dt><dd>{record.kind}</dd>
          <dt>OBSERVATION TIME</dt><dd>{formatTimestamp(record.observedAt)}</dd><dt>FIRST INGESTED</dt><dd>{formatTimestamp(record.firstIngestedAt ?? record.ingestedAt)}</dd>
          <dt>LAST SOURCE SIGHTING</dt><dd>{formatTimestamp(record.lastObservedInSnapshotAt ?? record.lastIngestedAt ?? record.ingestedAt)}</dd><dt>LAST MATERIAL CHANGE</dt><dd>{formatTimestamp(record.lastChangedAt)}</dd>
          <dt>REVISION COUNT</dt><dd>{record.revisionCount ?? "NOT AVAILABLE"}</dd><dt>LATEST INGEST RESULT</dt><dd>{record.ingestState?.toUpperCase() ?? "NOT AVAILABLE"}</dd>
          <dt>CURRENT RECORD HASH</dt><dd className="hashValue">{record.recordHash ?? "NOT AVAILABLE"}</dd>
        </dl></section>
        {metadataEntries.length > 0 && <section className="drawerEvidenceGroup"><header><b>SOURCE-SPECIFIC DETAILS</b><span>VALIDATED METADATA</span></header><dl>{metadataEntries.map(([key, value]) => <Fragment key={key}><dt>{key.replace(/([A-Z])/g, " $1").toUpperCase()}</dt><dd>{value === null ? "NULL / SOURCE-SUPPLIED" : String(value)}</dd></Fragment>)}</dl></section>}
        <div className="derived"><b>DERIVED</b><p>Display transforms and evidence trace decisions are derived from the retained record. No attribution, severity, ownership, intent, or geography is invented.</p></div>
        <section className="evidenceTrace">
          <header><b>EVIDENCE TRACE</b><span>SCHEMA v{trace.schemaVersion}</span></header>
          <dl><dt>IDENTITY</dt><dd>{trace.identityDecision}</dd><dt>CLASSIFICATION</dt><dd>{trace.classificationDecision}</dd><dt>ACCEPTED FIELDS</dt><dd>{trace.acceptedFields.join(", ")}</dd><dt>ABSENT OPTIONAL FIELDS</dt><dd>{trace.absentOptionalFields.join(", ") || "NONE"}</dd><dt>DISPLAY TRANSFORMS</dt><dd>{trace.displayTransforms.join(", ") || "NONE"}</dd></dl>
          <p>The trace describes the retained normalized record. Rejected upstream values are not retained here and no Observatory identity is assigned to them.</p>
        </section>
        <div className={`correlated ${correlationStatus}`}><b>CORRELATED // CURRENT-STATE EXACT-INDICATOR PEERS</b><p className="correlationReason">Reason: same normalized indicator observed in independent source records within the retained query window. This does not establish a shared campaign, actor, ownership, or attribution.</p>{correlationStatus === "loading" ? <p>QUERY IN PROGRESS — RESULT COUNT UNRESOLVED</p> : correlationStatus === "error" ? <p>CORRELATION READ FAILED — NO-MATCH STATE NOT ASSUMED</p> : peers.length ? peers.map((item) => <p key={item.id}>{item.source}{" // "}{item.sourceRecordId}</p>) : <p>NO CROSS-SOURCE PEERS RETURNED FOR THIS RETAINED QUERY</p>}</div>
        <div className="revisionHistory">
          <b>REVISION HISTORY</b>
          <article><span>CURRENT</span><time>{formatTimestamp(record.lastChangedAt)}</time><code>{record.recordHash ?? "HASH UNAVAILABLE"}</code></article>
          {revisionError && <p>REVISION LEDGER UNAVAILABLE</p>}
          {revisions?.events.map((event) => <article key={event.eventId}>
            <span>{event.eventType.toUpperCase()}</span><time>{formatTimestamp(event.detectedAt)}</time><code>{event.newHash ?? event.previousHash ?? "HASH UNAVAILABLE"}</code>
            {event.diff.map((item) => <p key={item.field}><b>{item.field}</b><s>{formatDiffValue(item.before)}</s><i>{formatDiffValue(item.after)}</i></p>)}
          </article>)}
          {!revisionError && revisions && !revisions.events.length && <p>NO MATERIAL CHANGE EVENTS RETAINED FOR THIS RECORD</p>}
        </div>
        {reference.trust === "first-party" && <a className="upstreamReference" href={reference.url} target="_blank" rel="noreferrer">OPEN VALIDATED UPSTREAM SOURCE PAGE ↗</a>}
        {reference.trust === "external" && <div className="externalReference"><b>EXTERNAL SOURCE REFERENCE</b><span>UNTRUSTED DESTINATION // {reference.hostname}</span><button onClick={() => navigator.clipboard.writeText(reference.url!)}>COPY REFERENCE</button></div>}
      </aside>
    </div>
  );
}

function displayIndicator(record: NormalizedObservation): string { if (!record.indicator) return record.title ?? record.id; return record.kind === "url" ? defangUrl(record.indicator) : record.indicator; }
function formatDiffValue(value: unknown): string { if (value === undefined) return "NOT PROVIDED"; if (Array.isArray(value)) return value.join(", ") || "EMPTY"; return String(value); }
