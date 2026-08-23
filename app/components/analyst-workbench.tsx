"use client";
import { useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { EventLedgerBounds, NormalizedObservation, ObservationEvent, TimeWindow } from "../../lib/threat-types";
import { createAcknowledgement, parseAcknowledgement, summarizeBriefing, type DeviceAcknowledgement } from "../../lib/briefing";
import { applyExportPolicy, buildExport, previewExport, type ExportFormat, type ExportPolicy } from "../../lib/export-policy";
import { formatTimestamp } from "./observatory-format";
import { readDeviceStorage, writeDeviceStorage } from "../../lib/device-storage";

const ACK_KEY = "badbanana:briefing:acknowledgement:v1";
const DEVICE_KEY = "badbanana:briefing:device:v1";
let volatileDeviceId: string | undefined;
const browserStorage = () => {
  try { return window.localStorage; } catch { return undefined; }
};

export function AnalystBriefing({ events, ledgerHasMore, ledger, records, datasetRevision, onSelect }: { events: ObservationEvent[]; ledgerHasMore: boolean; ledger?: EventLedgerBounds; records: NormalizedObservation[]; datasetRevision: string; onSelect(record: NormalizedObservation): void }) {
  const acknowledgement = useDeviceAcknowledgement();
  const importRef = useRef<HTMLInputElement>(null);
  const [ackError, setAckError] = useState<string | null>(null);
  const summary = useMemo(() => summarizeBriefing(events, acknowledgement, ledger), [acknowledgement, events, ledger]);
  const recordById = useMemo(() => new Map(records.map((record) => [record.id, record])), [records]);
  const sourceCounts = useMemo(() => [...summary.events.reduce((counts, event) => counts.set(event.source, (counts.get(event.source) ?? 0) + 1), new Map<string, number>())].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])), [summary.events]);
  const acknowledge = () => {
    if (!summary.latestEvent) return;
    try {
      const next = createAcknowledgement(summary.latestEvent, datasetRevision, deviceId());
      if (!writeDeviceStorage(browserStorage, ACK_KEY, JSON.stringify(next))) throw new Error("Device storage unavailable");
      setAckError(null);
      window.dispatchEvent(new Event(ACK_KEY));
    } catch {
      setAckError("DEVICE STORAGE UNAVAILABLE — ACKNOWLEDGEMENT WAS NOT SAVED");
    }
  };
  const exportState = () => {
    if (!acknowledgement) return;
    download("badbanana-device-acknowledgement.json", "application/json", JSON.stringify(acknowledgement, null, 2));
  };
  const importState = async (file?: File) => {
    if (!file) return;
    try {
      const parsed = parseAcknowledgement(JSON.parse(await file.text()));
      if (!parsed) throw new Error("Invalid acknowledgement");
      if (!writeDeviceStorage(browserStorage, ACK_KEY, JSON.stringify(parsed))) throw new Error("Device storage unavailable");
      setAckError(null);
      window.dispatchEvent(new Event(ACK_KEY));
    } catch { setAckError("ACKNOWLEDGEMENT IMPORT FAILED — FILE INVALID, UNSUPPORTED, OR DEVICE STORAGE UNAVAILABLE"); }
    finally { if (importRef.current) importRef.current.value = ""; }
  };
  const heading = summary.state === "initial-baseline" ? "INITIAL BASELINE" : summary.state === "ledger-gap" ? "ACKNOWLEDGEMENT PREDATES AVAILABLE LEDGER" : summary.state === "no-changes" ? "NO UNACKNOWLEDGED CHANGES" : "CHANGES SINCE DEVICE ACKNOWLEDGEMENT";
  return <section className="briefing">
    <header className="briefingHead"><div><p>DEVICE-LOCAL BRIEFING</p><h1>{heading}</h1></div><div className="briefingActions"><button disabled={!summary.latestEvent} onClick={acknowledge}>ACKNOWLEDGE CURRENT LEDGER</button><button disabled={!acknowledgement} onClick={exportState}>EXPORT ACK</button><button onClick={() => importRef.current?.click()}>IMPORT ACK</button><input ref={importRef} hidden type="file" accept="application/json" onChange={(event) => importState(event.target.files?.[0])}/></div></header>
    <p className="briefingNotice">This cursor exists only on this device. It never deletes or changes server ledger events. Clearing browser storage or changing devices restores the initial baseline unless you import an acknowledgement file.</p>
    {ackError && <div className="briefingError" role="alert"><b>{ackError}</b><span>No acknowledgement state was changed.</span></div>}
    <div className="briefingCounts"><span><small>NEW ON PAGE</small><b>{summary.newCount}</b></span><span><small>UPDATED ON PAGE</small><b>{summary.updatedCount}</b></span><span><small>REMOVED ON PAGE</small><b>{summary.removedCount}</b></span><span className="ledgerCoverage"><small>LEDGER PAGE</small><b>{events.length} SHOWN</b><em>{ledgerHasMore ? "MORE RETAINED" : "END OF RETAINED RESULTS"}</em></span></div>
    <div className="briefingSources"><b>SOURCE CONTRIBUTION // CURRENT BRIEFING DELTA</b><span>{sourceCounts.length ? sourceCounts.map(([source, count]) => `${source} ${count}`).join(" · ") : "NO NEWER SOURCE EVENTS"}</span>{acknowledgement && <small>DEVICE ACKNOWLEDGED {formatTimestamp(acknowledgement.acknowledgedAt)}</small>}</div>
    {summary.state === "initial-baseline" ? <div className="briefingEmpty"><b>NOT PRESENTED AS NEW ACTIVITY</b><span>The retained event ledger is shown as an initial reference baseline until this device acknowledges it.</span></div> : summary.state === "ledger-gap" ? <div className="briefingEmpty"><b>COMPLETE DELTA CANNOT BE PROVEN</b><span>The saved cursor is older than the retained ledger. Available events are shown without claiming completeness.</span></div> : summary.state === "no-changes" ? <div className="briefingEmpty"><b>CURRENT WITH RETAINED LEDGER</b><span>No newer event is available after the device acknowledgement.</span></div> : null}
    {summary.events.length > 0 && <div className="briefingLedger">{summary.events.slice(0, 100).map((event) => {
      const record = event.current ?? recordById.get(event.observationId);
      return <button key={event.eventId} disabled={!record} onClick={() => record && onSelect(record)}><em className={event.eventType}>{event.eventType.toUpperCase()}</em><time>{formatTimestamp(event.detectedAt)}</time><code>{event.sourceRecordId ?? event.observationId}</code><span>{event.diff.length ? event.diff.map((item) => item.field).join(" · ") : "initial source record"}</span></button>;
    })}</div>}
  </section>;
}

export function ExportWorkbench({ records, allSources, window, scope }: { records: NormalizedObservation[]; allSources: string[]; window: TimeWindow; scope: string }) {
  const sources = [...new Set(allSources)].sort();
  const [excludedSources, setExcludedSources] = useState<string[]>([]);
  const [includeMissingConfidence, setIncludeMissingConfidence] = useState(true);
  const [minimumConfidence, setMinimumConfidence] = useState("");
  const [selectedFormat, setSelectedFormat] = useState<ExportFormat | null>(null);
  const availableSelectedSources = sources.filter((source) => !excludedSources.includes(source));
  const policy: ExportPolicy = { schemaVersion: 1, window, sources: availableSelectedSources, includeWithoutConfidence: includeMissingConfidence, minimumConfidence: minimumConfidence === "" ? undefined : Number(minimumConfidence), currentStateOnly: true, preserveDisputes: true };
  const projected = applyExportPolicy(records, policy).length;
  const previews = Object.fromEntries((["csv", "jsonl", "stix", "defanged", "manifest"] as ExportFormat[]).map((format) => [format, previewExport(records, policy, format)])) as Record<ExportFormat, ReturnType<typeof previewExport>>;
  const confidenceCoverage = records.filter((record) => record.confidence !== undefined).length;
  const create = () => {
    if (!selectedFormat) return;
    const artifact = buildExport(records, policy, selectedFormat);
    download(artifact.filename, artifact.mimeType, artifact.content);
  };
  return <section className="exportWorkbench"><header><p>LOCAL CURRENT-STATE EXPORT</p><h1>EXPORT WORKBENCH</h1><span>Scope: {scope}. No upstream collection. Removed ledger entries are excluded. Missing confidence remains missing.</span></header>
    <div className="exportPolicy"><fieldset><legend>ALL CONFIGURED SOURCES</legend>{sources.map((source) => <label key={source}><input type="checkbox" checked={!excludedSources.includes(source)} onChange={() => setExcludedSources((current) => current.includes(source) ? current.filter((item) => item !== source) : [...current, source])}/>{source}</label>)}</fieldset><label>MINIMUM SOURCE CONFIDENCE <small>{confidenceCoverage} OF {records.length} VISIBLE RECORDS PROVIDE IT</small><input type="number" min="0" max="100" value={minimumConfidence} placeholder="NOT SET" onChange={(event) => setMinimumConfidence(event.target.value)}/></label><label className="exportCheck"><input type="checkbox" checked={includeMissingConfidence} onChange={(event) => setIncludeMissingConfidence(event.target.checked)}/> INCLUDE RECORDS WITHOUT SOURCE CONFIDENCE</label></div>
    <div className="exportFormats">{(["csv", "jsonl", "stix", "defanged", "manifest"] as ExportFormat[]).map((format) => { const preview = previews[format]; return <button className={selectedFormat === format ? "selected" : ""} key={format} onClick={() => setSelectedFormat(format)}><b>{format === "stix" ? "STIX 2.1" : format.toUpperCase()}</b><span>{preview.emittedRecords} EMITTED{preview.omittedRecords ? ` · ${preview.omittedRecords} OMITTED` : ""} · {format === "manifest" ? "policy + record hashes" : format === "defanged" ? "copy-safe text" : "validated current records"}</span></button>; })}</div>
    <div className="exportCommit"><span><b>{projected}</b> SELECTED{selectedFormat ? ` · ${previews[selectedFormat].emittedRecords} ${selectedFormat === "stix" ? "STIX OBJECTS" : "EMITTED"}${previews[selectedFormat].omittedRecords ? ` · ${previews[selectedFormat].omittedRecords} UNSUPPORTED` : ""}` : ""}</span><button disabled={!selectedFormat || projected === 0} onClick={create}>{selectedFormat ? `DOWNLOAD ${selectedFormat.toUpperCase()}` : "SELECT A FORMAT"}</button></div>
    <div className="exportInvariant"><b>POLICY BOUNDARY</b><span>{records.length} records on this visible page · {availableSelectedSources.length} selected sources · disputes preserved as separate source records · no implied block recommendation</span></div>
  </section>;
}

function deviceId(): string {
  const existing = readDeviceStorage(browserStorage, DEVICE_KEY);
  if (existing) return existing;
  volatileDeviceId ??= crypto.randomUUID();
  writeDeviceStorage(browserStorage, DEVICE_KEY, volatileDeviceId);
  return volatileDeviceId;
}

function useDeviceAcknowledgement(): DeviceAcknowledgement | null {
  const subscribe = (notify: () => void) => {
    const storage = (event: StorageEvent) => { if (event.key === ACK_KEY) notify(); };
    window.addEventListener("storage", storage);
    window.addEventListener(ACK_KEY, notify);
    return () => { window.removeEventListener("storage", storage); window.removeEventListener(ACK_KEY, notify); };
  };
  const raw = useSyncExternalStore(subscribe, () => readDeviceStorage(browserStorage, ACK_KEY), () => null);
  return useMemo(() => {
    try { return parseAcknowledgement(JSON.parse(raw ?? "null")); } catch { return null; }
  }, [raw]);
}

function download(filename: string, mimeType: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const anchor = document.createElement("a");
  anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
