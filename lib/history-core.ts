import type { FieldDiff, FreshnessSummary, HistoryHealth, IngestionHealth, NormalizedObservation, ObservationEvent, SourceHealth, SourceIngestCycle, SourceSnapshot, TimeWindow } from "./threat-types.ts";
import { filterByWindow, matchesSearch } from "./analysis.ts";
import { validateNormalizedObservation } from "./normalize.ts";

export const RETENTION_DAYS = 7;
export const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60_000;
export const INACTIVE_CISA_RETENTION_DAYS = 30;
export const INACTIVE_CISA_RETENTION_MS = INACTIVE_CISA_RETENTION_DAYS * 24 * 60 * 60_000;

export function inactiveCisaCutoff(now = Date.now()): string {
  return new Date(now - INACTIVE_CISA_RETENTION_MS).toISOString();
}

export function ingestionHealthWithCycles(health: IngestionHealth, latestSourceCycles: SourceIngestCycle[]): IngestionHealth {
  return { ...health, latestSourceCycles };
}

export function selectLeaseBackend(backends: Array<"d1" | "isolate-memory" | undefined>, fallback: "d1" | "isolate-memory"): "d1" | "isolate-memory" {
  if (backends.includes("isolate-memory")) return "isolate-memory";
  if (backends.includes("d1")) return "d1";
  return fallback;
}

export async function hashNormalizedObservation(record: NormalizedObservation): Promise<string> {
  const canonical = stableStringify({
    id: record.id,
    source: record.source,
    sourceRecordId: record.sourceRecordId,
    kind: record.kind,
    indicator: record.indicator,
    indicatorType: record.indicatorType,
    title: record.title,
    malwareFamily: record.malwareFamily,
    threatType: record.threatType,
    confidence: record.confidence,
    firstSeen: record.firstSeen,
    lastSeen: record.lastSeen,
    observedAt: record.observedAt,
    tags: canonicalTags(record.tags),
    reference: record.reference,
    metadata: record.metadata,
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function mergeObservation(
  existing: NormalizedObservation | undefined,
  incoming: NormalizedObservation,
  recordHash: string,
  ingestedAt: string,
  comparablePriorHash = existing?.recordHash,
): NormalizedObservation {
  const changed = Boolean(existing && comparablePriorHash && comparablePriorHash !== recordHash);
  return {
    ...incoming,
    ingestedAt,
    firstIngestedAt: existing?.firstIngestedAt ?? existing?.ingestedAt ?? ingestedAt,
    lastIngestedAt: ingestedAt,
    lastChangedAt: !existing || changed ? ingestedAt : existing.lastChangedAt ?? existing.firstIngestedAt ?? existing.ingestedAt,
    lastObservedInSnapshotAt: ingestedAt,
    revisionCount: !existing ? 1 : changed ? (existing.revisionCount ?? 1) + 1 : existing.revisionCount ?? 1,
    recordHash,
    ingestState: !existing ? "new" : changed ? "updated" : "seen",
  };
}

export interface LedgerWriteResult {
  records: NormalizedObservation[];
  events: ObservationEvent[];
  newRecords: number;
  updatedRecords: number;
  unchangedRecords: number;
}

export async function upsertMemoryLedger(
  history: Map<string, NormalizedObservation>,
  incoming: NormalizedObservation[],
  ingestedAt: string,
): Promise<LedgerWriteResult> {
  const records: NormalizedObservation[] = [];
  const events: ObservationEvent[] = [];
  let newRecords = 0;
  let updatedRecords = 0;
  let unchangedRecords = 0;
  for (const record of incoming) {
    if (!validateNormalizedObservation(record)) continue;
    const existing = history.get(record.id);
    const hash = await hashNormalizedObservation(record);
    const comparablePriorHash = existing ? await hashNormalizedObservation(existing) : undefined;
    const next = mergeObservation(existing, record, hash, ingestedAt, comparablePriorHash);
    history.set(record.id, next);
    records.push(next);
    if (!existing) {
      newRecords += 1;
      events.push(createObservationEvent("new", next, undefined, ingestedAt));
    } else if (comparablePriorHash && comparablePriorHash !== hash) {
      updatedRecords += 1;
      events.push(createObservationEvent("updated", next, existing, ingestedAt));
    } else {
      unchangedRecords += 1;
    }
  }
  return { records, events, newRecords, updatedRecords, unchangedRecords };
}

function canonicalTags(tags: string[]): string[] {
  return [...new Set(tags.map((tag) => tag.trim().toLowerCase()).filter(Boolean))].sort((left, right) => left.localeCompare(right));
}

export async function upsertMemoryHistory(
  history: Map<string, NormalizedObservation>,
  incoming: NormalizedObservation[],
  ingestedAt: string,
): Promise<NormalizedObservation[]> {
  return (await upsertMemoryLedger(history, incoming, ingestedAt)).records;
}

export function createObservationEvent(eventType: "new" | "updated" | "removed", current: NormalizedObservation | undefined, previous: NormalizedObservation | undefined, detectedAt: string): ObservationEvent {
  const record = current ?? previous;
  if (!record) throw new Error("Observation event requires a current or previous record");
  const hash = current?.recordHash ?? previous?.recordHash ?? "nohash";
  return {
    eventId: `${record.id}:${detectedAt}:${eventType}:${hash.slice(0, 12)}`,
    observationId: record.id,
    source: record.source,
    sourceRecordId: record.sourceRecordId,
    eventType,
    detectedAt,
    previousHash: previous?.recordHash,
    newHash: current?.recordHash,
    previous,
    current,
    diff: eventType === "updated" && previous && current ? diffNormalizedObservation(previous, current) : [],
  };
}

export function diffNormalizedObservation(previous: NormalizedObservation, current: NormalizedObservation): FieldDiff[] {
  const diffs: FieldDiff[] = [];
  const fields = ["title", "malwareFamily", "threatType", "confidence", "firstSeen", "lastSeen", "tags", "reference"] as const;
  for (const field of fields) {
    const before = previous[field];
    const after = current[field];
    if (stableStringify(before) !== stableStringify(after)) diffs.push({ field, before: diffValue(before), after: diffValue(after) });
  }
  const metadataKeys = [...new Set([...Object.keys(previous.metadata), ...Object.keys(current.metadata)])].sort();
  for (const key of metadataKeys) {
    const before = previous.metadata[key];
    const after = current.metadata[key];
    if (stableStringify(before) !== stableStringify(after)) diffs.push({ field: `metadata.${key}`, before: diffValue(before), after: diffValue(after) });
  }
  return diffs;
}

export function sourceEligibility(snapshot: SourceSnapshot | undefined, configured: boolean, now = Date.now()): "eligible" | "fresh" | "backoff" | "disabled" {
  if (!configured) return "disabled";
  if (snapshot && new Date(snapshot.expiresAt).getTime() > now) return "fresh";
  if (snapshot && isBackoffActive(snapshot.health, now)) return "backoff";
  return "eligible";
}

export function pruneMemoryEvents(events: ObservationEvent[], now = Date.now()): ObservationEvent[] {
  const cutoff = now - RETENTION_MS;
  return events.filter((event) => new Date(event.detectedAt).getTime() >= cutoff);
}

export function filterKevCatalogRecords(records: NormalizedObservation[], filters: { query?: string; vendor?: string; product?: string; ransomwareOnly?: boolean; addedSince?: string }): NormalizedObservation[] {
  return records.filter((record) => {
    if (record.source !== "cisa-kev" || !validateNormalizedObservation(record)) return false;
    if (filters.query && !matchesSearch(record, filters.query)) return false;
    if (filters.vendor && !String(record.metadata.vendor ?? "").toLowerCase().includes(filters.vendor.toLowerCase())) return false;
    if (filters.product && !String(record.metadata.product ?? "").toLowerCase().includes(filters.product.toLowerCase())) return false;
    if (filters.ransomwareOnly && String(record.metadata.knownRansomwareCampaignUse ?? "").toLowerCase() !== "known") return false;
    return !filters.addedSince || record.observedAt >= filters.addedSince;
  });
}

export function acquireInMemoryLease(
  leases: Map<string, { holder: string; expiresAt: number }>,
  source: string,
  holder: string,
  now: number,
  ttlMs: number,
): boolean {
  const current = leases.get(source);
  if (current && current.expiresAt > now) return false;
  leases.set(source, { holder, expiresAt: now + ttlMs });
  return true;
}

export function pruneMemoryHistory(history: Map<string, NormalizedObservation>, now = Date.now()): number {
  const cutoff = now - RETENTION_MS;
  let removed = 0;
  for (const [id, record] of history) {
    const lastIngested = new Date(record.lastIngestedAt ?? record.ingestedAt).getTime();
    if (!Number.isFinite(lastIngested) || lastIngested < cutoff) {
      history.delete(id);
      removed += 1;
    }
  }
  return removed;
}

export function backoffDelayMs(consecutiveFailures: number, retryAfterMs?: number): number {
  const schedule = [60_000, 120_000, 300_000, 900_000, 1_800_000];
  const scheduled = schedule[Math.min(Math.max(consecutiveFailures, 1), schedule.length) - 1];
  return Math.max(scheduled, Math.min(retryAfterMs ?? 0, 60 * 60_000));
}

export function nextRetryAt(consecutiveFailures: number, attemptedAt: string, retryAfterMs?: number): string {
  return new Date(new Date(attemptedAt).getTime() + backoffDelayMs(consecutiveFailures, retryAfterMs)).toISOString();
}

export function isBackoffActive(health: Pick<SourceHealth, "nextRetryAt">, now = Date.now()): boolean {
  return Boolean(health.nextRetryAt && new Date(health.nextRetryAt).getTime() > now);
}

export function statusDuringBackoff(recordCount: number): "stale" | "offline" {
  return recordCount > 0 ? "stale" : "offline";
}

export function summarizeFreshness(sources: SourceHealth[], generatedAt: string): FreshnessSummary {
  const enabled = sources.filter((source) => source.configured);
  const successes = enabled.map((source) => source.lastSuccess).filter((value): value is string => Boolean(value)).sort();
  let state: FreshnessSummary["state"] = "fresh";
  if (!enabled.length) state = "disabled";
  else if (enabled.every((source) => source.status === "offline")) state = "offline";
  else if (enabled.some((source) => source.status !== "healthy")) state = "stale";
  return {
    snapshotGenerated: generatedAt,
    latestSourceSuccess: successes.at(-1),
    oldestEnabledSourceSuccess: successes[0],
    state,
  };
}

export function snapshotOnlyHealth(records: NormalizedObservation[], reason: string, lastWrite?: string): HistoryHealth {
  const first = records.map((record) => record.firstIngestedAt ?? record.ingestedAt).sort()[0];
  const last = records.map((record) => record.lastIngestedAt ?? record.ingestedAt).sort().at(-1);
  return { mode: "snapshot-only", status: "degraded", retentionDays: RETENTION_DAYS, observationsStored: records.length, oldestObservation: first, newestObservation: last, lastWrite, reason };
}

export function searchStoredRecords(records: NormalizedObservation[], query: string, window: TimeWindow, limit = 100, now = Date.now()): NormalizedObservation[] {
  return filterByWindow(records.filter(validateNormalizedObservation), window, now).filter((record) => matchesSearch(record, query)).slice(0, limit);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).filter((key) => record[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function diffValue(value: unknown): string | number | boolean | null | string[] | undefined {
  if (value === undefined || value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) return value;
  return JSON.stringify(value);
}
