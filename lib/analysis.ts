import type { Correlation, NormalizedObservation, ObservatoryAnalytics, TimeWindow } from "./threat-types";

export const WINDOW_MS: Record<TimeWindow, number> = { "15m": 15 * 60_000, "1h": 60 * 60_000, "6h": 6 * 60 * 60_000, "24h": 24 * 60 * 60_000, "7d": 7 * 24 * 60 * 60_000 };

export function windowStart(window: TimeWindow, now = Date.now()): string {
  return new Date(now - WINDOW_MS[window]).toISOString();
}

export function filterByWindow(records: NormalizedObservation[], window: TimeWindow, now = Date.now()): NormalizedObservation[] {
  const cutoff = now - WINDOW_MS[window];
  return records.filter((record) => new Date(record.observedAt).getTime() >= cutoff);
}

export function correlate(records: NormalizedObservation[]): Correlation[] {
  const grouped = new Map<string, NormalizedObservation[]>();
  for (const record of filterCrossSourceCorrelationRecords(records)) {
    if (!record.indicator) continue;
    const key = record.indicator.toLowerCase();
    grouped.set(key, [...(grouped.get(key) ?? []), record]);
  }
  return [...grouped.entries()].filter(([, items]) => new Set(items.map((item) => item.source)).size > 1).map(([indicator, items]) => ({ indicator, observationIds: items.map((item) => item.id), sources: [...new Set(items.map((item) => item.source))] }));
}

export function filterCrossSourceCorrelationRecords(records: NormalizedObservation[]): NormalizedObservation[] {
  const sourceSets = new Map<string, Set<string>>();
  for (const record of records) {
    if (!record.indicator) continue;
    const key = record.indicator.toLowerCase();
    const sources = sourceSets.get(key) ?? new Set<string>();
    sources.add(record.source);
    sourceSets.set(key, sources);
  }
  return records.filter((record) => record.indicator && (sourceSets.get(record.indicator.toLowerCase())?.size ?? 0) > 1);
}

export function formatCorrelationCount(count: number, truncated: boolean): string {
  return truncated ? `≥${count} · QUERY BOUNDED` : String(count);
}

export function matchesSearch(record: NormalizedObservation, query: string): boolean {
  const needle = query.toLowerCase();
  return [record.indicator, record.title, record.malwareFamily, record.threatType, ...record.tags, ...Object.values(record.metadata)].some((value) => String(value ?? "").toLowerCase().includes(needle));
}

export function buildAnalytics(records: NormalizedObservation[]): ObservatoryAnalytics {
  return {
    bySource: countBy(records.map((record) => record.source)),
    byKind: countBy(records.map((record) => record.kind)),
    topMalwareFamilies: countBy(records.map((record) => record.malwareFamily).filter((value): value is string => Boolean(value))).slice(0, 8),
    overTime: countBy(records.map((record) => record.observedAt.slice(0, 13) + ":00Z")).sort((left, right) => left.label.localeCompare(right.label)),
  };
}

function countBy(values: string[]): Array<{ label: string; count: number }> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts].map(([label, count]) => ({ label, count })).sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}
