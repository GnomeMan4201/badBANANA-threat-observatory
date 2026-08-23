import type { ThreatSourceAdapter } from "../source-adapter";
import type { IngestionHealth, KevCatalogPayload, NormalizedObservation, ObservationScope, ObservatoryPayload, SearchPayload, SourceHealth, SourceIngestCycle, SourceSnapshot, TimeWindow } from "../threat-types";
import type { PageCursor } from "../request-validation";
import { correlate } from "../analysis";
import { nextRetryAt, selectLeaseBackend, sourceEligibility, statusDuringBackoff, summarizeFreshness } from "../history-core";
import { getCredential } from "./runtime-config";
import { readAllSourceCaches, readSourceCache, writeSourceCache } from "./cache";
import {
  acquireSourceLease,
  backfillSnapshotIfIncomplete,
  queryHistory,
  queryCorrelationRecords,
  queryGeoCandidateRecords,
  queryKevCatalog,
  readIngestionHealth,
  recordFetchAttempt,
  recordSourceCycle,
  releaseSourceLease,
  searchHistory,
  upsertObservationHistory,
  writeIngestionHealth,
} from "./history";
import { sourceAdapterById, sourceAdapters } from "./adapters";
import { UpstreamHttpError } from "./fetch-error";

interface SourceRunResult {
  snapshot: SourceSnapshot;
  outcome: "disabled" | "fresh-cache" | "backoff" | "lease-held" | "fetched" | "failure";
  leaseBackend?: "d1" | "isolate-memory";
}

export async function readObservatory(window: TimeWindow, limit = 100, cursor?: PageCursor | null, scope: ObservationScope = "all"): Promise<ObservatoryPayload> {
  const caches = await readAllSourceCaches(sourceAdapters.map((adapter) => adapter.id));
  const bySource = new Map(caches.map((snapshot) => [snapshot.health.id, snapshot]));
  const settled = sourceAdapters.map((adapter) => readSnapshot(adapter, bySource.get(adapter.id)));
  const fallbackRecords = settled.flatMap((snapshot) => snapshot.records);
  const [history, ingestion, correlationRecords] = await Promise.all([
    queryHistory(window, limit, fallbackRecords, cursor, { scope }),
    readIngestionHealth(sourceAdapters.length),
    queryCorrelationRecords(window, fallbackRecords),
  ]);
  const sources = settled.map((snapshot) => ({ ...snapshot.health, historyRecordCount: history.sourceCounts[snapshot.health.id] ?? 0 }));
  const generatedAt = new Date().toISOString();
  return {
    records: history.records,
    recentEvents: history.recentEvents,
    sources,
    correlations: correlate(correlationRecords.records),
    correlationCoverage: { scope: "window-current-state", truncated: correlationRecords.truncated },
    analytics: history.analytics,
    history: history.health,
    freshness: summarizeFreshness(sources, generatedAt),
    ingestion,
    pagination: history.pagination,
    window,
    generatedAt,
  };
}

export async function searchLocalObservatory(query: string, window: TimeWindow, limit = 100, cursor?: PageCursor | null, scope: ObservationScope = "all"): Promise<SearchPayload> {
  const snapshots = await readAllSourceCaches(sourceAdapters.map((adapter) => adapter.id));
  const history = await searchHistory(query, window, limit, snapshots.flatMap((snapshot) => snapshot.records), cursor, { scope });
  return { records: history.records, query, sources: [...new Set(history.records.map((record) => record.source))], window, history: history.health, pagination: history.pagination };
}

export async function readGeoCandidates(window: TimeWindow): Promise<{ records: NormalizedObservation[]; total: number; truncated: boolean }> {
  const snapshots = await readAllSourceCaches(sourceAdapters.map((adapter) => adapter.id));
  return queryGeoCandidateRecords(window, snapshots.flatMap((snapshot) => snapshot.records));
}

export async function readCurrentKevCatalog(limit: number, query: Parameters<typeof queryKevCatalog>[1]): Promise<KevCatalogPayload> {
  const raw = await readSourceCache("cisa-kev");
  const adapter = sourceAdapterById("cisa-kev");
  const snapshot = raw && adapter ? enrichSnapshot(adapter, raw) : undefined;
  return queryKevCatalog(limit, query, snapshot);
}

export async function runIngestionCycle(): Promise<IngestionHealth> {
  const startedAt = new Date().toISOString();
  const currentHealth = await readIngestionHealth(sourceAdapters.length);
  const plans = await Promise.all(sourceAdapters.map(async (adapter) => {
    const credential = adapter.credentialKey ? getCredential(adapter.credentialKey) : undefined;
    const configured = !adapter.credentialKey || Boolean(credential);
    const raw = await readSourceCache(adapter.id);
    const cached = raw ? enrichSnapshot(adapter, raw) : undefined;
    return { adapter, credential, cached, eligibility: sourceEligibility(cached, configured) };
  }));
  const sourcesEligible = plans.filter((plan) => plan.eligibility === "eligible").length;
  const attempts = await Promise.allSettled(plans.map((plan) => runSourceIngestion(plan.adapter, plan.cached, plan.credential)));
  const results = attempts.map((attempt, index): SourceRunResult => attempt.status === "fulfilled"
    ? attempt.value
    : { snapshot: internalFailureSnapshot(plans[index].adapter, attempt.reason), outcome: "failure" });
  const completedAt = new Date().toISOString();
  const failed = results.some((result) => result.outcome === "failure");
  const leaseBackend = selectLeaseBackend(results.map((result) => result.leaseBackend), currentHealth.leaseBackend);
  const health: IngestionHealth = {
    mode: "demand-driven",
    status: failed || leaseBackend === "isolate-memory" ? "degraded" : "healthy",
    schedulerSupported: false,
    lastCycleStarted: startedAt,
    lastCycleCompleted: completedAt,
    lastSuccessfulCycle: failed ? currentHealth.lastSuccessfulCycle : completedAt,
    sourcesEligible,
    totalSources: sourceAdapters.length,
    leaseBackend,
    reason: "Sites exposes no scheduled-trigger configuration; explicit maintenance requests run eligible source collection",
    latestSourceCycles: [],
  };
  await writeIngestionHealth(health);
  return readIngestionHealth(sourceAdapters.length);
}

async function runSourceIngestion(adapter: ThreatSourceAdapter, plannedCache?: SourceSnapshot, credential?: string): Promise<SourceRunResult> {
  if (adapter.credentialKey && !credential) return { snapshot: disabledSnapshot(adapter), outcome: "disabled" };
  const initialEligibility = sourceEligibility(plannedCache, true);
  if (initialEligibility === "fresh" && plannedCache) {
    await backfillSnapshotIfIncomplete(plannedCache);
    return { snapshot: plannedCache, outcome: "fresh-cache" };
  }
  if (initialEligibility === "backoff" && plannedCache) {
    const now = new Date().toISOString();
    const snapshot = { ...plannedCache, health: healthFromAdapter(adapter, { ...plannedCache.health, status: statusDuringBackoff(plannedCache.records.length), configured: true }) };
    await recordFetchAttempt({ source: adapter.id, attemptedAt: now, completedAt: now, status: "backoff", recordCount: plannedCache.records.length });
    return { snapshot, outcome: "backoff" };
  }

  const holder = crypto.randomUUID();
  const lease = await acquireSourceLease(adapter.id, holder);
  if (!lease.acquired) {
    const now = new Date().toISOString();
    const cycle = emptyCycle(adapter.id, now, "lease-held");
    await recordSourceCycle(cycle);
    return { snapshot: plannedCache ?? unavailableSnapshot(adapter), outcome: "lease-held", leaseBackend: lease.backend };
  }

  try {
    const raw = await readSourceCache(adapter.id);
    const cached = raw ? enrichSnapshot(adapter, raw) : undefined;
    const eligibility = sourceEligibility(cached, true);
    if (eligibility === "fresh" && cached) {
      await backfillSnapshotIfIncomplete(cached);
      return { snapshot: cached, outcome: "fresh-cache", leaseBackend: lease.backend };
    }
    if (eligibility === "backoff" && cached) return { snapshot: cached, outcome: "backoff", leaseBackend: lease.backend };
    return await fetchAndIngest(adapter, credential, cached, lease.backend);
  } finally {
    await releaseSourceLease(adapter.id, holder);
  }
}

async function fetchAndIngest(adapter: ThreatSourceAdapter, credential: string | undefined, cached: SourceSnapshot | undefined, leaseBackend: "d1" | "isolate-memory"): Promise<SourceRunResult> {
  const lastAttempt = new Date().toISOString();
  const startedAt = Date.now();
  try {
    const result = await adapter.fetchRecent(credential);
    const fetchedAt = new Date().toISOString();
    const historyWrite = await upsertObservationHistory(result.records, fetchedAt, { fullCurrentSource: adapter.coverageMode === "full-current" ? adapter.id : undefined });
    const snapshot: SourceSnapshot = {
      records: historyWrite.records,
      fetchedAt,
      expiresAt: new Date(Date.now() + adapter.cacheTtlMs).toISOString(),
      health: healthFromAdapter(adapter, {
        status: "healthy", configured: true, lastAttempt, lastSuccess: fetchedAt, fetchedAt,
        recordCount: result.records.length, latencyMs: Date.now() - startedAt,
        upstreamDataDate: result.upstreamDataDate, consecutiveFailures: 0,
      }),
    };
    await writeSourceCache(adapter.id, snapshot);
    const completedAt = new Date().toISOString();
    const cycle: SourceIngestCycle = {
      source: adapter.id, startedAt: lastAttempt, completedAt, status: "success",
      upstreamRecords: result.upstreamRecords, validRecords: result.records.length, rejectedRecords: result.rejectedRecords,
      newRecords: historyWrite.newRecords, updatedRecords: historyWrite.updatedRecords,
      unchangedRecords: historyWrite.unchangedRecords, removedRecords: historyWrite.removedRecords,
      latencyMs: Date.now() - startedAt,
      validationDiagnostics: result.validationDiagnostics,
    };
    await Promise.all([
      recordFetchAttempt({ source: adapter.id, attemptedAt: lastAttempt, completedAt, status: "success", latencyMs: cycle.latencyMs, recordCount: result.records.length }),
      recordSourceCycle(cycle),
    ]);
    return { snapshot, outcome: "fetched", leaseBackend };
  } catch (error) {
    const completedAt = new Date().toISOString();
    const failures = (cached?.health.consecutiveFailures ?? 0) + 1;
    const retryAt = nextRetryAt(failures, lastAttempt, error instanceof UpstreamHttpError ? error.retryAfterMs : undefined);
    const message = safeError(error);
    const failed: SourceSnapshot = cached?.records.length ? {
      ...cached,
      health: healthFromAdapter(adapter, { ...cached.health, status: "stale", configured: true, lastAttempt, latencyMs: Date.now() - startedAt, consecutiveFailures: failures, nextRetryAt: retryAt, error: message }),
    } : {
      records: [], fetchedAt: cached?.fetchedAt ?? lastAttempt, expiresAt: cached?.expiresAt ?? lastAttempt,
      health: healthFromAdapter(adapter, { ...cached?.health, status: "offline", configured: true, lastAttempt, recordCount: 0, latencyMs: Date.now() - startedAt, consecutiveFailures: failures, nextRetryAt: retryAt, error: message }),
    };
    const cycle: SourceIngestCycle = { ...emptyCycle(adapter.id, lastAttempt, "failure"), completedAt, latencyMs: Date.now() - startedAt };
    await Promise.all([
      writeSourceCache(adapter.id, failed),
      recordFetchAttempt({ source: adapter.id, attemptedAt: lastAttempt, completedAt, status: "failure", latencyMs: cycle.latencyMs, recordCount: 0, errorClass: errorClass(error) }),
      recordSourceCycle(cycle),
    ]);
    return { snapshot: failed, outcome: "failure", leaseBackend };
  }
}

function readSnapshot(adapter: ThreatSourceAdapter, cached?: SourceSnapshot): SourceSnapshot {
  if (adapter.credentialKey && !getCredential(adapter.credentialKey)) return disabledSnapshot(adapter);
  return cached ? enrichSnapshot(adapter, cached) : unavailableSnapshot(adapter);
}

function enrichSnapshot(adapter: ThreatSourceAdapter, snapshot: SourceSnapshot): SourceSnapshot {
  return { ...snapshot, health: healthFromAdapter(adapter, snapshot.health) };
}

function disabledSnapshot(adapter: ThreatSourceAdapter): SourceSnapshot {
  const now = new Date().toISOString();
  return { records: [], fetchedAt: now, expiresAt: now, health: healthFromAdapter(adapter, { status: "disabled", configured: false, recordCount: 0, consecutiveFailures: 0, reason: "Credential not configured" }) };
}

function unavailableSnapshot(adapter: ThreatSourceAdapter): SourceSnapshot {
  const now = new Date().toISOString();
  return { records: [], fetchedAt: now, expiresAt: now, health: healthFromAdapter(adapter, { status: "offline", configured: true, recordCount: 0, consecutiveFailures: 0, reason: "No validated source snapshot has been collected" }) };
}

function internalFailureSnapshot(adapter: ThreatSourceAdapter, error: unknown): SourceSnapshot {
  const now = new Date().toISOString();
  return { records: [], fetchedAt: now, expiresAt: now, health: healthFromAdapter(adapter, { status: "offline", configured: !adapter.credentialKey || Boolean(getCredential(adapter.credentialKey)), lastAttempt: now, recordCount: 0, consecutiveFailures: 1, nextRetryAt: nextRetryAt(1, now), error: safeError(error) }) };
}

function healthFromAdapter(adapter: ThreatSourceAdapter, health: Partial<SourceHealth> & Pick<SourceHealth, "status" | "configured" | "recordCount">): SourceHealth {
  return {
    id: adapter.id, name: adapter.name, authMode: adapter.authMode, refreshPolicy: adapter.refreshPolicy,
    upstreamUrl: adapter.upstreamUrl, dataUsed: adapter.dataUsed, coverage: adapter.coverage,
    coverageMode: adapter.coverageMode, ...health,
  };
}

function emptyCycle(source: string, startedAt: string, status: SourceIngestCycle["status"]): SourceIngestCycle {
  return { source, startedAt, completedAt: startedAt, status, upstreamRecords: 0, validRecords: 0, rejectedRecords: 0, newRecords: 0, updatedRecords: 0, unchangedRecords: 0, removedRecords: 0, latencyMs: 0 };
}

function safeError(error: unknown): string {
  if (error instanceof DOMException && error.name === "AbortError") return "Upstream timeout";
  return error instanceof Error ? error.message.slice(0, 160) : "Source request failed";
}

function errorClass(error: unknown): string {
  if (error instanceof DOMException && error.name === "AbortError") return "timeout";
  if (error instanceof UpstreamHttpError) return "upstream-http";
  return error instanceof Error ? error.name.slice(0, 80) : "unknown";
}
