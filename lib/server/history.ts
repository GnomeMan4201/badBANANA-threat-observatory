import { buildAnalytics, filterByWindow, filterCrossSourceCorrelationRecords, matchesSearch, windowStart } from "../analysis";
import { acquireInMemoryLease, createObservationEvent, filterKevCatalogRecords, inactiveCisaCutoff, ingestionHealthWithCycles, pruneMemoryEvents, pruneMemoryHistory, RETENTION_DAYS, RETENTION_MS, snapshotOnlyHealth, upsertMemoryLedger } from "../history-core";
import { validateNormalizedObservation } from "../normalize";
import { encodeCursor, type PageCursor } from "../request-validation";
import type {
  EventPayload,
  EventLedgerBounds,
  HistoryHealth,
  IngestionHealth,
  KevCatalogPayload,
  NormalizedObservation,
  ObservationEvent,
  ObservationKind,
  ObservationScope,
  ObservatoryAnalytics,
  PaginationInfo,
  RevisionPayload,
  SourceIngestCycle,
  SourceSnapshot,
  TimeWindow,
} from "../threat-types";
import { getDatabase } from "./runtime-config";
import type { RejectionReason, ValidationDiagnostic } from "../rejection-diagnostics";
import { createObservationsTable, currentStateSchemaStatements, eventLedgerSchemaStatements, observationColumnAdditions, operationColumnAdditions, operationsSchemaStatements } from "../../db/schema";

const memoryHistory = new Map<string, NormalizedObservation>();
let memoryEvents: ObservationEvent[] = [];
const memoryCycles: SourceIngestCycle[] = [];
const memoryLeases = new Map<string, { holder: string; expiresAt: number }>();
let memoryIngestion: IngestionHealth | undefined;
let schemaReady: Promise<void> | undefined;
let lastPruneAt = 0;
const CYCLE_RETENTION_MS = 2 * 24 * 60 * 60_000;

interface HistoryResult {
  records: NormalizedObservation[];
  health: HistoryHealth;
  pagination: PaginationInfo;
}

export interface HistoryWriteResult {
  records: NormalizedObservation[];
  events: ObservationEvent[];
  health: HistoryHealth;
  newRecords: number;
  updatedRecords: number;
  unchangedRecords: number;
  removedRecords: number;
}

export interface HistoryCollection extends HistoryResult {
  analytics: ObservatoryAnalytics;
  recentEvents: ObservationEvent[];
  sourceCounts: Record<string, number>;
}

export interface KevCatalogQuery {
  query?: string;
  vendor?: string;
  product?: string;
  ransomwareOnly?: boolean;
  addedSince?: string;
  cursor?: PageCursor | null;
}

export interface ObservationQueryScope {
  scope?: ObservationScope;
}

export async function upsertObservationHistory(
  records: NormalizedObservation[],
  ingestedAt: string,
  options: { fullCurrentSource?: string; recordEvents?: boolean } = {},
): Promise<HistoryWriteResult> {
  const database = getDatabase();
  if (!database) return upsertMemoryFallback(records, ingestedAt, "D1 unavailable; current isolate snapshots only");
  try {
    await ensureSchema(database);
    const existing = await loadExisting(database, records.map((record) => record.id));
    const ledger = await upsertMemoryLedger(existing, records, ingestedAt);
    for (const chunk of chunks(ledger.records, 35)) {
      await database.batch(chunk.map((record) => database.prepare(`
        INSERT INTO observations (
          id, source, source_record_id, kind, indicator, indicator_type, malware_family, observed_at,
          first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at,
          revision_count, record_hash, ingest_state, is_current, search_text, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          source_record_id = excluded.source_record_id,
          kind = excluded.kind,
          indicator = excluded.indicator,
          indicator_type = excluded.indicator_type,
          malware_family = excluded.malware_family,
          observed_at = excluded.observed_at,
          last_ingested_at = excluded.last_ingested_at,
          last_observed_snapshot_at = excluded.last_observed_snapshot_at,
          last_changed_at = excluded.last_changed_at,
          revision_count = excluded.revision_count,
          record_hash = excluded.record_hash,
          ingest_state = excluded.ingest_state,
          is_current = 1,
          search_text = excluded.search_text,
          payload_json = excluded.payload_json
      `).bind(
        record.id, record.source, record.sourceRecordId ?? null, record.kind, record.indicator ?? null,
        record.indicatorType ?? null, record.malwareFamily ?? null, record.observedAt, record.firstIngestedAt, record.lastIngestedAt,
        record.lastChangedAt, record.lastObservedInSnapshotAt, record.revisionCount ?? 1, record.recordHash, record.ingestState,
        searchText(record), JSON.stringify(record),
      )));
    }

    if (options.recordEvents !== false) await insertObservationEvents(database, ledger.events);
    const removedEvents = options.fullCurrentSource
      ? await markDefensibleRemovals(database, options.fullCurrentSource, new Set(records.map((record) => record.id)), ingestedAt, options.recordEvents !== false)
      : [];
    await opportunisticPrune(database, Date.now());
    return {
      ...ledger,
      events: options.recordEvents === false ? [] : [...ledger.events, ...removedEvents],
      removedRecords: removedEvents.length,
      health: await persistentHealth(database, ingestedAt),
    };
  } catch {
    return upsertMemoryFallback(records, ingestedAt, "Persistent current-state write failed; current snapshots remain available");
  }
}

export async function backfillSnapshotIfIncomplete(snapshot: SourceSnapshot): Promise<void> {
  const database = getDatabase();
  if (!database || !snapshot.records.length) return;
  try {
    await ensureSchema(database);
    const row = await database.prepare("SELECT COUNT(*) AS count FROM observations WHERE source = ? AND is_current = 1").bind(snapshot.health.id).first<{ count: number }>();
    if (Number(row?.count ?? 0) < snapshot.records.length) {
      await upsertObservationHistory(snapshot.records, snapshot.fetchedAt, { fullCurrentSource: snapshot.health.coverageMode === "full-current" ? snapshot.health.id : undefined, recordEvents: false });
    }
  } catch {
    // Snapshot serving remains independent from current-state repair.
  }
}

export async function queryHistory(window: TimeWindow, limit: number, fallbackRecords: NormalizedObservation[], cursor?: PageCursor | null, query: ObservationQueryScope = {}): Promise<HistoryCollection> {
  const database = getDatabase();
  if (!database) return fallbackCollection(window, limit, fallbackRecords, "D1 unavailable; historical coverage may be incomplete", cursor, query);
  try {
    await ensureSchema(database);
    const bounded = Math.min(Math.max(limit, 1), 500);
    const scope = databaseScope(query.scope);
    const cursorClause = cursor ? "AND (observed_at < ? OR (observed_at = ? AND id > ?))" : "";
    const bindings: unknown[] = [windowStart(window)];
    bindings.push(...scope.bindings);
    if (cursor) bindings.push(cursor.sort, cursor.sort, cursor.id);
    bindings.push(bounded + 1);
    const rows = await database.prepare(`
      SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state
      FROM observations
      WHERE observed_at >= ? AND is_current = 1 ${scope.clause} ${cursorClause}
      ORDER BY observed_at DESC, id ASC LIMIT ?
    `).bind(...bindings).all<HistoryRow>();
    const page = pageValues(parseRows(rows.results ?? []), bounded, (record) => ({ sort: record.observedAt, id: record.id }));
    const [health, recentEvents, sourceCounts, analytics] = await Promise.all([
      persistentHealth(database),
      readObservationEventsFromDatabase(database, 30),
      readSourceCounts(database),
      readAnalytics(database, windowStart(window)),
    ]);
    return { records: page.values, health, recentEvents, sourceCounts, analytics, pagination: page.pagination };
  } catch {
    return fallbackCollection(window, limit, fallbackRecords, "Persistent current-state read failed; using source snapshots", cursor, query);
  }
}

export async function searchHistory(query: string, window: TimeWindow, limit: number, fallbackRecords: NormalizedObservation[], cursor?: PageCursor | null, scopeQuery: ObservationQueryScope = {}): Promise<HistoryResult> {
  const database = getDatabase();
  if (!database) return fallbackSearch(query, window, limit, fallbackRecords, "D1 unavailable; search is limited to current snapshots", cursor, scopeQuery);
  try {
    await ensureSchema(database);
    const bounded = Math.min(Math.max(limit, 1), 100);
    const needle = `%${escapeLike(query.toLowerCase())}%`;
    const scope = databaseScope(scopeQuery.scope);
    const cursorClause = cursor ? "AND (observed_at < ? OR (observed_at = ? AND id > ?))" : "";
    const bindings: unknown[] = [windowStart(window), needle];
    bindings.push(...scope.bindings);
    if (cursor) bindings.push(cursor.sort, cursor.sort, cursor.id);
    bindings.push(bounded + 1);
    const rows = await database.prepare(`
      SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state
      FROM observations
      WHERE observed_at >= ? AND is_current = 1 AND search_text LIKE ? ESCAPE '\\' ${scope.clause} ${cursorClause}
      ORDER BY observed_at DESC, id ASC LIMIT ?
    `).bind(...bindings).all<HistoryRow>();
    const page = pageValues(parseRows(rows.results ?? []), bounded, (record) => ({ sort: record.observedAt, id: record.id }));
    return { records: page.values, health: await persistentHealth(database), pagination: page.pagination };
  } catch {
    return fallbackSearch(query, window, limit, fallbackRecords, "Persistent current-state search failed; using source snapshots", cursor, scopeQuery);
  }
}

export async function queryKevCatalog(limit: number, query: KevCatalogQuery, fallback?: SourceSnapshot): Promise<KevCatalogPayload> {
  const database = getDatabase();
  if (!database) return fallbackKevCatalog(limit, query, fallback);
  try {
    await ensureSchema(database);
    const bounded = Math.min(Math.max(limit, 1), 100);
    const conditions = ["source = 'cisa-kev'", "is_current = 1"];
    const bindings: unknown[] = [];
    if (query.query) { conditions.push("search_text LIKE ? ESCAPE '\\'"); bindings.push(`%${escapeLike(query.query.toLowerCase())}%`); }
    if (query.vendor) { conditions.push("LOWER(COALESCE(json_extract(payload_json, '$.metadata.vendor'), '')) LIKE ? ESCAPE '\\'"); bindings.push(`%${escapeLike(query.vendor.toLowerCase())}%`); }
    if (query.product) { conditions.push("LOWER(COALESCE(json_extract(payload_json, '$.metadata.product'), '')) LIKE ? ESCAPE '\\'"); bindings.push(`%${escapeLike(query.product.toLowerCase())}%`); }
    if (query.ransomwareOnly) conditions.push("LOWER(COALESCE(json_extract(payload_json, '$.metadata.knownRansomwareCampaignUse'), '')) = 'known'");
    if (query.addedSince) { conditions.push("observed_at >= ?"); bindings.push(query.addedSince); }
    if (query.cursor) {
      conditions.push("(observed_at < ? OR (observed_at = ? AND id > ?))");
      bindings.push(query.cursor.sort, query.cursor.sort, query.cursor.id);
    }
    const where = conditions.join(" AND ");
    const rows = await database.prepare(`
      SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state
      FROM observations WHERE ${where}
      ORDER BY observed_at DESC, id ASC LIMIT ?
    `).bind(...bindings, bounded + 1).all<HistoryRow>();
    const countConditions = conditions.filter((condition) => !condition.startsWith("(observed_at <"));
    const countBindings = query.cursor ? bindings.slice(0, -3) : bindings;
    const totalRow = await database.prepare(`SELECT COUNT(*) AS count FROM observations WHERE ${countConditions.join(" AND ")}`).bind(...countBindings).first<{ count: number }>();
    const [vendors, products] = await Promise.all([
      database.prepare("SELECT DISTINCT json_extract(payload_json, '$.metadata.vendor') AS value FROM observations WHERE source = 'cisa-kev' AND is_current = 1 AND json_extract(payload_json, '$.metadata.vendor') IS NOT NULL ORDER BY value ASC LIMIT 500").all<{ value: string }>(),
      database.prepare("SELECT DISTINCT json_extract(payload_json, '$.metadata.product') AS value FROM observations WHERE source = 'cisa-kev' AND is_current = 1 AND json_extract(payload_json, '$.metadata.product') IS NOT NULL ORDER BY value ASC LIMIT 500").all<{ value: string }>(),
    ]);
    const page = pageValues(parseRows(rows.results ?? []), bounded, (record) => ({ sort: record.observedAt, id: record.id }));
    return {
      records: page.values,
      total: Number(totalRow?.count ?? 0),
      vendors: (vendors.results ?? []).map((row) => row.value).filter(Boolean),
      products: (products.results ?? []).map((row) => row.value).filter(Boolean),
      pagination: page.pagination,
      health: fallback?.health,
      generatedAt: new Date().toISOString(),
    };
  } catch {
    return fallbackKevCatalog(limit, query, fallback);
  }
}

export async function queryObservationEvents(limit: number, cursor?: PageCursor | null): Promise<EventPayload> {
  const database = getDatabase();
  if (!database) {
    const filtered = applyCursor(memoryEvents, cursor, (event) => ({ sort: event.detectedAt, id: event.eventId }));
    const page = pageValues(filtered, limit, (event) => ({ sort: event.detectedAt, id: event.eventId }));
    return { events: page.values, pagination: page.pagination, history: memoryHealth("D1 unavailable; event history is isolate-local"), ledger: memoryLedgerBounds() };
  }
  try {
    await ensureSchema(database);
    const bounded = Math.min(Math.max(limit, 1), 100);
    const cursorClause = cursor ? "WHERE detected_at < ? OR (detected_at = ? AND event_id > ?)" : "";
    const bindings: unknown[] = cursor ? [cursor.sort, cursor.sort, cursor.id, bounded + 1] : [bounded + 1];
    const rows = await database.prepare(`SELECT * FROM observation_events ${cursorClause} ORDER BY detected_at DESC, event_id ASC LIMIT ?`).bind(...bindings).all<EventRow>();
    const page = pageValues(parseEventRows(rows.results ?? []), bounded, (event) => ({ sort: event.detectedAt, id: event.eventId }));
    return { events: page.values, pagination: page.pagination, history: await persistentHealth(database), ledger: await readEventLedgerBounds(database) };
  } catch {
    return { events: [], pagination: { hasMore: false }, history: memoryHealth("Persistent event history unavailable"), ledger: memoryLedgerBounds() };
  }
}

export async function queryGeoCandidateRecords(window: TimeWindow, fallbackRecords: NormalizedObservation[], limit = 2_000): Promise<{ records: NormalizedObservation[]; total: number; truncated: boolean }> {
  const filteredFallback = filterByWindow(fallbackRecords.filter(validateNormalizedObservation), window).filter((record) => record.kind === "ipv4" || record.kind === "ipv6");
  const database = getDatabase();
  if (!database) return { records: filteredFallback.slice(0, limit), total: filteredFallback.length, truncated: filteredFallback.length > limit };
  try {
    await ensureSchema(database);
    const cutoff = windowStart(window);
    const [rows, count] = await Promise.all([
      database.prepare(`SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state FROM observations WHERE observed_at >= ? AND is_current = 1 AND kind IN ('ipv4','ipv6') ORDER BY observed_at DESC, id ASC LIMIT ?`).bind(cutoff, limit).all<HistoryRow>(),
      database.prepare(`SELECT COUNT(*) AS count FROM observations WHERE observed_at >= ? AND is_current = 1 AND kind IN ('ipv4','ipv6')`).bind(cutoff).first<{ count: number }>(),
    ]);
    const total = Number(count?.count ?? 0);
    return { records: parseRows(rows.results ?? []), total, truncated: total > limit };
  } catch {
    return { records: filteredFallback.slice(0, limit), total: filteredFallback.length, truncated: filteredFallback.length > limit };
  }
}

export async function queryCorrelationRecords(window: TimeWindow, fallbackRecords: NormalizedObservation[], limit = 2_000): Promise<{ records: NormalizedObservation[]; truncated: boolean }> {
  const eligibleFallback = filterByWindow(fallbackRecords.filter(validateNormalizedObservation), window).filter((record) => Boolean(record.indicator));
  const correlatedFallback = filterCrossSourceCorrelationRecords(eligibleFallback);
  const database = getDatabase();
  if (!database) return { records: correlatedFallback.slice(0, limit), truncated: correlatedFallback.length > limit };
  try {
    await ensureSchema(database);
    const rows = await database.prepare(`
      SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state
      FROM observations
      WHERE observed_at >= ? AND is_current = 1 AND indicator IS NOT NULL
        AND LOWER(indicator) IN (
          SELECT LOWER(indicator) FROM observations
          WHERE observed_at >= ? AND is_current = 1 AND indicator IS NOT NULL
          GROUP BY LOWER(indicator) HAVING COUNT(DISTINCT source) > 1
        )
      ORDER BY observed_at DESC, id ASC LIMIT ?
    `).bind(windowStart(window), windowStart(window), limit + 1).all<HistoryRow>();
    const parsed = parseRows(rows.results ?? []);
    return { records: parsed.slice(0, limit), truncated: parsed.length > limit };
  } catch {
    return { records: correlatedFallback.slice(0, limit), truncated: correlatedFallback.length > limit };
  }
}

export async function queryObservationPeers(observationId: string, limit = 100): Promise<NormalizedObservation[]> {
  const database = getDatabase();
  if (!database) {
    const target = memoryHistory.get(observationId);
    if (!target?.indicator) return [];
    return [...memoryHistory.values()].filter((record) => record.id !== target.id && record.source !== target.source && record.indicator?.toLowerCase() === target.indicator?.toLowerCase()).slice(0, limit);
  }
  try {
    await ensureSchema(database);
    const rows = await database.prepare(`
      SELECT peer.payload_json, peer.first_ingested_at, peer.last_ingested_at, peer.last_changed_at, peer.last_observed_snapshot_at, peer.revision_count, peer.record_hash, peer.ingest_state
      FROM observations AS target
      JOIN observations AS peer ON LOWER(peer.indicator) = LOWER(target.indicator)
      WHERE target.id = ? AND target.is_current = 1 AND peer.is_current = 1 AND peer.id <> target.id AND peer.source <> target.source
      ORDER BY peer.observed_at DESC, peer.id ASC LIMIT ?
    `).bind(observationId, Math.min(Math.max(limit, 1), 100)).all<HistoryRow>();
    return parseRows(rows.results ?? []);
  } catch { return []; }
}

export async function queryObservationRevisions(observationId: string, limit: number, cursor?: PageCursor | null): Promise<RevisionPayload> {
  const database = getDatabase();
  if (!database) {
    const observation = memoryHistory.get(observationId);
    const filtered = memoryEvents.filter((event) => event.observationId === observationId);
    const page = pageValues(applyCursor(filtered, cursor, (event) => ({ sort: event.detectedAt, id: event.eventId })), limit, (event) => ({ sort: event.detectedAt, id: event.eventId }));
    return { observation, events: page.values, pagination: page.pagination, history: memoryHealth("D1 unavailable; revisions are isolate-local") };
  }
  try {
    await ensureSchema(database);
    const bounded = Math.min(Math.max(limit, 1), 100);
    const currentRow = await database.prepare("SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state FROM observations WHERE id = ? AND is_current = 1").bind(observationId).first<HistoryRow>();
    const cursorClause = cursor ? "AND (detected_at < ? OR (detected_at = ? AND event_id > ?))" : "";
    const bindings: unknown[] = [observationId];
    if (cursor) bindings.push(cursor.sort, cursor.sort, cursor.id);
    bindings.push(bounded + 1);
    const rows = await database.prepare(`SELECT * FROM observation_events WHERE observation_id = ? ${cursorClause} ORDER BY detected_at DESC, event_id ASC LIMIT ?`).bind(...bindings).all<EventRow>();
    const page = pageValues(parseEventRows(rows.results ?? []), bounded, (event) => ({ sort: event.detectedAt, id: event.eventId }));
    return { observation: currentRow ? parseRows([currentRow])[0] : undefined, events: page.values, pagination: page.pagination, history: await persistentHealth(database) };
  } catch {
    return { events: [], pagination: { hasMore: false }, history: memoryHealth("Persistent revision history unavailable") };
  }
}

export async function acquireSourceLease(source: string, holder: string, now = Date.now(), ttlMs = 2 * 60_000): Promise<{ acquired: boolean; backend: "d1" | "isolate-memory" }> {
  const database = getDatabase();
  if (!database) return acquireMemoryLease(source, holder, now, ttlMs);
  try {
    await ensureSchema(database);
    const expiresAt = new Date(now + ttlMs).toISOString();
    const nowIso = new Date(now).toISOString();
    await database.prepare(`
      INSERT INTO source_refresh_lease (source, holder, expires_at) VALUES (?, ?, ?)
      ON CONFLICT(source) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
      WHERE source_refresh_lease.expires_at <= ?
    `).bind(source, holder, expiresAt, nowIso).run();
    const row = await database.prepare("SELECT holder FROM source_refresh_lease WHERE source = ?").bind(source).first<{ holder: string }>();
    return { acquired: row?.holder === holder, backend: "d1" };
  } catch {
    return acquireMemoryLease(source, holder, now, ttlMs);
  }
}

export async function releaseSourceLease(source: string, holder: string): Promise<void> {
  const database = getDatabase();
  if (!database) { if (memoryLeases.get(source)?.holder === holder) memoryLeases.delete(source); return; }
  try {
    await ensureSchema(database);
    await database.prepare("DELETE FROM source_refresh_lease WHERE source = ? AND holder = ?").bind(source, holder).run();
  } catch {
    if (memoryLeases.get(source)?.holder === holder) memoryLeases.delete(source);
  }
}

export async function recordSourceCycle(cycle: SourceIngestCycle): Promise<void> {
  memoryCycles.unshift(cycle);
  memoryCycles.splice(200);
  const database = getDatabase();
  if (!database) return;
  try {
    await ensureSchema(database);
    await database.prepare(`
      INSERT INTO source_ingest_cycles (
        source, started_at, completed_at, status, upstream_records, valid_records, rejected_records,
        new_records, updated_records, unchanged_records, removed_records, latency_ms, validation_diagnostics_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(cycle.source, cycle.startedAt, cycle.completedAt, cycle.status, cycle.upstreamRecords, cycle.validRecords, cycle.rejectedRecords, cycle.newRecords, cycle.updatedRecords, cycle.unchangedRecords, cycle.removedRecords, cycle.latencyMs, JSON.stringify(cycle.validationDiagnostics ?? [])).run();
    await pruneOperationalRows(database);
  } catch {
    // Cycle telemetry never blocks ingestion.
  }
}

export async function writeIngestionHealth(health: IngestionHealth): Promise<void> {
  memoryIngestion = health;
  const database = getDatabase();
  if (!database) return;
  try {
    await ensureSchema(database);
    await database.prepare("INSERT INTO ingestion_runtime (id, payload_json, updated_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json, updated_at = excluded.updated_at").bind(JSON.stringify(health), new Date().toISOString()).run();
  } catch {
    // Runtime status remains available in the current isolate.
  }
}

export async function readIngestionHealth(totalSources: number): Promise<IngestionHealth> {
  const database = getDatabase();
  const fallback = memoryIngestion ?? defaultIngestionHealth(totalSources, database ? "d1" : "isolate-memory");
  if (!database) return { ...fallback, latestSourceCycles: memoryCycles.slice(0, 8) };
  try {
    await ensureSchema(database);
    const row = await database.prepare("SELECT payload_json FROM ingestion_runtime WHERE id = 1").first<{ payload_json: string }>();
    const parsed = row?.payload_json ? JSON.parse(row.payload_json) as IngestionHealth : fallback;
    return ingestionHealthWithCycles(parsed, await readLatestSourceCycles(database));
  } catch {
    return { ...fallback, status: "degraded", reason: "Persistent ingestion health unavailable", latestSourceCycles: memoryCycles.slice(0, 8) };
  }
}

export async function recordFetchAttempt(input: {
  source: string;
  attemptedAt: string;
  completedAt: string;
  status: "success" | "failure" | "backoff";
  latencyMs?: number;
  recordCount?: number;
  errorClass?: string;
}): Promise<void> {
  const database = getDatabase();
  if (!database) return;
  try {
    await ensureSchema(database);
    await database.prepare(`
      INSERT INTO source_fetch_log (source, attempted_at, completed_at, status, latency_ms, record_count, error_class)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(input.source, input.attemptedAt, input.completedAt, input.status, input.latencyMs ?? null, input.recordCount ?? null, input.errorClass ?? null).run();
    await pruneOperationalRows(database);
  } catch {
    // Operational logging must never break source collection.
  }
}

async function ensureSchema(database: D1Database): Promise<void> {
  if (!schemaReady) schemaReady = initializeSchema(database).catch((error) => { schemaReady = undefined; throw error; });
  await schemaReady;
}

async function initializeSchema(database: D1Database): Promise<void> {
  await database.prepare(createObservationsTable).run();
  await ensureObservationColumns(database);
  const statements = [...currentStateSchemaStatements, ...eventLedgerSchemaStatements, ...operationsSchemaStatements].map((sql) => database.prepare(sql));
  await database.batch(statements);
  await ensureOperationColumns(database);
}

async function ensureOperationColumns(database: D1Database): Promise<void> {
  for (const [table, name, definition] of operationColumnAdditions) {
    const columns = await database.prepare(`PRAGMA table_info(${table})`).all<{ name: string }>();
    if (!(columns.results ?? []).some((column) => column.name === name)) await database.prepare(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`).run();
  }
}

async function ensureObservationColumns(database: D1Database): Promise<void> {
  const columns = await database.prepare("PRAGMA table_info(observations)").all<{ name: string }>();
  const names = new Set((columns.results ?? []).map((column) => column.name));
  for (const [name, definition] of observationColumnAdditions) {
    if (!names.has(name)) await database.prepare(`ALTER TABLE observations ADD COLUMN ${name} ${definition}`).run();
  }
}

async function loadExisting(database: D1Database, ids: string[]): Promise<Map<string, NormalizedObservation>> {
  const existing = new Map<string, NormalizedObservation>();
  for (const chunk of chunks(ids, 75)) {
    if (!chunk.length) continue;
    const placeholders = chunk.map(() => "?").join(",");
    const rows = await database.prepare(`SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state FROM observations WHERE id IN (${placeholders})`).bind(...chunk).all<HistoryRow>();
    for (const record of parseRows(rows.results ?? [])) existing.set(record.id, record);
  }
  return existing;
}

async function insertObservationEvents(database: D1Database, events: ObservationEvent[]): Promise<void> {
  for (const chunk of chunks(events, 25)) {
    await database.batch(chunk.map((event) => database.prepare(`
      INSERT OR IGNORE INTO observation_events (
        event_id, observation_id, source, source_record_id, event_type, detected_at,
        previous_hash, new_hash, previous_payload_json, new_payload_json, diff_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      event.eventId, event.observationId, event.source, event.sourceRecordId ?? null, event.eventType, event.detectedAt,
      event.previousHash ?? null, event.newHash ?? null, event.previous ? JSON.stringify(event.previous) : null,
      event.current ? JSON.stringify(event.current) : null, JSON.stringify(event.diff),
    )));
  }
}

async function markDefensibleRemovals(database: D1Database, source: string, incomingIds: Set<string>, detectedAt: string, recordEvents: boolean): Promise<ObservationEvent[]> {
  const rows = await database.prepare("SELECT payload_json, first_ingested_at, last_ingested_at, last_changed_at, last_observed_snapshot_at, revision_count, record_hash, ingest_state FROM observations WHERE source = ? AND is_current = 1").bind(source).all<HistoryRow>();
  const removed = parseRows(rows.results ?? []).filter((record) => !incomingIds.has(record.id));
  const events = removed.map((record) => createObservationEvent("removed", undefined, record, detectedAt));
  if (recordEvents) await insertObservationEvents(database, events);
  for (const chunk of chunks(removed, 50)) {
    await database.batch(chunk.map((record) => database.prepare("UPDATE observations SET is_current = 0, last_changed_at = ?, ingest_state = 'seen' WHERE id = ?").bind(detectedAt, record.id)));
  }
  return events;
}

async function persistentHealth(database: D1Database, lastWrite?: string): Promise<HistoryHealth> {
  const row = await database.prepare("SELECT COUNT(*) AS count, MIN(first_ingested_at) AS oldest, MAX(last_ingested_at) AS newest FROM observations WHERE is_current = 1").first<{ count: number; oldest: string | null; newest: string | null }>();
  return {
    mode: "persistent", status: "healthy", retentionDays: RETENTION_DAYS,
    observationsStored: Number(row?.count ?? 0), oldestObservation: row?.oldest ?? undefined,
    newestObservation: row?.newest ?? undefined, lastWrite: lastWrite ?? row?.newest ?? undefined,
    lastPrune: lastPruneAt ? new Date(lastPruneAt).toISOString() : undefined,
  };
}

async function readObservationEventsFromDatabase(database: D1Database, limit: number): Promise<ObservationEvent[]> {
  const rows = await database.prepare("SELECT * FROM observation_events ORDER BY detected_at DESC, event_id ASC LIMIT ?").bind(limit).all<EventRow>();
  return parseEventRows(rows.results ?? []);
}

async function readSourceCounts(database: D1Database): Promise<Record<string, number>> {
  const rows = await database.prepare("SELECT source, COUNT(*) AS count FROM observations WHERE is_current = 1 GROUP BY source").all<{ source: string; count: number }>();
  return Object.fromEntries((rows.results ?? []).map((row) => [row.source, Number(row.count)]));
}

async function readAnalytics(database: D1Database, observedCutoff: string): Promise<ObservatoryAnalytics> {
  const [sources, kinds, families, hours] = await Promise.all([
    database.prepare("SELECT source AS label, COUNT(*) AS count FROM observations WHERE observed_at >= ? AND is_current = 1 GROUP BY source ORDER BY count DESC, label ASC").bind(observedCutoff).all<CountRow>(),
    database.prepare("SELECT kind AS label, COUNT(*) AS count FROM observations WHERE observed_at >= ? AND is_current = 1 GROUP BY kind ORDER BY count DESC, label ASC").bind(observedCutoff).all<CountRow>(),
    database.prepare("SELECT malware_family AS label, COUNT(*) AS count FROM observations WHERE observed_at >= ? AND is_current = 1 AND malware_family IS NOT NULL GROUP BY malware_family ORDER BY count DESC, label ASC LIMIT 8").bind(observedCutoff).all<CountRow>(),
    database.prepare("SELECT substr(observed_at, 1, 13) || ':00Z' AS label, COUNT(*) AS count FROM observations WHERE observed_at >= ? AND is_current = 1 GROUP BY label ORDER BY label ASC").bind(observedCutoff).all<CountRow>(),
  ]);
  const map = (result: D1Result<CountRow>) => (result.results ?? []).map((row) => ({ label: row.label, count: Number(row.count) }));
  return { bySource: map(sources), byKind: map(kinds), topMalwareFamilies: map(families), overTime: map(hours) };
}

async function opportunisticPrune(database: D1Database, now: number): Promise<void> {
  if (now - lastPruneAt < 15 * 60_000) return;
  const eventCutoff = new Date(now - RETENTION_MS).toISOString();
  await database.batch([
    database.prepare("DELETE FROM observation_events WHERE detected_at < ?").bind(eventCutoff),
    database.prepare("DELETE FROM observations WHERE source <> 'cisa-kev' AND last_ingested_at < ?").bind(eventCutoff),
    database.prepare("DELETE FROM observations WHERE source = 'cisa-kev' AND is_current = 0 AND last_changed_at < ?").bind(inactiveCisaCutoff(now)),
    database.prepare("DELETE FROM source_refresh_lease WHERE expires_at < ?").bind(new Date(now).toISOString()),
  ]);
  await pruneOperationalRows(database, now);
  lastPruneAt = now;
}

async function pruneOperationalRows(database: D1Database, now = Date.now()): Promise<void> {
  const cutoff = new Date(now - CYCLE_RETENTION_MS).toISOString();
  await database.batch([
    database.prepare("DELETE FROM source_fetch_log WHERE attempted_at < ?").bind(cutoff),
    database.prepare("DELETE FROM source_ingest_cycles WHERE completed_at < ?").bind(cutoff),
  ]);
  for (const source of ["cisa-kev", "threatfox", "urlhaus", "malwarebazaar"]) {
    await database.batch([
      database.prepare("DELETE FROM source_fetch_log WHERE source = ? AND id NOT IN (SELECT id FROM source_fetch_log WHERE source = ? ORDER BY attempted_at DESC LIMIT 200)").bind(source, source),
      database.prepare("DELETE FROM source_ingest_cycles WHERE source = ? AND id NOT IN (SELECT id FROM source_ingest_cycles WHERE source = ? ORDER BY completed_at DESC LIMIT 200)").bind(source, source),
    ]);
  }
}

async function readLatestSourceCycles(database: D1Database): Promise<SourceIngestCycle[]> {
  const rows = await database.prepare("SELECT id, source, started_at, completed_at, status, upstream_records, valid_records, rejected_records, new_records, updated_records, unchanged_records, removed_records, latency_ms, validation_diagnostics_json FROM source_ingest_cycles ORDER BY completed_at DESC, id DESC LIMIT 8").all<CycleRow>();
  return (rows.results ?? []).map((row) => ({
    id: Number(row.id), source: row.source, startedAt: row.started_at, completedAt: row.completed_at,
    status: normalizeCycleStatus(row.status), upstreamRecords: Number(row.upstream_records), validRecords: Number(row.valid_records),
    rejectedRecords: Number(row.rejected_records), newRecords: Number(row.new_records), updatedRecords: Number(row.updated_records),
    unchangedRecords: Number(row.unchanged_records), removedRecords: Number(row.removed_records), latencyMs: Number(row.latency_ms),
    validationDiagnostics: parseDiagnostics(row.validation_diagnostics_json),
  }));
}

function parseRows(rows: HistoryRow[]): NormalizedObservation[] {
  const records: NormalizedObservation[] = [];
  for (const row of rows) {
    try {
      const parsed = JSON.parse(row.payload_json) as NormalizedObservation;
      const enriched = {
        ...parsed, firstIngestedAt: row.first_ingested_at, lastIngestedAt: row.last_ingested_at,
        lastChangedAt: row.last_changed_at ?? row.first_ingested_at,
        lastObservedInSnapshotAt: row.last_observed_snapshot_at ?? row.last_ingested_at,
        revisionCount: Number(row.revision_count ?? 1), recordHash: row.record_hash,
        ingestState: normalizeIngestState(row.ingest_state),
      };
      if (validateNormalizedObservation(enriched)) records.push(enriched);
    } catch {
      // Corrupted rows fail closed.
    }
  }
  return records;
}

function parseEventRows(rows: EventRow[]): ObservationEvent[] {
  const events: ObservationEvent[] = [];
  for (const row of rows) {
    try {
      const previous = row.previous_payload_json ? JSON.parse(row.previous_payload_json) as NormalizedObservation : undefined;
      const current = row.new_payload_json ? JSON.parse(row.new_payload_json) as NormalizedObservation : undefined;
      if (previous && !validateNormalizedObservation(previous)) continue;
      if (current && !validateNormalizedObservation(current)) continue;
      events.push({
        eventId: row.event_id, observationId: row.observation_id, source: row.source,
        sourceRecordId: row.source_record_id ?? undefined, eventType: normalizeEventType(row.event_type), detectedAt: row.detected_at,
        previousHash: row.previous_hash ?? undefined, newHash: row.new_hash ?? undefined,
        previous, current, diff: JSON.parse(row.diff_json),
      });
    } catch {
      // Corrupted event evidence fails closed.
    }
  }
  return events;
}

function fallbackCollection(window: TimeWindow, limit: number, fallbackRecords: NormalizedObservation[], reason: string, cursor?: PageCursor | null, query: ObservationQueryScope = {}): HistoryCollection {
  const filtered = filterByWindow(fallbackRecords.filter(validateNormalizedObservation), window).filter((record) => recordMatchesScope(record, query.scope)).sort((a, b) => b.observedAt.localeCompare(a.observedAt) || a.id.localeCompare(b.id));
  const page = pageValues(applyCursor(filtered, cursor, (record) => ({ sort: record.observedAt, id: record.id })), limit, (record) => ({ sort: record.observedAt, id: record.id }));
  memoryEvents = pruneMemoryEvents(memoryEvents);
  return { records: page.values, recentEvents: memoryEvents.slice(0, 30), sourceCounts: countSources(fallbackRecords), analytics: buildAnalytics(page.values), health: memoryHealth(reason), pagination: page.pagination };
}

function fallbackSearch(query: string, window: TimeWindow, limit: number, fallbackRecords: NormalizedObservation[], reason: string, cursor?: PageCursor | null, scopeQuery: ObservationQueryScope = {}): HistoryResult {
  const filtered = filterByWindow(fallbackRecords.filter(validateNormalizedObservation), window).filter((record) => recordMatchesScope(record, scopeQuery.scope) && matchesSearch(record, query)).sort((a, b) => b.observedAt.localeCompare(a.observedAt) || a.id.localeCompare(b.id));
  const page = pageValues(applyCursor(filtered, cursor, (record) => ({ sort: record.observedAt, id: record.id })), limit, (record) => ({ sort: record.observedAt, id: record.id }));
  return { records: page.values, health: memoryHealth(reason), pagination: page.pagination };
}

function fallbackKevCatalog(limit: number, query: KevCatalogQuery, fallback?: SourceSnapshot): KevCatalogPayload {
  const records = filterKevCatalogRecords(fallback?.records ?? [], query);
  records.sort((a, b) => b.observedAt.localeCompare(a.observedAt) || a.id.localeCompare(b.id));
  const total = records.length;
  const page = pageValues(applyCursor(records, query.cursor, (record) => ({ sort: record.observedAt, id: record.id })), limit, (record) => ({ sort: record.observedAt, id: record.id }));
  return {
    records: page.values, total, vendors: uniqueMetadata(fallback?.records ?? [], "vendor"),
    products: uniqueMetadata(fallback?.records ?? [], "product"), pagination: page.pagination,
    health: fallback?.health, generatedAt: new Date().toISOString(),
  };
}

async function upsertMemoryFallback(records: NormalizedObservation[], ingestedAt: string, reason: string): Promise<HistoryWriteResult> {
  const ledger = await upsertMemoryLedger(memoryHistory, records, ingestedAt);
  memoryEvents = pruneMemoryEvents([...ledger.events, ...memoryEvents]);
  pruneMemoryHistory(memoryHistory);
  return { ...ledger, removedRecords: 0, health: memoryHealth(reason, ingestedAt) };
}

function memoryHealth(reason: string, lastWrite?: string): HistoryHealth { return snapshotOnlyHealth([...memoryHistory.values()], reason, lastWrite); }
function searchText(record: NormalizedObservation): string { return [record.indicator, record.title, record.malwareFamily, record.threatType, ...record.tags, ...Object.values(record.metadata)].map((value) => String(value ?? "").toLowerCase()).join(" ").slice(0, 8_000); }

function countSources(records: NormalizedObservation[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const record of records) counts[record.source] = (counts[record.source] ?? 0) + 1;
  return counts;
}

function databaseScope(scope: ObservationScope | undefined): { clause: string; bindings: unknown[] } {
  if (scope === "urlhaus") return { clause: "AND source = ?", bindings: ["urlhaus"] };
  if (scope === "malwarebazaar") return { clause: "AND source = ?", bindings: ["malwarebazaar"] };
  if (scope === "infrastructure") return { clause: "AND kind IN ('ipv4','ipv6','domain','infrastructure')", bindings: [] };
  return { clause: "", bindings: [] };
}

function recordMatchesScope(record: NormalizedObservation, scope: ObservationScope | undefined): boolean {
  if (scope === "urlhaus") return record.source === "urlhaus";
  if (scope === "malwarebazaar") return record.source === "malwarebazaar";
  if (scope === "infrastructure") return (["ipv4", "ipv6", "domain", "infrastructure"] as ObservationKind[]).includes(record.kind);
  return true;
}

async function readEventLedgerBounds(database: D1Database): Promise<EventLedgerBounds> {
  const row = await database.prepare("SELECT COUNT(*) AS count, MIN(detected_at) AS oldest, MAX(detected_at) AS newest FROM observation_events").first<{ count: number; oldest: string | null; newest: string | null }>();
  return { totalRetained: Number(row?.count ?? 0), oldestRetainedDetectedAt: row?.oldest ?? undefined, newestRetainedDetectedAt: row?.newest ?? undefined };
}

function memoryLedgerBounds(): EventLedgerBounds {
  const detected = memoryEvents.map((event) => event.detectedAt).sort();
  return { totalRetained: detected.length, oldestRetainedDetectedAt: detected[0], newestRetainedDetectedAt: detected.at(-1) };
}

function escapeLike(value: string): string { return value.replace(/[\\%_]/g, (match) => `\\${match}`); }
function parseDiagnostics(value: string | null): ValidationDiagnostic[] {
  if (!value) return [];
  const reasons = new Set<RejectionReason>(["REQUIRED_FIELD_MISSING", "TYPE_INVALID", "FORMAT_INVALID", "VALUE_OUT_OF_RANGE", "VALUE_TOO_LONG", "UNSUPPORTED_VALUE", "UNSAFE_SCHEME", "INVALID_INDICATOR", "NON_PUBLIC_IP", "PROVIDER_IDENTITY_MISMATCH", "RECORD_MALFORMED", "RESPONSE_SCHEMA_INVALID"]);
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is ValidationDiagnostic => Boolean(item && typeof item === "object" && typeof item.source === "string" && typeof item.field === "string" && reasons.has(item.reason as RejectionReason) && Number.isInteger(item.count) && item.count > 0 && item.normalizerVersion === 1)).slice(0, 40);
  } catch { return []; }
}
function chunks<T>(values: T[], size: number): T[][] { const result: T[][] = []; for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size)); return result; }

function pageValues<T>(values: T[], limit: number, cursorFor: (value: T) => PageCursor): { values: T[]; pagination: PaginationInfo } {
  const bounded = Math.min(Math.max(limit, 1), 500);
  const hasMore = values.length > bounded;
  const page = values.slice(0, bounded);
  return { values: page, pagination: { hasMore, nextCursor: hasMore && page.length ? encodeCursor(cursorFor(page.at(-1)!)) : undefined } };
}

function applyCursor<T>(values: T[], cursor: PageCursor | null | undefined, cursorFor: (value: T) => PageCursor): T[] {
  if (!cursor) return values;
  return values.filter((value) => { const current = cursorFor(value); return current.sort < cursor.sort || (current.sort === cursor.sort && current.id > cursor.id); });
}

function uniqueMetadata(records: NormalizedObservation[], key: string): string[] { return [...new Set(records.map((record) => record.metadata[key]).filter((value): value is string => typeof value === "string" && Boolean(value)))].sort().slice(0, 500); }

function acquireMemoryLease(source: string, holder: string, now: number, ttlMs: number): { acquired: boolean; backend: "isolate-memory" } {
  return { acquired: acquireInMemoryLease(memoryLeases, source, holder, now, ttlMs), backend: "isolate-memory" };
}

function defaultIngestionHealth(totalSources: number, leaseBackend: "d1" | "isolate-memory"): IngestionHealth {
  return {
    mode: "demand-driven", status: leaseBackend === "d1" ? "healthy" : "degraded", schedulerSupported: false,
    sourcesEligible: 0, totalSources, leaseBackend,
    reason: "Sites exposes no scheduled-trigger configuration; explicit maintenance requests run eligible source collection",
    latestSourceCycles: [],
  };
}

function normalizeIngestState(value: string): "new" | "seen" | "updated" { return value === "updated" ? "updated" : value === "seen" ? "seen" : "new"; }
function normalizeEventType(value: string): "new" | "updated" | "removed" { return value === "updated" ? "updated" : value === "removed" ? "removed" : "new"; }
function normalizeCycleStatus(value: string): SourceIngestCycle["status"] { return value === "failure" ? "failure" : value === "backoff" ? "backoff" : value === "lease-held" ? "lease-held" : "success"; }

interface HistoryRow {
  payload_json: string;
  first_ingested_at: string;
  last_ingested_at: string;
  last_changed_at?: string | null;
  last_observed_snapshot_at?: string | null;
  revision_count?: number | null;
  record_hash: string;
  ingest_state: string;
}

interface EventRow {
  event_id: string;
  observation_id: string;
  source: string;
  source_record_id: string | null;
  event_type: string;
  detected_at: string;
  previous_hash: string | null;
  new_hash: string | null;
  previous_payload_json: string | null;
  new_payload_json: string | null;
  diff_json: string;
}

interface CycleRow {
  id: number;
  source: string;
  started_at: string;
  completed_at: string;
  status: string;
  upstream_records: number;
  valid_records: number;
  rejected_records: number;
  new_records: number;
  updated_records: number;
  unchanged_records: number;
  removed_records: number;
  latency_ms: number;
  validation_diagnostics_json: string | null;
}

interface CountRow { label: string; count: number; }
