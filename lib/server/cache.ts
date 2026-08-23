import { parseTimestamp, validateSourceSnapshot } from "../normalize";
import type { SourceHealth, SourceSnapshot } from "../threat-types";
import { getDatabase } from "./runtime-config";

const memoryCache = new Map<string, SourceSnapshot>();
let schemaReady: Promise<void> | undefined;
const CHUNK_SIZE = 50;

interface CacheEnvelope {
  format: 2;
  generation: string;
  chunkCount: number;
  fetchedAt: string;
  expiresAt: string;
  health: SourceHealth;
}

export async function readSourceCache(sourceId: string): Promise<SourceSnapshot | undefined> {
  const memory = memoryCache.get(sourceId);
  const safeMemory = validateSourceSnapshot(memory, sourceId) ? memory : undefined;
  try {
    const database = getDatabase();
    if (!database) return safeMemory;
    await ensureTable(database);
    const row = await database.prepare("SELECT payload FROM threat_source_cache WHERE source_id = ?").bind(sourceId).first<{ payload: string }>();
    if (!row?.payload) return safeMemory;
    const parsed = JSON.parse(row.payload) as unknown;
    if (validateSourceSnapshot(parsed, sourceId)) {
      memoryCache.set(sourceId, parsed);
      return parsed;
    }
    if (!isEnvelope(parsed, sourceId)) return safeMemory;
    const chunks = await database.prepare("SELECT payload FROM threat_source_cache_chunks WHERE source_id = ? AND generation = ? ORDER BY chunk_index ASC").bind(sourceId, parsed.generation).all<{ payload: string }>();
    if ((chunks.results?.length ?? 0) !== parsed.chunkCount) return safeMemory;
    const records = (chunks.results ?? []).flatMap((chunk) => {
      const value = JSON.parse(chunk.payload) as unknown;
      return Array.isArray(value) ? value : [];
    });
    const snapshot: SourceSnapshot = { records, fetchedAt: parsed.fetchedAt, expiresAt: parsed.expiresAt, health: parsed.health };
    if (!validateSourceSnapshot(snapshot, sourceId)) return safeMemory;
    memoryCache.set(sourceId, snapshot);
    return snapshot;
  } catch {
    return safeMemory;
  }
}

export async function readAllSourceCaches(sourceIds: string[]): Promise<SourceSnapshot[]> {
  const snapshots = await Promise.all(sourceIds.map((sourceId) => readSourceCache(sourceId)));
  return snapshots.filter((snapshot): snapshot is SourceSnapshot => Boolean(snapshot));
}

export async function writeSourceCache(sourceId: string, snapshot: SourceSnapshot): Promise<void> {
  if (!validateSourceSnapshot(snapshot, sourceId)) return;
  memoryCache.set(sourceId, snapshot);
  try {
    const database = getDatabase();
    if (!database) return;
    await ensureTable(database);
    const generation = crypto.randomUUID();
    const recordChunks = chunks(snapshot.records, CHUNK_SIZE);
    for (const group of chunks(recordChunks, 8)) {
      await database.batch(group.map((records) => {
        const chunkIndex = recordChunks.indexOf(records);
        return database.prepare("INSERT INTO threat_source_cache_chunks (source_id, generation, chunk_index, payload) VALUES (?, ?, ?, ?)").bind(sourceId, generation, chunkIndex, JSON.stringify(records));
      }));
    }
    const envelope: CacheEnvelope = { format: 2, generation, chunkCount: recordChunks.length, fetchedAt: snapshot.fetchedAt, expiresAt: snapshot.expiresAt, health: snapshot.health };
    await database.prepare("INSERT INTO threat_source_cache (source_id, payload, updated_at) VALUES (?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at").bind(sourceId, JSON.stringify(envelope), new Date().toISOString()).run();
    await database.prepare("DELETE FROM threat_source_cache_chunks WHERE source_id = ? AND generation <> ?").bind(sourceId, generation).run();
  } catch {
    // The validated memory snapshot remains the safe per-isolate fallback.
  }
}

async function ensureTable(database: D1Database): Promise<void> {
  if (!schemaReady) schemaReady = database.batch([
    database.prepare("CREATE TABLE IF NOT EXISTS threat_source_cache (source_id TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"),
    database.prepare("CREATE TABLE IF NOT EXISTS threat_source_cache_chunks (source_id TEXT NOT NULL, generation TEXT NOT NULL, chunk_index INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(source_id, generation, chunk_index))"),
    database.prepare("CREATE INDEX IF NOT EXISTS idx_source_cache_chunks ON threat_source_cache_chunks(source_id, generation, chunk_index)"),
  ]).then(() => undefined).catch((error) => { schemaReady = undefined; throw error; });
  await schemaReady;
}

function isEnvelope(value: unknown, sourceId: string): value is CacheEnvelope {
  if (!value || typeof value !== "object") return false;
  const envelope = value as Partial<CacheEnvelope>;
  return envelope.format === 2 && typeof envelope.generation === "string" && envelope.generation.length <= 80 && Number.isInteger(envelope.chunkCount) && Number(envelope.chunkCount) >= 0 && Number(envelope.chunkCount) <= 100 && Boolean(parseTimestamp(envelope.fetchedAt)) && Boolean(parseTimestamp(envelope.expiresAt)) && envelope.health?.id === sourceId && Number.isInteger(envelope.health.recordCount);
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}
