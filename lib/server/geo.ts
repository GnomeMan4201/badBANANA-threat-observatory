import { geoSchemaStatements } from "../../db/schema";
import { extractPublicIp, GEO_PROVIDER_CHAIN_NAME, geoCacheExpiresAt, isGeoCacheEntryFresh, normalizeFreeIpApiGeo, normalizeGeoJsGeo, pruneExpiredGeoCache, setBoundedGeoCache, type ProviderGeoRecord } from "../geo";
import type { GeoPayload, GeoPoint, NormalizedObservation } from "../threat-types";
import { getDatabase } from "./runtime-config";

const PROVIDER_SITE = "https://www.geojs.io/";
const MAX_LOOKUPS_PER_REQUEST = 12;
const PERSISTENT_PRUNE_INTERVAL_MS = 15 * 60_000;
const memoryCache = new Map<string, GeoCacheRecord>();
let schemaReady: Promise<void> | undefined;
let lastPersistentPruneAt = 0;

interface GeoCacheRecord {
  ip: string;
  status: "success" | "error";
  provider: string;
  geo?: ProviderGeoRecord;
  enrichedAt: string;
  expiresAt: string;
  error?: string;
}

interface GeoCacheRow {
  ip: string;
  status: string;
  latitude: number | null;
  longitude: number | null;
  city: string | null;
  region: string | null;
  country: string | null;
  country_code: string | null;
  continent: string | null;
  asn: string | null;
  organization: string | null;
  provider: string;
  enriched_at: string;
  expires_at: string;
  error: string | null;
}

interface Candidate {
  ip: string;
  observationIds: string[];
  sources: string[];
  latestObservedAt: string;
}

export async function buildGeoPayload(records: NormalizedObservation[], coverage: { candidateRecords: number; candidateRecordsTruncated: boolean } = { candidateRecords: records.length, candidateRecordsTruncated: false }): Promise<GeoPayload> {
  const candidates = collectCandidates(records);
  const infrastructureRecords = records.filter((record) => record.kind === "ipv4" || record.kind === "ipv6");
  const excluded = infrastructureRecords.length - records.filter((record) => extractPublicIp(record)).length;
  const now = Date.now();
  pruneExpiredGeoCache(memoryCache, now);
  const loaded = await loadCache(candidates.map((candidate) => candidate.ip), now);
  const missing = candidates.filter((candidate) => {
    const cached = loaded.records.get(candidate.ip);
    return !isGeoCacheEntryFresh(cached, now);
  });
  const lookups = missing.slice(0, MAX_LOOKUPS_PER_REQUEST);
  const fetched = await Promise.all(lookups.map((candidate) => fetchGeo(candidate.ip)));
  await saveCache(fetched, loaded.mode);
  fetched.forEach((record) => loaded.records.set(record.ip, record));

  const points: GeoPoint[] = [];
  let unavailable = 0;
  for (const candidate of candidates) {
    const cached = loaded.records.get(candidate.ip);
    if (!isGeoCacheEntryFresh(cached, now)) continue;
    if (cached.status !== "success" || !cached.geo) { unavailable += 1; continue; }
    points.push({
      ...cached.geo,
      enrichedAt: cached.enrichedAt,
      observationIds: candidate.observationIds,
      sources: candidate.sources,
      latestObservedAt: candidate.latestObservedAt,
    });
  }

  return {
    points,
    records: records.filter((record) => Boolean(extractPublicIp(record))),
    candidates: candidates.length,
    excluded,
    unavailable,
    pending: Math.max(0, missing.length - lookups.length),
    candidateRecords: coverage.candidateRecords,
    candidateRecordsTruncated: coverage.candidateRecordsTruncated,
    cacheMode: loaded.mode,
    provider: { name: GEO_PROVIDER_CHAIN_NAME, url: PROVIDER_SITE, accuracy: "APPROXIMATE IP GEOLOCATION" },
    generatedAt: new Date().toISOString(),
  };
}

function collectCandidates(records: NormalizedObservation[]): Candidate[] {
  const byIp = new Map<string, Candidate>();
  for (const record of records) {
    const ip = extractPublicIp(record);
    if (!ip) continue;
    const existing = byIp.get(ip);
    if (existing) {
      existing.observationIds.push(record.id);
      if (!existing.sources.includes(record.source)) existing.sources.push(record.source);
      if (record.observedAt > existing.latestObservedAt) existing.latestObservedAt = record.observedAt;
    } else {
      byIp.set(ip, { ip, observationIds: [record.id], sources: [record.source], latestObservedAt: record.observedAt });
    }
  }
  return [...byIp.values()].sort((a, b) => b.latestObservedAt.localeCompare(a.latestObservedAt));
}

async function fetchGeo(ip: string): Promise<GeoCacheRecord> {
  const enrichedAt = new Date().toISOString();
  const primary = await fetchProvider("GEOJS", `https://get.geojs.io/v1/ip/geo/${encodeURIComponent(ip)}.json`, ip, normalizeGeoJsGeo);
  if (primary.geo) return successful(ip, enrichedAt, primary.geo);
  const fallback = await fetchProvider("FREEIPAPI", `https://free.freeipapi.com/api/json/${encodeURIComponent(ip)}`, ip, normalizeFreeIpApiGeo);
  if (fallback.geo) return successful(ip, enrichedAt, fallback.geo);
  return failed(ip, enrichedAt, [primary, fallback].map((attempt) => `${attempt.provider}:${attempt.error}`).join(" | "));
}

async function fetchProvider(provider: ProviderGeoRecord["provider"], endpoint: string, ip: string, normalize: (value: unknown, expectedIp: string) => ProviderGeoRecord | undefined): Promise<{ provider: string; geo?: ProviderGeoRecord; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4_500);
  try {
    const response = await fetch(endpoint, { headers: { Accept: "application/json" }, signal: controller.signal });
    if (!response.ok) return { provider, error: `HTTP ${response.status}` };
    const geo = normalize(await response.json() as unknown, ip);
    return geo ? { provider, geo } : { provider, error: "RESPONSE REJECTED" };
  } catch (error) {
    return { provider, error: error instanceof DOMException && error.name === "AbortError" ? "TIMEOUT" : "REQUEST FAILED" };
  } finally {
    clearTimeout(timer);
  }
}

function successful(ip: string, enrichedAt: string, geo: ProviderGeoRecord): GeoCacheRecord {
  return { ip, provider: geo.provider, status: "success", geo, enrichedAt, expiresAt: geoCacheExpiresAt("success") };
}

function failed(ip: string, enrichedAt: string, error: string): GeoCacheRecord {
  return { ip, provider: GEO_PROVIDER_CHAIN_NAME, status: "error", enrichedAt, expiresAt: geoCacheExpiresAt("error"), error };
}

async function loadCache(ips: string[], now: number): Promise<{ records: Map<string, GeoCacheRecord>; mode: "d1" | "isolate-memory" }> {
  const database = getDatabase();
  if (!database) return { records: readMemoryCache(ips), mode: "isolate-memory" };
  try {
    await ensureSchema(database);
    await opportunisticPrunePersistentGeoCache(database, now);
    const records = new Map<string, GeoCacheRecord>();
    if (!ips.length) return { records, mode: "d1" };
    for (const group of chunks(ips, 75)) {
      const placeholders = group.map(() => "?").join(",");
      const rows = await database.prepare(`SELECT * FROM geo_ip_cache WHERE ip IN (${placeholders})`).bind(...group).all<GeoCacheRow>();
      for (const row of rows.results ?? []) records.set(row.ip, parseRow(row));
    }
    return { records, mode: "d1" };
  } catch {
    return { records: readMemoryCache(ips), mode: "isolate-memory" };
  }
}

function readMemoryCache(ips: string[]): Map<string, GeoCacheRecord> {
  const records = new Map<string, GeoCacheRecord>();
  for (const ip of ips) {
    const cached = memoryCache.get(ip);
    if (cached) {
      setBoundedGeoCache(memoryCache, ip, cached);
      records.set(ip, cached);
    }
  }
  return records;
}

async function saveCache(records: GeoCacheRecord[], mode: "d1" | "isolate-memory"): Promise<void> {
  records.forEach((record) => setBoundedGeoCache(memoryCache, record.ip, record));
  if (mode !== "d1" || !records.length) return;
  const database = getDatabase();
  if (!database) return;
  try {
    await database.batch(records.map((record) => database.prepare(`
      INSERT INTO geo_ip_cache (ip, status, latitude, longitude, city, region, country, country_code, continent, asn, organization, provider, enriched_at, expires_at, error)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET status=excluded.status, latitude=excluded.latitude, longitude=excluded.longitude,
        city=excluded.city, region=excluded.region, country=excluded.country, country_code=excluded.country_code,
        continent=excluded.continent, asn=excluded.asn, organization=excluded.organization, provider=excluded.provider,
        enriched_at=excluded.enriched_at, expires_at=excluded.expires_at, error=excluded.error
    `).bind(
      record.ip, record.status, record.geo?.latitude ?? null, record.geo?.longitude ?? null,
      record.geo?.city ?? null, record.geo?.region ?? null, record.geo?.country ?? null,
      record.geo?.countryCode ?? null, record.geo?.continent ?? null, record.geo?.asn ?? null,
      record.geo?.organization ?? null, record.provider, record.enrichedAt, record.expiresAt, record.error ?? null,
    )));
  } catch {
    // Isolate memory retains this bounded result when persistence is unavailable.
  }
}

async function opportunisticPrunePersistentGeoCache(database: D1Database, now: number): Promise<void> {
  if (now - lastPersistentPruneAt < PERSISTENT_PRUNE_INTERVAL_MS) return;
  lastPersistentPruneAt = now;
  try {
    await database.prepare("DELETE FROM geo_ip_cache WHERE expires_at <= ?").bind(new Date(now).toISOString()).run();
  } catch {
    lastPersistentPruneAt = 0;
  }
}

function parseRow(row: GeoCacheRow): GeoCacheRecord {
  const activeProvider = row.provider === "GEOJS" || row.provider === "FREEIPAPI" ? row.provider : undefined;
  const valid = row.status === "success" && activeProvider && row.latitude !== null && row.longitude !== null && row.country && row.country_code;
  return {
    ip: row.ip,
    status: valid ? "success" : "error",
    provider: row.provider,
    geo: valid ? {
      ip: row.ip,
      provider: activeProvider as ProviderGeoRecord["provider"],
      latitude: row.latitude as number,
      longitude: row.longitude as number,
      city: row.city ?? undefined,
      region: row.region ?? undefined,
      country: row.country as string,
      countryCode: row.country_code as string,
      continent: row.continent ?? undefined,
      asn: row.asn ?? undefined,
      organization: row.organization ?? undefined,
    } : undefined,
    enrichedAt: row.enriched_at,
    expiresAt: row.expires_at,
    error: row.error ?? undefined,
  };
}

async function ensureSchema(database: D1Database): Promise<void> {
  if (!schemaReady) schemaReady = database.batch(geoSchemaStatements.map((statement) => database.prepare(statement))).then(() => undefined).catch((error) => { schemaReady = undefined; throw error; });
  await schemaReady;
}

function chunks<T>(values: T[], size: number): T[][] {
  const output: T[][] = [];
  for (let index = 0; index < values.length; index += size) output.push(values.slice(index, index + size));
  return output;
}
