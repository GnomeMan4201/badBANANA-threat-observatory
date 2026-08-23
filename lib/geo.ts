import { isValidIpv4, isValidIpv6, isValidPort } from "./normalize.ts";
import type { NormalizedObservation } from "./threat-types.ts";

export interface ProviderGeoRecord {
  ip: string;
  provider: "GEOJS" | "FREEIPAPI";
  latitude: number;
  longitude: number;
  city?: string;
  region?: string;
  country: string;
  countryCode: string;
  continent?: string;
  asn?: string;
  organization?: string;
}

export const GEO_PROVIDER_CHAIN_NAME = "GEOJS + FREEIPAPI";
export const GEO_SUCCESS_TTL_MS = 30 * 24 * 60 * 60_000;
export const GEO_FAILURE_TTL_MS = 5 * 60_000;
export const GEO_MEMORY_CACHE_MAX_ENTRIES = 2_000;

export function geoCacheExpiresAt(status: "success" | "error", now = Date.now()): string {
  return new Date(now + (status === "success" ? GEO_SUCCESS_TTL_MS : GEO_FAILURE_TTL_MS)).toISOString();
}

export function isGeoCacheEntryFresh(cached: { status: "success" | "error"; provider: string; expiresAt: string } | undefined, now = Date.now()): boolean {
  const expiresAt = cached ? Date.parse(cached.expiresAt) : Number.NaN;
  if (!cached || !Number.isFinite(expiresAt) || expiresAt <= now) return false;
  if (cached.status === "success") return cached.provider === "GEOJS" || cached.provider === "FREEIPAPI";
  return cached.provider === GEO_PROVIDER_CHAIN_NAME;
}

export function pruneExpiredGeoCache<T extends { expiresAt: string }>(cache: Map<string, T>, now = Date.now()): number {
  let removed = 0;
  for (const [key, record] of cache) {
    const expiresAt = Date.parse(record.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      cache.delete(key);
      removed += 1;
    }
  }
  return removed;
}

export function setBoundedGeoCache<T>(cache: Map<string, T>, key: string, value: T, maximumEntries = GEO_MEMORY_CACHE_MAX_ENTRIES): void {
  const limit = Math.max(1, Math.floor(maximumEntries));
  cache.delete(key);
  cache.set(key, value);
  while (cache.size > limit) {
    const oldest = cache.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

export function extractPublicIp(record: Pick<NormalizedObservation, "kind" | "indicator">): string | undefined {
  const value = record.indicator?.trim();
  if (!value || (record.kind !== "ipv4" && record.kind !== "ipv6")) return undefined;
  if (isValidIpv4(value) || isValidIpv6(value)) return canonicalPublicIp(value);
  const bracketed = value.match(/^\[([^\]]+)](?::(\d{1,5}))?$/);
  if (bracketed && isValidIpv6(bracketed[1]) && (!bracketed[2] || isValidPort(bracketed[2]))) return canonicalPublicIp(bracketed[1]);
  const ipv4Port = value.match(/^([^:]+):(\d{1,5})$/);
  if (ipv4Port && isValidIpv4(ipv4Port[1]) && isValidPort(ipv4Port[2])) return canonicalPublicIp(ipv4Port[1]);
  return undefined;
}

export function isPublicIp(value: string): boolean {
  if (isValidIpv4(value)) {
    const [a, b, c] = value.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
    if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (!isValidIpv6(value)) return false;
  const mapped = unwrapIpv4MappedIpv6(value);
  if (mapped) return isPublicIp(mapped);
  const normalized = value.toLowerCase();
  if (normalized === "::" || normalized === "::1") return false;
  if (/^f[cd]/.test(normalized) || /^fe[89ab]/.test(normalized) || normalized.startsWith("ff")) return false;
  if (normalized.startsWith("2001:db8")) return false;
  return true;
}

export function unwrapIpv4MappedIpv6(value: string): string | undefined {
  if (!isValidIpv6(value)) return undefined;
  const groups = expandIpv6(value).split(":");
  if (groups.length !== 8 || groups.slice(0, 5).some((group) => group !== "0000") || groups[5] !== "ffff") return undefined;
  const high = Number.parseInt(groups[6], 16);
  const low = Number.parseInt(groups[7], 16);
  return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
}

export function normalizeGeoJsGeo(value: unknown, expectedIp: string): ProviderGeoRecord | undefined {
  if (!value || typeof value !== "object") return undefined;
  const raw = value as Record<string, unknown>;
  return normalizeGeoFields({
    responseIp: raw.ip,
    latitude: raw.latitude,
    longitude: raw.longitude,
    country: raw.country,
    countryCode: raw.country_code,
    city: raw.city,
    region: raw.region,
    continent: raw.continent_code,
    asn: raw.asn,
    organization: raw.organization_name,
  }, expectedIp, "GEOJS");
}

export function normalizeFreeIpApiGeo(value: unknown, expectedIp: string): ProviderGeoRecord | undefined {
  if (!value || typeof value !== "object") return undefined;
  const raw = value as Record<string, unknown>;
  return normalizeGeoFields({
    responseIp: raw.ipAddress,
    latitude: raw.latitude,
    longitude: raw.longitude,
    country: raw.countryName,
    countryCode: raw.countryCode,
    city: raw.cityName,
    region: raw.regionName,
    continent: raw.continent,
    asn: raw.asn,
    organization: raw.asnOrganization,
  }, expectedIp, "FREEIPAPI");
}

function normalizeGeoFields(fields: {
  responseIp: unknown;
  latitude: unknown;
  longitude: unknown;
  country: unknown;
  countryCode: unknown;
  city?: unknown;
  region?: unknown;
  continent?: unknown;
  asn?: unknown;
  organization?: unknown;
}, expectedIp: string, provider: ProviderGeoRecord["provider"]): ProviderGeoRecord | undefined {
  if (typeof fields.responseIp !== "string" || !sameIp(fields.responseIp, expectedIp)) return undefined;
  const latitude = safeCoordinate(fields.latitude, -90, 90);
  const longitude = safeCoordinate(fields.longitude, -180, 180);
  const country = safeText(fields.country, 100);
  const countryCode = safeText(fields.countryCode, 2)?.toUpperCase();
  if (latitude === undefined || longitude === undefined || !country || !countryCode || !/^[A-Z]{2}$/.test(countryCode)) return undefined;
  return {
    ip: expectedIp,
    provider,
    latitude,
    longitude,
    country,
    countryCode,
    city: safeText(fields.city, 120),
    region: safeText(fields.region, 120),
    continent: safeText(fields.continent, 80),
    asn: normalizeAsn(fields.asn),
    organization: safeText(fields.organization, 180),
  };
}

function sameIp(left: string, right: string): boolean {
  const normalizedLeft = unwrapIpv4MappedIpv6(left) ?? left;
  const normalizedRight = unwrapIpv4MappedIpv6(right) ?? right;
  if (isValidIpv4(normalizedLeft) && isValidIpv4(normalizedRight)) return normalizedLeft === normalizedRight;
  if (!isValidIpv6(left) || !isValidIpv6(right)) return false;
  return expandIpv6(left) === expandIpv6(right);
}

function canonicalPublicIp(value: string): string | undefined {
  const mapped = unwrapIpv4MappedIpv6(value);
  if (mapped) return isPublicIp(mapped) ? mapped : undefined;
  return isPublicIp(value) ? value.toLowerCase() : undefined;
}

function expandIpv6(value: string): string {
  let candidate = value.toLowerCase();
  const dottedIndex = candidate.lastIndexOf(":");
  const dotted = dottedIndex >= 0 ? candidate.slice(dottedIndex + 1) : "";
  if (isValidIpv4(dotted)) {
    const octets = dotted.split(".").map(Number);
    candidate = `${candidate.slice(0, dottedIndex)}:${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const [left = "", right = ""] = candidate.split("::");
  const leftGroups = left ? left.split(":") : [];
  const rightGroups = right ? right.split(":") : [];
  const zeroGroups = candidate.includes("::") ? Array(Math.max(0, 8 - leftGroups.length - rightGroups.length)).fill("0") : [];
  return [...leftGroups, ...zeroGroups, ...rightGroups].map((group) => group.padStart(4, "0")).join(":");
}

function safeText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  return cleaned ? cleaned.slice(0, maxLength) : undefined;
}

function safeCoordinate(value: unknown, minimum: number, maximum: number): number | undefined {
  const coordinate = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : Number.NaN;
  return Number.isFinite(coordinate) && coordinate >= minimum && coordinate <= maximum ? coordinate : undefined;
}

function normalizeAsn(value: unknown): string | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value !== 64512) return `AS${value}`;
  const text = safeText(value, 24);
  if (!text || !/^(?:AS)?\d{1,10}$/i.test(text)) return undefined;
  const digits = text.replace(/^AS/i, "");
  return digits === "64512" ? undefined : `AS${digits}`;
}
