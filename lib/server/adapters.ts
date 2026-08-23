import { findSourceAdapter, type ThreatSourceAdapter } from "../source-adapter";
import { normalizeCisaKev } from "../normalizers/cisa";
import { normalizeThreatFox } from "../normalizers/threatfox";
import { normalizeUrlHaus } from "../normalizers/urlhaus";
import { normalizeMalwareBazaar } from "../normalizers/malwarebazaar";
import type { NormalizedObservation } from "../threat-types";
import { fetchWithTimeout } from "./fetch";
import { assertUpstreamOk } from "./fetch-error";
import { aggregateDiagnostics, diagnoseRejectedRecord } from "../rejection-diagnostics";

const FIFTEEN_MINUTES = 15 * 60 * 1_000;

export const cisaKevAdapter: ThreatSourceAdapter = {
  id: "cisa-kev", name: "CISA Known Exploited Vulnerabilities", cacheTtlMs: 30 * 60 * 1_000,
  authMode: "None", refreshPolicy: "30 minutes", upstreamUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  dataUsed: "CVE, vendor, product, vulnerability name, dates, required action, ransomware flag",
  coverage: "Full current CISA Known Exploited Vulnerabilities catalog",
  coverageMode: "full-current",
  async fetchRecent() {
    const response = await fetchWithTimeout("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { headers: { Accept: "application/json", "User-Agent": "badBANANA-Threat-Observatory/1.0" } });
    assertUpstreamOk(response);
    const payload = await response.json() as Record<string, unknown>;
    if (!Array.isArray(payload.vulnerabilities)) throw new Error("Invalid CISA schema");
    const ingestedAt = new Date().toISOString();
    const normalized = payload.vulnerabilities.map((raw) => ({ raw, record: normalizeCisaKev(raw, ingestedAt) }));
    const records = deduplicate(normalized.map((item) => item.record).filter((record): record is NormalizedObservation => Boolean(record)));
    const validationDiagnostics = aggregateDiagnostics(normalized.filter((item) => !item.record).map((item) => diagnoseRejectedRecord("cisa-kev", item.raw, ingestedAt)));
    if (!records.length) throw new Error("No valid CISA records");
    return { records, upstreamRecords: payload.vulnerabilities.length, rejectedRecords: payload.vulnerabilities.length - records.length, validationDiagnostics, upstreamDataDate: typeof payload.dateReleased === "string" ? payload.dateReleased : typeof payload.catalogVersion === "string" ? payload.catalogVersion : undefined };
  },
};

export const threatFoxAdapter: ThreatSourceAdapter = {
  id: "threatfox", name: "ThreatFox", credentialKey: "THREATFOX_AUTH_KEY", cacheTtlMs: FIFTEEN_MINUTES,
  authMode: "Auth-Key header", refreshPolicy: "15 minutes", upstreamUrl: "https://threatfox.abuse.ch/api/",
  dataUsed: "IOC, IOC type, threat type, malware family, confidence, timestamps, tags, reference",
  coverage: "Requested 24-hour IOC window from the ThreatFox API",
  coverageMode: "bounded-window",
  async fetchRecent(credential) {
    const response = await fetchWithTimeout("https://threatfox-api.abuse.ch/api/v1/", { method: "POST", headers: { "Auth-Key": requireCredential(credential), "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ query: "get_iocs", days: 1 }) });
    return normalizeApiList(response, "data", normalizeThreatFox, "ThreatFox", "threatfox");
  },
};

export const urlHausAdapter: ThreatSourceAdapter = {
  id: "urlhaus", name: "URLhaus", credentialKey: "URLHAUS_AUTH_KEY", cacheTtlMs: FIFTEEN_MINUTES,
  authMode: "Auth-Key header", refreshPolicy: "15 minutes", upstreamUrl: "https://urlhaus.abuse.ch/api/",
  dataUsed: "Malicious URL, status, host, first seen, threat, tags, source reference",
  coverage: "Latest 500 records returned by the URLhaus recent endpoint",
  coverageMode: "bounded-latest",
  async fetchRecent(credential) {
    const response = await fetchWithTimeout("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/", { headers: { "Auth-Key": requireCredential(credential), Accept: "application/json" } });
    return normalizeApiList(response, "urls", normalizeUrlHaus, "URLhaus", "urlhaus");
  },
};

export const malwareBazaarAdapter: ThreatSourceAdapter = {
  id: "malwarebazaar", name: "MalwareBazaar", credentialKey: "MALWAREBAZAAR_AUTH_KEY", cacheTtlMs: FIFTEEN_MINUTES,
  authMode: "Auth-Key header", refreshPolicy: "15 minutes", upstreamUrl: "https://bazaar.abuse.ch/api/",
  dataUsed: "Hash metadata, file type and size, family/signature, timestamps, tags, reporter",
  coverage: "Latest 100 records returned by the MalwareBazaar endpoint",
  coverageMode: "bounded-latest",
  async fetchRecent(credential) {
    const body = new URLSearchParams({ query: "get_recent", selector: "100" });
    const response = await fetchWithTimeout("https://mb-api.abuse.ch/api/v1/", { method: "POST", headers: { "Auth-Key": requireCredential(credential), "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }, body });
    return normalizeApiList(response, "data", normalizeMalwareBazaar, "MalwareBazaar", "malwarebazaar");
  },
};

export const sourceAdapters = [cisaKevAdapter, threatFoxAdapter, urlHausAdapter, malwareBazaarAdapter];

export function sourceAdapterById(id: string): ThreatSourceAdapter | undefined {
  return findSourceAdapter(sourceAdapters, id);
}

async function normalizeApiList(response: Response, listKey: string, normalize: (raw: unknown, ingestedAt: string) => NormalizedObservation | null, sourceName: string, sourceId: string) {
  assertUpstreamOk(response);
  const payload = await response.json() as Record<string, unknown>;
  if (payload.query_status !== "ok" || !Array.isArray(payload[listKey])) throw new Error(`Invalid ${sourceName} response`);
  const ingestedAt = new Date().toISOString();
  const upstream = payload[listKey] as unknown[];
  const normalized = upstream.map((raw) => ({ raw, record: normalize(raw, ingestedAt) }));
  const valid = normalized.map((item) => item.record).filter((record): record is NormalizedObservation => Boolean(record));
  const records = deduplicate(valid);
  if (!records.length) throw new Error(`No valid ${sourceName} records`);
  return { records, upstreamRecords: upstream.length, rejectedRecords: upstream.length - valid.length, validationDiagnostics: aggregateDiagnostics(normalized.filter((item) => !item.record).map((item) => diagnoseRejectedRecord(sourceId, item.raw, ingestedAt))) };
}

function deduplicate(records: NormalizedObservation[]): NormalizedObservation[] {
  return [...new Map(records.map((record) => [record.id, record])).values()];
}

function requireCredential(value?: string): string {
  if (!value) throw new Error("Credential not configured");
  return value;
}
