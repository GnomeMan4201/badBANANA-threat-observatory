import type { NormalizedObservation, ObservationKind, SourceSnapshot } from "./threat-types";

const KINDS = new Set<ObservationKind>(["vulnerability", "ipv4", "ipv6", "domain", "url", "hash", "malware", "infrastructure"]);

export function cleanString(value: unknown, maxLength = 800): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  return cleaned ? cleaned.slice(0, maxLength) : undefined;
}

export function cleanSourceRecordId(value: unknown, maxLength = 80): string | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return String(value);
  const identifier = cleanString(value, maxLength);
  return identifier && /^[A-Za-z0-9._:-]+$/.test(identifier) ? identifier : undefined;
}

export function cleanTags(value: unknown, max = 24): string[] {
  if (!Array.isArray(value)) return [];
  const canonical = value
    .map((tag) => cleanString(tag, 80)?.toLowerCase())
    .filter((tag): tag is string => Boolean(tag));
  return [...new Set(canonical)].sort((left, right) => left.localeCompare(right)).slice(0, max);
}

export function parseTimestamp(value: unknown): string | undefined {
  const text = cleanString(value, 64);
  if (!text) return undefined;
  const calendar = parseCalendarDate(text);
  if (calendar) return calendar;

  const isoLike = text.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(?:Z| UTC|([+-])(\d{2}):(\d{2}))?$/);
  if (isoLike) {
    const [, year, month, day, hour, minute, second = "00", fraction = "", offsetSign, offsetHour = "00", offsetMinute = "00"] = isoLike;
    if (!validCalendarParts(Number(year), Number(month), Number(day)) || !validTimeParts(Number(hour), Number(minute), Number(second))) return undefined;
    if (Number(offsetHour) > 14 || Number(offsetMinute) > 59 || (Number(offsetHour) === 14 && Number(offsetMinute) !== 0)) return undefined;
    const milliseconds = fraction.padEnd(3, "0").slice(0, 3);
    const zone = offsetSign ? `${offsetSign}${offsetHour}:${offsetMinute}` : "Z";
    return canonicalDate(`${year}-${month}-${day}T${hour}:${minute}:${second}.${milliseconds}${zone}`);
  }

  const slash = text.match(/^(\d{2})\/(\d{2})\/(\d{4}) (\d{2}):(\d{2}):(\d{2}) (?:GMT|UTC)$/);
  if (slash) {
    const [, month, day, year, hour, minute, second] = slash;
    if (!validCalendarParts(Number(year), Number(month), Number(day)) || !validTimeParts(Number(hour), Number(minute), Number(second))) return undefined;
    return canonicalDate(`${year}-${month}-${day}T${hour}:${minute}:${second}.000Z`);
  }

  const rfc = text.match(/^(?:(Sun|Mon|Tue|Wed|Thu|Fri|Sat), )?(\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2}):(\d{2}) (?:GMT|UTC)$/);
  if (rfc) {
    const [, weekday, day, monthName, year, hour, minute, second] = rfc;
    const month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].indexOf(monthName) + 1;
    if (!validCalendarParts(Number(year), month, Number(day)) || !validTimeParts(Number(hour), Number(minute), Number(second))) return undefined;
    const canonical = canonicalDate(`${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T${hour}:${minute}:${second}.000Z`);
    if (!canonical) return undefined;
    if (weekday && ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][new Date(canonical).getUTCDay()] !== weekday) return undefined;
    return canonical;
  }
  return undefined;
}

export function parseCalendarDate(value: unknown): string | undefined {
  const text = cleanString(value, 64);
  const match = text?.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match || !validCalendarParts(Number(match[1]), Number(match[2]), Number(match[3]))) return undefined;
  return `${match[1]}-${match[2]}-${match[3]}T00:00:00.000Z`;
}

function validCalendarParts(year: number, month: number, day: number): boolean {
  if (!Number.isInteger(year) || year < 1 || year > 9999 || !Number.isInteger(month) || month < 1 || month > 12 || !Number.isInteger(day) || day < 1) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1];
}

function validTimeParts(hour: number, minute: number, second: number): boolean {
  return Number.isInteger(hour) && hour >= 0 && hour <= 23 && Number.isInteger(minute) && minute >= 0 && minute <= 59 && Number.isInteger(second) && second >= 0 && second <= 59;
}

function canonicalDate(value: string): string | undefined {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

export function isValidIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

export function isValidPort(value: string): boolean {
  return /^\d{1,5}$/.test(value) && Number(value) >= 1 && Number(value) <= 65535;
}

export function isValidIpv6(value: string): boolean {
  if (!value || value.includes("%") || /[^0-9a-f:.]/i.test(value)) return false;
  if ((value.match(/::/g) ?? []).length > 1) return false;
  let candidate = value;
  let ipv4Groups = 0;
  const lastColon = candidate.lastIndexOf(":");
  const tail = lastColon >= 0 ? candidate.slice(lastColon + 1) : candidate;
  if (tail.includes(".")) {
    if (!isValidIpv4(tail)) return false;
    candidate = candidate.slice(0, lastColon);
    ipv4Groups = 2;
  }
  const compressed = candidate.includes("::");
  const groups = candidate.split(":").filter(Boolean);
  if (!groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return false;
  const total = groups.length + ipv4Groups;
  return compressed ? total < 8 : total === 8;
}

export function isValidDomain(value: string): boolean {
  if (value.length > 253 || value.endsWith(".") || value.includes("..")) return false;
  const labels = value.toLowerCase().split(".");
  return labels.length >= 2 && labels.every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

export function isSafeHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "http:") && Boolean(url.hostname);
  } catch {
    return false;
  }
}

export function safeReferenceUrl(value: unknown): string | undefined {
  const reference = cleanString(value, 2048);
  return reference && isSafeHttpUrl(reference) ? reference : undefined;
}

export function referencePolicy(value: unknown, source: string): { url?: string; hostname?: string; trust: "first-party" | "external" | "invalid" } {
  const safe = safeReferenceUrl(value);
  if (!safe) return { trust: "invalid" };
  const hostname = new URL(safe).hostname.toLowerCase();
  const firstParty = source === "cisa-kev"
    ? hostname === "cisa.gov" || hostname.endsWith(".cisa.gov")
    : ["threatfox", "urlhaus", "malwarebazaar"].includes(source) && (hostname === "abuse.ch" || hostname.endsWith(".abuse.ch"));
  return { url: safe, hostname, trust: firstParty ? "first-party" : "external" };
}

export function classifyIndicator(value: string, suppliedType?: string): ObservationKind {
  const type = suppliedType?.trim().toLowerCase().replace(/[_\s]+/g, "-") ?? "";
  if (["ipv4", "ip", "ip-address"].includes(type)) return isValidIpv4(value) ? "ipv4" : "infrastructure";
  if (type === "ipv6") return isValidIpv6(value) ? "ipv6" : "infrastructure";
  if (["domain", "hostname", "host"].includes(type)) return isValidDomain(value) ? "domain" : "infrastructure";
  if (["url", "uri"].includes(type)) return isSafeHttpUrl(value) ? "url" : "infrastructure";
  if (["md5-hash", "sha1-hash", "sha256-hash", "hash"].includes(type)) return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value) ? "hash" : "infrastructure";
  if (["ip:port", "ip-port"].includes(type)) return classifyIpPort(value) ?? "infrastructure";
  if (isValidIpv4(value)) return "ipv4";
  if (isValidIpv6(value)) return "ipv6";
  if (isSafeHttpUrl(value)) return "url";
  if (isValidDomain(value)) return "domain";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) return "hash";
  return "infrastructure";
}

export function classifyIpPort(value: string): "ipv4" | "ipv6" | undefined {
  const bracketed = value.match(/^\[([^\]]+)]:(\d{1,5})$/);
  if (bracketed) return isValidIpv6(bracketed[1]) && isValidPort(bracketed[2]) ? "ipv6" : undefined;
  const splitAt = value.lastIndexOf(":");
  if (splitAt < 1) return undefined;
  const host = value.slice(0, splitAt);
  const port = value.slice(splitAt + 1);
  if (!isValidPort(port)) return undefined;
  if (isValidIpv4(host)) return "ipv4";
  if (isValidIpv6(host)) return "ipv6";
  return undefined;
}

export function defangUrl(raw: string): string {
  return raw.replace(/^http:/i, "hxxp:").replace(/^https:/i, "hxxps:").replace(/\./g, "[.]");
}

export function validateNormalizedObservation(value: unknown): value is NormalizedObservation {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<NormalizedObservation>;
  return Boolean(
    cleanString(record.id, 300) && cleanString(record.source, 80) && record.kind && KINDS.has(record.kind) &&
    parseTimestamp(record.observedAt) && parseTimestamp(record.ingestedAt) && Array.isArray(record.tags) &&
    record.tags.every((tag) => typeof tag === "string" && tag.length <= 80) && record.metadata && typeof record.metadata === "object" &&
    (!record.reference || isSafeHttpUrl(record.reference))
  );
}

export function validateSourceSnapshot(value: unknown, sourceId?: string): value is SourceSnapshot {
  if (!value || typeof value !== "object") return false;
  const snapshot = value as Partial<SourceSnapshot>;
  return Boolean(
    parseTimestamp(snapshot.fetchedAt) && parseTimestamp(snapshot.expiresAt) && snapshot.health &&
    (!sourceId || snapshot.health.id === sourceId) && Array.isArray(snapshot.records) &&
    Number.isInteger(snapshot.health.recordCount) && snapshot.health.recordCount === snapshot.records.length &&
    snapshot.records.every((record) => validateNormalizedObservation(record) && (!sourceId || record.source === sourceId))
  );
}
