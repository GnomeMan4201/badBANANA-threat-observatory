import { classifyIndicator, cleanSourceRecordId, cleanString, cleanTags, isSafeHttpUrl, isValidDomain, isValidIpv4, isValidIpv6, classifyIpPort, parseTimestamp, safeReferenceUrl } from "../normalize.ts";
import type { NormalizedObservation } from "../threat-types";

function strictString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.trim();
  return cleaned && cleaned.length <= maxLength ? cleaned : undefined;
}

function validTypedIndicator(value: string, suppliedType: string): boolean {
  const type = suppliedType.trim().toLowerCase().replace(/[_\s]+/g, "-");
  if (["ipv4", "ip", "ip-address"].includes(type)) return isValidIpv4(value);
  if (type === "ipv6") return isValidIpv6(value);
  if (["domain", "hostname", "host"].includes(type)) return isValidDomain(value);
  if (["url", "uri"].includes(type)) return isSafeHttpUrl(value);
  if (["md5-hash", "sha1-hash", "sha256-hash", "hash"].includes(type)) return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value);
  if (["ip:port", "ip-port"].includes(type)) return Boolean(classifyIpPort(value));
  return true;
}

export function normalizeThreatFox(raw: unknown, ingestedAt: string): NormalizedObservation | null {
  if (!raw || typeof raw !== "object") return null;
  const source = raw as Record<string, unknown>;
  const sourceRecordId = cleanSourceRecordId(source.id);
  const indicator = strictString(source.ioc, 2048);
  const indicatorType = strictString(source.ioc_type, 80);
  const observedAt = parseTimestamp(source.first_seen);
  if (!sourceRecordId || !indicator || !indicatorType || !observedAt || !validTypedIndicator(indicator, indicatorType)) return null;
  const confidence = typeof source.confidence_level === "number" && source.confidence_level >= 0 && source.confidence_level <= 100 ? source.confidence_level : undefined;
  return {
    id: `threatfox:${sourceRecordId}`,
    source: "threatfox",
    sourceRecordId,
    kind: classifyIndicator(indicator, indicatorType),
    indicator,
    indicatorType,
    malwareFamily: cleanString(source.malware_printable, 160) ?? cleanString(source.malware, 160),
    threatType: cleanString(source.threat_type, 120),
    confidence,
    firstSeen: observedAt,
    lastSeen: parseTimestamp(source.last_seen),
    observedAt,
    tags: cleanTags(source.tags),
    reference: safeReferenceUrl(source.reference),
    ingestedAt,
    metadata: { reporter: cleanString(source.reporter, 160) },
  };
}
