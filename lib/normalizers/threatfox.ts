import { classifyIndicator, cleanSourceRecordId, cleanString, cleanTags, parseTimestamp, safeReferenceUrl } from "../normalize.ts";
import type { NormalizedObservation } from "../threat-types";

export function normalizeThreatFox(raw: unknown, ingestedAt: string): NormalizedObservation | null {
  if (!raw || typeof raw !== "object") return null;
  const source = raw as Record<string, unknown>;
  const sourceRecordId = cleanSourceRecordId(source.id);
  const indicator = cleanString(source.ioc, 2048);
  const indicatorType = cleanString(source.ioc_type, 80);
  const observedAt = parseTimestamp(source.first_seen);
  if (!sourceRecordId || !indicator || !indicatorType || !observedAt) return null;
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
