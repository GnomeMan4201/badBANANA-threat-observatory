import { cleanSourceRecordId, cleanString, cleanTags, defangUrl, isSafeHttpUrl, parseTimestamp, safeReferenceUrl, strictString } from "../normalize.ts";
import type { NormalizedObservation } from "../threat-types";

export function normalizeUrlHaus(raw: unknown, ingestedAt: string): NormalizedObservation | null {
  if (!raw || typeof raw !== "object") return null;
  const source = raw as Record<string, unknown>;
  const sourceRecordId = cleanSourceRecordId(source.id);
  const indicator = strictString(source.url, 4096);
  const observedAt = parseTimestamp(source.date_added);
  if (!sourceRecordId || !indicator || !isSafeHttpUrl(indicator) || !observedAt) return null;
  return {
    id: `urlhaus:${sourceRecordId}`,
    source: "urlhaus",
    sourceRecordId,
    kind: "url",
    indicator,
    indicatorType: "URL",
    threatType: cleanString(source.threat, 120),
    firstSeen: observedAt,
    observedAt,
    tags: cleanTags(source.tags),
    reference: safeReferenceUrl(source.urlhaus_reference),
    ingestedAt,
    metadata: {
      defanged: defangUrl(indicator),
      status: cleanString(source.url_status, 40),
      host: cleanString(source.host, 255),
      reporter: cleanString(source.reporter, 160),
    },
  };
}
