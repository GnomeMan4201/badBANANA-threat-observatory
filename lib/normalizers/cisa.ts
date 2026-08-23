import { cleanString, parseTimestamp } from "../normalize.ts";
import type { NormalizedObservation } from "../threat-types";

export function normalizeCisaKev(raw: unknown, ingestedAt: string): NormalizedObservation | null {
  if (!raw || typeof raw !== "object") return null;
  const source = raw as Record<string, unknown>;
  const cveId = cleanString(source.cveID, 24);
  const vendor = cleanString(source.vendorProject, 160);
  const product = cleanString(source.product, 160);
  const title = cleanString(source.vulnerabilityName, 400);
  const observedAt = parseTimestamp(source.dateAdded);
  const dueDateInput = cleanString(source.dueDate, 64);
  const dueDate = dueDateInput ? parseTimestamp(dueDateInput) : undefined;
  const requiredAction = cleanString(source.requiredAction, 800);
  if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId) || !vendor || !product || !title || !observedAt || (dueDateInput && !dueDate) || !requiredAction) return null;
  const ransomware = cleanString(source.knownRansomwareCampaignUse, 40);
  return {
    id: `cisa-kev:${cveId}`,
    source: "cisa-kev",
    sourceRecordId: cveId,
    kind: "vulnerability",
    indicator: cveId,
    indicatorType: "CVE",
    title,
    firstSeen: observedAt,
    observedAt,
    tags: [vendor.slice(0, 80), product.slice(0, 80), ...(ransomware ? [ransomware.slice(0, 80)] : [])],
    reference: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cveId)}`,
    ingestedAt,
    metadata: {
      vendor,
      product,
      requiredAction,
      dueDate,
      knownRansomwareCampaignUse: ransomware,
      notes: cleanString(source.notes),
    },
  };
}

export function normalizeCisaDataset(records: unknown[], ingestedAt: string): NormalizedObservation[] {
  return deduplicate(records.map((record) => normalizeCisaKev(record, ingestedAt)));
}

function deduplicate(records: Array<NormalizedObservation | null>): NormalizedObservation[] {
  const seen = new Set<string>();
  return records.filter((record): record is NormalizedObservation => {
    if (!record || seen.has(record.id)) return false;
    seen.add(record.id);
    return true;
  });
}
