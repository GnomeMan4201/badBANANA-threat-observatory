import type { NormalizedObservation, TimeWindow } from "./threat-types";
import { defangUrl } from "./normalize.ts";

export type ExportFormat = "csv" | "jsonl" | "stix" | "defanged" | "manifest";

export interface ExportPolicy {
  schemaVersion: 1;
  window: TimeWindow;
  sources: string[];
  includeWithoutConfidence: boolean;
  minimumConfidence?: number;
  maxAgeHours?: number;
  currentStateOnly: true;
  preserveDisputes: true;
}

export interface ExportArtifact {
  filename: string;
  mimeType: string;
  content: string;
  records: number;
  selectedRecords: number;
  omittedRecords: number;
  omissions: Array<{ id: string; reason: "UNSUPPORTED_STIX_REPRESENTATION" }>;
}

export interface ExportPreview { selectedRecords: number; emittedRecords: number; omittedRecords: number; }

export function applyExportPolicy(records: NormalizedObservation[], policy: ExportPolicy, now = Date.now()): NormalizedObservation[] {
  const sourceSet = new Set(policy.sources);
  return records.filter((record) => {
    if (!sourceSet.has(record.source)) return false;
    if (!policy.includeWithoutConfidence && record.confidence === undefined) return false;
    if (policy.minimumConfidence !== undefined && (record.confidence === undefined || record.confidence < policy.minimumConfidence)) return false;
    if (policy.maxAgeHours !== undefined && now - Date.parse(record.observedAt) > policy.maxAgeHours * 3_600_000) return false;
    return true;
  });
}

export function buildExport(records: NormalizedObservation[], policy: ExportPolicy, format: ExportFormat, generatedAt = new Date().toISOString()): ExportArtifact {
  const selected = applyExportPolicy(records, policy, Date.parse(generatedAt));
  const base = `badbanana-${policy.window}-${generatedAt.slice(0, 10)}`;
  if (format === "jsonl") return artifact(`${base}.jsonl`, "application/x-ndjson", selected.map((record) => JSON.stringify(exportRecord(record))).join("\n"), selected.length, selected.length, []);
  if (format === "csv") return artifact(`${base}.csv`, "text/csv", toCsv(selected), selected.length, selected.length, []);
  if (format === "defanged") return artifact(`${base}-defanged.txt`, "text/plain", toDefanged(selected, policy, generatedAt), selected.length, selected.length, []);
  if (format === "stix") {
    const stix = toStix(selected, generatedAt);
    return artifact(`${base}.stix.json`, "application/stix+json", JSON.stringify(stix.bundle, null, 2), selected.length, stix.bundle.objects.length, stix.omissions);
  }
  return artifact(`${base}-manifest.json`, "application/json", JSON.stringify({ schemaVersion: 1, generatedAt, policy, recordCount: selected.length, recordHashes: selected.map((record) => ({ id: record.id, hash: record.recordHash ?? null, source: record.source })) }, null, 2), selected.length, selected.length, []);
}

export function previewExport(records: NormalizedObservation[], policy: ExportPolicy, format: ExportFormat, now = Date.now()): ExportPreview {
  const selected = applyExportPolicy(records, policy, now);
  if (format !== "stix") return { selectedRecords: selected.length, emittedRecords: selected.length, omittedRecords: 0 };
  const emittedRecords = selected.filter((record) => Boolean(stixObject(record))).length;
  return { selectedRecords: selected.length, emittedRecords, omittedRecords: selected.length - emittedRecords };
}

function exportRecord(record: NormalizedObservation) {
  return { ...record, exportState: "current", provenance: { source: record.source, sourceRecordId: record.sourceRecordId ?? null }, limitations: record.confidence === undefined ? ["SOURCE CONFIDENCE NOT PROVIDED"] : [] };
}

function toCsv(records: NormalizedObservation[]): string {
  const columns = ["id", "source", "sourceRecordId", "kind", "indicator", "malwareFamily", "threatType", "confidence", "observedAt", "ingestedAt", "recordHash"] as const;
  return [columns.join(","), ...records.map((record) => columns.map((column) => csv(record[column])).join(","))].join("\n");
}

function spreadsheetSafe(value: unknown): string {
  const text = value === undefined ? "" : String(value);
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}

function csv(value: unknown): string {
  const text = spreadsheetSafe(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function toDefanged(records: NormalizedObservation[], policy: ExportPolicy, generatedAt: string): string {
  return [`# badBANANA current-state export`, `# generated ${generatedAt}`, `# policy ${JSON.stringify(policy)}`, `# confidence remains absent where the source did not provide it`, ...records.map((record) => [record.kind === "url" ? defangUrl(record.indicator ?? record.id) : (record.indicator ?? record.id), record.source, `confidence=${record.confidence ?? "not-provided"}`].map(spreadsheetSafe).join("\t"))].join("\n");
}

function toStix(records: NormalizedObservation[], generatedAt: string) {
  const rendered = records.map((record) => ({ record, object: stixObject(record) }));
  const objects = rendered.flatMap(({ object }) => object ? [object] : []);
  const omissions = rendered.filter(({ object }) => !object).map(({ record }) => ({ id: record.id, reason: "UNSUPPORTED_STIX_REPRESENTATION" as const }));
  return { bundle: {
    type: "bundle",
    id: `bundle--${crypto.randomUUID()}`,
    objects,
    x_badbanana_export: { selected_records: records.length, emitted_objects: objects.length, omitted_records: omissions.length, omissions },
  }, omissions };
}

function stixObject(record: NormalizedObservation): Record<string, unknown> | undefined {
  const common = {
    spec_version: "2.1",
    created: record.firstIngestedAt ?? record.ingestedAt,
    modified: record.lastChangedAt ?? record.ingestedAt,
    external_references: record.reference ? [{ source_name: record.source, url: record.reference }] : undefined,
    x_badbanana_source: record.source,
    x_badbanana_source_record_id: record.sourceRecordId,
    x_badbanana_record_hash: record.recordHash,
  };
  if (record.kind === "vulnerability" && record.indicator && /^CVE-\d{4}-\d{4,}$/i.test(record.indicator)) {
    return { ...common, type: "vulnerability", id: `vulnerability--${crypto.randomUUID()}`, name: record.indicator.toUpperCase(), description: record.title };
  }
  const pattern = stixPattern(record);
  if (!pattern) return undefined;
  return { ...common, type: "indicator", id: `indicator--${crypto.randomUUID()}`, name: record.title ?? record.malwareFamily ?? record.indicator ?? record.id, pattern_type: "stix", pattern, valid_from: record.observedAt, labels: [record.source, record.kind], confidence: record.confidence };
}

function stixPattern(record: NormalizedObservation): string | undefined {
  const value = record.indicator?.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  if (!value) return undefined;
  if (record.kind === "ipv4") return `[ipv4-addr:value = '${value}']`;
  if (record.kind === "ipv6") return `[ipv6-addr:value = '${value}']`;
  if (record.kind === "domain") return `[domain-name:value = '${value}']`;
  if (record.kind === "url") return `[url:value = '${value}']`;
  if (record.kind === "hash" || (record.kind === "malware" && /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(record.indicator ?? ""))) return `[file:hashes.'${value.length === 32 ? "MD5" : value.length === 40 ? "SHA-1" : "SHA-256"}' = '${value}']`;
  return undefined;
}

function artifact(filename: string, mimeType: string, content: string, selectedRecords: number, records: number, omissions: ExportArtifact["omissions"]): ExportArtifact {
  return { filename, mimeType, content, records, selectedRecords, omittedRecords: omissions.length, omissions };
}
