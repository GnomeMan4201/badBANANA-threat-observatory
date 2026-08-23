export type RejectionReason = "REQUIRED_FIELD_MISSING" | "TYPE_INVALID" | "FORMAT_INVALID" | "VALUE_OUT_OF_RANGE" | "VALUE_TOO_LONG" | "UNSUPPORTED_VALUE" | "UNSAFE_SCHEME" | "INVALID_INDICATOR" | "NON_PUBLIC_IP" | "PROVIDER_IDENTITY_MISMATCH" | "RECORD_MALFORMED" | "RESPONSE_SCHEMA_INVALID";

export interface ValidationDiagnostic {
  source: string;
  field: string;
  reason: RejectionReason;
  count: number;
  detectedAt: string;
  normalizerVersion: 1;
}

const SOURCE_FIELDS: Record<string, { id: string; indicator: string }> = {
  "cisa-kev": { id: "cveID", indicator: "cveID" },
  threatfox: { id: "id", indicator: "ioc_value" },
  urlhaus: { id: "id", indicator: "url" },
  malwarebazaar: { id: "sha256_hash", indicator: "sha256_hash" },
};

export function diagnoseRejectedRecord(source: string, raw: unknown, detectedAt: string): ValidationDiagnostic {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return diagnostic(source, "record", "RECORD_MALFORMED", detectedAt);
  const fields = SOURCE_FIELDS[source];
  if (!fields) return diagnostic(source, "record", "RECORD_MALFORMED", detectedAt);
  const record = raw as Record<string, unknown>;
  if (record[fields.id] === undefined || record[fields.id] === null || record[fields.id] === "") return diagnostic(source, fields.id, "REQUIRED_FIELD_MISSING", detectedAt);
  if (record[fields.indicator] === undefined || record[fields.indicator] === null || record[fields.indicator] === "") return diagnostic(source, fields.indicator, "REQUIRED_FIELD_MISSING", detectedAt);
  if (typeof record[fields.indicator] !== "string") return diagnostic(source, fields.indicator, "TYPE_INVALID", detectedAt);
  return diagnostic(source, "record", "RECORD_MALFORMED", detectedAt);
}

export function aggregateDiagnostics(values: ValidationDiagnostic[]): ValidationDiagnostic[] {
  const grouped = new Map<string, ValidationDiagnostic>();
  for (const value of values) {
    const key = `${value.source}\u0000${value.field}\u0000${value.reason}`;
    const current = grouped.get(key);
    grouped.set(key, current ? { ...current, count: current.count + value.count } : value);
  }
  return [...grouped.values()].sort((left, right) => left.field.localeCompare(right.field) || left.reason.localeCompare(right.reason));
}

function diagnostic(source: string, field: string, reason: RejectionReason, detectedAt: string): ValidationDiagnostic {
  return { source, field, reason, count: 1, detectedAt, normalizerVersion: 1 };
}
