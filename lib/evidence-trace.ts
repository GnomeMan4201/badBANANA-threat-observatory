import type { NormalizedObservation } from "./threat-types";

const OPTIONAL_FIELDS: Array<keyof NormalizedObservation> = ["sourceRecordId", "indicator", "indicatorType", "title", "malwareFamily", "threatType", "confidence", "firstSeen", "lastSeen", "reference"];

export interface EvidenceTrace {
  schemaVersion: 1;
  acceptedFields: string[];
  absentOptionalFields: string[];
  displayTransforms: string[];
  classificationDecision: string;
  identityDecision: string;
}

export function buildEvidenceTrace(record: NormalizedObservation): EvidenceTrace {
  const acceptedFields = Object.entries(record)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([field]) => field)
    .sort();
  return {
    schemaVersion: 1,
    acceptedFields,
    absentOptionalFields: OPTIONAL_FIELDS.filter((field) => record[field] === undefined).map(String),
    displayTransforms: record.kind === "url" ? ["URL defanged for display only; stored value unchanged"] : [],
    classificationDecision: record.indicatorType
      ? `Normalized kind ${record.kind} derived from validated indicator plus source type ${record.indicatorType}`
      : `Normalized kind ${record.kind} derived from validated source fields`,
    identityDecision: `Observatory identity ${record.id} derived from source ${record.source} and its stable source record identity`,
  };
}
