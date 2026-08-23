import type { EventLedgerBounds, ObservationEvent } from "./threat-types";
import { parseTimestamp } from "./normalize.ts";

export const ACKNOWLEDGEMENT_SCHEMA_VERSION = 1;

export interface DeviceAcknowledgement {
  schemaVersion: 1;
  acknowledgedEventId: string;
  acknowledgedDetectedAt: string;
  acknowledgedDatasetRevision: string;
  acknowledgedAt: string;
  deviceGeneratedId: string;
}

export type BriefingState = "initial-baseline" | "changes" | "ledger-gap" | "no-changes";

export interface BriefingSummary {
  state: BriefingState;
  events: ObservationEvent[];
  newCount: number;
  updatedCount: number;
  removedCount: number;
  latestEvent?: ObservationEvent;
}

export function summarizeBriefing(events: ObservationEvent[], acknowledgement?: DeviceAcknowledgement | null, ledger?: EventLedgerBounds): BriefingSummary {
  const ordered = [...events].sort((left, right) => right.detectedAt.localeCompare(left.detectedAt) || right.eventId.localeCompare(left.eventId));
  if (!acknowledgement) return counts("initial-baseline", ordered, ordered[0]);
  const acknowledgedIndex = ordered.findIndex((event) => event.eventId === acknowledgement.acknowledgedEventId);
  const oldestRetained = ledger?.oldestRetainedDetectedAt ?? ordered.at(-1)?.detectedAt;
  if (acknowledgedIndex < 0 && oldestRetained && acknowledgement.acknowledgedDetectedAt < oldestRetained) {
    return counts("ledger-gap", ordered, ordered[0]);
  }
  const newer = ordered.filter((event) => event.detectedAt > acknowledgement.acknowledgedDetectedAt);
  if (newer.length) return counts("changes", newer, ordered[0]);
  return counts("no-changes", [], ordered[0]);
}

export function createAcknowledgement(latest: ObservationEvent, datasetRevision: string, deviceGeneratedId: string, now = new Date().toISOString()): DeviceAcknowledgement {
  const acknowledgedDetectedAt = parseTimestamp(latest.detectedAt);
  const acknowledgedAt = parseTimestamp(now);
  if (!acknowledgedDetectedAt || !acknowledgedAt) throw new Error("Acknowledgement timestamps must be valid and canonicalizable");
  return {
    schemaVersion: ACKNOWLEDGEMENT_SCHEMA_VERSION,
    acknowledgedEventId: latest.eventId,
    acknowledgedDetectedAt,
    acknowledgedDatasetRevision: datasetRevision,
    acknowledgedAt,
    deviceGeneratedId,
  };
}

export function parseAcknowledgement(value: unknown): DeviceAcknowledgement | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<DeviceAcknowledgement>;
  if (candidate.schemaVersion !== ACKNOWLEDGEMENT_SCHEMA_VERSION) return null;
  if (![candidate.acknowledgedEventId, candidate.acknowledgedDetectedAt, candidate.acknowledgedDatasetRevision, candidate.acknowledgedAt, candidate.deviceGeneratedId].every((item) => typeof item === "string" && item.length > 0 && item.length <= 200)) return null;
  const acknowledgedDetectedAt = parseTimestamp(candidate.acknowledgedDetectedAt);
  const acknowledgedAt = parseTimestamp(candidate.acknowledgedAt);
  if (!acknowledgedDetectedAt || !acknowledgedAt) return null;
  return { ...(candidate as DeviceAcknowledgement), acknowledgedDetectedAt, acknowledgedAt };
}

function counts(state: BriefingState, events: ObservationEvent[], latestEvent?: ObservationEvent): BriefingSummary {
  return {
    state,
    events,
    newCount: events.filter((event) => event.eventType === "new").length,
    updatedCount: events.filter((event) => event.eventType === "updated").length,
    removedCount: events.filter((event) => event.eventType === "removed").length,
    latestEvent,
  };
}
