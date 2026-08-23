import type { NormalizedObservation, ObservationEvent } from "./threat-types";
import { defangUrl } from "./normalize";

export interface ReplayEntity {
  observationId: string;
  record: NormalizedObservation;
  state: "present" | "removed";
  event: ObservationEvent;
}

export function orderReplayEvents(events: ObservationEvent[]): ObservationEvent[] {
  return [...events].sort((left, right) => {
    const time = Date.parse(left.detectedAt) - Date.parse(right.detectedAt);
    return time || left.eventId.localeCompare(right.eventId);
  });
}

export function buildReplayFrame(events: ObservationEvent[], cursor: number): ReplayEntity[] {
  const ordered = orderReplayEvents(events);
  const entities = new Map<string, ReplayEntity>();
  ordered.slice(0, Math.max(0, cursor + 1)).forEach((event) => {
    const record = event.current ?? event.previous;
    if (!record) return;
    entities.set(event.observationId, {
      observationId: event.observationId,
      record,
      state: event.eventType === "removed" ? "removed" : "present",
      event,
    });
  });
  return [...entities.values()];
}

export function replaySourceOrder(events: ObservationEvent[]): string[] {
  const counts = new Map<string, number>();
  events.forEach((event) => counts.set(event.source, (counts.get(event.source) ?? 0) + 1));
  return [...counts.keys()].sort((left, right) => (counts.get(right) ?? 0) - (counts.get(left) ?? 0) || left.localeCompare(right));
}

export function replayIndicator(event: ObservationEvent): string {
  const record = event.current ?? event.previous;
  if (record?.kind === "url" && record.indicator) return defangUrl(record.indicator);
  return record?.indicator ?? record?.title ?? record?.sourceRecordId ?? event.observationId;
}
