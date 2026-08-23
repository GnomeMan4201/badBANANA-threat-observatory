export type EventWorkspace = "briefing" | "replay" | "events";

export interface EventRequestState {
  recentEventsCursor: string | null;
}

export function eventRequestPath(workspace: EventWorkspace, state: EventRequestState): string {
  const params = new URLSearchParams({ limit: workspace === "replay" ? "100" : "50" });
  if (workspace === "events" && state.recentEventsCursor) params.set("cursor", state.recentEventsCursor);
  return `/api/events?${params.toString()}`;
}
