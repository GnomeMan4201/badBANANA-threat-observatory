export type KevRecentRange = "today" | "7d" | "30d";

export function recentKevCutoffDate(range: KevRecentRange, now = Date.now()): string {
  const days = range === "today" ? 0 : range === "7d" ? 7 : 30;
  return new Date(now - days * 24 * 60 * 60_000).toISOString().slice(0, 10);
}

export function recentKevRangeLabel(range: KevRecentRange): string {
  return range === "today" ? "TODAY" : range.toUpperCase();
}
