export function formatUtcTime(date: Date): string {
  return `${date.toISOString().slice(11, 19)} UTC`;
}

export function formatTimestamp(value?: string): string {
  return value
    ? `${new Date(value).toISOString().replace("T", " ").slice(0, 19)} UTC`
    : "NOT PROVIDED";
}
