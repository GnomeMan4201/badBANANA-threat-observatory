import type { ObservationScope, TimeWindow } from "./threat-types";

const windows = new Set<TimeWindow>(["15m", "1h", "6h", "24h", "7d"]);
export function parseLimit(value: string | null): number { if (value === null || value.trim() === "") return 100; const parsed = Number(value); return Number.isFinite(parsed) ? Math.min(500, Math.max(1, Math.floor(parsed))) : 100; }
export function parseWindow(value: string | null): TimeWindow { return value && windows.has(value as TimeWindow) ? value as TimeWindow : "24h"; }
const scopes = new Set<ObservationScope>(["all", "urlhaus", "malwarebazaar", "infrastructure"]);
export function parseObservationScope(value: string | null): ObservationScope { return value && scopes.has(value as ObservationScope) ? value as ObservationScope : "all"; }
export function parseSearchQuery(value: string | null): string | null { if (!value) return null; const query = value.trim(); return query.length >= 2 && query.length <= 160 && !/[\u0000-\u001f]/.test(query) ? query : null; }
// Browser CSRF mitigation only: direct non-browser HTTP clients may omit Origin/Sec-Fetch-Site, so this is not an authentication boundary.
export function isSameOriginMutation(request: Request): boolean {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") return false;
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try { return new URL(origin).origin === new URL(request.url).origin; }
  catch { return false; }
}

export interface PageCursor { sort: string; id: string; }

export function encodeCursor(cursor: PageCursor): string {
  const bytes = new TextEncoder().encode(JSON.stringify(cursor));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function parseCursor(value: string | null): PageCursor | null {
  if (!value || value.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Partial<PageCursor>;
    if (typeof parsed.sort !== "string" || parsed.sort.length > 64 || typeof parsed.id !== "string" || !parsed.id || parsed.id.length > 320) return null;
    const timestamp = new Date(parsed.sort);
    return !Number.isNaN(timestamp.getTime()) && timestamp.toISOString() === parsed.sort ? { sort: parsed.sort, id: parsed.id } : null;
  } catch {
    return null;
  }
}
