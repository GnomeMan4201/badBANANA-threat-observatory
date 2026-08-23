import { checkRateLimit } from "../../../lib/rate-limit";
import { parseCursor, parseLimit, parseSearchQuery } from "../../../lib/request-validation";
import { readCurrentKevCatalog } from "../../../lib/server/observatory";
import { parseCalendarDate } from "../../../lib/normalize";

export async function GET(request: Request) {
  const rate = checkRateLimit(request);
  if (!rate.allowed) return Response.json({ records: [], error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const url = new URL(request.url);
  const cursorValue = url.searchParams.get("cursor");
  const cursor = parseCursor(cursorValue);
  if (cursorValue && !cursor) return Response.json({ records: [], error: "Invalid pagination cursor" }, { status: 400 });
  const rawQuery = url.searchParams.get("q");
  const query = rawQuery ? parseSearchQuery(rawQuery) ?? undefined : undefined;
  if (rawQuery && !query) return Response.json({ records: [], error: "Search query must contain 2-160 printable characters" }, { status: 400 });
  const vendor = boundedFilter(url.searchParams.get("vendor"));
  const product = boundedFilter(url.searchParams.get("product"));
  const addedSince = parseDateFilter(url.searchParams.get("addedSince"));
  if (url.searchParams.has("addedSince") && !addedSince) return Response.json({ records: [], error: "Invalid date filter" }, { status: 400 });
  const payload = await readCurrentKevCatalog(Math.min(parseLimit(url.searchParams.get("limit")), 100), {
    query,
    vendor,
    product,
    ransomwareOnly: url.searchParams.get("ransomware") === "known",
    addedSince,
    cursor,
  });
  return Response.json(payload, { headers: { "Cache-Control": "private, max-age=60", "X-Content-Type-Options": "nosniff" } });
}

function boundedFilter(value: string | null): string | undefined {
  const cleaned = value?.trim();
  return cleaned && cleaned.length <= 160 && !/[\u0000-\u001f]/.test(cleaned) ? cleaned : undefined;
}

function parseDateFilter(value: string | null): string | undefined {
  return parseCalendarDate(value);
}
