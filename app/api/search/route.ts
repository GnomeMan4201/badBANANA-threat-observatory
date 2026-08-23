import { checkRateLimit } from "../../../lib/rate-limit";
import { parseCursor, parseLimit, parseObservationScope, parseSearchQuery, parseWindow } from "../../../lib/request-validation";
import { searchLocalObservatory } from "../../../lib/server/observatory";

export async function GET(request: Request) {
  const rate = checkRateLimit(request);
  if (!rate.allowed) return Response.json({ records: [], error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const url = new URL(request.url);
  const query = parseSearchQuery(url.searchParams.get("q"));
  if (!query) return Response.json({ records: [], error: "Search query must contain 2-160 printable characters" }, { status: 400 });
  const cursorValue = url.searchParams.get("cursor");
  const cursor = parseCursor(cursorValue);
  if (cursorValue && !cursor) return Response.json({ records: [], error: "Invalid pagination cursor" }, { status: 400 });
  const payload = await searchLocalObservatory(query, parseWindow(url.searchParams.get("window")), Math.min(parseLimit(url.searchParams.get("limit")), 100), cursor, parseObservationScope(url.searchParams.get("scope")));
  return Response.json(payload, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
