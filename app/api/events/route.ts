import { checkRateLimit } from "../../../lib/rate-limit";
import { parseCursor, parseLimit } from "../../../lib/request-validation";
import { queryObservationEvents } from "../../../lib/server/history";

export async function GET(request: Request) {
  const rate = checkRateLimit(request);
  if (!rate.allowed) return Response.json({ events: [], error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const url = new URL(request.url);
  const cursorValue = url.searchParams.get("cursor");
  const cursor = parseCursor(cursorValue);
  if (cursorValue && !cursor) return Response.json({ events: [], error: "Invalid pagination cursor" }, { status: 400 });
  const payload = await queryObservationEvents(Math.min(parseLimit(url.searchParams.get("limit")), 100), cursor);
  return Response.json(payload, { headers: { "Cache-Control": "private, max-age=30", "X-Content-Type-Options": "nosniff" } });
}
