import { checkRateLimit } from "../../../lib/rate-limit";
import { parseCursor, parseLimit, parseObservationScope, parseWindow } from "../../../lib/request-validation";
import { readObservatory } from "../../../lib/server/observatory";

export async function GET(request: Request) {
  const rate = checkRateLimit(request);
  if (!rate.allowed) return Response.json({ error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const url = new URL(request.url);
  const limit = parseLimit(url.searchParams.get("limit"));
  const cursorValue = url.searchParams.get("cursor");
  const cursor = parseCursor(cursorValue);
  if (cursorValue && !cursor) return Response.json({ error: "Invalid pagination cursor" }, { status: 400, headers: { "X-Content-Type-Options": "nosniff" } });
  const payload = await readObservatory(parseWindow(url.searchParams.get("window")), limit, cursor, parseObservationScope(url.searchParams.get("scope")));
  return Response.json(payload, { headers: apiHeaders(rate.remaining, 30) });
}

export function apiHeaders(remaining: number, maxAge: number): Record<string, string> {
  return { "Cache-Control": `private, max-age=${maxAge}`, "X-Content-Type-Options": "nosniff", "X-RateLimit-Remaining": String(remaining) };
}
