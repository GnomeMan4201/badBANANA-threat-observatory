import { checkRateLimit } from "../../../lib/rate-limit";
import { queryObservationPeers } from "../../../lib/server/history";

export async function GET(request: Request) {
  const rate = checkRateLimit(request);
  if (!rate.allowed) return Response.json({ records: [], error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const id = new URL(request.url).searchParams.get("id")?.trim();
  if (!id || id.length > 320 || /[\u0000-\u001f]/.test(id)) return Response.json({ records: [], error: "Invalid observation identity" }, { status: 400 });
  return Response.json({ records: await queryObservationPeers(id), scope: "current-state exact-indicator equality" }, { headers: { "Cache-Control": "private, max-age=30", "X-Content-Type-Options": "nosniff" } });
}
