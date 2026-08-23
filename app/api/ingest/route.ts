import { checkIngestRateLimit } from "../../../lib/rate-limit";
import { isSameOriginMutation } from "../../../lib/request-validation";
import { runIngestionCycle } from "../../../lib/server/observatory";

export async function POST(request: Request) {
  if (!isSameOriginMutation(request)) return Response.json({ error: "Cross-origin maintenance request rejected" }, { status: 403, headers: { "X-Content-Type-Options": "nosniff" } });
  const rate = checkIngestRateLimit(request);
  if (!rate.allowed) return Response.json({ error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const ingestion = await runIngestionCycle();
  return Response.json({ ingestion }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
