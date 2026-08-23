import { checkRateLimit } from "../../../lib/rate-limit";
import { RATE_LIMIT_POLICY } from "../../../lib/rate-limit";
import { readObservatory } from "../../../lib/server/observatory";

export async function GET(request: Request) {
  const rate = checkRateLimit(request);
  if (!rate.allowed) return Response.json({ sources: [], error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const payload = await readObservatory("24h", 1);
  return Response.json({ sources: payload.sources, history: payload.history, freshness: payload.freshness, ingestion: payload.ingestion, rateLimit: RATE_LIMIT_POLICY, generatedAt: payload.generatedAt }, { headers: { "Cache-Control": "private, max-age=30", "X-Content-Type-Options": "nosniff" } });
}
