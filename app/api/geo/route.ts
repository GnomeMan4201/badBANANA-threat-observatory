import { checkGeoRateLimit } from "../../../lib/rate-limit";
import { parseWindow } from "../../../lib/request-validation";
import { buildGeoPayload } from "../../../lib/server/geo";
import { readGeoCandidates } from "../../../lib/server/observatory";

export async function GET(request: Request) {
  const rate = checkGeoRateLimit(request);
  if (!rate.allowed) return Response.json({ error: "Geography request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds), "X-Content-Type-Options": "nosniff" } });
  const url = new URL(request.url);
  const candidates = await readGeoCandidates(parseWindow(url.searchParams.get("window")));
  const payload = await buildGeoPayload(candidates.records, { candidateRecords: candidates.total, candidateRecordsTruncated: candidates.truncated });
  return Response.json(payload, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-RateLimit-Remaining": String(rate.remaining) } });
}
