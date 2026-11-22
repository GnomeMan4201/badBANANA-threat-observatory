import { checkIngestRateLimit } from "../../../lib/rate-limit";
import { isAuthorizedMaintenanceBearer } from "../../../lib/maintenance-auth";
import { isSameOriginMutation } from "../../../lib/request-validation";
import { runIngestionCycle } from "../../../lib/server/observatory";
import { getDatabase, getMaintenanceToken } from "../../../lib/server/runtime-config";

export async function POST(request: Request) {
  const authorization = request.headers.get("authorization");
  if (authorization !== null) {
    if (!(await isAuthorizedMaintenanceBearer(authorization, getMaintenanceToken()))) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: { "X-Content-Type-Options": "nosniff" } });
    }
  } else if (!isSameOriginMutation(request)) {
    return Response.json({ error: "Same-origin browser maintenance request required" }, { status: 403, headers: { "X-Content-Type-Options": "nosniff" } });
  }
  const rate = await checkIngestRateLimit(request, getDatabase());
  if (!rate.allowed) return Response.json({ error: "Request limit exceeded" }, { status: 429, headers: { "Retry-After": String(rate.retryAfterSeconds) } });
  const ingestion = await runIngestionCycle();
  return Response.json({ ingestion }, { headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
}
