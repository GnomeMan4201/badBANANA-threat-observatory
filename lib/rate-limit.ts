interface Bucket {
  count: number;
  resetsAt: number;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

const buckets = new Map<string, Bucket>();
const ingestionBuckets = new Map<string, Bucket>();
const geoBuckets = new Map<string, Bucket>();
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 120;
const MAX_INGEST_REQUESTS = 6;
const MAX_GEO_REQUESTS = 12;

export const RATE_LIMIT_POLICY = {
  mechanism: "fixed-window counters",
  scope: "reads/geo best-effort isolate-local; ingestion D1-shared when DB is available with isolate-local fallback",
  readRequestsPerMinute: MAX_REQUESTS,
  ingestRequestsPerMinute: MAX_INGEST_REQUESTS,
  geoRequestsPerMinute: MAX_GEO_REQUESTS,
} as const;

export function checkRateLimit(request: Request): RateLimitResult {
  return checkBucket(request, buckets, MAX_REQUESTS);
}

export function checkIngestRateLimit(request: Request, database?: D1Database): RateLimitResult | Promise<RateLimitResult> {
  if (!database) return checkBucket(request, ingestionBuckets, MAX_INGEST_REQUESTS);
  return checkD1Bucket(request, database, MAX_INGEST_REQUESTS).catch(() => {
    // Availability takes precedence over overstating the control: if D1 cannot service
    // the shared counter, fall back explicitly to the documented isolate-local bucket.
    return checkBucket(request, ingestionBuckets, MAX_INGEST_REQUESTS);
  });
}

export function checkGeoRateLimit(request: Request): RateLimitResult {
  return checkBucket(request, geoBuckets, MAX_GEO_REQUESTS);
}

async function checkD1Bucket(request: Request, database: D1Database, maximum: number): Promise<RateLimitResult> {
  const now = Date.now();
  const windowStart = Math.floor(now / WINDOW_MS) * WINDOW_MS;
  const rawKey = clientKey(request);
  const bucketKey = await sha256(rawKey);

  await database.prepare(`
    CREATE TABLE IF NOT EXISTS ingest_rate_limit (
      bucket_key TEXT NOT NULL,
      window_start INTEGER NOT NULL,
      count INTEGER NOT NULL,
      PRIMARY KEY (bucket_key, window_start)
    )
  `).run();
  await database.prepare(`
    INSERT INTO ingest_rate_limit (bucket_key, window_start, count)
    VALUES (?, ?, 1)
    ON CONFLICT(bucket_key, window_start) DO UPDATE SET count = count + 1
  `).bind(bucketKey, windowStart).run();

  const row = await database.prepare(
    "SELECT count FROM ingest_rate_limit WHERE bucket_key = ? AND window_start = ?",
  ).bind(bucketKey, windowStart).first<{ count: number }>();
  const count = typeof row?.count === "number" ? row.count : maximum + 1;

  if (count === 1) {
    await database.prepare("DELETE FROM ingest_rate_limit WHERE window_start < ?")
      .bind(windowStart - (2 * WINDOW_MS))
      .run();
  }

  return {
    allowed: count <= maximum,
    remaining: Math.max(0, maximum - count),
    retryAfterSeconds: Math.max(1, Math.ceil(((windowStart + WINDOW_MS) - now) / 1000)),
  };
}

function checkBucket(request: Request, store: Map<string, Bucket>, maximum: number): RateLimitResult {
  const now = Date.now();
  const key = clientKey(request);
  const current = store.get(key);
  const bucket = !current || current.resetsAt <= now
    ? { count: 0, resetsAt: now + WINDOW_MS }
    : current;

  bucket.count += 1;
  store.set(key, bucket);

  if (store.size > 2_000) {
    for (const [bucketKey, value] of store) {
      if (value.resetsAt <= now) store.delete(bucketKey);
    }
  }

  return {
    allowed: bucket.count <= maximum,
    remaining: Math.max(0, maximum - bucket.count),
    retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetsAt - now) / 1000)),
  };
}

function clientKey(request: Request): string {
  // Cloudflare Workers overwrite cf-connecting-ip at the edge; this keying assumption is only valid behind that trusted edge.
  return request.headers.get("cf-connecting-ip") ?? "anonymous";
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
