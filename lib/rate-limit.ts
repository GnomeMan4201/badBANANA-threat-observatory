interface Bucket {
  count: number;
  resetsAt: number;
}

const buckets = new Map<string, Bucket>();
const ingestionBuckets = new Map<string, Bucket>();
const geoBuckets = new Map<string, Bucket>();
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 120;
const MAX_INGEST_REQUESTS = 6;
const MAX_GEO_REQUESTS = 12;

export const RATE_LIMIT_POLICY = {
  mechanism: "in-memory fixed-window counter",
  scope: "best-effort isolate-local",
  readRequestsPerMinute: MAX_REQUESTS,
  ingestRequestsPerMinute: MAX_INGEST_REQUESTS,
  geoRequestsPerMinute: MAX_GEO_REQUESTS,
} as const;

export function checkRateLimit(request: Request): {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
} {
  return checkBucket(request, buckets, MAX_REQUESTS);
}

export function checkIngestRateLimit(request: Request): {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
} {
  return checkBucket(request, ingestionBuckets, MAX_INGEST_REQUESTS);
}

export function checkGeoRateLimit(request: Request): {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
} {
  return checkBucket(request, geoBuckets, MAX_GEO_REQUESTS);
}

function checkBucket(request: Request, store: Map<string, Bucket>, maximum: number): {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
} {
  const now = Date.now();
  const key = request.headers.get("cf-connecting-ip") ?? "anonymous";
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
