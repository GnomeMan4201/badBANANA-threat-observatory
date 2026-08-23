import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { isSameOriginMutation } from "../lib/request-validation.ts";

test("maintenance mutation requires an explicit exact same-origin browser origin", () => {
  assert.equal(isSameOriginMutation(new Request("https://observatory.test/api/ingest", { method: "POST" })), false);
  assert.equal(isSameOriginMutation(new Request("https://observatory.test/api/ingest", {
    method: "POST",
    headers: { origin: "https://observatory.test", "sec-fetch-site": "same-origin" },
  })), true);
  assert.equal(isSameOriginMutation(new Request("https://observatory.test/api/ingest", {
    method: "POST",
    headers: { origin: "https://foreign.test", "sec-fetch-site": "cross-site" },
  })), false);
});

test("ingest route uses the D1-backed shared limiter when the database binding exists", async () => {
  const route = await readFile(new URL("../app/api/ingest/route.ts", import.meta.url), "utf8");
  const limiter = await readFile(new URL("../lib/rate-limit.ts", import.meta.url), "utf8");
  assert.match(route, /await checkIngestRateLimit\(request, getDatabase\(\)\)/);
  assert.match(limiter, /CREATE TABLE IF NOT EXISTS ingest_rate_limit/);
  assert.match(limiter, /ON CONFLICT\(bucket_key, window_start\) DO UPDATE SET count = count \+ 1/);
  assert.match(limiter, /SHA-256/);
  assert.match(limiter, /isolate-local fallback/);
});
