import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import { stripTypeScriptTypes } from "node:module";
import { isSameOriginMutation } from "../lib/request-validation.ts";
import { isAuthorizedMaintenanceBearer } from "../lib/maintenance-auth.ts";

const INGEST_URL = "https://observatory.test/api/ingest";
const TOKEN = "a".repeat(48);

async function routeHarness(...tokenArgs) {
  const configuredToken = tokenArgs.length ? tokenArgs[0] : TOKEN;
  // Evaluate the unmodified POST implementation with isolated dependencies, so
  // assertions exercise the route itself without network calls or ingestion.
  const source = await readFile(new URL("../app/api/ingest/route.ts", import.meta.url), "utf8");
  const noImports = source.replace(/^import .*;\r?\n/gm, "");
  assert.doesNotMatch(noImports, /^import /m);
  const executable = stripTypeScriptTypes(noImports.replace("export async function POST", "async function POST"));
  assert.notEqual(executable, noImports);
  const calls = { ingestion: 0, limiter: 0 };
  const context = {
    Request, Response,
    isSameOriginMutation,
    isAuthorizedMaintenanceBearer,
    getMaintenanceToken: () => configuredToken,
    getDatabase: () => undefined,
    checkIngestRateLimit: async () => { calls.limiter += 1; return { allowed: true, retryAfterSeconds: 0 }; },
    runIngestionCycle: async () => { calls.ingestion += 1; return { mode: "demand-driven", status: "healthy" }; },
  };
  return { POST: runInNewContext(executable + "\nPOST", context), calls };
}

function request(headers = {}) {
  return new Request(INGEST_URL, { method: "POST", headers });
}

test("valid bearer token bypasses origin and runs ingestion after rate limit", async () => {
  const { POST, calls } = await routeHarness();
  const response = await POST(request({ Authorization: `Bearer ${TOKEN}`, Origin: "https://foreign.test", "sec-fetch-site": "cross-site" }));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ingestion: { mode: "demand-driven", status: "healthy" } });
  assert.equal(calls.limiter, 1);
  assert.equal(calls.ingestion, 1);
});

test("wrong bearer returns generic 401 without ingestion or origin fallback", async () => {
  const { POST, calls } = await routeHarness();
  const response = await POST(request({ Authorization: `Bearer ${"b".repeat(48)}`, Origin: "https://observatory.test", "sec-fetch-site": "same-origin" }));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "Unauthorized" });
  assert.equal(calls.limiter, 0);
  assert.equal(calls.ingestion, 0);
});

test("unset, too-short, and malformed bearer authorization all receive the same 401", async () => {
  for (const configured of [undefined, "short", TOKEN]) {
    const { POST, calls } = await routeHarness(configured);
    const value = configured === TOKEN ? "Basic not-a-bearer" : `Bearer ${TOKEN}`;
    const response = await POST(request({ Authorization: value, Origin: "https://observatory.test" }));
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "Unauthorized" });
    assert.equal(calls.ingestion, 0);
    assert.equal(calls.limiter, 0);
  }
});

test("absent authorization and cross-origin request retain 403 behavior", async () => {
  const { POST, calls } = await routeHarness();
  const response = await POST(request({ Origin: "https://foreign.test", "sec-fetch-site": "cross-site" }));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "Same-origin browser maintenance request required" });
  assert.equal(calls.ingestion, 0);
});

test("absent authorization and same-origin request still runs ingestion", async () => {
  const { POST, calls } = await routeHarness();
  const response = await POST(request({ Origin: "https://observatory.test", "sec-fetch-site": "same-origin" }));
  assert.equal(response.status, 200);
  assert.equal(calls.limiter, 1);
  assert.equal(calls.ingestion, 1);
});

test("constant-time digest comparison handles matching, different and invalid secrets", async () => {
  assert.equal(await isAuthorizedMaintenanceBearer(`Bearer ${TOKEN}`, TOKEN), true);
  assert.equal(await isAuthorizedMaintenanceBearer(`Bearer ${"b".repeat(48)}`, TOKEN), false);
  assert.equal(await isAuthorizedMaintenanceBearer(`Bearer ${TOKEN}`, undefined), false);
  assert.equal(await isAuthorizedMaintenanceBearer(`Bearer ${TOKEN}`, "short"), false);
});
