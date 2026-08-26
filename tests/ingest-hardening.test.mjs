import assert from "node:assert/strict";
import test from "node:test";
import { checkIngestRateLimit } from "../lib/rate-limit.ts";
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

test("D1-backed ingest limiter executes shared atomic increments and allows only six requests", async () => {
  const database = createD1RateLimitMock();
  const request = new Request("https://observatory.test/api/ingest", {
    method: "POST",
    headers: { "cf-connecting-ip": "198.51.100.44" },
  });

  const results = await Promise.all(Array.from({ length: 7 }, () => checkIngestRateLimit(request, database)));
  assert.equal(results.filter((result) => result.allowed).length, 6);
  assert.equal(results.filter((result) => !result.allowed).length, 1);
  assert.deepEqual(results.map((result) => result.remaining).sort((left, right) => right - left), [5, 4, 3, 2, 1, 0, 0]);
  assert.equal(database.state.counts.size, 1);
  const [[storedKey, count]] = database.state.counts.entries();
  assert.equal(count, 7);
  assert.notEqual(storedKey.split(":", 1)[0], "198.51.100.44");
  assert.match(storedKey.split(":", 1)[0], /^[a-f0-9]{64}$/);
});

test("D1 ingest limiter falls back to isolate-local limiting when shared storage fails", async () => {
  const failingDatabase = {
    prepare() {
      throw new Error("D1 unavailable");
    },
  };
  const request = new Request("https://observatory.test/api/ingest", {
    method: "POST",
    headers: { "cf-connecting-ip": "198.51.100.45" },
  });

  const results = [];
  for (let attempt = 0; attempt < 7; attempt += 1) {
    results.push(await checkIngestRateLimit(request, failingDatabase));
  }
  assert.equal(results.filter((result) => result.allowed).length, 6);
  assert.equal(results.at(-1).allowed, false);
});

function createD1RateLimitMock() {
  const state = { counts: new Map(), queue: Promise.resolve() };

  const database = {
    state,
    prepare(sql) {
      const normalized = sql.replace(/\s+/g, " ").trim();
      return {
        bind(...args) {
          return statement(normalized, args);
        },
        run() {
          return statement(normalized, []).run();
        },
        first() {
          return statement(normalized, []).first();
        },
      };
    },
  };

  function statement(sql, args) {
    return {
      async run() {
        if (sql.startsWith("CREATE TABLE IF NOT EXISTS ingest_rate_limit")) return { success: true };
        if (sql.startsWith("DELETE FROM ingest_rate_limit")) {
          const cutoff = args[0];
          for (const key of state.counts.keys()) {
            const windowStart = Number(key.split(":").at(-1));
            if (windowStart < cutoff) state.counts.delete(key);
          }
          return { success: true };
        }
        throw new Error(`Unexpected run SQL: ${sql}`);
      },
      async first() {
        if (!sql.startsWith("INSERT INTO ingest_rate_limit") || !sql.includes("RETURNING count")) {
          throw new Error(`Unexpected first SQL: ${sql}`);
        }
        const [bucketKey, windowStart] = args;
        let result;
        state.queue = state.queue.then(() => {
          const key = `${bucketKey}:${windowStart}`;
          const count = (state.counts.get(key) ?? 0) + 1;
          state.counts.set(key, count);
          result = { count };
        });
        await state.queue;
        return result;
      },
    };
  }

  return database;
}
