import test from "node:test";
import assert from "node:assert/strict";
import { aggregateDiagnostics, diagnoseRejectedRecord } from "../lib/rejection-diagnostics.ts";

test("rejection diagnostics retain bounded reasons without rejected values or synthetic identity", () => {
  const detectedAt = "2026-08-21T12:00:00.000Z";
  const missing = diagnoseRejectedRecord("urlhaus", { id: 7 }, detectedAt);
  assert.deepEqual(missing, { source: "urlhaus", field: "url", reason: "REQUIRED_FIELD_MISSING", count: 1, detectedAt, normalizerVersion: 1 });
  assert.equal("rawValue" in missing, false);
  assert.equal("observationId" in missing, false);
});

test("equal validation failures aggregate without changing their reason", () => {
  const detectedAt = "2026-08-21T12:00:00.000Z";
  const result = aggregateDiagnostics([
    diagnoseRejectedRecord("threatfox", null, detectedAt),
    diagnoseRejectedRecord("threatfox", [], detectedAt),
  ]);
  assert.equal(result.length, 1);
  assert.equal(result[0].reason, "RECORD_MALFORMED");
  assert.equal(result[0].count, 2);
});
