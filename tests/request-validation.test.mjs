import assert from "node:assert/strict";
import test from "node:test";
import { encodeCursor, parseCursor, parseLimit, parseSearchQuery, parseWindow } from "../lib/request-validation.ts";

test("bounds query inputs", () => {
  assert.equal(parseLimit("99999"), 500);
  assert.equal(parseLimit("bad"), 100);
  assert.equal(parseWindow("bogus"), "24h");
  assert.equal(parseWindow("6h"), "6h");
  assert.equal(parseSearchQuery("x"), null);
  assert.equal(parseSearchQuery("CVE-2026-12345"), "CVE-2026-12345");
  assert.equal(parseSearchQuery("a".repeat(161)), null);
});

test("pagination cursors round-trip and malformed cursors fail closed", () => {
  const encoded = encodeCursor({ sort: "2026-08-21T07:00:00.000Z", id: "cisa-kev:CVE-2026-1234" });
  assert.deepEqual(parseCursor(encoded), { sort: "2026-08-21T07:00:00.000Z", id: "cisa-kev:CVE-2026-1234" });
  assert.equal(parseCursor("not+base64"), null);
  assert.equal(parseCursor(encodeCursor({ sort: "not-a-time", id: "record" })), null);
  assert.equal(parseCursor("a".repeat(1025)), null);
});
