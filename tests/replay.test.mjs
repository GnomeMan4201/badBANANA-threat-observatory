import assert from "node:assert/strict";
import test from "node:test";
import { buildReplayFrame, orderReplayEvents, replayIndicator, replaySourceOrder } from "../lib/replay.ts";

const record = (id, source = "threatfox") => ({ id, source, kind: "domain", indicator: `${id}.example`, observedAt: "2026-08-21T00:00:00.000Z", tags: [], ingestedAt: "2026-08-21T00:00:01.000Z", metadata: {} });
const event = (eventId, observationId, eventType, detectedAt, current, previous, source = "threatfox") => ({ eventId, observationId, eventType, detectedAt, current, previous, source, diff: [] });

test("replay orders the ledger by observatory detection time", () => {
  const late = event("2", "b", "new", "2026-08-21T00:02:00.000Z", record("b"));
  const early = event("1", "a", "new", "2026-08-21T00:01:00.000Z", record("a"));
  assert.deepEqual(orderReplayEvents([late, early]).map((item) => item.eventId), ["1", "2"]);
});

test("replay applies material transitions without inventing unseen baseline state", () => {
  const first = record("a");
  const changed = { ...first, malwareFamily: "Example" };
  const events = [
    event("1", "a", "new", "2026-08-21T00:01:00.000Z", first),
    event("2", "a", "updated", "2026-08-21T00:02:00.000Z", changed, first),
    event("3", "a", "removed", "2026-08-21T00:03:00.000Z", undefined, changed),
  ];
  assert.equal(buildReplayFrame(events, 0)[0].state, "present");
  assert.equal(buildReplayFrame(events, 1)[0].record.malwareFamily, "Example");
  assert.equal(buildReplayFrame(events, 2)[0].state, "removed");
  assert.equal(buildReplayFrame(events, -1).length, 0);
});

test("source lanes are ordered by event count then name", () => {
  const events = [event("1", "a", "new", "2026-08-21T00:01:00.000Z", record("a", "urlhaus"), undefined, "urlhaus"), event("2", "b", "new", "2026-08-21T00:02:00.000Z", record("b", "cisa-kev"), undefined, "cisa-kev"), event("3", "c", "new", "2026-08-21T00:03:00.000Z", record("c", "urlhaus"), undefined, "urlhaus")];
  assert.deepEqual(replaySourceOrder(events), ["urlhaus", "cisa-kev"]);
});

test("replay defangs URL indicators while preserving other indicator types", () => {
  const urlRecord = { ...record("url", "urlhaus"), kind: "url", indicator: "http://112.198.130.112:60062/bin.sh" };
  const urlEvent = event("4", "url", "updated", "2026-08-21T00:04:00.000Z", urlRecord, undefined, "urlhaus");
  assert.equal(replayIndicator(urlEvent), "hxxp://112[.]198[.]130[.]112:60062/bin[.]sh");

  const domainEvent = event("5", "domain", "new", "2026-08-21T00:05:00.000Z", record("domain"));
  assert.equal(replayIndicator(domainEvent), "domain.example");
});
