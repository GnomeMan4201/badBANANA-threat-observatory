import assert from "node:assert/strict";
import test from "node:test";
import {
  acquireInMemoryLease,
  backoffDelayMs,
  diffNormalizedObservation,
  filterKevCatalogRecords,
  hashNormalizedObservation,
  inactiveCisaCutoff,
  ingestionHealthWithCycles,
  INACTIVE_CISA_RETENTION_MS,
  isBackoffActive,
  nextRetryAt,
  pruneMemoryEvents,
  pruneMemoryHistory,
  searchStoredRecords,
  selectLeaseBackend,
  snapshotOnlyHealth,
  statusDuringBackoff,
  statusForSnapshotRead,
  summarizeFreshness,
  sourceEligibility,
  upsertMemoryLedger,
  upsertMemoryHistory,
} from "../lib/history-core.ts";
import { findSourceAdapter } from "../lib/source-adapter.ts";

const base = {
  id: "threatfox:123",
  source: "threatfox",
  sourceRecordId: "123",
  kind: "domain",
  indicator: "signal.example",
  indicatorType: "domain",
  title: "Signal",
  observedAt: "2026-08-21T06:00:00.000Z",
  ingestedAt: "2026-08-21T06:10:00.000Z",
  tags: ["watch"],
  metadata: {},
};

test("history insertion creates one stable row", async () => {
  const history = new Map();
  const inserted = await upsertMemoryHistory(history, [base], "2026-08-21T06:10:00.000Z");
  assert.equal(history.size, 1);
  assert.equal(inserted[0].ingestState, "new");
  assert.equal(inserted[0].firstIngestedAt, "2026-08-21T06:10:00.000Z");
});

test("same source record re-ingestion preserves first and advances last ingestion", async () => {
  const history = new Map();
  await upsertMemoryHistory(history, [base], "2026-08-21T06:10:00.000Z");
  const repeated = await upsertMemoryHistory(history, [base], "2026-08-21T07:10:00.000Z");
  assert.equal(history.size, 1);
  assert.equal(repeated[0].firstIngestedAt, "2026-08-21T06:10:00.000Z");
  assert.equal(repeated[0].lastIngestedAt, "2026-08-21T07:10:00.000Z");
  assert.equal(repeated[0].ingestState, "seen");
});

test("record hash is stable and detects normalized change", async () => {
  assert.equal(await hashNormalizedObservation(base), await hashNormalizedObservation({ ...base }));
  const history = new Map();
  await upsertMemoryHistory(history, [base], "2026-08-21T06:10:00.000Z");
  const changed = await upsertMemoryHistory(history, [{ ...base, title: "Changed upstream" }], "2026-08-21T07:10:00.000Z");
  assert.equal(changed[0].ingestState, "updated");
});

test("tag ordering, case and duplication cannot create false material changes", async () => {
  const history = new Map();
  await upsertMemoryLedger(history, [{ ...base, tags: ["Linux", "botnet", "linux"] }], "2026-08-21T06:10:00.000Z");
  const repeated = await upsertMemoryLedger(history, [{ ...base, tags: ["BOTNET", "linux"] }], "2026-08-21T06:20:00.000Z");
  assert.equal(repeated.updatedRecords, 0);
  assert.equal(repeated.unchangedRecords, 1);
  assert.equal(repeated.events.length, 0);
});

test("new and changed records create events while unchanged sightings do not", async () => {
  const history = new Map();
  const first = await upsertMemoryLedger(history, [base], "2026-08-21T06:10:00.000Z");
  assert.equal(first.events.length, 1);
  assert.equal(first.events[0].eventType, "new");
  const unchanged = await upsertMemoryLedger(history, [base], "2026-08-21T06:20:00.000Z");
  assert.equal(unchanged.events.length, 0);
  assert.equal(unchanged.unchangedRecords, 1);
  assert.equal(unchanged.records[0].lastChangedAt, "2026-08-21T06:10:00.000Z");
  assert.equal(unchanged.records[0].revisionCount, 1);
  const changed = await upsertMemoryLedger(history, [{ ...base, confidence: 85 }], "2026-08-21T06:30:00.000Z");
  assert.equal(changed.events.length, 1);
  assert.equal(changed.events[0].eventType, "updated");
  assert.equal(changed.events[0].previous?.confidence, undefined);
  assert.equal(changed.events[0].current?.confidence, 85);
  assert.equal(changed.records[0].revisionCount, 2);
  const seenAgain = await upsertMemoryLedger(history, [{ ...base, confidence: 85 }], "2026-08-21T06:40:00.000Z");
  assert.equal(seenAgain.events.length, 0);
  assert.equal(seenAgain.records[0].lastChangedAt, "2026-08-21T06:30:00.000Z");
  assert.equal(seenAgain.records[0].revisionCount, 2);
});

test("field diff excludes volatile Observatory ingestion fields", () => {
  const diffs = diffNormalizedObservation(
    { ...base, lastIngestedAt: "2026-08-21T06:10:00.000Z", metadata: { score: 1 } },
    { ...base, confidence: 90, lastIngestedAt: "2026-08-21T07:10:00.000Z", metadata: { score: 2 } },
  );
  assert.deepEqual(diffs.map((diff) => diff.field), ["confidence", "metadata.score"]);
});

test("cross-source equal indicators remain independent evidence rows", async () => {
  const history = new Map();
  await upsertMemoryHistory(history, [base, { ...base, id: "urlhaus:987", source: "urlhaus", sourceRecordId: "987" }], "2026-08-21T06:10:00.000Z");
  assert.equal(history.size, 2);
  assert.deepEqual([...history.values()].map((record) => record.source).sort(), ["threatfox", "urlhaus"]);
});

test("seven-day retention prunes on Observatory last-ingested time", () => {
  const history = new Map([
    ["old", { ...base, id: "old", lastIngestedAt: "2026-08-13T00:00:00.000Z" }],
    ["kept", { ...base, id: "kept", lastIngestedAt: "2026-08-20T00:00:00.000Z" }],
  ]);
  assert.equal(pruneMemoryHistory(history, Date.parse("2026-08-21T00:00:00.000Z")), 1);
  assert.deepEqual([...history.keys()], ["kept"]);
});

test("history search is scoped to the selected source-time window", () => {
  const records = [base, { ...base, id: "old", observedAt: "2026-08-19T00:00:00.000Z" }];
  assert.deepEqual(searchStoredRecords(records, "signal", "24h", 100, Date.parse("2026-08-21T07:00:00.000Z")).map((record) => record.id), [base.id]);
});

test("D1-unavailable semantics report snapshot-only degradation", () => {
  const health = snapshotOnlyHealth([base], "D1 unavailable");
  assert.equal(health.mode, "snapshot-only");
  assert.equal(health.status, "degraded");
  assert.equal(health.retentionDays, 7);
});

test("source retry backoff is bounded and exposes next retry", () => {
  assert.deepEqual([1, 2, 3, 4, 8].map((failure) => backoffDelayMs(failure)), [60_000, 120_000, 300_000, 900_000, 1_800_000]);
  const retry = nextRetryAt(2, "2026-08-21T06:00:00.000Z");
  assert.equal(retry, "2026-08-21T06:02:00.000Z");
  assert.equal(isBackoffActive({ nextRetryAt: retry }, Date.parse("2026-08-21T06:01:00.000Z")), true);
  assert.equal(statusDuringBackoff(4), "stale");
  assert.equal(statusDuringBackoff(0), "offline");
});

test("ingestion eligibility respects configuration, TTL and backoff", () => {
  const snapshot = { records: [base], fetchedAt: "2026-08-21T06:00:00.000Z", expiresAt: "2026-08-21T06:30:00.000Z", health: { id: "threatfox" } };
  assert.equal(sourceEligibility(snapshot, false, Date.parse("2026-08-21T06:10:00.000Z")), "disabled");
  assert.equal(sourceEligibility(snapshot, true, Date.parse("2026-08-21T06:10:00.000Z")), "fresh");
  assert.equal(sourceEligibility({ ...snapshot, expiresAt: "2026-08-21T06:05:00.000Z", health: { id: "threatfox", nextRetryAt: "2026-08-21T06:20:00.000Z" } }, true, Date.parse("2026-08-21T06:10:00.000Z")), "backoff");
  assert.equal(sourceEligibility({ ...snapshot, expiresAt: "2026-08-21T06:05:00.000Z" }, true, Date.parse("2026-08-21T06:10:00.000Z")), "eligible");
});

test("expired healthy snapshots are reported stale on read", () => {
  const health = { id: "threatfox", status: "healthy" };
  const now = Date.parse("2026-08-26T22:00:00.000Z");
  assert.equal(statusForSnapshotRead({ expiresAt: "2026-08-24T23:20:00.000Z", health }, now), "stale");
  assert.equal(statusForSnapshotRead({ expiresAt: "2026-08-26T22:20:00.000Z", health }, now), "healthy");
  assert.equal(statusForSnapshotRead({ expiresAt: "invalid", health }, now), "stale");
  assert.equal(statusForSnapshotRead({ expiresAt: "2026-08-26T22:20:00.000Z", health: { ...health, status: "offline" } }, now), "offline");
});

test("a concurrent refresh lease admits one holder until expiry", () => {
  const leases = new Map();
  assert.equal(acquireInMemoryLease(leases, "cisa-kev", "a", 1_000, 120_000), true);
  assert.equal(acquireInMemoryLease(leases, "cisa-kev", "b", 2_000, 120_000), false);
  assert.equal(acquireInMemoryLease(leases, "cisa-kev", "b", 121_001, 120_000), true);
});

test("stored ingestion health preserves the backend used by the reported cycle", () => {
  const stored = {
    mode: "demand-driven", status: "degraded", schedulerSupported: false,
    sourcesEligible: 1, totalSources: 4, leaseBackend: "isolate-memory",
    reason: "Persistent coordination was unavailable", latestSourceCycles: [],
  };
  const hydrated = ingestionHealthWithCycles(stored, [{ source: "threatfox", startedAt: "2026-08-21T06:00:00.000Z", completedAt: "2026-08-21T06:00:01.000Z", status: "success", upstreamRecords: 1, validRecords: 1, rejectedRecords: 0, newRecords: 1, updatedRecords: 0, unchangedRecords: 0, removedRecords: 0, latencyMs: 1_000 }]);
  assert.equal(hydrated.leaseBackend, "isolate-memory");
  assert.equal(hydrated.status, "degraded");
  assert.equal(hydrated.latestSourceCycles.length, 1);
  assert.equal(selectLeaseBackend(["d1", "isolate-memory"], "d1"), "isolate-memory");
});

test("inactive CISA current-state rows have a bounded 30-day retention cutoff", () => {
  const now = Date.parse("2026-08-21T00:00:00.000Z");
  assert.equal(Date.parse(inactiveCisaCutoff(now)), now - INACTIVE_CISA_RETENTION_MS);
});

test("source adapters are selected by stable identity rather than array position", () => {
  const adapters = [{ id: "threatfox" }, { id: "cisa-kev" }];
  assert.equal(findSourceAdapter(adapters, "cisa-kev")?.id, "cisa-kev");
  assert.equal(findSourceAdapter(adapters, "missing"), undefined);
});

test("event retention keeps only seven days of meaningful changes", () => {
  const events = [
    { eventId: "old", observationId: base.id, source: base.source, eventType: "new", detectedAt: "2026-08-10T00:00:00.000Z", diff: [] },
    { eventId: "new", observationId: base.id, source: base.source, eventType: "updated", detectedAt: "2026-08-20T00:00:00.000Z", diff: [] },
  ];
  assert.deepEqual(pruneMemoryEvents(events, Date.parse("2026-08-21T00:00:00.000Z")).map((event) => event.eventId), ["new"]);
});

test("full CISA catalog filters retain old current records independently of the recent window", () => {
  const oldKev = { ...base, id: "cisa-kev:CVE-2020-0001", source: "cisa-kev", indicator: "CVE-2020-0001", kind: "vulnerability", observedAt: "2020-01-01T00:00:00.000Z", metadata: { vendor: "Microsoft", product: "Windows", knownRansomwareCampaignUse: "Known" } };
  const other = { ...oldKev, id: "cisa-kev:CVE-2020-0002", indicator: "CVE-2020-0002", metadata: { vendor: "Other", product: "Appliance", knownRansomwareCampaignUse: "Unknown" } };
  assert.deepEqual(filterKevCatalogRecords([oldKev, other], { vendor: "micro", ransomwareOnly: true }).map((record) => record.id), [oldKev.id]);
  assert.equal(filterKevCatalogRecords([oldKev], {}).length, 1);
  assert.equal(searchStoredRecords([oldKev], "CVE-2020", "7d", 100, Date.parse("2026-08-21T00:00:00.000Z")).length, 0);
});

test("global freshness derives from source success rather than response generation", () => {
  const summary = summarizeFreshness([{ id: "a", name: "A", status: "stale", configured: true, lastSuccess: "2026-08-21T05:00:00.000Z", recordCount: 1, authMode: "None", refreshPolicy: "15m", upstreamUrl: "https://example.test", dataUsed: "test" }], "2026-08-21T07:00:00.000Z");
  assert.equal(summary.snapshotGenerated, "2026-08-21T07:00:00.000Z");
  assert.equal(summary.latestSourceSuccess, "2026-08-21T05:00:00.000Z");
  assert.equal(summary.state, "stale");
});
