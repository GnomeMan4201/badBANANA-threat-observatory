import test from "node:test";
import assert from "node:assert/strict";
import { createAcknowledgement, parseAcknowledgement, summarizeBriefing } from "../lib/briefing.ts";
import { buildEvidenceTrace } from "../lib/evidence-trace.ts";
import { applyExportPolicy, buildExport } from "../lib/export-policy.ts";
import { readDeviceStorage, writeDeviceStorage } from "../lib/device-storage.ts";

const record = {
  id: "urlhaus:7", source: "urlhaus", sourceRecordId: "7", kind: "url", indicator: "https://bad.example/drop.exe",
  indicatorType: "url", observedAt: "2026-08-21T10:00:00.000Z", ingestedAt: "2026-08-21T10:01:00.000Z",
  tags: [], metadata: {}, recordHash: "abc123",
};

const events = [
  { eventId: "e2", observationId: record.id, source: record.source, eventType: "updated", detectedAt: "2026-08-21T11:00:00.000Z", diff: [{ field: "threatType", before: "a", after: "b" }], current: record },
  { eventId: "e1", observationId: record.id, source: record.source, eventType: "new", detectedAt: "2026-08-21T10:00:00.000Z", diff: [], current: record },
];

test("first device view is an explicit baseline, not claimed new activity", () => {
  const summary = summarizeBriefing(events, null);
  assert.equal(summary.state, "initial-baseline");
  assert.equal(summary.events.length, 2);
});

test("device acknowledgement exposes only genuinely newer retained events", () => {
  const acknowledgement = createAcknowledgement(events[1], "revision-1", "device-1", "2026-08-21T10:05:00.000Z");
  const summary = summarizeBriefing(events, acknowledgement);
  assert.equal(summary.state, "changes");
  assert.deepEqual(summary.events.map((event) => event.eventId), ["e2"]);
});

test("acknowledgement older than retained ledger fails closed before counting newer events", () => {
  const acknowledgement = createAcknowledgement(events[1], "revision-old", "device-1", "2026-08-20T00:00:00.000Z");
  acknowledgement.acknowledgedEventId = "pruned-event";
  acknowledgement.acknowledgedDetectedAt = "2026-08-19T00:00:00.000Z";
  const summary = summarizeBriefing(events, acknowledgement, { oldestRetainedDetectedAt: "2026-08-21T10:00:00.000Z", newestRetainedDetectedAt: "2026-08-21T11:00:00.000Z", totalRetained: 2 });
  assert.equal(summary.state, "ledger-gap");
});

test("acknowledgement import is versioned and fails closed", () => {
  const valid = createAcknowledgement(events[0], "revision-2", "device-1");
  assert.deepEqual(parseAcknowledgement(valid), valid);
  assert.equal(parseAcknowledgement({ ...valid, schemaVersion: 99 }), null);
  assert.equal(parseAcknowledgement({ ...valid, acknowledgedAt: "not-a-date" }), null);
});

test("acknowledgement timestamps canonicalize supported alternate formats", () => {
  const valid = createAcknowledgement(events[0], "revision-2", "device-1", "Sat, 22 Aug 2026 11:00:00 GMT");
  assert.equal(valid.acknowledgedAt, "2026-08-22T11:00:00.000Z");
  const imported = parseAcknowledgement({ ...valid, acknowledgedAt: "08/22/2026 11:00:00 UTC" });
  assert.equal(imported?.acknowledgedAt, "2026-08-22T11:00:00.000Z");
  assert.equal(parseAcknowledgement({ ...valid, acknowledgedAt: "02/31/2026 11:00:00 UTC" }), null);
  assert.equal(parseAcknowledgement({ ...valid, acknowledgedAt: "Mon, 22 Aug 2026 11:00:00 GMT" }), null);
});

test("equivalent acknowledgement formats produce identical briefing semantics", () => {
  const canonical = createAcknowledgement(events[1], "revision-1", "device-1", "2026-08-21T10:05:00.000Z");
  const alternate = parseAcknowledgement({ ...canonical, acknowledgedAt: "08/21/2026 10:05:00 UTC" });
  assert.deepEqual(summarizeBriefing(events, alternate), summarizeBriefing(events, canonical));
  const newest = createAcknowledgement(events[0], "revision-2", "device-1");
  assert.equal(summarizeBriefing(events, newest).state, "no-changes");
});

test("device storage failures are non-fatal", () => {
  const unavailable = () => { throw new Error("blocked"); };
  const broken = () => ({ getItem() { throw new Error("read blocked"); }, setItem() { throw new Error("write blocked"); } });
  assert.equal(readDeviceStorage(unavailable, "ack"), null);
  assert.equal(writeDeviceStorage(unavailable, "ack", "{}"), false);
  assert.equal(readDeviceStorage(broken, "ack"), null);
  assert.equal(writeDeviceStorage(broken, "ack", "{}"), false);
});

test("evidence trace distinguishes accepted fields, absence, and display-only transforms", () => {
  const trace = buildEvidenceTrace(record);
  assert.ok(trace.acceptedFields.includes("indicator"));
  assert.ok(trace.absentOptionalFields.includes("confidence"));
  assert.match(trace.displayTransforms[0], /stored value unchanged/);
});

test("export policy never converts absent confidence into a value", () => {
  const policy = { schemaVersion: 1, window: "24h", sources: ["urlhaus"], includeWithoutConfidence: true, currentStateOnly: true, preserveDisputes: true };
  const selected = applyExportPolicy([record], policy, Date.parse("2026-08-21T12:00:00.000Z"));
  assert.equal(selected[0].confidence, undefined);
  const artifact = buildExport([record], policy, "jsonl", "2026-08-21T12:00:00.000Z");
  assert.match(artifact.content, /SOURCE CONFIDENCE NOT PROVIDED/);
  assert.doesNotMatch(artifact.content, /"confidence":0/);
});

test("defanged export is copy-safe while STIX retains the validated raw observable", () => {
  const policy = { schemaVersion: 1, window: "24h", sources: ["urlhaus"], includeWithoutConfidence: true, currentStateOnly: true, preserveDisputes: true };
  assert.match(buildExport([record], policy, "defanged", "2026-08-21T12:00:00.000Z").content, /hxxps:\/\/bad\[\.\]example/);
  assert.match(buildExport([record], policy, "stix", "2026-08-21T12:00:00.000Z").content, /https:\/\/bad\.example\/drop\.exe/);
});

test("empty export source allow-list selects zero records", () => {
  const policy = { schemaVersion: 1, window: "24h", sources: [], includeWithoutConfidence: true, currentStateOnly: true, preserveDisputes: true };
  assert.equal(applyExportPolicy([record], policy).length, 0);
});

test("STIX represents CISA vulnerabilities and MalwareBazaar hashes without false counts", () => {
  const cisa = { ...record, id: "cisa-kev:CVE-2026-12345", source: "cisa-kev", sourceRecordId: "CVE-2026-12345", kind: "vulnerability", indicator: "CVE-2026-12345", title: "Example flaw" };
  const malware = { ...record, id: `malwarebazaar:${"a".repeat(64)}`, source: "malwarebazaar", sourceRecordId: "a".repeat(64), kind: "malware", indicator: "a".repeat(64) };
  const unsupported = { ...record, id: "other:1", source: "other", kind: "infrastructure", indicator: "opaque-value" };
  const policy = { schemaVersion: 1, window: "24h", sources: ["cisa-kev", "malwarebazaar", "other"], includeWithoutConfidence: true, currentStateOnly: true, preserveDisputes: true };
  const artifact = buildExport([cisa, malware, unsupported], policy, "stix", "2026-08-21T12:00:00.000Z");
  const bundle = JSON.parse(artifact.content);
  assert.equal(artifact.selectedRecords, 3);
  assert.equal(artifact.records, 2);
  assert.equal(artifact.omittedRecords, 1);
  assert.equal(bundle.objects.length, 2);
  assert.equal(bundle.x_badbanana_export.omitted_records, 1);
  assert.ok(bundle.objects.some((object) => object.type === "vulnerability"));
  assert.ok(bundle.objects.some((object) => object.pattern?.includes("SHA-256")));
});
