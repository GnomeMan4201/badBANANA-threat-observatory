import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { eventRequestPath } from "../lib/event-view.ts";
import { recentKevCutoffDate, recentKevRangeLabel } from "../lib/kev-time.ts";

test("Recent Events pagination cannot leak into Briefing or Replay requests", () => {
  const state = { recentEventsCursor: "page-three-cursor" };
  assert.match(eventRequestPath("events", state), /cursor=page-three-cursor/);
  assert.doesNotMatch(eventRequestPath("briefing", state), /cursor=/);
  assert.doesNotMatch(eventRequestPath("replay", state), /cursor=/);
});

test("Briefing always requests the newest retained ledger page", () => {
  assert.equal(eventRequestPath("briefing", { recentEventsCursor: null }), "/api/events?limit=50");
  assert.equal(eventRequestPath("briefing", { recentEventsCursor: "stale" }), "/api/events?limit=50");
});

test("CISA recent scopes are explicitly day-granular", () => {
  const now = Date.parse("2026-08-22T16:35:00.000Z");
  assert.equal(recentKevRangeLabel("today"), "TODAY");
  assert.equal(recentKevRangeLabel("7d"), "7D");
  assert.equal(recentKevRangeLabel("30d"), "30D");
  assert.equal(recentKevCutoffDate("today", now), "2026-08-22");
  assert.equal(recentKevCutoffDate("7d", now), "2026-08-15");
  assert.equal(recentKevCutoffDate("30d", now), "2026-07-23");
});

test("evidence drawer imports every React hook it uses", async () => {
  const source = await readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8");
  assert.match(source, /import \{[^}]*\buseRef\b[^}]*\} from "react";/);
});

test("source reads never render unresolved counts as factual zero states", async () => {
  const [ui, views] = await Promise.all([
    readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(ui, /FAILED — COUNTS UNRESOLVED/);
  assert.match(ui, /LOADING — COUNTS UNRESOLVED/);
  assert.match(ui, /READ FAILED — ZERO RESULTS NOT ASSUMED/);
  assert.match(ui, /READ IN PROGRESS — ZERO RESULTS NOT ASSUMED/);
  assert.doesNotMatch(ui, /payload\?\.records\.length \?\? 0/);
  assert.doesNotMatch(ui, /payload\?\.sources\.length \?\? 0/);
  assert.match(views, /NO VALIDATED RESULTS IN THIS SCOPE/);
});

test("correlation requests are stable across the one-second clock", async () => {
  const [ui, drawer] = await Promise.all([
    readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(ui, /const correlated = useMemo\(/);
  assert.match(drawer, /fetch\(`\/api\/correlations\?id=\$\{encodeURIComponent\(record\.id\)\}`/);
  assert.match(drawer, /\}, \[record\.id\]\);/);
  assert.doesNotMatch(drawer, /\}, \[record\.id, correlated\]\);/);
  assert.doesNotMatch(`${ui}\n${drawer}`, /window\.alert/);
});


test("active unresolved search never falls back to ordinary records or export", async () => {
  const ui = await readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8");
  assert.match(ui, /if \(!searching\) return payload\?\.records \?\? \[\];/);
  assert.match(ui, /return searchStatus === "ready" \? searchResults \?\? \[\] : \[\];/);
  assert.match(ui, /searching && searchStatus !== "ready" \? <SearchExportState/);
  assert.match(ui, /setSearchStatus\("loading"\);/);
  assert.match(ui, /setSearchResults\(null\);/);
  assert.match(ui, /SEARCH FAILED — ZERO RESULTS NOT ASSUMED/);
  assert.match(ui, /SEARCH READ FAILED — FALLBACK RECORDS NOT EXPORTED/);
});

test("Briefing fallback cannot drive acknowledgement semantics", async () => {
  const ui = await readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8");
  assert.match(ui, /briefingStatus === "ready" && briefingPayload \? <AnalystBriefing events=\{briefingPayload\.events\}/);
  assert.doesNotMatch(ui, /<AnalystBriefing events=\{briefingPayload\?\.events \?\? payload\.recentEvents\}/);
  assert.match(ui, /PAGE-BOUNDED FALLBACK \/\/ OBSERVATIONAL ONLY/);
  assert.match(ui, /not used to determine acknowledgement delta, no-change state, or ledger-gap state/);
});

test("GEO unresolved states do not present zero counts and correlation filter names its actual scope", async () => {
  const [views, geo, ui] = await Promise.all([
    readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/geo-map.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(views, /IP RECORDS <b>UNRESOLVED<\/b>/);
  assert.doesNotMatch(views, /geo\?\.candidateRecords \?\? 0/);
  assert.match(geo, /Geographic enrichment results unresolved; no geolocated count is claimed/);
  assert.match(ui, /CROSS-SOURCE PEER IN CURRENT WINDOW/);
  assert.doesNotMatch(ui, /CROSS-SOURCE PEER IN LOADED SET/);
});
