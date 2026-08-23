import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkIngestRateLimit, RATE_LIMIT_POLICY } from "../lib/rate-limit.ts";
import { isSameOriginMutation } from "../lib/request-validation.ts";
import {
  classifyIndicator,
  classifyIpPort,
  isValidIpv4,
  isValidIpv6,
  referencePolicy,
  safeReferenceUrl,
  validateSourceSnapshot,
} from "../lib/normalize.ts";

test("strict IPv4 validation rejects invalid octets and ambiguous formatting", () => {
  assert.equal(isValidIpv4("203.0.113.7"), true);
  assert.equal(isValidIpv4("999.1.1.1"), false);
  assert.equal(isValidIpv4("01.2.3.4"), false);
});

test("IPv6 classification rejects arbitrary colon-containing input", () => {
  assert.equal(isValidIpv6("2001:db8::1"), true);
  assert.equal(classifyIndicator("not:an:address", "ipv6"), "infrastructure");
  assert.equal(isValidIpv6("http:thing"), false);
});

test("ip:port validates both address and port range", () => {
  assert.equal(classifyIpPort("203.0.113.7:443"), "ipv4");
  assert.equal(classifyIpPort("[2001:db8::1]:8443"), "ipv6");
  assert.equal(classifyIpPort("203.0.113.7:70000"), undefined);
});

test("reference URLs allow HTTP(S) and reject active or local schemes", () => {
  assert.equal(safeReferenceUrl("https://example.test/report"), "https://example.test/report");
  assert.equal(safeReferenceUrl("javascript:alert(1)"), undefined);
  assert.equal(safeReferenceUrl("data:text/html,test"), undefined);
  assert.equal(safeReferenceUrl("file:///tmp/evidence"), undefined);
});

test("arbitrary HTTP references remain explicitly external", () => {
  assert.equal(referencePolicy("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "cisa-kev").trust, "first-party");
  const external = referencePolicy("https://reports.example.test/analysis", "threatfox");
  assert.equal(external.trust, "external");
  assert.equal(external.hostname, "reports.example.test");
});

test("corrupted cached snapshots fail closed", () => {
  const corrupt = { fetchedAt: "not-a-date", expiresAt: "2026-08-21T07:00:00Z", health: { id: "a" }, records: [{ source: "a" }] };
  assert.equal(validateSourceSnapshot(corrupt, "a"), false);
  const incomplete = { fetchedAt: "2026-08-21T06:00:00Z", expiresAt: "2026-08-21T07:00:00Z", health: { id: "a", recordCount: 2 }, records: [] };
  assert.equal(validateSourceSnapshot(incomplete, "a"), false);
});

test("search route queries local history and never invokes source collection", async () => {
  const route = await readFile(new URL("../app/api/search/route.ts", import.meta.url), "utf8");
  assert.match(route, /searchLocalObservatory/);
  assert.doesNotMatch(route, /collectObservatory|fetchRecent/);
});

test("search failure is distinct from an empty result in the UI", async () => {
  const ui = await readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8");
  assert.match(ui, /SEARCH UNAVAILABLE — NO-MATCH STATE NOT ASSUMED/);
  assert.match(ui, /HISTORY DEGRADED/);
});

test("current state, event retention, revisions, cycles and leases have distinct schemas", async () => {
  const store = await readFile(new URL("../lib/server/history.ts", import.meta.url), "utf8");
  const schema = await readFile(new URL("../db/schema.ts", import.meta.url), "utf8");
  assert.match(schema, /idx_observations_current_time/);
  assert.match(schema, /idx_observations_ingest/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS observation_events/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS source_ingest_cycles/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS source_refresh_lease/);
  assert.match(store, /DELETE FROM observation_events WHERE detected_at < \?/);
  assert.match(store, /DELETE FROM source_ingest_cycles WHERE completed_at < \?/);
  assert.match(store, /source = 'cisa-kev' AND is_current = 0 AND last_changed_at < \?/);
  assert.match(store, /source_refresh_lease\.expires_at <= \?/);
});

test("ordinary observation reads never import ingestion or source adapters", async () => {
  const route = await readFile(new URL("../app/api/observations/route.ts", import.meta.url), "utf8");
  const server = await readFile(new URL("../lib/server/observatory.ts", import.meta.url), "utf8");
  const readFunction = server.slice(server.indexOf("export async function readObservatory"), server.indexOf("export async function searchLocalObservatory"));
  assert.match(route, /readObservatory/);
  assert.doesNotMatch(route, /runIngestionCycle|fetchRecent/);
  assert.doesNotMatch(readFunction, /fetchRecent|runSourceIngestion/);
});

test("production ingestion isolates individual source failures", async () => {
  const server = await readFile(new URL("../lib/server/observatory.ts", import.meta.url), "utf8");
  const cycle = server.slice(server.indexOf("export async function runIngestionCycle"), server.indexOf("async function runSourceIngestion"));
  assert.match(cycle, /Promise\.allSettled/);
  assert.match(cycle, /attempt\.status === "fulfilled"/);
  assert.match(cycle, /internalFailureSnapshot/);
});

test("geography derives candidates locally and uses only the fixed provider chain", async () => {
  const route = await readFile(new URL("../app/api/geo/route.ts", import.meta.url), "utf8");
  const server = await readFile(new URL("../lib/server/geo.ts", import.meta.url), "utf8");
  const history = await readFile(new URL("../lib/server/history.ts", import.meta.url), "utf8");
  const schema = await readFile(new URL("../db/schema.ts", import.meta.url), "utf8");
  const readme = await readFile(new URL("../README.md", import.meta.url), "utf8");
  assert.match(route, /readGeoCandidates/);
  assert.match(route, /buildGeoPayload\(candidates\.records/);
  assert.match(history, /queryGeoCandidateRecords/);
  assert.match(route, /"Cache-Control": "no-store"/);
  assert.doesNotMatch(route, /searchParams\.get\(["']ip/);
  assert.match(server, /https:\/\/get\.geojs\.io\/v1\/ip\/geo\//);
  assert.match(server, /https:\/\/free\.freeipapi\.com\/api\/json\//);
  assert.match(server, /MAX_LOOKUPS_PER_REQUEST = 12/);
  assert.match(server, /DELETE FROM geo_ip_cache WHERE expires_at <= \?/);
  assert.doesNotMatch(server, /IPWHOIS\.IO/);
  assert.match(schema, /CREATE TABLE IF NOT EXISTS geo_ip_cache/);
  assert.match(readme, /providers can therefore observe which public addresses are queried/);
});

test("ingestion mode and rate-limit strength are reported accurately", async () => {
  const server = await readFile(new URL("../lib/server/observatory.ts", import.meta.url), "utf8");
  const limiter = await readFile(new URL("../lib/rate-limit.ts", import.meta.url), "utf8");
  assert.match(server, /mode: "demand-driven"/);
  assert.match(server, /schedulerSupported: false/);
  assert.match(limiter, /best-effort isolate-local/);
  assert.equal(RATE_LIMIT_POLICY.ingestRequestsPerMinute, 6);
  const request = new Request("https://observatory.test/api/ingest", { headers: { "cf-connecting-ip": "192.0.2.81" } });
  for (let attempt = 0; attempt < 6; attempt += 1) assert.equal(checkIngestRateLimit(request).allowed, true);
  assert.equal(checkIngestRateLimit(request).allowed, false);
});

test("maintenance mutation rejects cross-origin browser triggers", () => {
  assert.equal(isSameOriginMutation(new Request("https://observatory.test/api/ingest", { method: "POST", headers: { origin: "https://observatory.test", "sec-fetch-site": "same-origin" } })), true);
  assert.equal(isSameOriginMutation(new Request("https://observatory.test/api/ingest", { method: "POST", headers: { origin: "https://foreign.test", "sec-fetch-site": "cross-site" } })), false);
});

test("CISA catalog and recent-window APIs keep distinct time semantics", async () => {
  const kevRoute = await readFile(new URL("../app/api/kev/route.ts", import.meta.url), "utf8");
  const observationRoute = await readFile(new URL("../app/api/observations/route.ts", import.meta.url), "utf8");
  assert.match(kevRoute, /readCurrentKevCatalog/);
  assert.doesNotMatch(kevRoute, /parseWindow|window=7d/);
  assert.match(observationRoute, /parseWindow/);
});

test("source views and search apply validated scope before database pagination", async () => {
  const [observations, search, history, ui] = await Promise.all([
    readFile(new URL("../app/api/observations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/search/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/history.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(observations, /parseObservationScope/);
  assert.match(search, /parseObservationScope/);
  assert.match(history, /WHERE observed_at >= \? AND is_current = 1 \$\{scope\.clause\} \$\{cursorClause\}/);
  assert.match(ui, /scopeForView/);
  assert.doesNotMatch(ui, /case "urls": return records\.filter/);
});

test("recent KEV and exact-indicator peers use dedicated server queries", async () => {
  const [views, correlationRoute] = await Promise.all([
    readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/correlations/route.ts", import.meta.url), "utf8"),
  ]);
  assert.match(views, /addedSince: recentKevCutoffDate\(recentRange\)/);
  assert.match(views, /RECENT KEV \/ DAY-GRANULAR/);
  assert.doesNotMatch(views, /RECENT KEV \/ \{window\.toUpperCase\(\)\}/);
  assert.doesNotMatch(views, /recentRecords/);
  assert.match(correlationRoute, /queryObservationPeers/);
});

test("correlation candidates require distinct sources before the safety bound", async () => {
  const [history, ui] = await Promise.all([
    readFile(new URL("../lib/server/history.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(history, /HAVING COUNT\(DISTINCT source\) > 1/);
  assert.match(ui, /formatCorrelationCount/);
});

test("every source declares its real coverage boundary", async () => {
  const adapters = await readFile(new URL("../lib/server/adapters.ts", import.meta.url), "utf8");
  assert.match(adapters, /Full current CISA Known Exploited Vulnerabilities catalog/);
  assert.match(adapters, /Requested 24-hour IOC window/);
  assert.match(adapters, /Latest 500 records returned/);
  assert.match(adapters, /Latest 100 records returned/);
});

test("primary visualizations expose keyboard interaction and mobile data stays bounded", async () => {
  const relationship = await readFile(new URL("../app/components/relationship-field.tsx", import.meta.url), "utf8");
  const geography = await readFile(new URL("../app/components/geo-map.tsx", import.meta.url), "utf8");
  const observations = await readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(relationship, /tabIndex=\{0\}/);
  assert.match(relationship, /ArrowLeft/);
  assert.match(relationship, /fitField\(field,width,height\)/);
  assert.match(relationship, /drawFieldLabels\(ctx,field\.nodes,hover,width,height\)/);
  assert.match(geography, /tabIndex=\{0\}/);
  assert.match(geography, /event\.key === "Enter"/);
  assert.match(observations, /<IndicatorCell record=\{record\}/);
  assert.match(observations, /className=\{`indicatorCell \$\{longHash/);
  assert.match(observations, /className="changeCell" data-label="CHANGED FIELDS"/);
  assert.match(styles, /html,body,\.shell\{max-width:100%;overflow-x:hidden\}/);
  assert.match(styles, /\.indicatorCell,\.changeCell,\.contextCell\{min-width:0;overflow-wrap:anywhere/);
  assert.match(styles, /\.nav\{position:relative;height:48px;min-height:48px;flex-wrap:nowrap/);
  assert.match(styles, /\.tr\.obs\.th,\.tr\.eventRow\.th\{display:none\}/);
});
