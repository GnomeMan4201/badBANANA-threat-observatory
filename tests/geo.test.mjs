import test from "node:test";
import assert from "node:assert/strict";
import {
  extractPublicIp,
  GEO_FAILURE_TTL_MS,
  geoCacheExpiresAt,
  isGeoCacheEntryFresh,
  isPublicIp,
  normalizeFreeIpApiGeo,
  normalizeGeoJsGeo,
  pruneExpiredGeoCache,
  setBoundedGeoCache,
  unwrapIpv4MappedIpv6,
} from "../lib/geo.ts";

test("geography accepts public IPs and rejects reserved or documentation ranges", () => {
  assert.equal(isPublicIp("8.8.8.8"), true);
  assert.equal(isPublicIp("2606:4700:4700::1111"), true);
  for (const value of ["10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.1", "192.0.2.4", "198.51.100.4", "203.0.113.4", "::1", "fc00::1", "fe80::1", "2001:db8::1"]) {
    assert.equal(isPublicIp(value), false, value);
  }
});

test("geography extracts validated public IPs without treating arbitrary infrastructure as lookup input", () => {
  assert.equal(extractPublicIp({ kind: "ipv4", indicator: "8.8.8.8:443" }), "8.8.8.8");
  assert.equal(extractPublicIp({ kind: "ipv6", indicator: "[2606:4700:4700::1111]:443" }), "2606:4700:4700::1111");
  assert.equal(extractPublicIp({ kind: "ipv4", indicator: "8.8.8.8:99999" }), undefined);
  assert.equal(extractPublicIp({ kind: "domain", indicator: "example.com" }), undefined);
  assert.equal(extractPublicIp({ kind: "ipv4", indicator: "192.168.0.1" }), undefined);
});

test("IPv4-mapped IPv6 values are unwrapped before public-range checks", () => {
  assert.equal(unwrapIpv4MappedIpv6("::ffff:8.8.8.8"), "8.8.8.8");
  assert.equal(isPublicIp("::ffff:8.8.8.8"), true);
  assert.equal(extractPublicIp({ kind: "ipv6", indicator: "[::ffff:8.8.8.8]:443" }), "8.8.8.8");
  for (const value of ["::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.1.1", "::ffff:192.0.2.4"]) {
    assert.equal(isPublicIp(value), false, value);
  }
});

test("geo cache policy rejects legacy providers and retries failures after five minutes", () => {
  const now = Date.parse("2026-08-21T12:00:00.000Z");
  assert.equal(Date.parse(geoCacheExpiresAt("error", now)) - now, GEO_FAILURE_TTL_MS);
  assert.equal(isGeoCacheEntryFresh({ status: "error", provider: "GEOJS + FREEIPAPI", expiresAt: geoCacheExpiresAt("error", now) }, now), true);
  assert.equal(isGeoCacheEntryFresh({ status: "error", provider: "IPWHOIS.IO", expiresAt: geoCacheExpiresAt("error", now) }, now), false);
  assert.equal(isGeoCacheEntryFresh({ status: "success", provider: "GEOJS", expiresAt: "not-a-date" }, now), false);
});

test("expired memory geo entries are physically removed", () => {
  const now = Date.parse("2026-08-21T12:00:00.000Z");
  const cache = new Map([
    ["expired", { expiresAt: "2026-08-21T11:59:59.000Z" }],
    ["invalid", { expiresAt: "not-a-date" }],
    ["fresh", { expiresAt: "2026-08-21T12:05:00.000Z" }],
  ]);
  assert.equal(pruneExpiredGeoCache(cache, now), 2);
  assert.deepEqual([...cache.keys()], ["fresh"]);
});

test("isolate geo cache enforces a hard entry ceiling", () => {
  const cache = new Map();
  setBoundedGeoCache(cache, "a", 1, 2);
  setBoundedGeoCache(cache, "b", 2, 2);
  setBoundedGeoCache(cache, "c", 3, 2);
  assert.deepEqual([...cache.keys()], ["b", "c"]);
  setBoundedGeoCache(cache, "b", 4, 2);
  assert.deepEqual([...cache.entries()], [["c", 3], ["b", 4]]);
});

test("GeoJS geography is bounded, typed and tied to the requested IP", () => {
  const raw = {
    ip: "8.8.8.8",
    continent_code: "NA",
    country: "United States",
    country_code: "US",
    region: "California",
    city: "Mountain View",
    latitude: "37.4056",
    longitude: "-122.0775",
    asn: 15169,
    organization_name: "Google LLC",
  };
  assert.deepEqual(normalizeGeoJsGeo(raw, "8.8.8.8"), {
    ip: "8.8.8.8", provider: "GEOJS", latitude: 37.4056, longitude: -122.0775, country: "United States", countryCode: "US",
    city: "Mountain View", region: "California", continent: "NA", asn: "AS15169", organization: "Google LLC",
  });
  assert.equal(normalizeGeoJsGeo(raw, "1.1.1.1"), undefined);
  assert.equal(normalizeGeoJsGeo({ ...raw, ip: "2606:4700:4700:0:0:0:0:1111" }, "2606:4700:4700::1111")?.countryCode, "US");
  assert.equal(normalizeGeoJsGeo({ ...raw, ip: "::ffff:8.8.8.8" }, "8.8.8.8")?.countryCode, "US");
  assert.equal(normalizeGeoJsGeo({ ...raw, latitude: 120 }, "8.8.8.8"), undefined);
});

test("FreeIPAPI fallback is normalized to the same evidence model", () => {
  const raw = {
    ipAddress: "1.1.1.1", latitude: -33.8688, longitude: 151.209, countryName: "Australia", countryCode: "AU",
    cityName: "Sydney", regionName: "New South Wales", continent: "Oceania", asn: "13335", asnOrganization: "Cloudflare, Inc.",
  };
  assert.deepEqual(normalizeFreeIpApiGeo(raw, "1.1.1.1"), {
    ip: "1.1.1.1", provider: "FREEIPAPI", latitude: -33.8688, longitude: 151.209, country: "Australia", countryCode: "AU",
    city: "Sydney", region: "New South Wales", continent: "Oceania", asn: "AS13335", organization: "Cloudflare, Inc.",
  });
  assert.equal(normalizeFreeIpApiGeo({ ...raw, ipAddress: "8.8.8.8" }, "1.1.1.1"), undefined);
});
