import assert from "node:assert/strict";
import test from "node:test";
import { normalizeCisaDataset, normalizeCisaKev } from "../lib/normalizers/cisa.ts";
import { normalizeThreatFox } from "../lib/normalizers/threatfox.ts";
import { normalizeUrlHaus } from "../lib/normalizers/urlhaus.ts";
import { normalizeMalwareBazaar } from "../lib/normalizers/malwarebazaar.ts";
import { parseCalendarDate, parseTimestamp } from "../lib/normalize.ts";
const at="2026-08-21T00:00:00.000Z";
const cisa={cveID:"CVE-2026-12345",vendorProject:"Vendor",product:"Product",vulnerabilityName:"Example",dateAdded:"2026-08-20",requiredAction:"Mitigate",knownRansomwareCampaignUse:"Known"};
test("CISA validates, preserves absence and deduplicates",()=>{const record=normalizeCisaKev(cisa,at);assert.equal(record?.indicator,"CVE-2026-12345");assert.equal(record?.metadata.dueDate,undefined);assert.equal("countryCode" in (record??{}),false);assert.equal(normalizeCisaDataset([cisa,cisa],at).length,1);assert.equal(normalizeCisaKev({...cisa,cveID:"invalid"},at),null);const long=normalizeCisaKev({...cisa,vendorProject:"v".repeat(120)},at);assert.equal(long?.tags[0].length,80);assert.equal(long?.metadata.vendor,"v".repeat(120))});
test("ThreatFox validates supplied IOC semantics",()=>{const record=normalizeThreatFox({id:"41",ioc:"203.0.113.42:443",ioc_type:"ip:port",threat_type:"botnet_cc",malware_printable:"Example",confidence_level:75,first_seen:"2026-08-21 00:00:00 UTC",last_seen:null,tags:["c2"]},at);assert.equal(record?.kind,"ipv4");assert.equal(record?.confidence,75);assert.equal(record?.lastSeen,undefined);for(const sample of [{ioc:"not:an:address",ioc_type:"ipv6"},{ioc:"999.1.1.1",ioc_type:"ipv4"},{ioc:"javascript:alert(1)",ioc_type:"url"},{ioc:"not a domain",ioc_type:"domain"},{ioc:"xyz",ioc_type:"sha256_hash"},{ioc:"203.0.113.7:70000",ioc_type:"ip:port"},{ioc:"totally-not-an-indicator-###",ioc_type:"asn"},{ioc:"example.com",ioc_type:"cve"}])assert.equal(normalizeThreatFox({id:`bad-${sample.ioc_type}`,first_seen:"2026-08-21 00:00:00 UTC",...sample},at),null);assert.equal(normalizeThreatFox({id:"too-long",ioc:"a".repeat(2049),ioc_type:"domain",first_seen:"2026-08-21 00:00:00 UTC"},at),null)});
test("URLhaus rejects non-URLs and retains raw URL only as data",()=>{const record=normalizeUrlHaus({id:"9",url:"http://bad.example/payload",date_added:"2026-08-21 00:00:00 UTC",url_status:"online",host:"bad.example",tags:["exe"]},at);assert.equal(record?.kind,"url");assert.equal(record?.metadata.defanged,"hxxp://bad[.]example/payload");assert.equal(normalizeUrlHaus({id:"9",url:"javascript:alert(1)",date_added:"2026-08-21"},at),null)});
test("abuse.ch numeric source identifiers remain stable strings",()=>{const url=normalizeUrlHaus({id:12345,url:"https://example.test/payload",date_added:"2026-08-21 09:00:00 UTC",tags:[]},at);const fox=normalizeThreatFox({id:67890,ioc:"203.0.113.7:443",ioc_type:"ip:port",first_seen:"2026-08-21 09:00:00 UTC",tags:[]},at);assert.equal(url?.sourceRecordId,"12345");assert.equal(fox?.sourceRecordId,"67890")});
test("MalwareBazaar is metadata-only and validates hashes without truncation",()=>{const hash="a".repeat(64);const record=normalizeMalwareBazaar({sha256_hash:hash,sha1_hash:"b".repeat(40),md5_hash:"c".repeat(32),first_seen:"2026-08-21 00:00:00",file_type:"exe",file_size:42,signature:"Example"},at);assert.equal(record?.indicator,hash);assert.equal(record?.metadata.fileSize,42);assert.equal("download" in (record?.metadata??{}),false);assert.equal(normalizeMalwareBazaar({sha256_hash:"bad",first_seen:"2026-08-21"},at),null);assert.equal(normalizeMalwareBazaar({sha256_hash:hash+"deadbeef",first_seen:"2026-08-21"},at),null);assert.equal(normalizeMalwareBazaar({sha256_hash:hash,sha1_hash:"b".repeat(41),first_seen:"2026-08-21"},at),null);assert.equal(normalizeMalwareBazaar({sha256_hash:hash,md5_hash:"c".repeat(33),first_seen:"2026-08-21"},at),null)});
test("tag order, case and duplicates canonicalize before hashing",()=>{const left=normalizeThreatFox({id:"tag-1",ioc:"8.8.8.8",ioc_type:"ipv4",first_seen:"2026-08-21 00:00:00 UTC",tags:["Linux","botnet","linux"]},at);const right=normalizeThreatFox({id:"tag-1",ioc:"8.8.8.8",ioc_type:"ipv4",first_seen:"2026-08-21 00:00:00 UTC",tags:["BOTNET","linux"]},at);assert.deepEqual(left?.tags,["botnet","linux"]);assert.deepEqual(right?.tags,left?.tags)});
test("calendar parsing rejects rollovers and accepts real leap days",()=>{for(const value of ["2026-02-31","2026-04-31","2026-02-29","2026-13-01","2026-00-01"])assert.equal(parseCalendarDate(value),undefined);assert.equal(parseCalendarDate("2028-02-29"),"2028-02-29T00:00:00.000Z");assert.equal(parseTimestamp("2026-02-31"),undefined);assert.equal(parseTimestamp("2026-08-21T10:05:00.000Z"),"2026-08-21T10:05:00.000Z")});
test("CISA rejects impossible supplied dates",()=>{assert.equal(normalizeCisaKev({...cisa,dateAdded:"2026-02-31"},at),null);assert.equal(normalizeCisaKev({...cisa,dueDate:"2026-04-31"},at),null);assert.equal(normalizeCisaKev({...cisa,dueDate:"2028-02-29"},at)?.metadata.dueDate,"2028-02-29T00:00:00.000Z")});

test("alternate timestamp formats preserve four-digit years without Date.UTC century rollover", () => {
  for (const year of ["0001", "0026", "0099", "0100", "1900", "2000"]) {
    const iso = parseTimestamp(`${year}-08-22T11:00:00Z`);
    const slash = parseTimestamp(`08/22/${year} 11:00:00 UTC`);
    const rfc = parseTimestamp(`22 Aug ${year} 11:00:00 GMT`);
    assert.equal(slash, iso);
    assert.equal(rfc, iso);
    assert.equal(iso?.slice(0, 4), year);
  }
});
