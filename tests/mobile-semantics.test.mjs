import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("mobile chrome has one freshness readout and contextual time controls", async () => {
  const [ui, topbar] = await Promise.all([readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"), readFile(new URL("../app/components/topbar.tsx", import.meta.url), "utf8")]);
  assert.match(topbar, /DATA STATE \/\/ \{state\}/);
  assert.doesNotMatch(ui, /alwaysVisible dataState/);
  assert.match(ui, /\{scopedView && <section className=\{`analytics/);
  assert.match(ui, /searchEnabled=\{scopedView\}/);
});

test("export preserves visible search scope while unrelated workspaces clear it", async () => {
  const ui = await readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8");
  assert.match(ui, /"malware", "export"/);
  assert.match(ui, /!scopedViews\.has\(nextView\) && query\) changeQuery\(""\)/);
  assert.match(ui, /onClick=\{\(\) => changeView\(item\.id\)\}/);
});

test("touch navigation cannot preserve a false active tab", async () => {
  const [ui, css] = await Promise.all([readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"), readFile(new URL("../app/globals.css", import.meta.url), "utf8")]);
  assert.match(ui, /aria-current=\{view === item\.id \? "page" : undefined\}/);
  assert.match(ui, /onPointerUp=\{\(event\) => event\.currentTarget\.blur\(\)\}/);
  assert.match(css, /@media\(hover:none\)\{\.nav button:hover:not\(\.active\),\.nav button:focus:not\(\.active\)/);
});

test("page-bounded counts and export scope are stated instead of implied", async () => {
  const [ui, workbench] = await Promise.all([readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"), readFile(new URL("../app/components/analyst-workbench.tsx", import.meta.url), "utf8")]);
  assert.match(ui, /sourceReadState === "ready" && payload/);
  assert.match(ui, /PAGE OBS <b>\{payload\.records\.length\} SHOWN<\/b>/);
  assert.match(ui, /COUNTS UNRESOLVED/);
  assert.match(ui, /filtersActive \? "FILTERED VISIBLE PAGE"/);
  assert.match(workbench, /NEW ON PAGE/);
  assert.match(workbench, /LEDGER PAGE/);
  assert.match(workbench, /MORE RETAINED/);
  assert.match(workbench, /records on this visible page/);
  assert.match(workbench, /SELECT A FORMAT/);
});

test("visual semantics do not use cluster cardinality as a red severity signal", async () => {
  const [map, field] = await Promise.all([readFile(new URL("../app/components/geo-map.tsx", import.meta.url), "utf8"), readFile(new URL("../app/components/relationship-field.tsx", import.meta.url), "utf8")]);
  assert.doesNotMatch(map, /marker\.points\.length > 1 \? "#d84f31"/);
  assert.match(field, /url:"#72aef8"/);
  assert.match(field, /OBSERVATION \/ TYPE COLOR/);
});

test("static labels no longer resemble controls and event cards lead with the change", async () => {
  const [views, sources, css] = await Promise.all([
    readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/information-views.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);
  assert.doesNotMatch(views, /className="honesty"/);
  assert.doesNotMatch(sources, /className="honesty"/);
  assert.match(views, /CHANGED FIELDS<\/span><span>RECORD/);
  assert.match(views, /className="changeCell"[\s\S]*className="indicatorCell"/);
  assert.match(css, /\.sectionHead p,\.method>p,\.methodIntro p\{color:var\(--acid\)\}/);
  assert.match(css, /\.analytics \.windowControls\{position:static;flex:1 1 calc\(100% - 48px\)/);
});

test("mobile evidence cards expose long hashes, explicit absence, and reversible pagination", async () => {
  const views = await readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8");
  assert.match(views, /className="indicatorActions"/);
  assert.match(views, />COPY<\/button>/);
  assert.match(views, /record\.confidence \?\? "NOT PROVIDED"/);
  assert.match(views, />PREVIOUS<\/button>/);
  assert.match(views, /PAGE \{page\} · TOTAL PAGES UNKNOWN/);
});

test("brand animation is confined to the mark and honors reduced motion", async () => {
  const [topbar, views, brandCss] = await Promise.all([
    readFile(new URL("../app/components/topbar.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/observation-views.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/brand-eye.css", import.meta.url), "utf8"),
  ]);
  assert.match(topbar, /className="sigilMotion"/);
  assert.match(topbar, /autoPlay/);
  assert.match(topbar, /muted/);
  assert.match(topbar, /loop/);
  assert.match(topbar, /playsInline/);
  assert.match(topbar, /poster="\/brand-eye-poster\.jpg"/);
  assert.match(brandCss, /@media\(prefers-reduced-motion:reduce\)[\s\S]*\.sigilMotion\{display:none\}/);
  assert.doesNotMatch(views, /<video|brand-eye-loop/);
  assert.match(views, /mode === "relationships" \? <RelationshipField/);
});

test("replay exposes bounded event-driven transport instead of decorative motion", async () => {
  const [observatory, replay, css] = await Promise.all([
    readFile(new URL("../app/observatory.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/components/observatory-replay.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);
  assert.match(observatory, /id: "replay", label: "Replay"/);
  assert.match(replay, /PAGE-BOUNDED RECONSTRUCTION/);
  assert.match(replay, /Motion represents ledger transitions only/);
  assert.match(replay, /type="range"/);
  assert.match(replay, /prefers-reduced-motion/);
  assert.match(css, /\.replayNode\.removed i\{background:#090a08/);
});
