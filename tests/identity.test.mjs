import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

async function findAssetReferences(directory) {
  const hits = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
    if (entry.isDirectory()) {
      hits.push(...await findAssetReferences(url));
      continue;
    }
    if (!/\.(?:css|tsx?|jsx?)$/.test(entry.name)) continue;
    const source = await readFile(url, "utf8");
    if (/brand-eye-(?:poster\.jpg|loop\.mp4)/.test(source)) hits.push(url.pathname);
  }
  return hits;
}

test("source metadata and identity contain no starter branding", async () => {
  const layout = await readFile(new URL("../app/layout.tsx", import.meta.url), "utf8");
  const favicon = await readFile(new URL("../public/favicon.svg", import.meta.url), "utf8");
  assert.match(layout, /badBANANA \/\/ THREAT OBSERVATORY/);
  assert.match(layout, /og\.png/);
  assert.doesNotMatch(layout + favicon, /Starter Project|#68C4FF/);
});

test("Observatory eye uses one normal static asset in the top-left header only", async () => {
  const [topbar, css, layout, poster] = await Promise.all([
    readFile(new URL("../app/components/topbar.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/brand-eye.css", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../public/brand-eye-poster.jpg", import.meta.url)),
  ]);

  assert.match(topbar, /<img className="sigilArtwork" src="\/brand-eye-poster\.jpg"/);
  assert.doesNotMatch(topbar, /brand-eye-loop\.mp4|sigilGlow|sigilScan|<video/);
  assert.equal(poster[0], 0xff);
  assert.equal(poster[1], 0xd8);
  assert.equal(poster.at(-2), 0xff);
  assert.equal(poster.at(-1), 0xd9);

  assert.match(css, /width:76px;\s*\n\s*height:76px/);
  assert.match(css, /@media\(max-width:900px\)\{\.sigil\{width:68px;height:68px;flex-basis:68px\}/);
  assert.match(css, /@media\(max-width:700px\)\{\.sigil\{width:64px;height:64px;flex-basis:64px\}/);
  assert.match(css, /@media\(max-width:560px\)\{\.sigil\{width:60px;height:60px;flex-basis:60px\}/);
  assert.doesNotMatch(css, /data:image|@keyframes|animation:|footer|observatory-eye/);
  assert.doesNotMatch(layout, /brand-eye-(?:poster\.jpg|loop\.mp4)/);

  const references = await findAssetReferences(new URL("../app/", import.meta.url));
  assert.equal(references.length, 1);
  assert.match(references[0], /app\/components\/topbar\.tsx$/);
});
