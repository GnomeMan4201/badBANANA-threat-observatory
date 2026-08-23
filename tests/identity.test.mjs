import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("source metadata and identity contain no starter branding", async () => {
  const layout = await readFile(new URL("../app/layout.tsx", import.meta.url), "utf8");
  const favicon = await readFile(new URL("../public/favicon.svg", import.meta.url), "utf8");
  assert.match(layout, /badBANANA \/\/ THREAT OBSERVATORY/);
  assert.match(layout, /og\.png/);
  assert.doesNotMatch(layout + favicon, /Starter Project|#68C4FF/);
});

test("Observatory eye identity embeds the supplied artwork and honors reduced motion", async () => {
  const [topbar, css] = await Promise.all([
    readFile(new URL("../app/components/topbar.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/brand-eye.css", import.meta.url), "utf8"),
  ]);
  assert.match(topbar, /sigilArtwork/);
  assert.match(topbar, /sigilGlow/);
  assert.match(topbar, /sigilScan/);
  assert.match(css, /data:image\/jpeg;base64/);
  assert.match(css, /@keyframes eyeBreathe/);
  assert.match(css, /prefers-reduced-motion:reduce/);
  assert.doesNotMatch(topbar + css, /brand-gnome-observatory|brand-eye-loop\.mp4|brand-eye-poster\.jpg/);
});
