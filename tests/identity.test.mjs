import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("source metadata and identity contain no starter branding", async () => {
  const layout = await readFile(new URL("../app/layout.tsx", import.meta.url), "utf8");
  const favicon = await readFile(new URL("../public/favicon.svg", import.meta.url), "utf8");
  assert.match(layout, /badBANANA \/\/ THREAT OBSERVATORY/);
  assert.match(layout, /og\.png/);
  assert.doesNotMatch(layout + favicon, /Starter Project|#68C4FF/);
});

test("Observatory eye identity has animated and static assets", async () => {
  const [topbar, css] = await Promise.all([
    readFile(new URL("../app/components/topbar.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/brand-eye.css", import.meta.url), "utf8"),
  ]);
  await Promise.all([
    access(new URL("../public/brand-eye-loop.mp4", import.meta.url)),
    access(new URL("../public/brand-eye-poster.jpg", import.meta.url)),
  ]);
  assert.match(topbar, /brand-eye-loop\.mp4/);
  assert.match(topbar, /brand-eye-poster\.jpg/);
  assert.match(css, /prefers-reduced-motion:reduce/);
  assert.doesNotMatch(topbar + css, /brand-gnome-observatory/);
});
