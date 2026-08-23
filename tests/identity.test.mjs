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
