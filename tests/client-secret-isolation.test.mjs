import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
test("client output contains no feed secret names or values",async()=>{const files=await walk(new URL("../dist/client",import.meta.url).pathname);const content=(await Promise.all(files.map(file=>readFile(file,"utf8").catch(()=>"")))).join("\n");assert.doesNotMatch(content,/THREATFOX_AUTH_KEY|URLHAUS_AUTH_KEY|MALWAREBAZAAR_AUTH_KEY|YOUR-AUTH-KEY/i)});
async function walk(dir){const entries=await readdir(dir,{withFileTypes:true});const nested=await Promise.all(entries.map(entry=>entry.isDirectory()?walk(join(dir,entry.name)):[join(dir,entry.name)]));return nested.flat()}
