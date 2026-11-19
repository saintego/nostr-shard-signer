// Static checks of the pages served from the signer's origin (examples/,
// portal/). A script there runs with access to the signer's keys and sessions,
// so no page may load script from a URL the visitor can influence (#58).
import { test, expect } from "@playwright/test";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pages = ["examples", "portal"].flatMap((dir) =>
  readdirSync(path.join(root, dir))
    .filter((f) => f.endsWith(".html"))
    .map((f) => path.join(dir, f)),
);

// `.src = <not a string literal>` or setAttribute("src", <not a string literal>).
// Reviewed lines carry a `// static-src-ok` comment.
const dynamicSrc = [
  /\.src\s*=(?!=)(?!\s*["'`][^"'`$]*["'`]\s*;?\s*(\/\/.*)?$)/,
  /setAttribute\(\s*["']src["']\s*,(?!\s*["'][^"']*["']\s*\))/,
];

test("pages on the signer's origin don't build script URLs at runtime", () => {
  expect(pages.length).toBeGreaterThan(0);
  const offenders = [];
  for (const file of pages) {
    readFileSync(path.join(root, file), "utf8").split("\n").forEach((line, i) => {
      if (line.includes("static-src-ok")) return;
      if (dynamicSrc.some((re) => re.test(line))) offenders.push(`${file}:${i + 1}: ${line.trim()}`);
    });
  }
  expect(offenders, "review these lines, then mark them // static-src-ok").toEqual([]);
});

// Signer popups must be unnamed (#77): the page that embeds the signer counts
// as "familiar with" a window the signer's iframe opened, so it could find a
// named popup with window.open("", name) and navigate it to a look-alike page.
test("the signer opens its windows without a name", () => {
  const files = ["nostr-bridge.js"];
  const walk = (dir) => {
    for (const e of readdirSync(path.join(root, dir), { withFileTypes: true })) {
      const rel = path.join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== "vendor") walk(rel); }
      else if (/\.(ts|tsx|js)$/.test(e.name)) files.push(rel);
    }
  };
  walk("bunker/src");
  const offenders = [];
  for (const file of files) {
    readFileSync(path.join(root, file), "utf8").split("\n").forEach((line, i) => {
      if (line.trim().startsWith("//")) return;
      const m = line.match(/window\.open\(([^,)]*)(?:,\s*([^,)]*))?/);
      if (m && m[2] !== undefined && m[2].trim() !== "'_blank'" && m[2].trim() !== '"_blank"')
        offenders.push(`${file}:${i + 1}: ${line.trim()}`);
    });
  }
  expect(offenders).toEqual([]);
});
