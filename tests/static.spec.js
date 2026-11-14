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
