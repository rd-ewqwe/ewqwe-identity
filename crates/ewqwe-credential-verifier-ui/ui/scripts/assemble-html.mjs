/**
 * Assemble index.html from partials.
 *
 * Reads index.template.html (the skeleton with <!--#include src="..." --> directives)
 * and produces index.html by replacing each directive with the content of the
 * referenced file. The indentation of each include directive is prepended to
 * every line of the included content, so the partials can be stored at column 0.
 *
 * Run before `vite dev` / `vite build`:
 *   node scripts/assemble-html.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const SKELETON = resolve(ROOT, "index.template.html");
const OUTPUT = resolve(ROOT, "index.html");
const INCLUDE_RE = /^(\s*)<!--#include\s+src="([^"]+)"\s*-->$/gm;

let html = readFileSync(SKELETON, "utf-8");

html = html.replace(INCLUDE_RE, (_match, indent, srcPath) => {
  const fullPath = resolve(ROOT, srcPath);
  try {
    const content = readFileSync(fullPath, "utf-8");
    // Prepend the same indentation as the include directive to every line
    const indented = content
      .split("\n")
      .map((line) => (line.trim() ? indent + line : line))
      .join("\n");
    return indented;
  } catch (e) {
    console.error(`[assemble] failed to include "${srcPath}":`, e.message);
    return `<!-- ERROR: failed to include "${srcPath}" -->`;
  }
});

writeFileSync(OUTPUT, html, "utf-8");
console.log(`[assemble] wrote ${OUTPUT}`);
