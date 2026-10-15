#!/usr/bin/env node
// skill-scan: check a Claude / agent skill folder before you install it.
// Usage: npx github:thebigasif/skill-scan <folder> [--json]
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { scanSkill } from "../rules.js";

const args = process.argv.slice(2);
const json = args.includes("--json");
const target = resolve(args.find((a) => !a.startsWith("--")) ?? ".");
const TEXT = /\.(md|mdx|txt|py|sh|bash|zsh|js|mjs|cjs|ts|json|ya?ml|toml|rb|pl|ps1|php|html|css|csv|xml|ini|cfg)$|(^|\/)[^./]+$/i;
const SKIP = new Set(["node_modules", ".git", ".venv", "__pycache__", "dist"]);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (st.size <= 200_000 && TEXT.test(name)) out.push(p);
  }
  return out;
}

/** Every folder under target that holds a SKILL.md is one skill. */
function skillDirs(root) {
  if (existsSync(join(root, "SKILL.md"))) return [root];
  const dirs = [];
  for (const f of walk(root)) if (f.endsWith("/SKILL.md")) dirs.push(f.slice(0, -"/SKILL.md".length));
  return dirs;
}

const dirs = skillDirs(target);
if (!dirs.length) { console.error(`No SKILL.md found under ${target}`); process.exit(2); }
const results = dirs.map((dir) => {
  const files = walk(dir).map((p) => ({ path: relative(dir, p), text: readFileSync(p, "utf8") }));
  const r = scanSkill(files, readFileSync(join(dir, "SKILL.md"), "utf8"));
  return { skill: r.meta.name ?? (relative(target, dir) || "."), dir: relative(process.cwd(), dir) || ".", grade: r.grade, score: r.score, findings: r.findings };
});

if (json) console.log(JSON.stringify(results, null, 2));
else {
  const SEV = { critical: "\x1b[41m CRIT \x1b[0m", high: "\x1b[31m HIGH \x1b[0m", medium: "\x1b[33m MED  \x1b[0m", low: "\x1b[2m LOW  \x1b[0m" };
  for (const r of results) {
    console.log(`\n${r.skill}  grade ${r.grade} (${r.score}/100)  ${r.dir}`);
    if (!r.findings.length) console.log("  no findings");
    for (const f of r.findings) console.log(`  ${SEV[f.severity]} ${f.file}:${f.line}  ${f.note}\n         ${f.text}`);
  }
  console.log("\nSame rules mcp.market runs on 5,000+ public skills, already graded: https://mcp.market/skills");
}
process.exit(results.some((r) => r.grade === "F") ? 1 : 0);
