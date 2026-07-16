import { spawnSync } from "node:child_process";
import { basename } from "node:path";
import { buildFinding } from "./engine.js";
import type { Finding, Rule, ScanContext } from "./types.js";

const ALLOWED = new Set([".env.example", ".env.sample", ".env.template"]);
const ENV_FILE_RE = /^\.env(\..+)?$/;

/**
 * Flags dotenv files that git would ship: already tracked, or untracked but
 * not covered by .gitignore (`git ls-files --cached --others
 * --exclude-standard`). Outside a git repo the check is skipped — there is
 * no commit surface to leak through.
 */
export function checkEnvFileCommitted(rule: Rule, ctx: ScanContext): Finding[] {
  const result = spawnSync(
    "git",
    ["-C", ctx.root, "ls-files", "--cached", "--others", "--exclude-standard"],
    { encoding: "utf8", timeout: 1_500 },
  );
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") {
    return [];
  }
  const findings: Finding[] = [];
  for (const rel of result.stdout.split("\n")) {
    if (!rel) continue;
    const name = basename(rel);
    if (!ENV_FILE_RE.test(name) || ALLOWED.has(name)) continue;
    findings.push(
      buildFinding(rule, rel, 1, "dotenv file is tracked by git or not covered by .gitignore", ctx),
    );
  }
  return findings;
}
