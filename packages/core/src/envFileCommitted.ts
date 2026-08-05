import { spawnSync } from "node:child_process";
import { basename } from "node:path";
import { buildFinding } from "./engine.js";
import type { Finding, Rule, ScanContext } from "./types.js";

const ALLOWED = new Set([".env.example", ".env.sample", ".env.template"]);
const ENV_FILE_RE = /^\.env(\..+)?$/;
// Templates are commonly named for what they configure --
// `.env.deploy-verify.example`, `.env.staging.sample` -- not just `.env.example`.
// Matching the bare names alone reported placeholder templates as committed
// secrets, which is a false positive that blocks a release for a file that by
// definition holds no credentials.
const TEMPLATE_SUFFIX_RE = /\.(example|sample|template)$/i;

function isTemplateName(name: string): boolean {
  return ALLOWED.has(name) || TEMPLATE_SUFFIX_RE.test(name);
}

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
    if (!ENV_FILE_RE.test(name) || isTemplateName(name)) continue;
    findings.push(
      buildFinding(rule, rel, 1, "dotenv file is tracked by git or not covered by .gitignore", ctx),
    );
  }
  return findings;
}
