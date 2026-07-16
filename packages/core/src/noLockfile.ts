import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { buildFinding } from "./engine.js";
import type { Finding, Rule, ScanContext } from "./types.js";

const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lockb", "bun.lock"];
const LOCKFILE_MANAGERS: Record<string, string> = {
  "pnpm-lock.yaml": "pnpm",
  "package-lock.json": "npm",
  "yarn.lock": "yarn",
  "bun.lockb": "bun",
  "bun.lock": "bun",
};

/**
 * Flags a root package.json with no lockfile next to it. Without a lockfile
 * every install resolves dependencies fresh, so builds are not reproducible
 * and a hijacked patch release lands silently.
 */
export function checkNoLockfile(rule: Rule, ctx: ScanContext): Finding[] {
  if (!existsSync(join(ctx.root, "package.json"))) return [];
  // Monorepo members resolve against a lockfile higher up — climb a few
  // levels before declaring the project lockfile-less.
  let dir = ctx.root;
  for (let depth = 0; depth < 8; depth++) {
    if (LOCKFILES.some((name) => existsSync(join(dir, name)))) return [];
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return [buildFinding(rule, "package.json", 1, "no lockfile found next to package.json", ctx)];
}

export function checkPackageManagerDrift(rule: Rule, ctx: ScanContext): Finding[] {
  const packageJsonPath = join(ctx.root, "package.json");
  if (!existsSync(packageJsonPath)) return [];

  const lockfiles = LOCKFILES.filter((name) => existsSync(join(ctx.root, name)));
  if (lockfiles.length === 0) return [];

  const findings: Finding[] = [];
  const declared = declaredPackageManager(packageJsonPath);
  const managers = new Set(lockfiles.map((name) => LOCKFILE_MANAGERS[name]));

  if (lockfiles.length > 1) {
    findings.push(
      buildFinding(
        rule,
        "package.json",
        packageManagerLine(packageJsonPath),
        `multiple lockfiles present: ${lockfiles.join(", ")}`,
        ctx,
      ),
    );
  }

  if (declared && !managers.has(declared)) {
    findings.push(
      buildFinding(
        rule,
        "package.json",
        packageManagerLine(packageJsonPath),
        `packageManager declares ${declared}, but lockfiles are for ${[...managers].join(", ")}`,
        ctx,
      ),
    );
  }

  if (declared && managers.size > 1) {
    const mismatched = lockfiles.filter((name) => LOCKFILE_MANAGERS[name] !== declared);
    if (mismatched.length > 0 && findings.length === 0) {
      findings.push(
        buildFinding(
          rule,
          "package.json",
          packageManagerLine(packageJsonPath),
          `stale lockfiles do not match ${declared}: ${mismatched.join(", ")}`,
          ctx,
        ),
      );
    }
  }

  return findings.slice(0, 1);
}

function declaredPackageManager(packageJsonPath: string): string | null {
  try {
    const text = readFileSync(packageJsonPath, "utf8");
    const pkg = JSON.parse(text) as { packageManager?: unknown };
    if (typeof pkg.packageManager !== "string") return null;
    const manager = pkg.packageManager.split("@")[0];
    return manager && ["npm", "pnpm", "yarn", "bun"].includes(manager) ? manager : null;
  } catch {
    return null;
  }
}

function packageManagerLine(packageJsonPath: string): number {
  try {
    const text = readFileSync(packageJsonPath, "utf8");
    const index = text.indexOf('"packageManager"');
    if (index < 0) return 1;
    return text.slice(0, index).split(/\r?\n/).length;
  } catch {
    return 1;
  }
}
