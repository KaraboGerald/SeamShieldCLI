import { basename, extname } from "node:path";
import type { RuleCheck } from "./types.js";
import type { WalkedFile } from "./walker.js";

/** Supports exact names plus simple `*` wildcards. */
export function matchBasenamePattern(name: string, pattern: string): boolean {
  if (pattern.includes("*")) {
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    return new RegExp(`^${escaped}$`).test(name);
  }
  return name === pattern;
}

export function fileMatchesRule(file: WalkedFile, check: RuleCheck): boolean {
  const name = basename(file.rel);
  if (check.exclude?.basenames?.some((p) => matchBasenamePattern(name, p))) return false;
  if (check.exclude?.dirs) {
    const segments = file.rel.split(/[\\/]/);
    if (check.exclude.dirs.some((d) => segments.includes(d))) return false;
  }
  const include = check.include;
  if (!include || (!include.extensions && !include.basenames && !include.path_contains)) {
    return true;
  }
  const rel = file.rel.split("\\").join("/");
  if (
    include.path_contains &&
    !include.path_contains.some((segment) => rel.includes(segment))
  ) {
    return false;
  }
  if (!include.extensions && !include.basenames) return true;
  const ext = extname(name).toLowerCase();
  if (include.extensions?.includes(ext)) return true;
  if (include.basenames?.some((p) => matchBasenamePattern(name, p))) return true;
  return false;
}
