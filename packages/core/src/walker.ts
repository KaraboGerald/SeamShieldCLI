import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next",
  "build",
  "out",
  "coverage",
  "target",
  ".gradle",
  ".turbo",
  ".vercel",
  ".cache",
  ".pnpm-store",
]);

const MAX_FILE_BYTES = 1_000_000;

export interface WalkedFile {
  abs: string;
  rel: string;
}

interface IgnoreRule {
  pattern: string;
  negated: boolean;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegex(pattern: string): RegExp {
  let source = "";
  for (const char of pattern) {
    source += char === "*" ? "[^/]*" : escapeRegex(char);
  }
  return new RegExp(`^${source}$`);
}

function loadGitignore(root: string): IgnoreRule[] {
  let text: string;
  try {
    text = readFileSync(join(root, ".gitignore"), "utf8");
  } catch {
    return [];
  }
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => {
      const negated = line.startsWith("!");
      return { pattern: (negated ? line.slice(1) : line).replace(/^\/+/, ""), negated };
    })
    .filter((rule) => rule.pattern.length > 0);
}

function globMatches(value: string, pattern: string): boolean {
  const normalized = value.split("\\").join("/");
  const clean = pattern.replace(/\/$/, "");
  if (clean.includes("*")) {
    const re = globToRegex(clean);
    if (re.test(normalized)) return true;
    const base = normalized.split("/").pop() ?? normalized;
    return !clean.includes("/") && re.test(base);
  }
  if (clean.includes("/")) return normalized === clean || normalized.startsWith(`${clean}/`);
  const segments = normalized.split("/");
  return segments.includes(clean);
}

function isGitIgnored(rel: string, rules: IgnoreRule[]): boolean {
  let ignored = false;
  const normalized = rel.split("\\").join("/");
  for (const rule of rules) {
    if (!globMatches(normalized, rule.pattern)) continue;
    ignored = !rule.negated;
  }
  return ignored;
}

export function walk(root: string): WalkedFile[] {
  const files: WalkedFile[] = [];
  const gitignore = loadGitignore(root);
  const visit = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        const rel = relative(root, abs).split("\\").join("/");
        if (SKIP_DIRS.has(entry.name)) continue;
        if (entry.name === ".worktrees") continue;
        if (rel === ".claude/worktrees" || rel.endsWith("/.claude/worktrees")) continue;
        if (isGitIgnored(rel, gitignore)) continue;
        visit(abs);
      } else if (entry.isFile()) {
        try {
          if (statSync(abs).size > MAX_FILE_BYTES) continue;
        } catch {
          continue;
        }
        const rel = relative(root, abs).split("\\").join("/");
        if (isGitIgnored(rel, gitignore)) continue;
        files.push({ abs, rel });
      }
    }
  };
  visit(root);
  return files;
}

/** Reads each file at most once per scan; binary and unreadable files map to null. */
export class FileCache {
  private cache = new Map<string, string | null>();

  read(abs: string): string | null {
    const cached = this.cache.get(abs);
    if (cached !== undefined) return cached;
    let value: string | null = null;
    try {
      const buf = readFileSync(abs);
      value = buf.includes(0) ? null : buf.toString("utf8");
    } catch {
      value = null;
    }
    this.cache.set(abs, value);
    return value;
  }
}
