import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { buildFinding } from "./engine.js";
import type { Finding, Rule, ScanContext, Severity } from "./types.js";
import type { WalkedFile } from "./walker.js";

const DEP_FIELDS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
] as const;

interface Dependency {
  name: string;
  spec: string;
  manifestRel: string;
  line: number;
}

interface CacheEntry<T> {
  ok: boolean;
  value?: T;
  time: number;
}

export interface DependencyNetworkOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function dependencyLine(text: string, name: string): number {
  const needle = `"${name}"`;
  const index = text.indexOf(needle);
  if (index < 0) return 1;
  return text.slice(0, index).split(/\r?\n/).length;
}

function collectDependencies(ctx: ScanContext, files: WalkedFile[]): Dependency[] {
  const deps: Dependency[] = [];
  for (const file of files) {
    if (!file.rel.endsWith("package.json")) continue;
    let text: string;
    let pkg: Record<string, unknown>;
    try {
      text = readFileSync(file.abs, "utf8");
      pkg = JSON.parse(text) as Record<string, unknown>;
    } catch {
      continue;
    }
    for (const field of DEP_FIELDS) {
      const block = pkg[field];
      if (!block || typeof block !== "object") continue;
      for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
        if (typeof spec !== "string") continue;
        deps.push({ name, spec, manifestRel: file.rel, line: dependencyLine(text, name) });
      }
    }
  }
  // De-dupe repeated workspace manifests while preserving the first location.
  const seen = new Set<string>();
  return deps.filter((dep) => {
    const key = `${dep.name}@${dep.spec}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function cachePath(ctx: ScanContext, kind: string, key: string): string {
  const safe = encodeURIComponent(key).replace(/[!'()*]/g, "_");
  return join(ctx.root, ".seamshield", "cache", kind, `${safe}.json`);
}

function readCache<T>(ctx: ScanContext, kind: string, key: string): T | undefined {
  try {
    const entry = readJson(cachePath(ctx, kind, key)) as CacheEntry<T>;
    if (!entry.ok) return undefined;
    if (Date.now() - entry.time > 24 * 60 * 60 * 1000) return undefined;
    return entry.value;
  } catch {
    return undefined;
  }
}

function writeCache<T>(ctx: ScanContext, kind: string, key: string, value: T): void {
  const path = cachePath(ctx, kind, key);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ ok: true, value, time: Date.now() } satisfies CacheEntry<T>));
}

async function fetchJson(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  fetchImpl: typeof fetch,
): Promise<{ status: number; body: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { ...init, signal: controller.signal });
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { status: response.status, body };
  } finally {
    clearTimeout(timer);
  }
}

export async function checkHallucinatedPackages(
  rule: Rule,
  ctx: ScanContext,
  files: WalkedFile[],
  options: DependencyNetworkOptions = {},
): Promise<Finding[]> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (!fetchImpl) return [];
  const timeoutMs = options.timeoutMs ?? 750;
  const findings: Finding[] = [];
  for (const dep of collectDependencies(ctx, files)) {
    const cached = readCache<{ exists: boolean }>(ctx, "npm", dep.name);
    let exists = cached?.exists;
    if (exists === undefined) {
      try {
        const encoded = dep.name.startsWith("@") ? dep.name.replace("/", "%2F") : dep.name;
        const result = await fetchJson(
          `https://registry.npmjs.org/${encoded}`,
          { headers: { accept: "application/vnd.npm.install-v1+json" } },
          timeoutMs,
          fetchImpl,
        );
        exists = result.status !== 404;
        if (result.status >= 200 && result.status < 500) {
          writeCache(ctx, "npm", dep.name, { exists });
        }
      } catch {
        continue;
      }
    }
    if (exists === false) {
      findings.push(
        buildFinding(rule, dep.manifestRel, dep.line, `${dep.name} returned 404 from npm`, ctx),
      );
    }
  }
  return findings;
}

function normalizedVersion(spec: string): string | null {
  const exact = spec.trim().replace(/^[~^]/, "");
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(exact) ? exact : null;
}

function vulnSeverity(vuln: Record<string, unknown>): Severity {
  const haystack = JSON.stringify(vuln).toLowerCase();
  return haystack.includes("kev") || haystack.includes("known exploited") ? "block" : "high";
}

export async function checkKnownVulnerabilities(
  rule: Rule,
  ctx: ScanContext,
  files: WalkedFile[],
  options: DependencyNetworkOptions = {},
): Promise<Finding[]> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (!fetchImpl) return [];
  const deps = collectDependencies(ctx, files)
    .map((dep) => ({ ...dep, version: normalizedVersion(dep.spec) }))
    .filter((dep): dep is Dependency & { version: string } => dep.version !== null);
  if (deps.length === 0) return [];
  const timeoutMs = options.timeoutMs ?? 750;
  const findings: Finding[] = [];

  for (const dep of deps) {
    const cacheKey = `${dep.name}@${dep.version}`;
    let vulns = readCache<Record<string, unknown>[]>(ctx, "osv", cacheKey);
    if (!vulns) {
      try {
        const result = await fetchJson(
          "https://api.osv.dev/v1/query",
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              package: { ecosystem: "npm", name: dep.name },
              version: dep.version,
            }),
          },
          timeoutMs,
          fetchImpl,
        );
        if (result.status < 200 || result.status >= 300) continue;
        const body = result.body as { vulns?: Record<string, unknown>[] };
        vulns = body.vulns ?? [];
        writeCache(ctx, "osv", cacheKey, vulns);
      } catch {
        continue;
      }
    }
    for (const vuln of vulns.slice(0, 3)) {
      const id = typeof vuln.id === "string" ? vuln.id : "OSV";
      const severity = vulnSeverity(vuln);
      findings.push(
        buildFinding(
          { ...rule, severity },
          dep.manifestRel,
          dep.line,
          `${dep.name}@${dep.version} is affected by ${id}`,
          ctx,
        ),
      );
    }
  }
  return findings;
}
