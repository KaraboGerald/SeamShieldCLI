import { basename } from "node:path";
import { buildFinding } from "./engine.js";
import type { Finding, Rule, ScanContext } from "./types.js";
import type { FileCache, WalkedFile } from "./walker.js";

const PUBLIC_SECRET_ENV_RE =
  /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_).*(?:SECRET|PRIVATE|PASSWORD|SERVICE_ROLE|API_KEY|TOKEN)/i;
const ADMIN_ROUTE_RE = /\/(?:api\/)?(?:admin|internal|debug|ops|backoffice)(?:\/|$)/i;
const MIDDLEWARE_AUTH_RE = /\b(?:auth|currentUser|getToken|getServerSession|clerkMiddleware|withAuth|NextResponse\.redirect|verify|jwt|session|cookie)\b/i;

function walkJson(value: unknown, visit: (path: string[], value: unknown) => void, path: string[] = []): void {
  visit(path, value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkJson(item, visit, [...path, String(index)]));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) walkJson(item, visit, [...path, key]);
  }
}

function valueAtPath(root: unknown, path: string[]): unknown {
  let current = root;
  for (const segment of path) {
    if (Array.isArray(current)) {
      current = current[Number(segment)];
      continue;
    }
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function hasVercelAuthSignal(root: unknown): boolean {
  let found = false;
  walkJson(root, (path, value) => {
    if (found || typeof value !== "string") return;
    const key = path[path.length - 1] ?? "";
    if (/authorization|x-vercel-protection-bypass|middleware|auth|token/i.test(`${key}:${value}`)) {
      found = true;
    }
  });
  return found;
}

function normalizeRoutePattern(value: string): string {
  return value
    .replace(/\(\.\*\)/g, ":path*")
    .replace(/\/:path\*.*$/, "/")
    .replace(/\/\(\.\*\).*$/, "/")
    .replace(/\/\*.*$/, "/")
    .replace(/\/+$/, "") || "/";
}

function middlewareFiles(files: WalkedFile[]): WalkedFile[] {
  return files.filter((file) => {
    const rel = file.rel.split("\\").join("/");
    return /^(?:src\/)?middleware\.[jt]s$/.test(rel);
  });
}

function extractMiddlewareMatchers(content: string): string[] {
  const matcherBlock = content.match(/matcher\s*:\s*(\[[\s\S]*?\]|["'][^"']+["'])/);
  if (!matcherBlock) return [];
  return [...matcherBlock[1].matchAll(/["']([^"']+)["']/g)].map((match) => match[1]);
}

function routeCoveredByMiddleware(route: string, matcher: string): boolean {
  const normalizedRoute = route.replace(/\/+$/, "") || "/";
  const normalizedMatcher = normalizeRoutePattern(matcher);
  return normalizedRoute === normalizedMatcher || normalizedRoute.startsWith(`${normalizedMatcher}/`);
}

function hasRepoMiddlewareProtection(files: WalkedFile[], cache: FileCache, routes: string[]): boolean {
  for (const file of middlewareFiles(files)) {
    const content = cache.read(file.abs);
    if (!content || !MIDDLEWARE_AUTH_RE.test(content)) continue;
    const matchers = extractMiddlewareMatchers(content);
    if (matchers.length === 0) return true;
    if (routes.some((route) => matchers.some((matcher) => routeCoveredByMiddleware(route, matcher)))) {
      return true;
    }
  }
  return false;
}

function lineForNeedle(content: string, needle: string): number {
  const index = content.indexOf(needle);
  if (index === -1) return 1;
  return content.slice(0, index).split(/\r?\n/).length;
}

function addFinding(
  findings: Finding[],
  rule: Rule,
  file: string,
  line: number,
  evidence: string,
  ctx: ScanContext,
): void {
  findings.push(buildFinding(rule, file, line, evidence.slice(0, 120), ctx));
}

export function checkVercelConfig(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (basename(file.rel) !== "vercel.json") continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(content) as unknown;
    } catch {
      continue;
    }
    const hasAuthSignal = hasVercelAuthSignal(parsed);

    walkJson(parsed, (path, value) => {
      const key = path[path.length - 1] ?? "";
      if (typeof value !== "string") return;

      if (PUBLIC_SECRET_ENV_RE.test(key)) {
        addFinding(findings, rule, file.rel, lineForNeedle(content, key), `public env ${key}`, ctx);
      }

      const joinedPath = path.join(".");
      if (
        /^(routes|rewrites|redirects)\.\d+\.(source|src|destination|dest)$/.test(joinedPath) &&
        ADMIN_ROUTE_RE.test(value) &&
        !hasAuthSignal &&
        !hasRepoMiddlewareProtection(files, cache, [value])
      ) {
        addFinding(
          findings,
          rule,
          file.rel,
          lineForNeedle(content, value),
          `public ${joinedPath} exposes ${value}`,
          ctx,
        );
      }

      if (/^crons\.\d+\.path$/.test(joinedPath) && ADMIN_ROUTE_RE.test(value) && !hasAuthSignal) {
        addFinding(
          findings,
          rule,
          file.rel,
          lineForNeedle(content, value),
          `cron path targets privileged route ${value}`,
          ctx,
        );
      }
    });

    const headers = valueAtPath(parsed, ["headers"]);
    if (Array.isArray(headers)) {
      for (const header of headers) {
        const stringified = JSON.stringify(header);
        if (
          /access-control-allow-origin/i.test(stringified) &&
          /"\*"/.test(stringified) &&
          /access-control-allow-credentials/i.test(stringified) &&
          /true/i.test(stringified)
        ) {
          addFinding(
            findings,
            rule,
            file.rel,
            lineForNeedle(content, "Access-Control-Allow-Origin"),
            "wildcard CORS origin with credentials in vercel.json",
            ctx,
          );
        }
      }
    }
  }
  return findings;
}
