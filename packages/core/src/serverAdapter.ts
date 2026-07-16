import { buildFinding, isSuppressed } from "./engine.js";
import { fileMatchesRule } from "./matchers.js";
import type { Finding, Rule, ScanContext } from "./types.js";
import type { FileCache, WalkedFile } from "./walker.js";

const AUTH_RE =
  /\b(?:auth|Auth|session|Session|jwt|JWT|bearer|Bearer|cookie|Cookie|signature|webhook|x-api-key|apiKey|API_KEY|requireAuth|requireAdmin|requireRole|verify|authorize|ensureTenant|requireTenant|requireOrg|requireTeam|requireMembership)\b/;
const PUBLIC_RE = /\b(?:public|health|ready|readiness|liveness|metrics|status|ping|webhook)\b/i;
const SENSITIVE_ROUTE_RE =
  /\/(?:admin|internal|ops|debug|backoffice|users?|accounts?|tenants?|orgs?|teams?|impersonat|delete|billing|secrets?)(?:\/|$|-|_)?/i;
const SENSITIVE_HANDLER_RE =
  /\b(?:deleteUser|deleteMany|impersonate|setRole|updateRole|admin|secret|billing|tenantId|orgId|teamId|userId|accountId|prisma\.\w+\.(?:delete|deleteMany|update|create)|db\.\w*\.(?:delete|update|insert|patch)|db\.(?:delete|update|insert|patch))\b/i;
const MUTATING_METHODS = new Set(["post", "put", "patch", "delete"]);
const WEBHOOK_SIGNATURE_RE = /\b(?:verify(?:Webhook|Signature|Event)|constructEvent|webhook(?:Signature|Verifier)|signature(?:Header)?|svix|stripe\.webhooks)\b/i;

interface RouterInfo {
  name: string;
  hasAuthMiddleware: boolean;
}

interface MountInfo {
  router: string;
  prefix: string;
  hasAuthMiddleware: boolean;
}

interface RouteInfo {
  router: string;
  method: string;
  path: string;
  line: number;
  statement: string;
}

export function checkServerGroupedRouters(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!fileMatchesRule(file, rule.check)) continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    if (!/\b(?:express|fastify|Hono|Router|router|app|server)\b/.test(content)) continue;

    const lines = content.split(/\r?\n/);
    if (lines.some((_, index) => isSuppressed(lines, index, rule.id))) continue;

    const routers = collectRouters(content);
    const mounts = collectMounts(content);
    const routes = collectRoutes(content);
    const authByRouter = new Map<string, boolean>();
    for (const router of routers.values()) authByRouter.set(router.name, router.hasAuthMiddleware);
    for (const mount of mounts) {
      authByRouter.set(
        mount.router,
        Boolean(authByRouter.get(mount.router) || mount.hasAuthMiddleware),
      );
    }

    const matchedRoutes = new Set<string>();
    for (const route of routes) {
      const routeKey = `${route.router}:${route.line}:${route.method}:${route.path}`;
      if (matchedRoutes.has(routeKey)) continue;
      if (!isPrivilegedRoute(route, mounts)) continue;
      if (routeHasAuth(route, content, authByRouter, mounts)) continue;
      matchedRoutes.add(routeKey);
      findings.push(
        buildFinding(
          rule,
          file.rel,
          route.line,
          `grouped ${route.router}.${route.method}(${route.path}) has no recognized auth middleware`,
          ctx,
        ),
      );
    }
  }

  return findings;
}

export function checkWebhookSignatureBoundary(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!fileMatchesRule(file, rule.check)) continue;
    const content = cache.read(file.abs);
    if (content === null || !/\b(?:express|fastify|Hono|Router|router|app|server)\b/.test(content)) continue;
    const lines = content.split(/\r?\n/);
    for (const route of collectRoutes(content)) {
      if (route.method !== "post" || !/webhook/i.test(route.path)) continue;
      if (isSuppressed(lines, route.line - 1, rule.id)) continue;
      const nearby = lines.slice(Math.max(0, route.line - 1), Math.min(lines.length, route.line + 24)).join("\n");
      if (WEBHOOK_SIGNATURE_RE.test(route.statement) || WEBHOOK_SIGNATURE_RE.test(nearby)) continue;
      findings.push(buildFinding(rule, file.rel, route.line, `webhook route ${route.router}.post(${route.path}) has no recognizable signature verification`, ctx));
    }
  }
  return findings;
}

function collectRouters(content: string): Map<string, RouterInfo> {
  const routers = new Map<string, RouterInfo>();
  const routerDeclRe =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express\.)?Router\s*\(|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+Hono\s*\(/g;
  for (const match of content.matchAll(routerDeclRe)) {
    const name = match[1] ?? match[2];
    if (name) routers.set(name, { name, hasAuthMiddleware: false });
  }

  for (const match of content.matchAll(/\b([A-Za-z_$][\w$]*)\.use\s*\(([^)]*)\)/g)) {
    const router = routers.get(match[1]);
    if (!router) continue;
    if (AUTH_RE.test(match[2] ?? "")) router.hasAuthMiddleware = true;
  }

  return routers;
}

function collectMounts(content: string): MountInfo[] {
  const mounts: MountInfo[] = [];
  const mountRe =
    /\b(?:app|server)\.(?:use|route|register)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*([^)\n;]+)\)/g;
  for (const match of content.matchAll(mountRe)) {
    const prefix = match[1] ?? "/";
    const args = match[2] ?? "";
    const routerMatch = [...args.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)].at(-1);
    const router = routerMatch?.[1];
    if (!router || ["requireAuth", "auth", "verify", "authorize"].includes(router)) continue;
    mounts.push({ router, prefix, hasAuthMiddleware: AUTH_RE.test(args.replace(router, "")) });
  }
  return mounts;
}

function collectRoutes(content: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  const routeRe =
    /\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|route)\s*\(\s*["'`]([^"'`]+)["'`]([^;]*)/gi;
  for (const match of content.matchAll(routeRe)) {
    const router = match[1];
    const method = (match[2] ?? "").toLowerCase();
    const path = match[3] ?? "/";
    if (!router || !method) continue;
    if (
      method === "route" &&
      /^(?:app|server)$/i.test(router) &&
      /,\s*[A-Za-z_$][\w$]*\s*\)?\s*;?\s*$/.test(match[4] ?? "")
    ) {
      continue;
    }
    routes.push({
      router,
      method,
      path,
      line: lineForOffset(content, match.index ?? 0),
      statement: match[0] ?? "",
    });
  }
  return routes;
}

function routeHasAuth(
  route: RouteInfo,
  content: string,
  authByRouter: Map<string, boolean>,
  mounts: MountInfo[],
): boolean {
  if (AUTH_RE.test(route.statement)) return true;
  if (authByRouter.get(route.router)) return true;
  if (mounts.some((mount) => mount.router === route.router && mount.hasAuthMiddleware)) return true;
  if (hasPriorRouterAuthUse(route, content)) return true;

  const routePrefix = new RegExp(`\\b${escapeRegExp(route.router)}\\.(?:get|post|put|patch|delete|route)\\s*\\(`);
  const beforeFirstRoute = content.slice(0, Math.max(0, content.search(routePrefix)));
  return new RegExp(`\\b${escapeRegExp(route.router)}\\.use\\s*\\([^)]*(?:${AUTH_RE.source})`, "i").test(
    beforeFirstRoute,
  );
}

function hasPriorRouterAuthUse(route: RouteInfo, content: string): boolean {
  const lines = content.split(/\r?\n/).slice(0, Math.max(0, route.line - 1));
  return lines.some(
    (line) =>
      new RegExp(`\\b${escapeRegExp(route.router)}\\.use\\s*\\(`).test(line) && AUTH_RE.test(line),
  );
}

function isPrivilegedRoute(route: RouteInfo, mounts: MountInfo[]): boolean {
  const mountedPrefixes = mounts
    .filter((mount) => mount.router === route.router)
    .map((mount) => mount.prefix);
  const fullRoutes = mountedPrefixes.length
    ? mountedPrefixes.map((prefix) => joinRoute(prefix, route.path))
    : [route.path];
  if (fullRoutes.some((path) => SENSITIVE_ROUTE_RE.test(path))) return true;
  if (MUTATING_METHODS.has(route.method) && !fullRoutes.some((path) => PUBLIC_RE.test(path))) {
    return SENSITIVE_HANDLER_RE.test(route.statement) || /admin|internal|private/i.test(route.router);
  }
  return false;
}

function joinRoute(prefix: string, path: string): string {
  return `${prefix.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`.replace(/\/+/g, "/");
}

function lineForOffset(content: string, offset: number): number {
  return content.slice(0, offset).split(/\r?\n/).length;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
