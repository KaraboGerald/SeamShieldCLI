import { buildFinding, isSuppressed } from "./engine.js";
import type { Finding, Rule, ScanContext } from "./types.js";
import type { FileCache, WalkedFile } from "./walker.js";

const PUBLIC_FUNCTION_RE =
  /\bexport\s+const\s+(?<name>[A-Za-z_$][\w$]*)\s*=\s*(?<kind>query|mutation|action)\s*\(/g;
const INTERNAL_FUNCTION_RE = /\binternal(?:Query|Mutation|Action)\s*\(/;
const AUTH_MARKER_RE =
  /\b(?:ctx\.auth|getAuthUserId|getUserIdentity|requireAuth|requireInternalToken|getCaller|requireRole|requireAdmin|requireTenant|requireTeam|requireOrg|requireWorkspace|requireMembership|requireTeamMember|requireOrgMember|requireTenantMember|assertTenant|assertTeam|assertOrg|authorizeTenant|authorizeTeam|authorizeOrg|checkMembership)\b/;
const PUBLIC_INTENT_RE =
  /\b(?:seamshield-public|publicIntent|publicMutation|publicAction|allowAnonymous|rateLimit|rateLimiter|RATE_LIMITED|waitlist_join|emailHash|hashKey|normalizeEmail|isValidEmail)\b/;
const SENSITIVE_ACTION_RE =
  /\b(?:ctx\.db\.(?:insert|patch|replace|delete)|process\.env|admin|tenant|team|org|role|invite|token|secret|apiKey|webhook|billing|subscription|delete|recompute|backfill|sync|migrate)\b/i;
const PRIVILEGED_PUBLIC_RE =
  /\b(?:admin|tenant|team|org|workspace|role|invite|token|secret|apiKey|webhook|billing|subscription|delete|recompute|backfill|sync|migrate)\b/i;
const PUBLIC_SAFE_WRITE_RE =
  /\bctx\.db\.insert\s*\(\s*["'](?:waitlist|waitlists|leads|contacts|feedback|events|analytics|telemetry|publicEvents|signups)["']/i;
const TENANT_ARG_RE =
  /\bargs\.(?:tenantId|teamId|orgId|organizationId|workspaceId|accountId)\b/;
const TENANT_WRITE_RE =
  /\bctx\.db\.(?:insert|patch|replace|delete)\b/;

function lineForOffset(content: string, offset: number): number {
  return content.slice(0, offset).split(/\r?\n/).length;
}

function statementWindow(content: string, start: number): string {
  const end = content.indexOf("\nexport const", start + 1);
  const next = end === -1 ? content.length : end;
  return content.slice(start, next);
}

function isConvexSource(file: WalkedFile): boolean {
  const rel = file.rel.split("\\").join("/");
  return (
    rel.startsWith("convex/") &&
    !rel.includes("/_generated/") &&
    (rel.endsWith(".ts") || rel.endsWith(".js"))
  );
}

function hasSafePublicIntent(window: string): boolean {
  if (!PUBLIC_INTENT_RE.test(window)) return false;
  if (!SENSITIVE_ACTION_RE.test(window)) return true;
  if (PRIVILEGED_PUBLIC_RE.test(window)) return false;
  if (PUBLIC_SAFE_WRITE_RE.test(window) && /\b(?:rateLimit|rateLimiter|RATE_LIMITED|emailHash|hashKey|normalizeEmail|isValidEmail)\b/.test(window)) {
    return true;
  }
  return /\/\*\s*seamshield-public\s*\*\/[\s\S]{0,160}\breturn\s+(?:null|undefined|true|false|[\w.]+)\b/.test(window);
}

export function checkConvexPublicFunctions(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!isConvexSource(file)) continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    if (INTERNAL_FUNCTION_RE.test(content)) continue;

    PUBLIC_FUNCTION_RE.lastIndex = 0;
    for (const match of content.matchAll(PUBLIC_FUNCTION_RE)) {
      const kind = match.groups?.kind;
      const name = match.groups?.name ?? "function";
      const offset = match.index ?? 0;
      const window = statementWindow(content, offset);
      if (AUTH_MARKER_RE.test(window) || hasSafePublicIntent(window)) continue;
      if (kind === "query" && !SENSITIVE_ACTION_RE.test(window)) continue;
      if (!SENSITIVE_ACTION_RE.test(window)) continue;

      const line = lineForOffset(content, offset);
      const lines = content.split(/\r?\n/);
      if (isSuppressed(lines, line - 1, rule.id)) continue;
      findings.push(
        buildFinding(
          rule,
          file.rel,
          line,
          `${kind ?? "function"} ${name} has sensitive server capability and no recognized auth marker`,
          ctx,
        ),
      );
    }
  }
  return findings;
}

export function checkConvexTenantBoundWrites(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!isConvexSource(file)) continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    if (INTERNAL_FUNCTION_RE.test(content)) continue;

    PUBLIC_FUNCTION_RE.lastIndex = 0;
    for (const match of content.matchAll(PUBLIC_FUNCTION_RE)) {
      const kind = match.groups?.kind ?? "function";
      const name = match.groups?.name ?? "function";
      const offset = match.index ?? 0;
      const window = statementWindow(content, offset);
      if (!TENANT_ARG_RE.test(window) || !TENANT_WRITE_RE.test(window)) continue;
      if (AUTH_MARKER_RE.test(window)) continue;
      const line = lineForOffset(content, offset);
      const lines = content.split(/\r?\n/);
      if (isSuppressed(lines, line - 1, rule.id)) continue;
      findings.push(
        buildFinding(
          rule,
          file.rel,
          line,
          `${kind} ${name} writes tenant/org-scoped data using caller-provided args without membership proof`,
          ctx,
        ),
      );
    }
  }
  return findings;
}
