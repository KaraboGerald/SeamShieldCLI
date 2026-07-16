import { buildFinding, isSuppressed } from "./engine.js";
import type { Finding, Rule, ScanContext } from "./types.js";
import type { FileCache, WalkedFile } from "./walker.js";

const SERVER_ACTION_RE = /["']use server["']|export\s+async\s+function|async\s+function\s+\w+Action|\bserver action\b/i;
const TRUSTED_CLIENT_FIELD_RE =
  /\b(?:formData|get|body|req\.json|request\.json|args|input|payload|data)\s*(?:\.get\s*\(\s*["'](?:role|tenantId|teamId|orgId|organizationId|workspaceId|userId|accountId)["']|\.\s*(?:role|tenantId|teamId|orgId|organizationId|workspaceId|userId|accountId)\b)/i;
const PRIVILEGED_USE_RE =
  /\b(?:admin|requireAdmin|deleteUser|deleteMany|updateRole|setRole|role|tenantId|teamId|orgId|organizationId|workspaceId|userId|accountId|db\.(?:insert|update|delete|deleteMany|patch)|prisma\.\w+\.(?:create|update|delete|deleteMany)|convex\.mutation)\b/i;
const SERVER_AUTHZ_RE =
  /\b(?:auth\s*\(|currentUser|getServerSession|getAuthUserId|requireAuth|requireRole|requireAdmin|requireTenant|requireTeam|requireOrg|requireMembership|assertTenant|authorizeTenant|authorizeOrg|authorizeTeam|checkMembership)\b/;

function isNextSource(file: WalkedFile): boolean {
  const rel = file.rel.split("\\").join("/");
  return (
    (rel.startsWith("app/") || rel.startsWith("pages/") || rel.startsWith("src/app/") || rel.startsWith("src/pages/")) &&
    (rel.endsWith(".ts") || rel.endsWith(".tsx") || rel.endsWith(".js") || rel.endsWith(".jsx"))
  );
}

function lineForOffset(content: string, offset: number): number {
  return content.slice(0, offset).split(/\r?\n/).length;
}

export function checkNextServerActionTrustedClient(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!isNextSource(file)) continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    if (!SERVER_ACTION_RE.test(content)) continue;
    if (!TRUSTED_CLIENT_FIELD_RE.test(content) || !PRIVILEGED_USE_RE.test(content)) continue;
    if (SERVER_AUTHZ_RE.test(content)) continue;

    const offset = content.search(TRUSTED_CLIENT_FIELD_RE);
    const line = lineForOffset(content, Math.max(0, offset));
    const lines = content.split(/\r?\n/);
    if (isSuppressed(lines, line - 1, rule.id)) continue;
    findings.push(
      buildFinding(
        rule,
        file.rel,
        line,
        "server action uses role, tenant, org, or user id from client-controlled input without server authorization proof",
        ctx,
      ),
    );
  }
  return findings;
}
