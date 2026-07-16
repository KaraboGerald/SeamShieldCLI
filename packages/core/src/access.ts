import pc from "picocolors";
import { stableId } from "./ids.js";
import {
  SEVERITY_RANK,
  type AccessActor,
  type AccessLane,
  type AccessLaneKind,
  type AccessMap,
  type AccessPermission,
  type AccessRisk,
  type Finding,
  type RuleFix,
  type ScanResult,
  type Severity,
  type ShipVerdict,
} from "./types.js";

interface LaneTemplate {
  actor: AccessActor;
  lane: AccessLaneKind;
  asset: (finding: Finding) => string;
  permission: AccessPermission;
  condition: string;
  risk: AccessRisk;
  provider: string;
}

const ROUTE_ASSET_RE = /^(?:app|pages)\/(.+?)(?:\/route)?\.[tj]sx?$/;

function envAsset(finding: Finding): string {
  const evidence = finding.spans[0]?.evidence ?? "";
  const upper = evidence.match(/[A-Z][A-Z0-9_]{3,}/)?.[0];
  if (upper) return `env:${upper}`;
  if (finding.finding.rule_id.includes("supabase")) return "env:SUPABASE_SERVICE_ROLE_KEY";
  if (finding.finding.rule_id.includes("next-public")) return "env:NEXT_PUBLIC_*SECRET*";
  return "env:server_secret";
}

function routeAsset(finding: Finding): string {
  const normalized = finding.finding.file.split("\\").join("/");
  const route = ROUTE_ASSET_RE.exec(normalized)?.[1];
  if (route) return `/${route.replace(/\/page$|\/route$/, "")}`;
  return normalized;
}

function packageAsset(finding: Finding): string {
  const evidence = finding.spans[0]?.evidence ?? "";
  const quoted = evidence.match(/"([^"]+)"/)?.[1];
  return quoted && quoted.trim().length > 1 ? `package:${quoted}` : "package.json";
}

function databaseAsset(finding: Finding): string {
  if (finding.finding.file.includes("firestore")) return "firestore.rules";
  if (finding.finding.file.includes("convex/")) return `convex:${routeAsset(finding)}`;
  if (finding.finding.file.includes("supabase/")) return "supabase:database";
  return finding.finding.file;
}

const RULE_TEMPLATES: Record<string, LaneTemplate> = {
  "ss/client/supabase-service-role-in-client": {
    actor: "frontend_bundle",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "client_exposed",
    risk: "client_to_server_secret",
    provider: "supabase",
  },
  "ss/secrets/supabase-service-role-key": {
    actor: "server_runtime",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "hardcoded_or_committed",
    risk: "server_secret_exposure",
    provider: "supabase",
  },
  "ss/supabase/rls-disabled": {
    actor: "public_user",
    lane: "database",
    asset: databaseAsset,
    permission: "read",
    condition: "rls_disabled",
    risk: "public_database_access",
    provider: "supabase",
  },
  "ss/supabase/permissive-policy": {
    actor: "public_user",
    lane: "database",
    asset: databaseAsset,
    permission: "write",
    condition: "permissive_policy",
    risk: "public_database_access",
    provider: "supabase",
  },
  "ss/firebase/open-rules": {
    actor: "public_user",
    lane: "database",
    asset: databaseAsset,
    permission: "write",
    condition: "open_rules",
    risk: "public_database_access",
    provider: "firebase",
  },
  "ss/client/firebase-admin-in-client": {
    actor: "frontend_bundle",
    lane: "env_variable",
    asset: () => "firebase:admin_sdk",
    permission: "admin",
    condition: "client_exposed",
    risk: "client_to_admin",
    provider: "firebase",
  },
  "ss/convex/mutation-no-auth": {
    actor: "public_user",
    lane: "server_action",
    asset: databaseAsset,
    permission: "execute",
    condition: "no_auth_check",
    risk: "anonymous_write",
    provider: "convex",
  },
  "ss/convex/internal-not-internal": {
    actor: "public_user",
    lane: "server_action",
    asset: databaseAsset,
    permission: "execute",
    condition: "internal_function_public",
    risk: "untrusted_admin_surface",
    provider: "convex",
  },
  "ss/convex/public-function-no-auth": {
    actor: "public_user",
    lane: "server_action",
    asset: databaseAsset,
    permission: "execute",
    condition: "sensitive_public_function_no_auth",
    risk: "anonymous_write",
    provider: "convex",
  },
  "ss/convex/tenant-bound-write": {
    actor: "public_user",
    lane: "server_action",
    asset: databaseAsset,
    permission: "write",
    condition: "caller_supplied_tenant_id",
    risk: "anonymous_write",
    provider: "convex",
  },
  "ss/auth/api-route-no-auth": {
    actor: "public_user",
    lane: "http_route",
    asset: routeAsset,
    permission: "execute",
    condition: "no_auth_or_signature",
    risk: "anonymous_execute",
    provider: "web",
  },
  "ss/auth/admin-route-unprotected": {
    actor: "public_user",
    lane: "http_route",
    asset: routeAsset,
    permission: "admin",
    condition: "no_server_auth",
    risk: "untrusted_admin_surface",
    provider: "web",
  },
  "ss/auth/client-only-guard": {
    actor: "authenticated_user",
    lane: "http_route",
    asset: routeAsset,
    permission: "admin",
    condition: "client_only_role_check",
    risk: "client_to_admin",
    provider: "web",
  },
  "ss/next/server-action-trusted-client": {
    actor: "authenticated_user",
    lane: "server_action",
    asset: routeAsset,
    permission: "admin",
    condition: "trusted_client_authorization_field",
    risk: "client_to_admin",
    provider: "nextjs",
  },
  "ss/auth/cors-wildcard-with-credentials": {
    actor: "public_user",
    lane: "http_route",
    asset: routeAsset,
    permission: "execute",
    condition: "wildcard_origin_with_credentials",
    risk: "cors_credential_theft",
    provider: "web",
  },
  "ss/server/route-no-auth": {
    actor: "public_user",
    lane: "self_hosted_server",
    asset: routeAsset,
    permission: "execute",
    condition: "no_auth_middleware",
    risk: "anonymous_execute",
    provider: "self-hosted",
  },
  "ss/deploy/public-env-secret": {
    actor: "deploy_platform",
    lane: "deploy_config",
    asset: envAsset,
    permission: "read",
    condition: "public_or_build_exposed",
    risk: "deploy_secret_exposure",
    provider: "deploy",
  },
  "ss/vercel/config-access-risk": {
    actor: "deploy_platform",
    lane: "deploy_config",
    asset: routeAsset,
    permission: "execute",
    condition: "vercel_public_deploy_surface",
    risk: "deploy_secret_exposure",
    provider: "vercel",
  },
  "ss/client/server-secret-env-in-client": {
    actor: "frontend_bundle",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "client_exposed",
    risk: "client_to_server_secret",
    provider: "web",
  },
  "ss/client/next-public-secret": {
    actor: "frontend_bundle",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "next_public_exposed",
    risk: "client_to_server_secret",
    provider: "nextjs",
  },
  "ss/secrets/env-file-committed": {
    actor: "ai_agent",
    lane: "filesystem",
    asset: () => ".env",
    permission: "modify",
    condition: "committed_or_staged",
    risk: "agent_to_secret",
    provider: "agent",
  },
  "ss/agent/secrets-in-agent-files": {
    actor: "ai_agent",
    lane: "agent_tooling",
    asset: routeAsset,
    permission: "read",
    condition: "agent_instruction_exposes_secret",
    risk: "agent_to_secret",
    provider: "agent",
  },
  "ss/agent/mcp-inline-credentials": {
    actor: "ai_agent",
    lane: "agent_tooling",
    asset: routeAsset,
    permission: "read",
    condition: "inline_mcp_credentials",
    risk: "agent_to_secret",
    provider: "agent",
  },
  "ss/agent/overbroad-permissions": {
    actor: "ai_agent",
    lane: "agent_tooling",
    asset: routeAsset,
    permission: "execute",
    condition: "overbroad_tool_permission",
    risk: "agent_to_secret",
    provider: "agent",
  },
  "ss/agent/risky-filesystem-permissions": {
    actor: "ai_agent",
    lane: "agent_tooling",
    asset: routeAsset,
    permission: "modify",
    condition: "agent_can_touch_secrets_or_broad_paths",
    risk: "agent_to_secret",
    provider: "agent",
  },
  "ss/ai/public-provider-key": {
    actor: "frontend_bundle",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "public_ai_provider_key",
    risk: "client_to_server_secret",
    provider: "ai",
  },
  "ss/ai/untrusted-model-base-url": {
    actor: "server_runtime",
    lane: "http_route",
    asset: routeAsset,
    permission: "execute",
    condition: "unofficial_model_gateway",
    risk: "untrusted_model_gateway",
    provider: "ai",
  },
  "ss/server/webhook-missing-signature": {
    actor: "public_user",
    lane: "http_route",
    asset: routeAsset,
    permission: "execute",
    condition: "missing_signature_verification",
    risk: "webhook_missing_signature",
    provider: "node",
  },
  "ss/deps/postinstall-script": {
    actor: "dependency",
    lane: "package_install",
    asset: packageAsset,
    permission: "execute",
    condition: "install_lifecycle_script",
    risk: "dependency_to_shell",
    provider: "npm",
  },
  "ss/deps/unpinned-spec": {
    actor: "dependency",
    lane: "package_install",
    asset: packageAsset,
    permission: "install",
    condition: "latest_or_star",
    risk: "unreproducible_dependency",
    provider: "npm",
  },
  "ss/deps/known-vuln": {
    actor: "dependency",
    lane: "package_install",
    asset: packageAsset,
    permission: "execute",
    condition: "known_vulnerability",
    risk: "known_vulnerable_dependency",
    provider: "npm",
  },
  "ss/deps/hallucinated-package": {
    actor: "dependency",
    lane: "package_install",
    asset: packageAsset,
    permission: "install",
    condition: "package_not_found",
    risk: "unknown_package",
    provider: "npm",
  },
  "ss/deps/no-lockfile": {
    actor: "dependency",
    lane: "package_install",
    asset: () => "lockfile",
    permission: "install",
    condition: "missing_lockfile",
    risk: "unreproducible_dependency",
    provider: "npm",
  },
  "ss/deps/package-manager-drift": {
    actor: "dependency",
    lane: "package_install",
    asset: () => "lockfile",
    permission: "install",
    condition: "package_manager_lockfile_drift",
    risk: "unreproducible_dependency",
    provider: "npm",
  },
  "ss/secrets/hardcoded-provider-key": {
    actor: "server_runtime",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "hardcoded",
    risk: "server_secret_exposure",
    provider: "provider",
  },
  "ss/secrets/generic-credential-assignment": {
    actor: "server_runtime",
    lane: "env_variable",
    asset: envAsset,
    permission: "read",
    condition: "credential_assignment",
    risk: "server_secret_exposure",
    provider: "provider",
  },
  "ss/secrets/private-key-file": {
    actor: "server_runtime",
    lane: "filesystem",
    asset: routeAsset,
    permission: "read",
    condition: "private_key_file",
    risk: "server_secret_exposure",
    provider: "provider",
  },
};

function fallbackTemplate(finding: Finding): LaneTemplate {
  if (finding.finding.file.includes("coolify") || finding.finding.file.includes("docker")) {
    return {
      actor: "deploy_platform",
      lane: "deploy_config",
      asset: routeAsset,
      permission: "execute",
      condition: "deploy_config_change",
      risk: "deploy_secret_exposure",
      provider: "deploy",
    };
  }
  return {
    actor: "server_runtime",
    lane: "filesystem",
    asset: routeAsset,
    permission: "read",
    condition: "scanner_finding",
    risk: "server_secret_exposure",
    provider: "generic",
  };
}

function toLane(finding: Finding): AccessLane {
  const template = RULE_TEMPLATES[finding.finding.rule_id] ?? fallbackTemplate(finding);
  const lane = {
    actor: template.actor,
    lane: template.lane,
    asset: template.asset(finding),
    permission: template.permission,
    condition: template.condition,
    risk: template.risk,
    severity: finding.finding.severity,
    provider: template.provider,
    source: {
      rule_id: finding.finding.rule_id,
      title: finding.finding.title,
      file: finding.finding.file,
      line: finding.finding.line,
      evidence: finding.spans[0]?.evidence,
    },
    fix: finding.finding.fix,
  };
  return {
    lane_id: stableId("lane", [
      lane.source.rule_id,
      lane.source.file,
      lane.source.line,
      lane.actor,
      lane.lane,
      lane.asset,
      lane.permission,
      lane.condition,
      lane.risk,
    ]),
    ...lane,
  };
}

function countBy<T extends string>(items: AccessLane[], pick: (item: AccessLane) => T): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) counts[pick(item)] = (counts[pick(item)] ?? 0) + 1;
  return counts;
}

export function buildAccessMap(result: ScanResult): AccessMap {
  const lanes = result.findings.map(toLane).sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.actor.localeCompare(b.actor) ||
      a.asset.localeCompare(b.asset) ||
      a.source.rule_id.localeCompare(b.source.rule_id),
  );
  return {
    schema: "seamshield.access-map/v1",
    target: result.target,
    profile: result.profile,
    policy_bundle_digest: result.policyBundleDigest,
    summary: {
      lanes_total: lanes.length,
      by_actor: countBy(lanes, (lane) => lane.actor),
      by_risk: countBy(lanes, (lane) => lane.risk),
      by_severity: countBy(lanes, (lane) => lane.severity),
    },
    lanes,
  };
}

export function buildShipVerdict(result: ScanResult): ShipVerdict {
  const access = buildAccessMap(result);
  const critical = access.lanes.filter((lane) => lane.severity === "block" || lane.severity === "high");
  const warnings = access.lanes.filter((lane) => lane.severity === "warn" || lane.severity === "info");
  return {
    schema: "seamshield.ship/v1",
    target: result.target,
    verdict: critical.length > 0 ? "UNSAFE TO SHIP" : "SAFE TO SHIP",
    exitCode: critical.length > 0 ? 1 : 0,
    access,
    critical,
    warnings,
  };
}

export function renderAccessJson(access: AccessMap): string {
  return JSON.stringify(access, null, 2);
}

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  block: (s) => pc.red(s),
  high: (s) => pc.magenta(s),
  warn: (s) => pc.yellow(s),
  info: (s) => pc.dim(s),
};

function renderLane(lane: AccessLane): string[] {
  return [
    `  -> ${lane.lane} -> ${lane.asset}`,
    `     permission: ${lane.permission}`,
    `     condition: ${lane.condition}`,
    `     risk: ${SEVERITY_COLOR[lane.severity](lane.risk)} (${lane.source.rule_id})`,
  ];
}

export function renderAccessTable(access: AccessMap): string {
  const lines = [pc.bold("Access Map"), ""];
  if (access.lanes.length === 0) {
    lines.push(pc.green("No dangerous access lanes found."));
    return lines.join("\n");
  }
  const actors = [...new Set(access.lanes.map((lane) => lane.actor))];
  for (const actor of actors) {
    lines.push(pc.bold(actor));
    for (const lane of access.lanes.filter((candidate) => candidate.actor === actor)) {
      lines.push(...renderLane(lane));
    }
    lines.push("");
  }
  lines.push(pc.dim(`policy bundle ${access.policy_bundle_digest.slice(0, 12)}`));
  return lines.join("\n");
}

export function renderShipTable(verdict: ShipVerdict): string {
  const lines = [pc.bold("SeamShield Ship Check"), "", `Verdict: ${verdict.verdict}`, ""];
  if (verdict.critical.length > 0) {
    lines.push(pc.red("Critical"));
    verdict.critical.forEach((lane, i) => {
      lines.push(
        `${i + 1}. ${lane.actor} can ${lane.permission} ${lane.asset} (${lane.risk})`,
        `   ${lane.source.file}:${lane.source.line} ${lane.source.rule_id}`,
      );
    });
    lines.push("");
  }
  if (verdict.warnings.length > 0) {
    lines.push(pc.yellow("Warnings"));
    verdict.warnings.forEach((lane, i) => {
      lines.push(
        `${i + 1}. ${lane.actor} can ${lane.permission} ${lane.asset} (${lane.risk})`,
        `   ${lane.source.file}:${lane.source.line} ${lane.source.rule_id}`,
      );
    });
    lines.push("");
  }
  if (verdict.critical.length === 0 && verdict.warnings.length === 0) {
    lines.push(pc.green("No dangerous access lanes found."), "");
  }
  lines.push("Next:", "npx @seamshield/cli access", "npx @seamshield/cli fix-plan");
  return lines.join("\n");
}
