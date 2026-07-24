export type Severity = "block" | "high" | "warn" | "info";

export const SEVERITY_RANK: Record<Severity, number> = {
  block: 0,
  high: 1,
  warn: 2,
  info: 3,
};

export interface RulePattern {
  name: string;
  regex: string;
}

export interface RuleInclude {
  extensions?: string[];
  basenames?: string[];
  /** File matches only when its relative path contains one of these substrings. */
  path_contains?: string[];
}

export interface RuleExclude {
  basenames?: string[];
  dirs?: string[];
}

export interface RuleCheck {
  type: "regex" | "absence" | "builtin";
  builtin?:
    | "env-file-committed"
    | "no-lockfile"
    | "package-manager-drift"
    | "hallucinated-package"
    | "known-vuln"
    | "convex-public-function-no-auth"
    | "convex-tenant-bound-write"
    | "next-server-action-trusted-client"
    | "server-grouped-router-boundary"
    | "webhook-signature-boundary"
    | "vercel-config";
  include?: RuleInclude;
  exclude?: RuleExclude;
  /** File-level gate: the rule only applies to files whose content matches this regex. */
  file_contains?: string;
  patterns?: RulePattern[];
  patterns_from?: string;
  redact?: boolean;
}

export interface RuleFix {
  summary: string;
  agent_prompt: string;
  doc_url?: string;
}

export interface Rule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  framework_ref: string;
  check: RuleCheck;
  fix: RuleFix;
}

export interface Span {
  start: number;
  end: number;
  label: string;
  evidence: string;
}

/**
 * Profile of the canonical-security-ir event shape
 * (seamshield-final-framework/security/schemas/canonical-security-ir.schema.json)
 * specialized for scanner findings, plus the `finding` extension.
 */
export interface Finding {
  event_id: string;
  event_type: "scan.finding";
  time: string;
  tenant: string;
  decision: "deny" | "scan";
  route: { plane: "evidence"; lane: "cpu"; reason: string[] };
  engines: { name: string; version: string; role?: string }[];
  provenance: { policy_bundle_digest: string };
  spans: Span[];
  finding: {
    rule_id: string;
    severity: Severity;
    title: string;
    file: string;
    line: number;
    fix: RuleFix;
  };
}

export interface ScanContext {
  root: string;
  policyBundleDigest: string;
  engineVersion: string;
}

export type FailOn = "block" | "high" | "warn" | "never";
export type ScanProfile = "community" | "workspace" | "incident";

export interface ScanOptions {
  rulesDir?: string;
  rulepack?: {
    manifestPath: string;
    publicKey: string;
    entitlementTier: "pro" | "enterprise";
    allowedChannels: readonly ("stable" | "preview" | "security")[];
    previousRulesDigest?: string;
  };
  failOn?: FailOn;
  network?: "on" | "off";
  fetchImpl?: typeof fetch;
  networkTimeoutMs?: number;
  profile?: ScanProfile;
}

export interface ScanResult {
  target: string;
  profile: ScanProfile;
  findings: Finding[];
  exitCode: number;
  filesScanned: number;
  rulesLoaded: number;
  policyBundleDigest: string;
  engineVersion: string;
  networkSkipped?: boolean;
}

export type AccessActor =
  | "public_user"
  | "authenticated_user"
  | "frontend_bundle"
  | "server_runtime"
  | "ai_agent"
  | "dependency"
  | "deploy_platform"
  | "database_policy"
  | "storage_policy";

export type AccessLaneKind =
  | "http_route"
  | "server_action"
  | "env_variable"
  | "database"
  | "storage"
  | "filesystem"
  | "package_install"
  | "deploy_config"
  | "agent_tooling"
  | "self_hosted_server";

export type AccessPermission =
  | "read"
  | "write"
  | "execute"
  | "modify"
  | "admin"
  | "install";

export type AccessRisk =
  | "anonymous_execute"
  | "anonymous_write"
  | "client_to_server_secret"
  | "client_to_admin"
  | "server_secret_exposure"
  | "agent_to_secret"
  | "dependency_to_shell"
  | "public_database_access"
  | "public_storage_access"
  | "deploy_secret_exposure"
  | "cors_credential_theft"
  | "untrusted_admin_surface"
  | "webhook_missing_signature"
  | "untrusted_model_gateway"
  | "unreproducible_dependency"
  | "known_vulnerable_dependency"
  | "unknown_package";

export interface AccessLane {
  lane_id: string;
  actor: AccessActor;
  lane: AccessLaneKind;
  asset: string;
  permission: AccessPermission;
  condition: string;
  risk: AccessRisk;
  severity: Severity;
  provider: string;
  source: {
    rule_id: string;
    title: string;
    file: string;
    line: number;
    evidence?: string;
  };
  fix: RuleFix;
}

export interface AccessMap {
  schema: "seamshield.access-map/v1";
  target: string;
  profile: ScanProfile;
  policy_bundle_digest: string;
  summary: {
    lanes_total: number;
    by_actor: Record<string, number>;
    by_risk: Record<string, number>;
    by_severity: Record<string, number>;
  };
  lanes: AccessLane[];
}

export interface ShipVerdict {
  schema: "seamshield.ship/v1";
  target: string;
  verdict: "SAFE TO SHIP" | "UNSAFE TO SHIP";
  exitCode: number;
  access: AccessMap;
  critical: AccessLane[];
  warnings: AccessLane[];
}

export type InventoryConfidence = "high" | "medium" | "low";

export interface InventoryComponent {
  record_id: string;
  ecosystem:
    | "npm"
    | "mcp"
    | "agent-skill"
    | "editor-extension"
    | "deploy"
    | "pypi"
    | "go"
    | "maven"
    | "nuget"
    | "rubygems"
    | "composer"
    | "cargo";
  name: string;
  version?: string;
  source_type: string;
  source_file: string;
  package_manager?: string;
  credential_fields_present?: string[];
  confidence: InventoryConfidence;
}

export interface RepositoryCapability {
  id: string;
  confidence: InventoryConfidence;
  signals: string[];
}

export interface RepositoryCapabilities {
  schema: "seamshield.repository-capabilities/v1";
  languages: RepositoryCapability[];
  frameworks: RepositoryCapability[];
  coverage: {
    baseline: string[];
    deep_access_lane_adapters: string[];
    dependency_ecosystems: string[];
    unknown_language_policy: "baseline_only";
  };
}

export interface InventoryResult {
  schema: "seamshield.inventory/v1";
  target: string;
  profile: ScanProfile;
  generated_at: string;
  components: InventoryComponent[];
  capabilities: RepositoryCapabilities;
  summary: {
    components_total: number;
    by_ecosystem: Record<string, number>;
    by_confidence: Record<string, number>;
  };
}
