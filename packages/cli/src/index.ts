#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { accessSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { constants as fsConstants } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { parse, stringify } from "yaml";
import {
  buildAccessMap,
  buildFixPlan,
  buildShipVerdict,
  collectInventory,
  renderAccessJson,
  renderAccessNdjson,
  renderAccessTable,
  renderInventoryJson,
  renderInventoryNdjson,
  renderInventoryTable,
  renderJson,
  renderSarif,
  renderScanNdjson,
  renderShipTable,
  renderTable,
  scan,
  scanAsync,
  writeInvestigationMarkdown,
  writeMarkdownFixPlan,
  writeTestPlan,
  type AccessLane,
  type FailOn,
  type Finding,
  type FixPlanAgent,
  type InventoryComponent,
  type ScanProfile,
  type TestPlanAgent,
} from "@seamshield/core";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { homepage?: string; version: string };

const FORMATS = ["table", "json", "sarif", "ndjson"];
const ACCESS_FORMATS = ["table", "json", "ndjson"];
const INVENTORY_FORMATS = ["table", "json", "ndjson"];
const FAIL_ON = ["block", "high", "warn", "never"];
const PROFILES = ["community", "workspace", "incident"];
const FIX_AGENTS = ["claude", "cursor", "codex", "generic"];
const TEST_PLAN_AGENTS = ["codex", "generic"];
const CONTEXT_AGENTS = ["claude", "cursor", "codex", "gemini", "cline", "windsurf", "copilot", "opencode"];
const PRIVACY_FORMATS = ["table", "json"];
const STATUS_FORMATS = ["table", "json"];
const AUDIT_FORMATS = ["table", "json"];
type ContextAgent = (typeof CONTEXT_AGENTS)[number];

function cliPackageDir(): string {
  return resolve(dirname(currentBin()), "..");
}
const INSPECT_FORMATS = ["table", "json"];

const INSPECT_IGNORED_DIRECTORIES = new Set([
  ".git", ".next", ".nuxt", ".svelte-kit", ".turbo", ".seamshield", "build", "coverage", "dist",
  "node_modules", "target", "vendor", ".venv", "venv", "__pycache__",
]);
const INSPECT_MAX_FILES = 3_000;
const INSPECT_CONTENT_BYTES = 16_384;

type InspectionSurface = {
  id: string;
  label: string;
  status: "observed" | "not_observed";
  evidence_count: number;
  local_evidence: string[];
};

type RepositoryInspection = {
  schema: "seamshield.repository-inspection/v1";
  generated_at: string;
  target: string;
  source_upload: false;
  local_execution: true;
  file_inventory: { scanned_files: number; capped: boolean; languages: Record<string, number> };
  surfaces: InspectionSurface[];
  protection_gaps: Array<{ id: string; priority: "high" | "medium"; summary: string; next_action: string }>;
  protection_manifest: {
    schema: "seamshield.protection-manifest/v1";
    source_upload: false;
    raw_paths_excluded: true;
    prompts_excluded: true;
    credentials_excluded: true;
    detected_capabilities: string[];
    required_next_receipts: string[];
  };
};

function parseContextAgents(value: string | undefined): ContextAgent[] | null {
  if (!value) return null;
  const requested = value.split(/[,\s]+/).map((part) => part.trim()).filter(Boolean);
  const unique = [...new Set(requested)];
  if (unique.length === 0) {
    console.error(`seamshield: --agents requires one or more of: ${CONTEXT_AGENTS.join(", ")}, all`);
    process.exitCode = 2;
    return null;
  }
  if (unique.includes("all")) {
    if (unique.length > 1) {
      console.error("seamshield: use --agents all by itself");
      process.exitCode = 2;
      return null;
    }
    return [...CONTEXT_AGENTS];
  }
  const invalid = unique.filter((agent) => !CONTEXT_AGENTS.includes(agent));
  if (invalid.length > 0) {
    console.error(`seamshield: unknown --agents value "${invalid.join(", ")}" (expected: ${CONTEXT_AGENTS.join(", ")}, all)`);
    process.exitCode = 2;
    return null;
  }
  return unique as ContextAgent[];
}

function assertChoice(value: string | undefined, allowed: string[], label: string): boolean {
  if (value && !allowed.includes(value)) {
    console.error(`seamshield: unknown --${label} "${value}" (expected: ${allowed.join(", ")})`);
    process.exitCode = 2;
    return false;
  }
  return true;
}

function assertOptions(opts: { format?: string; failOn?: string }): boolean {
  if (!assertChoice(opts.format, FORMATS, "format")) {
    return false;
  }
  if (opts.failOn && !FAIL_ON.includes(opts.failOn)) {
    console.error(`seamshield: unknown --fail-on "${opts.failOn}" (expected: ${FAIL_ON.join(", ")})`);
    process.exitCode = 2;
    return false;
  }
  return true;
}

function render(format: string, result: Awaited<ReturnType<typeof scanAsync>>): string {
  if (format === "json") return renderJson(result);
  if (format === "sarif") return renderSarif(result);
  if (format === "ndjson") return renderScanNdjson(result);
  return renderTable(result);
}

function assertProfile(profile: string | undefined, roots: string[] = []): profile is ScanProfile | undefined {
  if (!assertChoice(profile, PROFILES, "profile")) return false;
  if (profile && profile !== "community" && roots.length === 0) {
    console.error(`seamshield: --profile ${profile} requires at least one explicit --root`);
    process.exitCode = 2;
    return false;
  }
  return true;
}

function collectRoot(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}

function buildPrivacyReport(target: string) {
  return {
    schema: "seamshield.privacy/v1",
    target: resolve(target),
    tier: "Community",
    source_upload: false,
    local_execution: true,
    static_scan: {
      reads_source_locally: true,
      uploads_source: false,
      transmits_findings: false,
    },
    default_network: "offline for ship, access, init, investigate, triage, and privacy; scan, fix-plan, and test-plan use network dependency checks unless --offline is passed",
    network_when_online: [
      "npm registry package metadata for dependency existence checks",
      "OSV package/version vulnerability lookups",
    ],
    files_written: [
      ".seamshield/investigations/*.md for scan and ship unless disabled where supported",
      ".seamshield/fix-plan.json and .seamshield/fix-plans/*.md for fix-plan",
      ".seamshield/test-plan.json and .seamshield/test-plans/*.md for test-plan",
      ".seamshield/config.yaml for init and triage",
      "agent context files and .claude/settings.json when init or guard install is used",
      ".github/workflows/seamshield.yml when init is used without --no-ci",
    ],
    redaction: [
      "secret evidence is redacted before findings, JSON, SARIF, investigations, fix plans, and test plans are emitted",
      "fix prompts are generated without exposing full secret values",
    ],
    rule_updates: {
      automatic_untrusted_updates: false,
      learn_command: "local/no-upload stub until signed rulepack support is intentionally added",
    },
    commercial_boundary: {
      pro: "advanced controls, CVE-to-control updates, premium adapters, advanced guard rules, advanced fix plans, local premium rulepacks, SeamShield Auth up to 100k MAU",
      enterprise:
        "private deployment, policy server, internal mirrors, CI enforcement, audit trails, SSO/RBAC, custom controls, compliance workflows, usage-based SeamShield Auth",
    },
  };
}

function renderPrivacyTable(report: ReturnType<typeof buildPrivacyReport>): string {
  return [
    "SeamShield Privacy Report",
    "",
    `Target: ${report.target}`,
    `Tier: ${report.tier}`,
    `Source upload: ${report.source_upload ? "yes" : "no"}`,
    `Local execution: ${report.local_execution ? "yes" : "no"}`,
    "",
    "Community scanning does not upload source code or findings.",
    `Default network: ${report.default_network}`,
    "",
    "Network only when explicitly enabled:",
    ...report.network_when_online.map((item) => `- ${item}`),
    "",
    "Files SeamShield may write:",
    ...report.files_written.map((item) => `- ${item}`),
    "",
    "Redaction:",
    ...report.redaction.map((item) => `- ${item}`),
    "",
    "Rule updates:",
    `- Automatic untrusted updates: ${report.rule_updates.automatic_untrusted_updates ? "yes" : "no"}`,
    `- learn: ${report.rule_updates.learn_command}`,
  ].join("\n");
}

function inspectRepositoryFiles(root: string): { files: string[]; capped: boolean; languages: Record<string, number> } {
  const files: string[] = [];
  const languages: Record<string, number> = {};
  let capped = false;
  const visit = (directory: string) => {
    if (capped) return;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && INSPECT_IGNORED_DIRECTORIES.has(entry.name)) continue;
      const absolute = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      files.push(relative(root, absolute));
      const extension = extname(entry.name).toLowerCase() || "[no extension]";
      languages[extension] = (languages[extension] ?? 0) + 1;
      if (files.length >= INSPECT_MAX_FILES) {
        capped = true;
        return;
      }
    }
  };
  visit(root);
  return { files, capped, languages };
}

function localFileContains(root: string, paths: string[], expression: RegExp): string[] {
  const evidence: string[] = [];
  for (const path of paths) {
    if (evidence.length >= 24) break;
    const extension = extname(path).toLowerCase();
    if (!new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java", ".kt", ".cs", ".json", ".yaml", ".yml", ".toml", ".xml"]).has(extension)) continue;
    try {
      const stat = statSync(join(root, path));
      if (stat.size > 1_000_000) continue;
      const body = readFileSync(join(root, path), "utf8").slice(0, INSPECT_CONTENT_BYTES);
      if (expression.test(body)) evidence.push(path);
      expression.lastIndex = 0;
    } catch {
      // A changed or unreadable local file is simply omitted from reconnaissance.
    }
  }
  return evidence;
}

function surface(id: string, label: string, evidence: string[]): InspectionSurface {
  return {
    id,
    label,
    status: evidence.length > 0 ? "observed" : "not_observed",
    evidence_count: evidence.length,
    local_evidence: evidence,
  };
}

function buildRepositoryInspection(target: string): RepositoryInspection {
  const root = resolve(target);
  const inventory = inspectRepositoryFiles(root);
  const matching = (...candidates: string[]) => inventory.files.filter((path) => candidates.some((candidate) => path.endsWith(candidate)));
  const packageEvidence = matching("package.json");
  const authEvidence = [
    ...localFileContains(root, packageEvidence, /(?:nextauth|better-auth|convex|supabase|firebase|auth0|clerk|lucia|passport|keycloak)/i),
    ...localFileContains(root, inventory.files, /(?:getServerSession|auth\.getUserIdentity|createClient\(|verifyIdToken|requireAuth|authenticate)/i),
  ];
  const serverEvidence = [
    ...matching("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    ...localFileContains(root, inventory.files, /(?:listen\(|createServer\(|FastAPI\(|Django|Rails\.application|gin\.Default\(|app\.Run\()/),
  ];
  const ciEvidence = inventory.files.filter((path) => path.startsWith(".github/workflows/") || path === ".gitlab-ci.yml" || path === ".circleci/config.yml" || path.startsWith("azure-pipelines"));
  const deployEvidence = [
    ...matching("vercel.json", "netlify.toml", "wrangler.toml", "coolify.json", "fly.toml", "render.yaml", "railway.json", "app.yaml"),
    ...localFileContains(root, inventory.files, /(?:coolify|devpush|vercel|cloudflare|netlify|railway|render\.com)/i),
  ];
  const runtimeEvidence = [
    ...matching("package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts"),
  ];
  const agentEvidence = inventory.files.filter((path) => /(?:^|\/)(?:AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.clinerules\/|\.cursor\/rules\/|\.windsurf\/rules\/|\.github\/copilot-instructions\.md)/.test(path));
  const surfaces = [
    surface("runtime", "Application runtimes", runtimeEvidence),
    surface("server", "Server and service boundaries", serverEvidence),
    surface("auth", "Existing authentication", [...new Set(authEvidence)]),
    surface("ci", "Continuous integration", ciEvidence),
    surface("deploy", "Deployment and hosting", [...new Set(deployEvidence)]),
    surface("agent", "AI coding-agent instructions", agentEvidence),
  ];
  const observed = (id: string) => surfaces.find((item) => item.id === id)?.status === "observed";
  const protectionGaps: RepositoryInspection["protection_gaps"] = [];
  if (!observed("ci")) protectionGaps.push({ id: "ci_missing", priority: "high", summary: "No supported CI workflow was found.", next_action: "Install the generated CI workflow, then verify the first protected push or merge." });
  if (!observed("server")) protectionGaps.push({ id: "server_boundary_unknown", priority: "medium", summary: "No deployable server boundary was identified from local metadata.", next_action: "Use the local agent review to identify the production ingress and add Sentinel discovery there." });
  if (!observed("auth")) protectionGaps.push({ id: "auth_boundary_unknown", priority: "medium", summary: "No known authentication integration was identified.", next_action: "Ask the local agent to map sign-in, session verification, and sensitive routes before enabling SeamAuth enforcement." });
  if (!observed("deploy")) protectionGaps.push({ id: "deploy_target_unknown", priority: "medium", summary: "No supported deployment configuration was identified.", next_action: "Record the hosting provider during project setup; SeamShield will generate a provider-specific pre-deploy gate." });
  if (!observed("agent")) protectionGaps.push({ id: "agent_instructions_missing", priority: "medium", summary: "No local AI agent instruction file was found.", next_action: "Run seamshield init or seamshield agent-context so your coding agent follows the protection review." });
  const capabilities = surfaces.filter((item) => item.status === "observed").map((item) => item.id);
  return {
    schema: "seamshield.repository-inspection/v1",
    generated_at: new Date().toISOString(),
    target: root,
    source_upload: false,
    local_execution: true,
    file_inventory: { scanned_files: inventory.files.length, capped: inventory.capped, languages: inventory.languages },
    surfaces,
    protection_gaps: protectionGaps,
    protection_manifest: {
      schema: "seamshield.protection-manifest/v1",
      source_upload: false,
      raw_paths_excluded: true,
      prompts_excluded: true,
      credentials_excluded: true,
      detected_capabilities: capabilities,
      required_next_receipts: ["repository_connection", "protected_ci_run", ...(observed("server") ? ["sentinel_discovery"] : []), ...(observed("auth") ? ["seamauth_runtime_decision"] : [])],
    },
  };
}

function renderRepositoryInspection(report: RepositoryInspection): string {
  return [
    "SeamShield Repository Inspection",
    "",
    `Target: ${report.target}`,
    `Files inspected locally: ${report.file_inventory.scanned_files}${report.file_inventory.capped ? " (capped)" : ""}`,
    "Source upload: no",
    "",
    "Observed surfaces:",
    ...report.surfaces.map((item) => `- ${item.label}: ${item.status === "observed" ? `observed (${item.evidence_count} local evidence file${item.evidence_count === 1 ? "" : "s"})` : "not observed"}`),
    "",
    "Protection gaps:",
    ...(report.protection_gaps.length > 0 ? report.protection_gaps.map((gap) => `- [${gap.priority}] ${gap.summary} Next: ${gap.next_action}`) : ["- No baseline setup gaps detected. Review the local agent assessment before enforcement."]),
    "",
    "Wrote local-only outputs:",
    "- .seamshield/repository-assessment.md (local evidence and agent review instructions)",
    "- .seamshield/protection-manifest.json (bounded metadata only; not uploaded by this command)",
  ].join("\n");
}

function writeRepositoryInspection(target: string): { report: RepositoryInspection; assessmentPath: string; manifestPath: string } {
  const root = resolve(target);
  const report = buildRepositoryInspection(root);
  const outputDirectory = join(root, ".seamshield");
  mkdirSync(outputDirectory, { recursive: true });
  const assessmentPath = join(outputDirectory, "repository-assessment.md");
  const manifestPath = join(outputDirectory, "protection-manifest.json");
  const localEvidence = report.surfaces.flatMap((item) => item.local_evidence.map((path) => `- ${item.label}: \`${path}\``));
  const assessment = [
    "# SeamShield Local Repository Assessment",
    "",
    "This assessment was generated locally. It is not uploaded by SeamShield. Do not paste source, credentials, prompts, or session values into external tools.",
    "",
    "## Local Evidence",
    ...(localEvidence.length > 0 ? localEvidence : ["- No supported framework markers found. Inspect the repository structure locally."]),
    "",
    "## Gaps To Resolve",
    ...(report.protection_gaps.length > 0 ? report.protection_gaps.map((gap) => `- **${gap.priority} - ${gap.id}:** ${gap.summary} ${gap.next_action}`) : ["- No baseline setup gaps detected."]),
    "",
    "## Local AI Review Contract",
    "Use your local coding agent to inspect this repository. It must map the actual request ingress, auth verification, runtime/server processes, deployment workflow, and sensitive access lanes. It must cite local paths and line ranges in its response, propose approval-gated changes only, and never print or transmit secrets, raw tokens, source files, prompts, customer data, or session values.",
    "",
    "Required output: (1) architecture map, (2) authentication and authorization boundaries, (3) server/deployment boundaries, (4) top risks ranked by reachability, (5) recommended SeamShield Build, Guard, Sentinel, and SeamAuth integration points, and (6) a test plan proving each integration.",
  ].join("\n");
  writeFileSync(assessmentPath, `${assessment}\n`);
  writeFileSync(manifestPath, `${JSON.stringify(report.protection_manifest, null, 2)}\n`);
  return { report, assessmentPath, manifestPath };
}

function maybeWriteInvestigation(result: Awaited<ReturnType<typeof scanAsync>>, enabled: boolean | undefined): void {
  if (enabled === false) return;
  const out = writeInvestigationMarkdown(result);
  console.error(`Investigation written: ${out}`);
}

function auditDateStamp(now = new Date()): string {
  return now.toISOString().slice(0, 10);
}

function auditDirFor(target: string): string {
  return join(resolve(target), ".seamshield", "audits", `${auditDateStamp()}-local-audit`);
}

function auditSeverity(severity: string): "informational" | "low" | "medium" | "high" | "critical" {
  if (severity === "block") return "critical";
  if (severity === "high") return "high";
  if (severity === "warn") return "medium";
  return "informational";
}

function findingScope(file: string): string {
  const name = file.split(/[\\/]/).pop() ?? "repo";
  return name.replace(/\.[^.]+$/, "") || "repo";
}

function buildAuditFindings(result: Awaited<ReturnType<typeof scanAsync>>) {
  const access = buildAccessMap(result);
  return access.lanes.map((lane) => ({
    verdict: "confirmed",
    title: lane.source.title,
    description: `${lane.actor} can ${lane.permission} ${lane.asset} through ${lane.lane} when ${lane.condition}.`,
    root_cause: `${findingScope(lane.source.file)} in ${lane.source.file} does not enforce ${lane.condition}, allowing ${lane.risk}.`,
    intended_behavior: `Only the intended actor should be able to ${lane.permission} ${lane.asset} after server-side, provider-side, or internal-only authorization is proven.`,
    trace: [
      {
        kind: "entrypoint",
        file: lane.source.file,
        line: lane.source.line,
        scope: findingScope(lane.source.file),
        description: `${lane.provider} surface detected by ${lane.source.rule_id}.`,
      },
      {
        kind: "sink",
        file: lane.source.file,
        line: lane.source.line,
        scope: findingScope(lane.source.file),
        description: `${lane.actor} reaches ${lane.asset} with ${lane.permission} permission.`,
      },
    ],
    conditions: [
      {
        kind: "system_configuration",
        description: `Scanner evidence is local and metadata-only; verify production reachability before treating this as exploitable.`,
      },
    ],
    execution: {
      attacker_perspective: lane.actor,
      payloads: lane.source.evidence ? [lane.source.evidence] : [],
      instructions: [
        `Inspect ${lane.source.file}:${lane.source.line}.`,
        `Confirm whether ${lane.actor} can reach ${lane.asset} in the deployed environment.`,
        `Verify whether ${lane.condition} is enforced outside client-controlled state.`,
      ],
      expected_result: `If reachable without the intended control, the attacker obtains ${lane.permission} access to ${lane.asset}.`,
    },
    remediation: {
      strategy: lane.fix.summary,
      code_changes: [],
    },
    severity: {
      likelihood: {
        score: auditSeverity(lane.severity),
        reason: `SeamShield classified this lane as ${lane.severity}.`,
      },
      impact: {
        score: auditSeverity(lane.severity),
        reason: `Risk category: ${lane.risk}.`,
      },
      overall_severity: auditSeverity(lane.severity),
    },
    confidence: {
      score: "medium",
      reason: "The finding is scanner-confirmed against local source evidence but has not been independently exploited or reviewed.",
    },
    seamshield: {
      lane_id: lane.lane_id,
      rule_id: lane.source.rule_id,
      provider: lane.provider,
      risk: lane.risk,
      source_upload: false,
    },
  }));
}

function auditSchema() {
  return {
    schema: "seamshield.audit-findings-schema/v1",
    output_schema: {
      type: "array",
      items: {
        oneOf: [
          {
            type: "object",
            description: "Confirmed local SeamShield audit finding.",
            required: [
              "verdict",
              "title",
              "description",
              "root_cause",
              "intended_behavior",
              "trace",
              "conditions",
              "execution",
              "remediation",
              "severity",
              "confidence",
              "seamshield",
            ],
          },
          {
            type: "object",
            description: "Rejected finding after human or independent verification.",
            required: ["verdict", "reason"],
          },
        ],
      },
    },
  };
}

function buildAuditBundle(result: Awaited<ReturnType<typeof scanAsync>>, outDir: string) {
  const access = buildAccessMap(result);
  const verdict = buildShipVerdict(result);
  const findings = buildAuditFindings(result);
  const critical = access.lanes.filter((lane) => lane.severity === "block" || lane.severity === "high");
  const warnings = access.lanes.filter((lane) => lane.severity === "warn");
  const architecture = [
    "# SeamShield Local Architecture",
    "",
    `Target: \`${result.target}\``,
    `Files scanned: ${result.filesScanned}`,
    `Rules loaded: ${result.rulesLoaded}`,
    `Source upload: false`,
    "",
    "## Trust Boundaries",
    "",
    "- Source code and findings stayed local.",
    "- Access lanes are normalized as Actor -> Lane -> Asset -> Permission -> Condition -> Risk.",
    "- Production exploitability still requires human verification of runtime reachability and deployed controls.",
    "",
    "## Coverage",
    "",
    ...Object.entries(access.summary.by_risk).map(([risk, count]) => `- ${risk}: ${count}`),
    "",
  ].join("\n");
  const report = [
    "# SeamShield Audit Report",
    "",
    `Verdict: **${verdict.verdict}**`,
    `Generated: ${new Date().toISOString()}`,
    `Policy bundle: \`${result.policyBundleDigest}\``,
    "",
    "## Executive Summary",
    "",
    verdict.verdict === "SAFE TO SHIP"
      ? "No block or high unsafe-to-ship access lanes were found by the controls that ran."
      : `${critical.length} block/high access lane(s) should be fixed or explicitly accepted before shipping.`,
    "",
    "This audit reports access-lane risk. It does not claim the whole application has no vulnerabilities.",
    "",
    "## Findings",
    "",
    findings.length === 0
      ? "_No findings from the controls that ran._"
      : "| Severity | Rule | Asset | Location |\n| --- | --- | --- | --- |\n" +
        access.lanes
          .map((lane) => `| ${lane.severity} | \`${lane.source.rule_id}\` | \`${lane.asset}\` | \`${lane.source.file}:${lane.source.line}\` |`)
          .join("\n"),
    "",
    "## Hardening Notes",
    "",
    warnings.length > 0
      ? `Review ${warnings.length} warning lane(s) after release blockers are resolved.`
      : "No warning lanes were found by the controls that ran.",
    "",
    "## Positive Patterns",
    "",
    "- Audit bundle generated without uploading source.",
    "- Findings use deterministic local rule evidence.",
    "- JSON findings are structured for later confirmed/rejected review.",
    "",
  ].join("\n");
  const detail = [
    "# SeamShield Findings Detail",
    "",
    ...findings.flatMap((finding, index) => [
      `## ${index + 1}. ${finding.title}`,
      "",
      `Severity: ${finding.severity.overall_severity}`,
      `Rule: \`${finding.seamshield.rule_id}\``,
      `Lane: \`${finding.seamshield.lane_id}\``,
      "",
      "### Trace",
      "",
      ...finding.trace.map((step) => `- ${step.kind}: \`${step.file}:${step.line}\` ${step.description}`),
      "",
      "### Verification",
      "",
      "- [ ] Verify the file and line still match the current source.",
      "- [ ] Verify production reachability.",
      "- [ ] Verify the remediation blocks the lane without weakening auth.",
      "",
    ]),
  ].join("\n");

  mkdirSync(outDir, { recursive: true });
  const files = {
    architecture: join(outDir, "architecture.md"),
    report: join(outDir, "REPORT.md"),
    detail: join(outDir, "FINDINGS-DETAIL.md"),
    findings: join(outDir, "findings.json"),
    schema: join(outDir, "report-schema.json"),
  };
  writeFileSync(files.architecture, architecture);
  writeFileSync(files.report, report);
  writeFileSync(files.detail, detail);
  writeFileSync(files.findings, `${JSON.stringify(findings, null, 2)}\n`);
  writeFileSync(files.schema, `${JSON.stringify(auditSchema(), null, 2)}\n`);
  return {
    schema: "seamshield.audit/v1",
    target: result.target,
    out_dir: outDir,
    source_upload: false,
    verdict: verdict.verdict,
    findings_total: findings.length,
    critical_total: critical.length,
    warnings_total: warnings.length,
    files,
    next: [
      "Review REPORT.md and FINDINGS-DETAIL.md.",
      "Treat block/high lanes as release blockers until fixed or explicitly accepted.",
      "Use findings.json for later confirmed/rejected review workflows.",
    ],
  };
}

function renderAuditTable(report: ReturnType<typeof buildAuditBundle>): string {
  return [
    "SeamShield Audit",
    "",
    `Target: ${report.target}`,
    `Output: ${report.out_dir}`,
    `Verdict: ${report.verdict}`,
    `Source upload: ${report.source_upload ? "yes" : "no"}`,
    `Findings: ${report.findings_total}`,
    `Critical: ${report.critical_total}`,
    `Warnings: ${report.warnings_total}`,
    "",
    "Wrote:",
    ...Object.values(report.files).map((file) => `- ${file}`),
    "",
    "Next:",
    ...report.next.map((item) => `- ${item}`),
  ].join("\n");
}

async function runScan(
  path: string,
  opts: { format: string; failOn: string; offline?: boolean; investigation?: boolean; profile?: string; root?: string[] },
) {
  if (!assertOptions(opts)) return;
  if (!assertProfile(opts.profile, opts.root ?? [])) return;
  const target = opts.root?.[0] ?? path;
  if (!existsSync(target)) {
    console.error(`seamshield: path not found: ${target}`);
    process.exitCode = 2;
    return;
  }
  try {
    const result = await scanAsync(target, {
      failOn: opts.failOn as FailOn,
      network: opts.offline ? "off" : "on",
      profile: (opts.profile as ScanProfile | undefined) ?? "community",
    });
    maybeWriteInvestigation(result, opts.investigation);
    console.log(render(opts.format, result));
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(`seamshield: scan failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  }
}

async function readScanForCommand(path: string, offline = true, profile: ScanProfile = "community") {
  if (!existsSync(path)) {
    console.error(`seamshield: path not found: ${path}`);
    process.exitCode = 2;
    return null;
  }
  try {
    return await scanAsync(path, { failOn: "never", network: offline ? "off" : "on", profile });
  } catch (error) {
    console.error(`seamshield: scan failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
    return null;
  }
}

function writeSection(path: string, marker: string, body: string): string {
  mkdirSync(dirname(path), { recursive: true });
  const existing = existsSync(path) ? readFileSync(path, "utf8") : "";
  const next = existing.includes(marker)
    ? existing.replace(new RegExp(`${marker}[\\s\\S]*?(?=\\n# |\\n?$)`), body.trimEnd())
    : `${existing.trimEnd()}${existing.trim() ? "\n\n" : ""}${body}`;
  writeFileSync(path, next.endsWith("\n") ? next : `${next}\n`);
  return path;
}

function agentContextBody(kind: ContextAgent): string {
  const fixAgent = kind === "codex" || kind === "claude" || kind === "cursor" ? kind : "generic";
  return [
    "# SEAMSHIELD",
    "",
    "- Read `.seamshield/repository-assessment.md` before proposing SeamShield setup. Use its local evidence to map the real ingress, auth, server, CI, and deployment paths; do not infer them from framework names alone.",
    "- Keep the review local: cite file paths and line ranges, but never print or transmit secrets, raw tokens, sessions, prompts, customer data, or complete source files.",
    "- Run `npx @seamshield/cli ship .` before deploys and `npx @seamshield/cli scan --offline` before committing AI-generated changes.",
    "- Review `.seamshield/investigations/` after scans; it explains findings and open access lanes in Markdown.",
    "- Never hardcode provider keys, service-role keys, private keys, or dotenv contents.",
    "- Do not expose server secrets through `NEXT_PUBLIC_*` or client components.",
    "- Do not rely on client-only auth for private data; enforce auth server-side.",
    "- Keep Supabase RLS enabled, Firebase rules closed by default, and Convex privileged mutations authenticated or internal.",
    `- If SeamShield reports findings, inspect \`npx @seamshield/cli access .\` and apply \`npx @seamshield/cli fix-plan . --agent ${fixAgent}\`.`,
    "",
  ].join("\n");
}

function agentContextPath(target: string, kind: ContextAgent): string {
  if (kind === "codex") return join(target, "AGENTS.md");
  if (kind === "claude") return join(target, "CLAUDE.md");
  if (kind === "cursor") return join(target, ".cursor", "rules", "seamshield.mdc");
  if (kind === "gemini") return join(target, "GEMINI.md");
  if (kind === "cline") return join(target, ".clinerules", "seamshield.md");
  if (kind === "windsurf") return join(target, ".windsurf", "rules", "seamshield.md");
  if (kind === "copilot") return join(target, ".github", "copilot-instructions.md");
  return join(target, ".opencode", "AGENTS.md");
}

function writeAgentContext(target: string, kind: ContextAgent): string {
  const out = agentContextPath(target, kind);
  const body = agentContextBody(kind);
  if (kind === "codex" || kind === "claude" || kind === "gemini" || kind === "copilot" || kind === "opencode") {
    return writeSection(out, "# SEAMSHIELD", body);
  }
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, body);
  return out;
}

function writeAgentContexts(target: string, kinds: ContextAgent[]): string[] {
  return kinds.map((kind) => writeAgentContext(target, kind));
}

interface TriageConfig {
  ignore?: string[];
  suppress?: { rule: string; file: string; line?: number; reason?: string }[];
  rules?: { disable?: string[] };
}

function defaultConfig(): TriageConfig {
  return {
    ignore: ["node_modules/**", "dist/**", "build/**", ".next/**", "coverage/**"],
    suppress: [],
    rules: { disable: [] },
  };
}

function readTriageConfig(target: string): TriageConfig {
  const path = join(target, ".seamshield", "config.yaml");
  if (!existsSync(path)) return {};
  const parsed = parse(readFileSync(path, "utf8"));
  return parsed && typeof parsed === "object" ? (parsed as TriageConfig) : {};
}

function writeTriageConfig(target: string, config: TriageConfig): string {
  const out = join(target, ".seamshield", "config.yaml");
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, stringify(config));
  return out;
}

function ensureConfig(target: string): string {
  const out = join(target, ".seamshield", "config.yaml");
  if (!existsSync(out)) return writeTriageConfig(target, defaultConfig());
  return out;
}

type CiProvider = "github" | "gitlab" | "bitbucket" | "azure" | "circleci" | "generic";

type CiBinding = {
  provider: CiProvider;
  repository: string;
  repository_id?: string;
  issuer: string;
  audience: string;
  jwks_uri?: string;
  default_branch: string;
  workflow_ref: string;
};

type CiPlan = {
  provider: CiProvider;
  repository?: string;
  binding?: CiBinding;
  status: "configured" | "authorization_required" | "unsupported";
  reason?: string;
};

type CiAutomation = { projectId: string; apiUrl: string; provider: CiProvider };

function paidCiCommands(): string[] {
  return [
    "npx @seamshield/cli fix-plan . --offline --agent generic || true",
    "npx @seamshield/cli test-plan . --offline --agent generic || true",
    "npx @seamshield/cli sync . --ci --offline",
  ];
}

function writeGithubAction(target: string, automation?: CiAutomation): string {
  const out = join(target, ".github", "workflows", "seamshield.yml");
  mkdirSync(dirname(out), { recursive: true });
  const connected = automation ? [
    "permissions:",
    "  contents: read",
    "  id-token: write",
    "",
  ] : [];
  const automationEnvironment = automation ? [
    "    env:",
    `      SEAMSHIELD_PROJECT_ID: ${automation.projectId}`,
    `      SEAMSHIELD_API_URL: ${automation.apiUrl}`,
    "      SEAMSHIELD_CI_PROVIDER: github",
  ] : [];
  const commands = automation ? paidCiCommands().map((command) => `          ${command}`) : ["          npx @seamshield/cli ship . --offline"];
  writeFileSync(
    out,
    [
      "name: SeamShield",
      "",
      "on:",
      "  workflow_call:",
      "  pull_request:",
      "  push:",
      "    branches: [main]",
      "",
      ...connected,
      "jobs:",
      "  ship:",
      "    runs-on: ubuntu-latest",
      ...automationEnvironment,
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - uses: actions/setup-node@v4",
      "        with:",
      "          node-version: 20",
      `      - name: ${automation ? "SeamShield continuous Build and Guard" : "SeamShield ship check"}`,
      "        run: |",
      ...commands,
      "      - name: Upload SeamShield investigations",
      "        if: failure()",
      "        uses: actions/upload-artifact@v4",
      "        with:",
      "          name: seamshield-investigations",
      "          path: .seamshield/investigations/",
      "          if-no-files-found: ignore",
      "      - name: Upload SeamShield remediation plan",
      "        if: always()",
      "        uses: actions/upload-artifact@v4",
      "        with:",
      "          name: seamshield-remediation-plan",
      "          path: |",
      "            .seamshield/fix-plan.json",
      "            .seamshield/fix-plans/",
      "          if-no-files-found: ignore",
      "",
    ].join("\n"),
  );
  return out;
}

function writeGitlabCi(target: string, automation?: CiAutomation): string {
  const out = join(target, ".gitlab-ci.yml");
  const config = existsSync(out) ? parse(readFileSync(out, "utf8")) || {} : {};
  const stages = Array.isArray(config.stages) ? config.stages : [];
  if (!stages.includes("security")) stages.push("security");
  config.stages = stages;
  config.seamshield = {
    stage: "security",
    image: "node:20",
    ...(automation ? {
      variables: {
        SEAMSHIELD_PROJECT_ID: automation.projectId,
        SEAMSHIELD_API_URL: automation.apiUrl,
        SEAMSHIELD_CI_PROVIDER: "gitlab",
      },
      id_tokens: { SEAMSHIELD_ID_TOKEN: { aud: "https://platform.seamshield.com" } },
    } : {}),
    script: automation ? paidCiCommands() : [
      "npx @seamshield/cli ship . --offline",
      "npx @seamshield/cli inventory . --format ndjson --profile community > seamshield-inventory.ndjson",
    ],
    artifacts: { when: "on_failure", paths: [".seamshield/investigations/", "seamshield-inventory.ndjson"] },
  };
  writeFileSync(out, stringify(config));
  return out;
}

function writeBitbucketPipeline(target: string, automation: CiAutomation): string {
  const out = join(target, "bitbucket-pipelines.yml");
  const config = existsSync(out) ? parse(readFileSync(out, "utf8")) || {} : {};
  const step = {
    step: {
      name: "SeamShield Build and Guard",
      image: "node:20",
      oidc: true,
      script: [
        `export SEAMSHIELD_PROJECT_ID=${automation.projectId}`,
        `export SEAMSHIELD_API_URL=${automation.apiUrl}`,
        "export SEAMSHIELD_CI_PROVIDER=bitbucket",
        ...paidCiCommands(),
      ],
      artifacts: [".seamshield/investigations/**", ".seamshield/fix-plans/**", ".seamshield/test-plans/**"],
    },
  };
  config.pipelines ||= {};
  config.pipelines.default = [...(Array.isArray(config.pipelines.default) ? config.pipelines.default.filter((item: any) => item?.step?.name !== step.step.name) : []), step];
  config.pipelines["pull-requests"] ||= {};
  config.pipelines["pull-requests"]["**"] = [...(Array.isArray(config.pipelines["pull-requests"]["**"]) ? config.pipelines["pull-requests"]["**"].filter((item: any) => item?.step?.name !== step.step.name) : []), step];
  writeFileSync(out, stringify(config));
  return out;
}

function writeAzurePipeline(target: string, automation: CiAutomation): string {
  const out = join(target, "azure-pipelines.yml");
  const config = existsSync(out) ? parse(readFileSync(out, "utf8")) || {} : {};
  const job = {
    job: "SeamShield",
    displayName: "SeamShield Build and Guard",
    pool: { vmImage: "ubuntu-latest" },
    variables: {
      SEAMSHIELD_PROJECT_ID: automation.projectId,
      SEAMSHIELD_API_URL: automation.apiUrl,
      SEAMSHIELD_CI_PROVIDER: "azure",
    },
    steps: [
      { checkout: "self" },
      { script: paidCiCommands().join("\n"), displayName: "Run SeamShield", env: { SEAMSHIELD_ID_TOKEN: "$(SEAMSHIELD_ID_TOKEN)" } },
    ],
  };
  if (Array.isArray(config.stages)) {
    config.stages = [...config.stages.filter((stage: any) => stage?.stage !== "SeamShield"), { stage: "SeamShield", jobs: [job] }];
  } else {
    config.jobs = [...(Array.isArray(config.jobs) ? config.jobs.filter((item: any) => item?.job !== "SeamShield") : []), job];
  }
  writeFileSync(out, stringify(config));
  return out;
}

function writeCircleConfig(target: string, automation: CiAutomation): string {
  const out = join(target, ".circleci", "config.yml");
  mkdirSync(dirname(out), { recursive: true });
  const config = existsSync(out) ? parse(readFileSync(out, "utf8")) || {} : { version: 2.1 };
  config.version ||= 2.1;
  config.jobs ||= {};
  config.jobs.seamshield = {
    docker: [{ image: "cimg/node:20.18" }],
    environment: {
      SEAMSHIELD_PROJECT_ID: automation.projectId,
      SEAMSHIELD_API_URL: automation.apiUrl,
      SEAMSHIELD_CI_PROVIDER: "circleci",
    },
    steps: ["checkout", { run: { name: "SeamShield Build and Guard", command: paidCiCommands().join("\n") } }],
  };
  config.workflows ||= { seamshield: { jobs: ["seamshield"] } };
  for (const workflow of Object.values(config.workflows) as any[]) {
    if (!workflow || typeof workflow !== "object") continue;
    workflow.jobs = Array.isArray(workflow.jobs) ? workflow.jobs.filter((job: any) => job !== "seamshield") : [];
    workflow.jobs.push("seamshield");
  }
  writeFileSync(out, stringify(config));
  return out;
}

function writeGenericCiScript(target: string, automation: CiAutomation): string {
  const out = join(target, ".seamshield", "ci", "seamshield.sh");
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, [
    "#!/usr/bin/env sh",
    "set -eu",
    `export SEAMSHIELD_PROJECT_ID=${automation.projectId}`,
    `export SEAMSHIELD_API_URL=${automation.apiUrl}`,
    "export SEAMSHIELD_CI_PROVIDER=generic",
    ": \"${SEAMSHIELD_ID_TOKEN:?provide the CI provider OIDC token}\"",
    ...paidCiCommands(),
    "",
  ].join("\n"), { mode: 0o755 });
  chmodSync(out, 0o755);
  return out;
}

const DEFAULT_CONNECTED_API_URL = "https://platform.seamshield.com/api";

function trustedConnectedApiUrl(value: unknown): string | null {
  try {
    const url = new URL(String(value || "").trim());
    const expected = new URL(DEFAULT_CONNECTED_API_URL);
    return url.origin === expected.origin && url.pathname.replace(/\/$/, "") === expected.pathname ? DEFAULT_CONNECTED_API_URL : null;
  } catch {
    return null;
  }
}

type LocalConnection = {
  schema: "seamshield.local-connection/v1";
  project: { id?: string; name?: string; primary_domain?: string };
  api_url: string;
  server_key?: string;
  receipt_digest?: string | null;
  scan_receipt_digest?: string | null;
  connected_at?: string;
  last_sync_at?: string;
  source_upload: false;
  ci?: { provider: CiProvider; repository?: string; status: "configured" | "authorization_required" | "unsupported"; reason?: string };
};

function connectedApiUrl(explicit: unknown, stored: LocalConnection | null): string {
  const selected = String(explicit || "").trim();
  if (selected) return selected.replace(/\/$/, "");
  return trustedConnectedApiUrl(stored?.api_url) || DEFAULT_CONNECTED_API_URL;
}

function connectionPath(target: string): string { return join(target, ".seamshield", "connection.json"); }

function readLocalConnection(target: string): LocalConnection | null {
  const path = connectionPath(target);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed && parsed.schema === "seamshield.local-connection/v1" ? parsed as LocalConnection : null;
  } catch { return null; }
}

function ignoreLocalConnection(target: string): void {
  const path = join(target, ".gitignore");
  const entries = [".seamshield/connection.json", ".seamshield/sentinel.json"];
  const current = existsSync(path) ? readFileSync(path, "utf8") : "";
  const existing = new Set(current.split(/\r?\n/));
  const missing = entries.filter((entry) => !existing.has(entry));
  if (missing.length) writeFileSync(path, `${current}${current && !current.endsWith("\n") ? "\n" : ""}${missing.join("\n")}\n`);
}

function writeLocalConnection(target: string, connection: LocalConnection): void {
  mkdirSync(join(target, ".seamshield"), { recursive: true });
  const path = connectionPath(target);
  writeFileSync(path, `${JSON.stringify(connection, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  ignoreLocalConnection(target);
}

type SentinelService = {
  service_ref: string;
  exposure: "unknown";
  transport: "tcp";
  port: number;
  state: "unknown";
};

type SentinelEnrollment = {
  schema: "seamshield.sentinel-enrollment/v2";
  runtime_id: string;
  api_url: string;
  enrolled_at: string;
};

function sentinelIdentityPath(target: string): string { return join(target, ".seamshield", "sentinel.json"); }

function readSentinelEnrollment(target: string): SentinelEnrollment | null {
  const path = sentinelIdentityPath(target);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    if (parsed?.schema === "seamshield.sentinel-enrollment/v2" && /^runtime_[a-zA-Z0-9_-]{8,160}$/.test(String(parsed.runtime_id || ""))) return parsed as SentinelEnrollment;
  } catch { /* Invalid local state is treated as not enrolled. */ }
  return null;
}

function writeSentinelEnrollment(target: string, enrollment: SentinelEnrollment): void {
  const path = sentinelIdentityPath(target);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(enrollment, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  ignoreLocalConnection(target);
}

function boundedListeningTcpPorts(): SentinelService[] {
  const attempts: Array<{ command: string; args: string[]; parse: (output: string) => number[] }> = [
    {
      command: "ss",
      args: ["-H", "-ltn"],
      parse: (output) => [...output.matchAll(/:(\d+)\s*$/gm)].map((match) => Number(match[1])),
    },
    {
      command: "lsof",
      args: ["-nP", "-iTCP", "-sTCP:LISTEN"],
      parse: (output) => [...output.matchAll(/:(\d+)\s+\(LISTEN\)/g)].map((match) => Number(match[1])),
    },
  ];
  for (const attempt of attempts) {
    try {
      const output = execFileSync(attempt.command, attempt.args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      const ports = [...new Set(attempt.parse(output).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535))].sort((a, b) => a - b).slice(0, 32);
      return ports.map((port) => ({ service_ref: `tcp-${port}`, exposure: "unknown", transport: "tcp", port, state: "unknown" }));
    } catch { /* Try the next platform-native listener utility. */ }
  }
  return [];
}

function shellQuote(value: string): string { return `'${String(value).replaceAll("'", `'"'"'`)}'`; }

function installSentinelSchedule(target: string): number {
  const stored = readLocalConnection(target);
  const enrollment = readSentinelEnrollment(target);
  const runtimeId = process.env.SEAMSHIELD_SENTINEL_RUNTIME_ID || enrollment?.runtime_id || "";
  if (!runtimeId) {
    console.error("seamshield sentinel install: enroll this runtime first with the one-time command from Sentinel");
    return 2;
  }
  if (process.platform !== "linux") {
    console.error("seamshield sentinel install: systemd user services are supported on Linux hosts only; use sentinel observe from your existing scheduler on this platform");
    return 2;
  }
  const safeId = String(runtimeId).replace(/[^a-zA-Z0-9_.-]/g, "_");
  const configDir = join(homedir(), ".config", "seamshield", "sentinel", safeId);
  const systemdDir = join(homedir(), ".config", "systemd", "user");
  const envPath = join(configDir, "sentinel.env");
  const runnerPath = join(configDir, "run");
  const unit = `seamshield-sentinel-${safeId}`;
  const suppliedSentinelKey = String(process.env.SEAMSHIELD_SENTINEL_KEY || "").trim();
  mkdirSync(configDir, { recursive: true });
  mkdirSync(systemdDir, { recursive: true });
  if (!existsSync(envPath)) {
    writeFileSync(envPath, [
      "# Keep this file mode 0600. Values stay on this host and are never committed.",
      `SEAMSHIELD_API_URL=${enrollment?.api_url || stored?.api_url || process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL}`,
      `SEAMSHIELD_SENTINEL_RUNTIME_ID=${runtimeId}`,
      "SEAMSHIELD_SENTINEL_KEY=",
      "# Optional: enables the local Cloudflare edge collector.",
      "CLOUDFLARE_API_TOKEN=",
      "",
    ].join("\n"), { mode: 0o600 });
    chmodSync(envPath, 0o600);
  }
  if (suppliedSentinelKey) {
    const current = readFileSync(envPath, "utf8");
    const keyLine = `SEAMSHIELD_SENTINEL_KEY=${shellQuote(suppliedSentinelKey)}`;
    const next = /^SEAMSHIELD_SENTINEL_KEY=.*$/m.test(current)
      ? current.replace(/^SEAMSHIELD_SENTINEL_KEY=.*$/m, keyLine)
      : `${current.trimEnd()}\n${keyLine}\n`;
    writeFileSync(envPath, next, { mode: 0o600 });
    chmodSync(envPath, 0o600);
  }
  writeFileSync(runnerPath, [
    "#!/usr/bin/env sh",
    "set -eu",
    `set -a; . ${shellQuote(envPath)}; set +a`,
    `: \"${"${SEAMSHIELD_SENTINEL_KEY:?set SEAMSHIELD_SENTINEL_KEY in sentinel.env}"}\"`,
    `${shellQuote(process.execPath)} ${shellQuote(currentBin())} sentinel observe ${shellQuote(target)}`,
    `if [ -n \"${"${CLOUDFLARE_API_TOKEN:-}"}\" ]; then ${shellQuote(process.execPath)} ${shellQuote(currentBin())} sentinel cloudflare ${shellQuote(target)}; fi`,
    "",
  ].join("\n"), { mode: 0o700 });
  chmodSync(runnerPath, 0o700);
  const servicePath = join(systemdDir, `${unit}.service`);
  const timerPath = join(systemdDir, `${unit}.timer`);
  writeFileSync(servicePath, ["[Unit]", "Description=SeamShield Sentinel runtime observation", "", "[Service]", "Type=oneshot", `ExecStart=${runnerPath}`, ""].join("\n"));
  writeFileSync(timerPath, ["[Unit]", "Description=Run SeamShield Sentinel every 15 minutes", "", "[Timer]", "OnBootSec=2min", "OnUnitActiveSec=15min", "Persistent=true", "", "[Install]", "WantedBy=timers.target", ""].join("\n"));
  const reload = spawnSync("systemctl", ["--user", "daemon-reload"], { encoding: "utf8" });
  const enable = reload.status === 0 ? spawnSync("systemctl", ["--user", "enable", "--now", `${unit}.timer`], { encoding: "utf8" }) : null;
  if (reload.status !== 0 || enable?.status !== 0) {
    console.error(`seamshield sentinel install: wrote ${servicePath} and ${timerPath}, but systemctl --user could not enable the timer. Enable ${unit}.timer from this host user.`);
    return 2;
  }
  console.log(`Sentinel schedule installed · ${unit}.timer`);
  console.log(`Every 15 minutes · server observation${existsSync(envPath) ? " · optional Cloudflare observation when CLOUDFLARE_API_TOKEN is set" : ""}`);
  console.log(`Secret file: ${envPath} (mode 0600) · ${suppliedSentinelKey ? "enrollment key stored from the protected process environment" : "set SEAMSHIELD_SENTINEL_KEY before the first run"} · source upload: false`);
  return 0;
}

async function enrollSentinel(target: string, options: { apiUrl?: string; runtimeId?: string }): Promise<number> {
  const runtimeId = String(options.runtimeId || process.env.SEAMSHIELD_SENTINEL_RUNTIME_ID || "").trim();
  if (!/^runtime_[a-zA-Z0-9_-]{8,160}$/.test(runtimeId)) {
    console.error("seamshield sentinel enroll: --runtime-id must be the opaque runtime id from the Sentinel enrollment screen");
    return 2;
  }
  const apiUrl = (options.apiUrl || process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL).replace(/\/$/, "");
  writeSentinelEnrollment(target, { schema: "seamshield.sentinel-enrollment/v2", runtime_id: runtimeId, api_url: apiUrl, enrolled_at: new Date().toISOString() });
  console.log(`Sentinel runtime enrolled · ${runtimeId}`);
  console.log("Next: run seamshield sentinel observe from this runtime, or seamshield sentinel install on Linux for continuous 15-minute observations.");
  console.log("Source upload: false · enrollment credentials remain in your server or CI secret store.");
  return 0;
}

async function observeSentinel(target: string, options: { apiUrl?: string; runtimeId?: string; environment?: string }): Promise<number> {
  const stored = readLocalConnection(target);
  const enrollment = readSentinelEnrollment(target);
  const apiUrl = connectedApiUrl(options.apiUrl || process.env.SEAMSHIELD_API_URL, stored);
  const runtimeId = options.runtimeId || process.env.SEAMSHIELD_SENTINEL_RUNTIME_ID || enrollment?.runtime_id || "";
  const sentinelKey = process.env.SEAMSHIELD_SENTINEL_KEY || "";
  if (!runtimeId || !sentinelKey) {
    console.error("seamshield sentinel observe: enroll this runtime first, then set SEAMSHIELD_SENTINEL_KEY only in the server or CI secret store");
    return 2;
  }
  if (!existsSync(target)) {
    console.error(`seamshield: path not found: ${target}`);
    return 2;
  }
  const environment = String(options.environment || process.env.SEAMSHIELD_ENVIRONMENT || "production").trim().toLowerCase();
  if (!/^[a-z][a-z0-9_-]{1,39}$/.test(environment)) {
    console.error("seamshield sentinel observe: --environment must be a short environment label");
    return 2;
  }
  const services = boundedListeningTcpPorts();
  const response = await fetch(`${apiUrl}/v1/sentinel/runtimes/${encodeURIComponent(runtimeId)}/receipts`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", "x-seamshield-sentinel-key": sentinelKey },
    body: JSON.stringify({ environment, collector_version: pkg.version, services, firewall_state: "unknown", tls_state: "unknown" }),
  });
  const body = await response.json().catch(() => ({})) as { error?: string; sentinel_observation?: { created_at?: string; digest?: string } };
  if (!response.ok) {
    console.error(`seamshield sentinel observe: ${String(body.error || `collector receipt rejected (${response.status})`)}`);
    return response.status === 401 || response.status === 403 ? 2 : 1;
  }
  console.log(`Sentinel observation recorded · ${runtimeId}`);
  console.log(`Runtime: ${runtimeId} · ${environment}`);
  console.log(`Services: ${services.length} bounded TCP listeners · attach matching workload references in Sentinel to project their posture`);
  console.log(`Receipt: ${String(body.sentinel_observation?.digest || "recorded").slice(0, 18)} · ${body.sentinel_observation?.created_at || new Date().toISOString()}`);
  console.log("Source upload: false · hostnames, IP addresses, logs, and credentials excluded");
  return 0;
}

async function observeCloudflare(target: string, options: { apiUrl?: string; edgeAttachmentIds?: string[] }): Promise<number> {
  const stored = readLocalConnection(target);
  const enrollment = readSentinelEnrollment(target);
  const apiUrl = connectedApiUrl(options.apiUrl || process.env.SEAMSHIELD_API_URL, stored);
  const sentinelKey = process.env.SEAMSHIELD_SENTINEL_KEY || "";
  const cloudflareToken = String(process.env.CLOUDFLARE_API_TOKEN || "").trim();
  const edgeAttachmentIds = options.edgeAttachmentIds?.length ? options.edgeAttachmentIds : String(process.env.SEAMSHIELD_SENTINEL_EDGE_ATTACHMENT_IDS || "").split(",").map((value) => value.trim()).filter(Boolean);
  if (!enrollment?.runtime_id || !sentinelKey || !edgeAttachmentIds.length) {
    console.error("seamshield sentinel cloudflare: enroll the runtime, set SEAMSHIELD_SENTINEL_KEY, and set SEAMSHIELD_SENTINEL_EDGE_ATTACHMENT_IDS from the Sentinel edge attachment");
    return 2;
  }
  if (!cloudflareToken) {
    console.error("seamshield sentinel cloudflare: set CLOUDFLARE_API_TOKEN in the customer secret store; it is used locally and never sent to SeamShield");
    return 2;
  }
  const cf = async (path: string) => {
    const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, { headers: { authorization: `Bearer ${cloudflareToken}`, accept: "application/json" } });
    const body = await response.json().catch(() => ({})) as { success?: boolean; result?: unknown; result_info?: { total_count?: number } };
    if (!response.ok || !body.success) throw new Error(`Cloudflare API request failed (${response.status})`);
    return body;
  };
  try {
    const zones = await cf("/zones?per_page=50") as { result?: Array<{ id?: string }> };
    const records = [];
    for (const zone of (zones.result || []).slice(0, 50)) {
      const zoneId = String(zone.id || "");
      if (!zoneId) continue;
      const [dns, redirect] = await Promise.all([
        cf(`/zones/${encodeURIComponent(zoneId)}/dns_records?per_page=1`) as Promise<{ result_info?: { total_count?: number } }>,
        cf(`/zones/${encodeURIComponent(zoneId)}/settings/always_use_https`) as Promise<{ result?: { value?: string } }>,
      ]);
      const body = {
        zone_ref: `cfz_${createHash("sha256").update(zoneId, "utf8").digest("hex").slice(0, 32)}`,
        dns_records_count: Math.max(0, Number(dns.result_info?.total_count || 0)),
        proxied_records_count: 0,
        https_redirect: redirect.result?.value === "on" ? "enabled" : redirect.result?.value === "off" ? "disabled" : "unknown",
        firewall_state: "unknown",
        tls_state: "unknown",
      };
      const response = await fetch(`${apiUrl}/v1/sentinel/edge/receipts`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "x-seamshield-sentinel-key": sentinelKey },
        body: JSON.stringify({ ...body, edge_attachment_ids: edgeAttachmentIds }),
      });
      const receipt = await response.json().catch(() => ({})) as { error?: string; sentinel_observation?: { digest?: string } };
      if (!response.ok) throw new Error(String(receipt.error || `SeamShield receipt rejected (${response.status})`));
      records.push(receipt.sentinel_observation?.digest || "recorded");
    }
    console.log(`Sentinel Cloudflare observations recorded · ${enrollment.runtime_id}`);
    console.log(`Zones: ${records.length} opaque zone references · DNS names and Cloudflare token excluded`);
    console.log(`Receipts: ${records.map((value) => String(value).slice(0, 12)).join(" · ") || "none"}`);
    console.log("Source upload: false · Cloudflare token stays in the local secret store");
    return 0;
  } catch (error) {
    console.error(`seamshield sentinel cloudflare: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

function gitRemote(target: string): string {
  const remote = spawnSync("git", ["config", "--get", "remote.origin.url"], { cwd: target, encoding: "utf8" });
  return remote.status === 0 ? String(remote.stdout || "").trim() : "";
}

function remoteRepository(remote: string): { host: string; path: string } | null {
  const match = remote.match(/^(?:https?:\/\/|ssh:\/\/git@|git@)([^/:]+)(?::\d+)?[/:](.+?)(?:\.git)?$/i);
  if (!match) return null;
  return { host: match[1].toLowerCase(), path: match[2].replace(/^\/+|\/+$/g, "") };
}

function detectCiProvider(target: string, override?: string): CiProvider {
  if (override && ["github", "gitlab", "bitbucket", "azure", "circleci", "generic"].includes(override)) return override as CiProvider;
  if (existsSync(join(target, ".circleci", "config.yml"))) return "circleci";
  if (existsSync(join(target, "azure-pipelines.yml"))) return "azure";
  if (existsSync(join(target, "bitbucket-pipelines.yml"))) return "bitbucket";
  if (existsSync(join(target, ".gitlab-ci.yml"))) return "gitlab";
  if (existsSync(join(target, ".github", "workflows", "seamshield.yml"))) return "github";
  const remote = remoteRepository(gitRemote(target));
  if (remote?.host === "github.com") return "github";
  if (remote?.host === "gitlab.com") return "gitlab";
  if (remote?.host === "bitbucket.org") return "bitbucket";
  if (remote?.host === "dev.azure.com" || remote?.host.endsWith(".visualstudio.com")) return "azure";
  return "generic";
}

function buildCiPlan(target: string, options: { ciProvider?: string; ciRepositoryId?: string; ciIssuer?: string; ciJwksUri?: string; ciAudience?: string }): CiPlan {
  const provider = detectCiProvider(target, options.ciProvider || process.env.SEAMSHIELD_CI_PROVIDER);
  const remote = remoteRepository(gitRemote(target));
  const repository = remote?.path.replace(/\/_git\//, "/") || basename(target);
  const repositoryId = options.ciRepositoryId || process.env.SEAMSHIELD_CI_REPOSITORY_ID;
  const defaultBranch = process.env.SEAMSHIELD_CI_DEFAULT_BRANCH || "main";
  const base = { provider, repository, repository_id: repositoryId, default_branch: defaultBranch };
  if (provider === "github") return { provider, repository, status: "configured", binding: { ...base, issuer: "https://token.actions.githubusercontent.com", audience: "https://platform.seamshield.com", jwks_uri: "https://token.actions.githubusercontent.com/.well-known/jwks", workflow_ref: ".github/workflows/seamshield.yml" } };
  if (provider === "gitlab" && remote?.host === "gitlab.com") return { provider, repository, status: "configured", binding: { ...base, issuer: "https://gitlab.com", audience: "https://platform.seamshield.com", jwks_uri: "https://gitlab.com/oauth/discovery/keys", workflow_ref: ".gitlab-ci.yml" } };
  if (provider === "bitbucket") {
    const workspace = repository.split("/")[0];
    if (!repositoryId || !options.ciAudience && !process.env.SEAMSHIELD_CI_AUDIENCE) return { provider, repository, status: "authorization_required", reason: "Bitbucket repository UUID and OIDC audience are required from the workspace integration." };
    const issuer = `https://api.bitbucket.org/2.0/workspaces/${workspace}/pipelines-config/identity/oidc`;
    return { provider, repository, status: "configured", binding: { ...base, repository_id: repositoryId, issuer, audience: options.ciAudience || process.env.SEAMSHIELD_CI_AUDIENCE || "", jwks_uri: `${issuer}/keys.json`, workflow_ref: "bitbucket-pipelines.yml" } };
  }
  if (provider === "azure" || provider === "circleci" || provider === "generic") {
    const issuer = options.ciIssuer || process.env.SEAMSHIELD_CI_ISSUER || "";
    const audience = options.ciAudience || process.env.SEAMSHIELD_CI_AUDIENCE || "";
    if (!repositoryId || !issuer || !audience) return { provider, repository, status: "authorization_required", reason: `${provider} requires its provider integration identity, issuer, and audience before CI can be activated.` };
    const workflow_ref = provider === "azure" ? "azure-pipelines.yml" : provider === "circleci" ? ".circleci/config.yml" : ".seamshield/ci/seamshield.sh";
    return { provider, repository, status: "configured", binding: { ...base, repository_id: repositoryId, issuer, audience, jwks_uri: options.ciJwksUri || process.env.SEAMSHIELD_CI_JWKS_URI, workflow_ref } };
  }
  return { provider, repository, status: "unsupported", reason: "No supported CI provider was detected." };
}

function installCiAutomation(target: string, automation: CiAutomation, plan: CiPlan): NonNullable<LocalConnection["ci"]> {
  if (!plan.binding || plan.status !== "configured") return { provider: plan.provider, repository: plan.repository, status: plan.status, reason: plan.reason };
  if (plan.provider === "github") writeGithubAction(target, automation);
  else if (plan.provider === "gitlab") writeGitlabCi(target, automation);
  else if (plan.provider === "bitbucket") writeBitbucketPipeline(target, automation);
  else if (plan.provider === "azure") writeAzurePipeline(target, automation);
  else if (plan.provider === "circleci") writeCircleConfig(target, automation);
  else writeGenericCiScript(target, automation);
  return { provider: plan.provider, repository: plan.repository, status: "configured" };
}

function printCiActivationGuide(plan: CiPlan, ci?: LocalConnection["ci"]): void {
  if (!ci || ci.status !== "configured") return;
  const workflow = plan.binding?.workflow_ref || "provider-native workflow";
  console.log(`CI workflow created locally: ${workflow}`);
  if (ci.provider === "github") {
    console.log("Next approval: commit and push .github/workflows/seamshield.yml to your default branch.");
    console.log("GitHub Actions then runs SeamShield on pull requests and pushes to main; the first signed OIDC receipt activates continuous protection.");
    console.log("Private repositories can use this reusable workflow as the dependency of their production deploy job. This gates deployment even when the GitHub plan cannot enforce a required branch check.");
    console.log("No GitHub token, repository secret, or long-lived CI key is required.");
    return;
  }
  console.log(`Commit and push ${workflow}; the first provider OIDC receipt activates continuous protection.`);
  console.log("No long-lived SeamShield CI key is written to the repository.");
}

type SecurityAgentJob = {
  schema: "seamshield.security-agent-job/v1";
  id: string;
  project_id: string;
  action_id: string;
  kind: "run_scan" | "investigate_high_lanes" | "install_ci_workflow" | "repair_ci_automation" | "apply_source_fix" | string;
  state: string;
  issued_at: string;
  expires_at: string;
  signature: string;
  source_upload: false;
  metadata_only: true;
};

function executableSecurityAgentJob(job: SecurityAgentJob, projectId: string): boolean {
  return job?.schema === "seamshield.security-agent-job/v1"
    && job.project_id === projectId
    && typeof job.id === "string"
    && /^saj_[a-f0-9-]+$/i.test(job.id)
    && typeof job.signature === "string"
    && job.signature.length >= 32
    && Date.parse(job.expires_at) > Date.now()
    && job.source_upload === false
    && job.metadata_only === true;
}

async function submitSecurityAgentJobReceipt(args: {
  apiUrl: string;
  projectId: string;
  jobId: string;
  headers: Record<string, string>;
  status: "completed" | "failed";
  resultCode: string;
  evidenceDigest?: string;
}): Promise<void> {
  const response = await fetch(`${args.apiUrl}/v1/projects/${encodeURIComponent(args.projectId)}/agent/jobs/${encodeURIComponent(args.jobId)}/receipt`, {
    method: "POST",
    headers: args.headers,
    body: JSON.stringify({
      status: args.status,
      result_code: args.resultCode,
      evidence_digest: args.evidenceDigest || undefined,
      source_upload: false,
      metadata_only: true,
    }),
  });
  if (!response.ok) throw new Error(`Agent receipt rejected (${response.status})`);
}

async function processSecurityAgentJobs(args: {
  target: string;
  apiUrl: string;
  projectId: string;
  headers: Record<string, string>;
  connection: LocalConnection;
  result: Awaited<ReturnType<typeof scanAsync>>;
  scanReceiptDigest: string;
  ciPlan: CiPlan | null;
}): Promise<{ processed: number; waiting: number }> {
  const getHeaders = Object.fromEntries(Object.entries(args.headers).filter(([key]) => key.toLowerCase() !== "content-type"));
  const response = await fetch(`${args.apiUrl}/v1/projects/${encodeURIComponent(args.projectId)}/agent/jobs`, {
    headers: getHeaders,
  });
  if (!response.ok) throw new Error(`Agent queue unavailable (${response.status})`);
  const body = await response.json().catch(() => ({})) as { jobs?: SecurityAgentJob[] };
  const jobs = Array.isArray(body.jobs) ? body.jobs.slice(0, 8) : [];
  let processed = 0;
  let waiting = 0;
  const supported = new Set(["run_scan", "investigate_high_lanes", "install_ci_workflow", "repair_ci_automation", "apply_source_fix"]);

  for (const job of jobs) {
    if (!executableSecurityAgentJob(job, args.projectId) || !supported.has(job.kind)) {
      waiting += 1;
      continue;
    }
    const claim = await fetch(`${args.apiUrl}/v1/projects/${encodeURIComponent(args.projectId)}/agent/jobs/${encodeURIComponent(job.id)}/claim`, {
      method: "POST",
      headers: args.headers,
      body: "{}",
    });
    if (claim.status === 409) continue;
    if (!claim.ok) throw new Error(`Agent job claim rejected (${claim.status})`);

    try {
      let evidenceDigest = args.scanReceiptDigest;
      let resultCode = job.kind === "run_scan" ? "scan_receipt_recorded" : "high_lane_investigation_recorded";

      if (job.kind === "install_ci_workflow" || job.kind === "repair_ci_automation") {
        if (!args.ciPlan?.binding || args.ciPlan.status !== "configured") {
          await submitSecurityAgentJobReceipt({ ...args, jobId: job.id, status: "failed", resultCode: "ci_provider_authorization_required" });
          waiting += 1;
          continue;
        }
        const ci = installCiAutomation(args.target, { projectId: args.projectId, apiUrl: args.apiUrl, provider: args.ciPlan.provider }, args.ciPlan);
        const bindingResponse = await fetch(`${args.apiUrl}/v1/projects/${encodeURIComponent(args.projectId)}/ci/bind`, {
          method: "POST",
          headers: args.headers,
          body: JSON.stringify(args.ciPlan.binding),
        });
        const bindingBody = await bindingResponse.json().catch(() => ({})) as { ci_binding_receipt?: { digest?: string } };
        if (!bindingResponse.ok || !bindingBody.ci_binding_receipt?.digest) throw new Error(`CI binding rejected (${bindingResponse.status})`);
        evidenceDigest = bindingBody.ci_binding_receipt.digest;
        resultCode = job.kind === "repair_ci_automation" ? "ci_automation_repaired" : "ci_workflow_installed";
        writeLocalConnection(args.target, { ...args.connection, ci, last_sync_at: new Date().toISOString() });
      } else if (job.kind === "apply_source_fix") {
        const out = join(resolve(args.target), ".seamshield", "fix-plan.json");
        mkdirSync(dirname(out), { recursive: true });
        writeFileSync(out, `${JSON.stringify(buildFixPlan(args.result, { agent: "generic" }), null, 2)}\n`);
        writeMarkdownFixPlan(args.result, { agent: "generic" });
        writeTestPlan(args.result, { agent: "generic" });
        resultCode = "approval_gated_remediation_plan_prepared";
      }

      await submitSecurityAgentJobReceipt({ ...args, jobId: job.id, status: "completed", resultCode, evidenceDigest });
      processed += 1;
      console.log(`Security Agent: ${job.kind} · ${resultCode}`);
    } catch (error) {
      const resultCode = `executor_failed_${job.kind}`.slice(0, 80);
      await submitSecurityAgentJobReceipt({ ...args, jobId: job.id, status: "failed", resultCode }).catch(() => {});
      throw error;
    }
  }
  return { processed, waiting };
}

async function providerIdentityToken(provider: CiProvider, audience: string): Promise<string> {
  if (process.env.SEAMSHIELD_ID_TOKEN) return process.env.SEAMSHIELD_ID_TOKEN;
  if (provider === "github") {
    const requestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    if (!requestUrl || !requestToken) throw new Error("GitHub OIDC identity is unavailable; the workflow needs id-token: write permission");
    const url = new URL(requestUrl);
    url.searchParams.set("audience", audience);
    const response = await fetch(url, { headers: { authorization: `Bearer ${requestToken}`, accept: "application/json" } });
    const body = await response.json().catch(() => ({})) as { value?: string };
    if (!response.ok || !body.value) throw new Error(`GitHub OIDC identity request failed (${response.status})`);
    return body.value;
  }
  if (provider === "bitbucket" && process.env.BITBUCKET_STEP_OIDC_TOKEN) return process.env.BITBUCKET_STEP_OIDC_TOKEN;
  if (provider === "circleci" && process.env.CIRCLE_OIDC_TOKEN_V2) return process.env.CIRCLE_OIDC_TOKEN_V2;
  throw new Error(`${provider} OIDC identity is unavailable; expose it as SEAMSHIELD_ID_TOKEN in the provider-native SeamShield job`);
}

async function exchangeCiCredential(apiUrl: string, projectId: string, provider: CiProvider, audience: string, observation: { workflow_present: boolean; branch_protection_present: boolean | null; deployment_gate_present: boolean }): Promise<string> {
  const idToken = await providerIdentityToken(provider, audience);
  const response = await fetch(`${apiUrl}/v1/projects/${encodeURIComponent(projectId)}/ci/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ provider, id_token: idToken, observation }),
  });
  const body = await response.json().catch(() => ({})) as { access_token?: string; error?: string };
  if (!response.ok || !body.access_token) throw new Error(String(body.error || `CI identity exchange failed (${response.status})`));
  return body.access_token;
}

function requireReceiptDigest(value: unknown, label: string): string {
  const digest = typeof value === "string" ? value.trim() : "";
  if (!digest) throw new Error(`backend did not return a signed ${label} receipt`);
  return digest;
}

async function verifyDeploymentGate(options: { projectId?: string; commit?: string; branch?: string; environment: string; apiUrl: string }): Promise<void> {
  const projectId = options.projectId || process.env.SEAMSHIELD_PROJECT_ID || "";
  const commitDigest = options.commit || process.env.SEAMSHIELD_DEPLOY_COMMIT || process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || process.env.BITBUCKET_COMMIT || process.env.BUILD_SOURCEVERSION || process.env.CIRCLE_SHA1 || "";
  const serverKey = process.env.SEAMSHIELD_SERVER_KEY || "";
  if (!projectId) throw new Error("set SEAMSHIELD_PROJECT_ID or pass --project-id");
  if (!commitDigest) throw new Error("set SEAMSHIELD_DEPLOY_COMMIT or pass --commit");
  if (!serverKey) throw new Error("set SEAMSHIELD_SERVER_KEY in the deployment host secret store");
  const url = new URL(`${options.apiUrl.replace(/\/$/, "")}/v1/projects/${encodeURIComponent(projectId)}/release-gates/verification`);
  url.searchParams.set("commit_digest", commitDigest);
  url.searchParams.set("environment", options.environment);
  const branch = options.branch || process.env.SEAMSHIELD_DEPLOY_BRANCH || "";
  if (branch) url.searchParams.set("branch", branch);
  const response = await fetch(url, { headers: { "x-seamshield-server-key": serverKey, accept: "application/json" } });
  const body = await response.json().catch(() => ({})) as { error?: string; deployment_gate?: { allowed?: boolean; reason?: string; release_receipt_digest?: string | null; receipt_created_at?: string | null } };
  const gate = body.deployment_gate;
  if (!response.ok || !gate?.allowed) {
    throw new Error(`deployment gate denied: ${gate?.reason || body.error || `verification failed (${response.status})`}`);
  }
  console.log(`Deployment gate passed · ${projectId} · ${commitDigest.slice(0, 12)}`);
  console.log(`Release receipt: ${(gate.release_receipt_digest || "").slice(0, 18)}`);
  console.log(`Receipt time: ${gate.receipt_created_at || "verified"}`);
  console.log("Source upload: false · deployment host received metadata-only verification");
}

async function connectProject(target: string, options: { projectId?: string; token?: string; apiUrl?: string; offline?: boolean; ci?: boolean; ciProvider?: string; ciRepositoryId?: string; ciIssuer?: string; ciJwksUri?: string; ciAudience?: string }): Promise<number> {
  const startedAt = Date.now();
  const stored = readLocalConnection(target);
  const projectId = options.projectId || process.env.SEAMSHIELD_PROJECT_ID || stored?.project.id || "";
  const serverKey = process.env.SEAMSHIELD_SERVER_KEY || stored?.server_key || "";
  const connectionToken = options.token || "";
  const apiUrl = connectedApiUrl(options.apiUrl || process.env.SEAMSHIELD_API_URL, stored);
  if (!connectionToken && (!projectId || (!serverKey && !options.ci))) {
    console.error("seamshield connect: run the one-time Platform connection command first");
    return 2;
  }
  if (!existsSync(target)) {
    console.error(`seamshield: path not found: ${target}`);
    return 2;
  }
  const result = await scanAsync(target, { network: options.offline ? "off" : "on", failOn: "never", profile: "community" });
  const access = buildAccessMap(result);
  const counts = { critical: access.summary.by_severity.critical || 0, high: access.summary.by_severity.high || 0, medium: access.summary.by_severity.medium || 0, low: access.summary.by_severity.low || 0, total: access.lanes.length };
  const idempotencyKey = `cli:${Date.now()}:${process.pid}`;
  const inventory = collectInventory(target, { profile: "community" });
  const pathLabel = basename(target) || "local repository";
  const ciPlan = options.ci === false ? null : buildCiPlan(target, options);
  const projectLanes = access.lanes.slice(0, 200).map((lane) => ({
    lane_id: lane.lane_id,
    actor: lane.actor,
    lane: lane.lane,
    asset: lane.asset,
    permission: lane.permission,
    condition: lane.condition,
    risk: lane.risk,
    severity: lane.severity,
    adapter: lane.provider,
    file: lane.source.file,
    line: lane.source.line,
    control: lane.risk,
    confidence: lane.severity === "block" ? 1 : lane.severity === "high" ? 0.9 : 0.75,
    fix_id: lane.risk,
    fix_summary: lane.fix.summary,
    source_title: lane.source.title,
  }));
  if (connectionToken) {
    const response = await fetch(`${apiUrl}/v1/projects/connections/redeem`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ token: connectionToken, path_label: pathLabel, ci_binding: ciPlan?.binding, scan: { idempotency_key: idempotencyKey, profile: "community", counts, lanes: projectLanes }, inventory: { components: inventory.components.map((component: InventoryComponent) => ({ ecosystem: component.ecosystem, name: component.name, version: component.version })) } }) });
    const body = await response.json().catch(() => ({})) as { error?: string; connection?: { digest?: string; project?: { id?: string; name?: string; primary_domain?: string } }; connection_credential?: { server_key?: string }; scan_receipt?: { digest?: string; created_at?: string }; dependency_receipt?: { digest?: string } };
    if (!response.ok) {
      const next = body.error === "connection_token_invalid_or_expired"
        ? "Generate a fresh connection command in Build → Platform, or run `seamshield sync .` to refresh the existing connection."
        : "The local connection was left unchanged.";
      console.error(`seamshield connect: ${String(body.error || `connection token rejected (${response.status})`)}. ${next}`);
      return 1;
    }
    let connectionDigest = "";
    let scanDigest = "";
    let dependencyDigest = "";
    try {
      connectionDigest = requireReceiptDigest(body.connection?.digest, "connection");
      scanDigest = requireReceiptDigest(body.scan_receipt?.digest, "scan");
      dependencyDigest = requireReceiptDigest(body.dependency_receipt?.digest, "dependency inventory");
    } catch (error) {
      console.error(`seamshield connect: ${error instanceof Error ? error.message : String(error)}. The local connection was left unchanged.`);
      return 1;
    }
    if (!body.connection?.project?.id || !body.connection_credential?.server_key) { console.error("seamshield connect: backend did not return a reusable project credential"); return 1; }
    if (stored) console.log(`Replacing existing local enrollment for ${stored.project.name || stored.project.id} after receipt verification.`);
    console.log(`Connected ${pathLabel} via one-time project token`);
    console.log(`Project: ${body.connection?.project?.name || body.connection?.project?.id || "connected project"}${body.connection?.project?.primary_domain ? ` · ${body.connection.project.primary_domain}` : ""}`);
    console.log(`Connection receipt: ${connectionDigest.slice(0, 18)}`);
    console.log(`Scan receipt: ${scanDigest.slice(0, 18)}`);
    console.log(`Receipt time: ${body.scan_receipt?.created_at || new Date().toISOString()}`);
    console.log(`Dependency receipt: ${dependencyDigest.slice(0, 18)}`);
    console.log("Source upload: false · absolute local path excluded");
    const local: LocalConnection = { schema: "seamshield.local-connection/v1", project: body.connection.project, api_url: apiUrl, server_key: body.connection_credential.server_key, receipt_digest: connectionDigest, scan_receipt_digest: scanDigest, connected_at: body.scan_receipt?.created_at || new Date().toISOString(), last_sync_at: body.scan_receipt?.created_at || new Date().toISOString(), source_upload: false };
    if (options.ci !== false && ciPlan) local.ci = installCiAutomation(target, { projectId: body.connection.project.id, apiUrl, provider: ciPlan.provider }, ciPlan);
    writeLocalConnection(target, local);
    console.log(`Persistent enrollment: ${connectionPath(target)} (git ignored · mode 0600)`);
    console.log(`CI: ${local.ci?.status === "configured" ? `${local.ci.provider} OIDC configured for ${local.ci.repository}` : local.ci?.reason || "local sync remains active"}`);
    printCiActivationGuide(ciPlan || buildCiPlan(target, options), local.ci);
    return result.exitCode === 0 ? 0 : result.exitCode;
  }
  let automationToken = "";
  if (options.ci) {
    const provider = detectCiProvider(target, options.ciProvider || process.env.SEAMSHIELD_CI_PROVIDER || stored?.ci?.provider);
    const audience = options.ciAudience || process.env.SEAMSHIELD_CI_AUDIENCE || (provider === "github" || provider === "gitlab" ? "https://platform.seamshield.com" : "");
    const ciStatus = buildCiStatus(target);
    const branchProtection = /^(?:1|true|yes)$/i.test(process.env.SEAMSHIELD_BRANCH_PROTECTION || "")
      ? true
      : /^(?:0|false|no)$/i.test(process.env.SEAMSHIELD_BRANCH_PROTECTION || "")
        ? false
        : null;
    try { automationToken = await exchangeCiCredential(apiUrl, projectId, provider, audience, { workflow_present: ciStatus.checks.workflow_exists, branch_protection_present: branchProtection, deployment_gate_present: ciStatus.checks.deployment_gate_ready }); }
    catch (error) { console.error(`seamshield sync: ${error instanceof Error ? error.message : String(error)}`); return 1; }
  }
  const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
  if (automationToken) headers.authorization = `Bearer ${automationToken}`;
  else headers["x-seamshield-server-key"] = serverKey;
  const localCiStatus = buildCiStatus(target);
  const scanResponse = await fetch(`${apiUrl}/v1/projects/${encodeURIComponent(projectId)}/scan-metadata/receipts`, { method: "POST", headers, body: JSON.stringify({ idempotency_key: idempotencyKey, profile: "community", path_label: pathLabel, counts, lanes: projectLanes, automation_observation: { workflow_present: localCiStatus.checks.workflow_exists, repository_identity_match: true, workflow_identity_match: localCiStatus.checks.continuous_sync, branch_protection_present: /^(?:1|true|yes)$/i.test(process.env.SEAMSHIELD_BRANCH_PROTECTION || "") ? true : /^(?:0|false|no)$/i.test(process.env.SEAMSHIELD_BRANCH_PROTECTION || "") ? false : null, deployment_gate_present: localCiStatus.checks.deployment_gate_ready, observed_at: new Date().toISOString() } }) });
  if (!scanResponse.ok) { console.error(`seamshield connect: scan metadata rejected (${scanResponse.status})`); return 1; }
  const inventoryResponse = await fetch(`${apiUrl}/v1/projects/${encodeURIComponent(projectId)}/dependencies/receipts`, { method: "POST", headers, body: JSON.stringify({ idempotency_key: idempotencyKey, components: inventory.components.map((component: InventoryComponent) => ({ ecosystem: component.ecosystem, name: component.name, version: component.version })) }) });
  if (!inventoryResponse.ok) { console.error(`seamshield connect: dependency inventory rejected (${inventoryResponse.status})`); return 1; }
  const verdict = buildShipVerdict(result);
  const branch = process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_REF_NAME || process.env.BITBUCKET_BRANCH || process.env.BUILD_SOURCEBRANCHNAME || process.env.CIRCLE_BRANCH || "main";
  const commitDigest = process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || process.env.BITBUCKET_COMMIT || process.env.BUILD_SOURCEVERSION || process.env.CIRCLE_SHA1;
  const blockedLaneIds = projectLanes.filter((lane) => lane.severity === "block").map((lane) => lane.lane_id);
  const releaseResponse = await fetch(`${apiUrl}/v1/projects/${encodeURIComponent(projectId)}/release-gates/receipts`, { method: "POST", headers, body: JSON.stringify({ idempotency_key: idempotencyKey, branch, commit_digest: commitDigest, decision: verdict.exitCode === 0 ? "passed" : "blocked", counts, lane_ids: blockedLaneIds, duration_ms: Date.now() - startedAt }) });
  if (!releaseResponse.ok) { console.error(`seamshield connect: release receipt rejected (${releaseResponse.status})`); return 1; }
  const guardHeaders: Record<string, string> = { accept: "application/json" };
  if (automationToken) guardHeaders.authorization = `Bearer ${automationToken}`;
  else guardHeaders["x-seamshield-server-key"] = serverKey;
  const guardResponse = await fetch(`${apiUrl}/v1/projects/${encodeURIComponent(projectId)}/guard/policy`, { headers: guardHeaders });
  if (!guardResponse.ok) { console.error(`seamshield connect: Guard policy rejected (${guardResponse.status})`); return 1; }
  const [scanBody, inventoryBody, releaseBody] = await Promise.all([
    scanResponse.json() as Promise<{ scan_receipt?: { digest?: string; created_at?: string } }>,
    inventoryResponse.json() as Promise<{ dependency_receipt?: { digest?: string } }>,
    releaseResponse.json() as Promise<{ release_receipt?: { digest?: string } }>,
  ]);
  let scanDigest = "";
  let dependencyDigest = "";
  let releaseDigest = "";
  try {
    scanDigest = requireReceiptDigest(scanBody.scan_receipt?.digest, "scan");
    dependencyDigest = requireReceiptDigest(inventoryBody.dependency_receipt?.digest, "dependency inventory");
    releaseDigest = requireReceiptDigest(releaseBody.release_receipt?.digest, "release gate");
  } catch (error) {
    console.error(`seamshield sync: ${error instanceof Error ? error.message : String(error)}. The local connection was left unchanged.`);
    return 1;
  }
  const prior = stored || { schema: "seamshield.local-connection/v1" as const, project: { id: projectId }, api_url: apiUrl, server_key: serverKey, source_upload: false as const };
  const refreshedConnection: LocalConnection = { ...prior, project: { ...prior.project, id: projectId }, api_url: apiUrl, server_key: serverKey, scan_receipt_digest: scanDigest, last_sync_at: scanBody.scan_receipt?.created_at || new Date().toISOString(), source_upload: false };
  writeLocalConnection(target, refreshedConnection);
  console.log(`Refreshed ${resolve(target)} for project ${prior.project.name || projectId}`);
  console.log(`Scan receipt: ${scanDigest.slice(0, 18)}`);
  console.log(`Dependency receipt: ${dependencyDigest.slice(0, 18)}`);
  console.log(`Release receipt: ${releaseDigest.slice(0, 18)}`);
  console.log("Guard policy: verified");
  try {
    const agent = await processSecurityAgentJobs({
      target,
      apiUrl,
      projectId,
      headers,
      connection: refreshedConnection,
      result,
      scanReceiptDigest: scanDigest,
      ciPlan,
    });
    console.log(`Security Agent: ${agent.processed} job${agent.processed === 1 ? "" : "s"} processed${agent.waiting ? ` · ${agent.waiting} waiting for supported evidence` : ""}`);
  } catch (error) {
    console.error(`seamshield sync: Security Agent queue warning: ${error instanceof Error ? error.message : String(error)}`);
  }
  console.log("Source upload: false · future CI runs can keep this connection current");
  return result.exitCode === 0 ? 0 : result.exitCode;
}

function workflowPath(target: string, provider = detectCiProvider(target)): string {
  if (provider === "gitlab") return join(target, ".gitlab-ci.yml");
  if (provider === "bitbucket") return join(target, "bitbucket-pipelines.yml");
  if (provider === "azure") return join(target, "azure-pipelines.yml");
  if (provider === "circleci") return join(target, ".circleci", "config.yml");
  if (provider === "generic") return join(target, ".seamshield", "ci", "seamshield.sh");
  return join(target, ".github", "workflows", "seamshield.yml");
}

function buildCiStatus(target: string) {
  const root = resolve(target);
  const connection = readLocalConnection(root);
  const provider = detectCiProvider(root, connection?.ci?.provider);
  const path = workflowPath(root, provider);
  const content = existsSync(path) ? readFileSync(path, "utf8") : "";
  const workflowExists = content.length > 0;
  const runsOfflineShip = content.includes("npx @seamshield/cli ship . --offline") || content.includes("npx @seamshield/cli sync . --ci");
  const continuousSync = content.includes("npx @seamshield/cli sync . --ci");
  const oidcConfigured = /id-token|id_tokens|oidc:\s*true|OIDC_TOKEN|SEAMSHIELD_ID_TOKEN/i.test(content);
  const deploymentGateReady = provider === "github" && content.includes("workflow_call:") && continuousSync && oidcConfigured;
  const uploadsInvestigations =
    content.includes("actions/upload-artifact") &&
    content.includes(".seamshield/investigations/") &&
    content.includes("if: failure()");
  const usesNode20 = content.includes("node-version: 20");
  const checkoutConfigured = content.includes("actions/checkout");
  const installed = workflowExists && runsOfflineShip;
  const diagnostics: Array<{ category: "provider_identity" | "permissions" | "workflow_installation"; code: string; message: string }> = [];
  if (connection?.ci?.status === "authorization_required") diagnostics.push({ category: "provider_identity", code: "provider_identity_incomplete", message: connection.ci.reason || "The provider integration identity is incomplete." });
  if (!workflowExists) diagnostics.push({ category: "workflow_installation", code: "workflow_missing", message: `The provider workflow was not found at ${path}.` });
  if (workflowExists && connection && !oidcConfigured) diagnostics.push({ category: "permissions", code: "oidc_permission_missing", message: "The connected workflow cannot request a provider OIDC identity." });
  if (workflowExists && connection && !continuousSync) diagnostics.push({ category: "workflow_installation", code: "continuous_sync_missing", message: "The workflow does not run connected Build and Guard synchronization." });
  if (workflowExists && connection && provider === "github" && !deploymentGateReady) diagnostics.push({ category: "workflow_installation", code: "deployment_gate_missing", message: "This workflow cannot yet be called by a production deploy job as its SeamShield gate." });
  return {
    schema: "seamshield.ci-status/v1",
    target: root,
    provider,
    workflow_path: path,
    status: installed ? "installed" : "not_installed",
    checks: {
      workflow_exists: workflowExists,
      checkout_configured: checkoutConfigured,
      node_20_configured: usesNode20,
      offline_ship_check: runsOfflineShip,
      investigations_uploaded_on_failure: uploadsInvestigations,
      continuous_sync: continuousSync,
      oidc_configured: oidcConfigured,
      deployment_gate_ready: deploymentGateReady,
    },
    diagnostics,
    next: installed
      ? continuousSync ? "CI is configured for continuous paid-project Build and Guard sync." : "CI is configured for the Community offline ship check."
      : "Run `seamshield ci install .` after connecting the project.",
  };
}

function renderCiStatusTable(status: ReturnType<typeof buildCiStatus>): string {
  return [
    "SeamShield CI Status",
    "",
    `Target: ${status.target}`,
    `Provider: ${status.provider}`,
    `Workflow: ${status.workflow_path}`,
    `Status: ${status.status}`,
    "",
    `Workflow exists: ${status.checks.workflow_exists ? "yes" : "no"}`,
    `Checkout configured: ${status.checks.checkout_configured ? "yes" : "no"}`,
    `Node 20 configured: ${status.checks.node_20_configured ? "yes" : "no"}`,
    `Offline ship check: ${status.checks.offline_ship_check ? "yes" : "no"}`,
    `Investigations uploaded on failure: ${status.checks.investigations_uploaded_on_failure ? "yes" : "no"}`,
    `Continuous sync: ${status.checks.continuous_sync ? "yes" : "no"}`,
    `OIDC configured: ${status.checks.oidc_configured ? "yes" : "no"}`,
    `Reusable deployment gate: ${status.checks.deployment_gate_ready ? "yes" : "no"}`,
    "",
    "Recovery diagnostics:",
    ...(status.diagnostics.length
      ? status.diagnostics.map((item) => `- ${item.category}: ${item.code} - ${item.message}`)
      : ["- none"]),
    "",
    `Next: ${status.next}`,
  ].join("\n");
}

function agentContextStatus(target: string) {
  const root = resolve(target);
  const files = CONTEXT_AGENTS.map((agent) => ({
    agent,
    path: agentContextPath(root, agent),
    exists: existsSync(agentContextPath(root, agent)),
  }));
  return {
    expected: files.length,
    present: files.filter((file) => file.exists).length,
    files,
  };
}

function ruleArtifactStatus(target: string) {
  const rulesDir = join(resolve(target), "packages", "cli", "rules");
  if (!existsSync(rulesDir)) {
    return { checked: false, duplicate_rule_files: [] as string[] };
  }
  const duplicates = spawnSync("find", [rulesDir, "-name", "* 2.yaml", "-print"], {
    encoding: "utf8",
  }).stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  return { checked: true, duplicate_rule_files: duplicates };
}

function packageReleaseStatus() {
  const expectedHomepage = "https://seamshield.com";
  const npm = spawnSync("npm", ["view", "@seamshield/cli", "version", "--json"], {
    encoding: "utf8",
    timeout: 2500,
  });
  const latest = npm.status === 0 ? npm.stdout.trim().replace(/^"|"$/g, "") : null;
  return {
    homepage: pkg.homepage ?? "",
    expected_homepage: expectedHomepage,
    homepage_ok: pkg.homepage === expectedHomepage,
    npm_latest_version: latest,
    npm_latest_status: latest ? (latest === pkg.version ? "current" : "behind") : "unknown",
  };
}

function runJsonCommand(command: string, args: string[], cwd: string, timeout = 5000): { ok: boolean; value: unknown; error?: string } {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", timeout });
  if (result.status !== 0) {
    return { ok: false, value: null, error: (result.stderr || result.stdout || `${command} failed`).trim() };
  }
  try {
    return { ok: true, value: JSON.parse(result.stdout) };
  } catch (error) {
    return { ok: false, value: null, error: error instanceof Error ? error.message : String(error) };
  }
}

function buildReleaseVerifyReport(target: string) {
  const root = resolve(target);
  const packageDir = cliPackageDir();
  const packageJsonPath = join(packageDir, "package.json");
  const packageJson = readJsonFile(packageJsonPath) as {
    name?: string;
    version?: string;
    homepage?: string;
    bin?: Record<string, string> | string;
    files?: string[];
  } | null;
  const artifacts = ruleArtifactStatus(root);
  const pack = runJsonCommand("npm", ["pack", "--dry-run", "--json"], packageDir, 20_000);
  const packEntries =
    pack.ok && Array.isArray(pack.value)
      ? ((pack.value[0] as { files?: Array<{ path: string }> } | undefined)?.files ?? []).map((file) => file.path)
      : [];
  const duplicatePackedRules = packEntries.filter((entry) => /rules\/.* 2\.ya?ml$/.test(entry));
  const requiredPackEntries = ["dist/index.js", "package.json"];
  const distTags = runJsonCommand("npm", ["view", "@seamshield/cli", "dist-tags", "--json"], root, 5000);
  const tags = distTags.ok && distTags.value && typeof distTags.value === "object" ? distTags.value as Record<string, string> : {};
  const checks = {
    package_json_readable: packageJson !== null,
    official_scope: packageJson?.name === "@seamshield/cli",
    homepage_ok: packageJson?.homepage === "https://seamshield.com",
    bin_ok: typeof packageJson?.bin === "object" && packageJson.bin?.seamshield === "dist/index.js",
    files_ok: Array.isArray(packageJson?.files) && ["dist", "rules", "schemas"].every((item) => packageJson.files?.includes(item)),
    rule_artifacts_clean: artifacts.duplicate_rule_files.length === 0,
    pack_dry_run_ok: pack.ok,
    pack_required_entries_ok: requiredPackEntries.every((entry) => packEntries.includes(entry)),
    pack_duplicate_rules_clean: duplicatePackedRules.length === 0,
    npm_dist_tags_checked: distTags.ok,
    npm_latest_matches_local: tags.latest ? tags.latest === packageJson?.version : false,
  };
  const required = [
    checks.package_json_readable,
    checks.official_scope,
    checks.homepage_ok,
    checks.bin_ok,
    checks.files_ok,
    checks.rule_artifacts_clean,
    checks.pack_dry_run_ok,
    checks.pack_required_entries_ok,
    checks.pack_duplicate_rules_clean,
  ];
  return {
    schema: "seamshield.release-verify/v1",
    target: root,
    package_dir: packageDir,
    package: {
      name: packageJson?.name ?? null,
      version: packageJson?.version ?? null,
      homepage: packageJson?.homepage ?? null,
      bin: packageJson?.bin ?? null,
      files: packageJson?.files ?? [],
    },
    checks,
    npm: {
      dist_tags_checked: distTags.ok,
      dist_tags: tags,
      error: distTags.ok ? null : distTags.error ?? "npm dist-tag check failed",
    },
    pack: {
      dry_run_ok: pack.ok,
      file_count: packEntries.length,
      required_entries: requiredPackEntries,
      duplicate_rule_files: duplicatePackedRules,
      error: pack.ok ? null : pack.error ?? "npm pack --dry-run failed",
    },
    status: required.every(Boolean) ? "ok" : "needs_attention",
    next: [
      ...(!checks.official_scope ? ["Publish only `@seamshield/cli`; do not publish personal `seamshield`."] : []),
      ...(!checks.homepage_ok ? ["Set package homepage to https://seamshield.com."] : []),
      ...(!checks.bin_ok ? ["Set bin.seamshield to dist/index.js before publish."] : []),
      ...(!checks.files_ok ? ["Keep package files limited to dist, rules, and schemas."] : []),
      ...(!checks.rule_artifacts_clean || !checks.pack_duplicate_rules_clean ? ["Remove duplicate generated rule files before publish."] : []),
      ...(!checks.pack_dry_run_ok || !checks.pack_required_entries_ok ? ["Run `pnpm pack --dry-run` in packages/cli and inspect contents."] : []),
      ...(!checks.npm_dist_tags_checked ? ["Npm dist-tag check was unavailable; retry before publishing if network is available."] : []),
      ...(checks.npm_dist_tags_checked && !checks.npm_latest_matches_local ? ["Local package version does not match npm latest; publish or bump intentionally."] : []),
    ],
  };
}

function renderReleaseVerifyTable(report: ReturnType<typeof buildReleaseVerifyReport>): string {
  const row = (label: string, ok: boolean) => `${ok ? "OK" : "WARN"}  ${label}`;
  return [
    "SeamShield Release Verify",
    "",
    `Package: ${report.package.name ?? "unknown"}@${report.package.version ?? "unknown"}`,
    `Package dir: ${report.package_dir}`,
    `Status: ${report.status}`,
    "",
    row("official @seamshield/cli scope", report.checks.official_scope),
    row("homepage is seamshield.com", report.checks.homepage_ok),
    row("bin.seamshield is dist/index.js", report.checks.bin_ok),
    row("package files are dist/rules/schemas", report.checks.files_ok),
    row("local rule artifacts clean", report.checks.rule_artifacts_clean),
    row("npm pack dry run", report.checks.pack_dry_run_ok),
    row("packed required entries", report.checks.pack_required_entries_ok),
    row("packed duplicate rules clean", report.checks.pack_duplicate_rules_clean),
    row("npm dist-tags checked", report.checks.npm_dist_tags_checked),
    row("npm latest matches local", report.checks.npm_latest_matches_local),
    "",
    "Next:",
    ...(report.next.length > 0 ? report.next.map((item) => `- ${item}`) : ["- Release metadata is ready for org-scoped publishing."]),
  ].join("\n");
}

function webAppStatus(target: string) {
  const root = join(resolve(target), "Web apps");
  const pages = ["index.html", "login.html", "security.html", "privacy.html", "terms.html"];
  const assets = [
    "assets/seamshield-icon.png",
    "assets/seamshield-lockup.png",
    "assets/seamshield-mono.png",
    "assets/seamshield.css",
    "assets/site.js",
    "assets/mesh.js",
    "app/releaseguard.css",
    "app/ss-auth.js",
    "app/ss-build.js",
    "app/ss-extend.js",
    "app/ss-ir.js",
    "app/ss-modules.js",
  ];
  const present = existsSync(root);
  const missing_pages = pages.filter((page) => !existsSync(join(root, page)));
  const missing_assets = assets.filter((asset) => !existsSync(join(root, asset)));
  const serverPath = join(root, "server.cjs");
  const serverSource = existsSync(serverPath) ? readFileSync(serverPath, "utf8") : "";
  const legacy_platform_redirect_ok =
    serverSource.includes('url.pathname === "/platform.html"') &&
    serverSource.includes("consoleOrigin") &&
    serverSource.includes("301");
  const favicon_missing = pages.filter((page) => {
    const file = join(root, page);
    if (!existsSync(file)) return true;
    const html = readFileSync(file, "utf8");
    return !html.includes('rel="icon"') || !html.includes("assets/seamshield-icon.png") || !html.includes('rel="apple-touch-icon"');
  });
  return {
    path: root,
    present,
    required_pages: pages.length,
    required_assets: assets.length,
    missing_pages,
    missing_assets,
    favicon_missing,
    legacy_platform_redirect_ok,
    required_pages_ok: present && missing_pages.length === 0,
    required_assets_ok: present && missing_assets.length === 0,
    favicon_links_ok: present && favicon_missing.length === 0,
  };
}

function buildDoctorReport(target: string) {
  const root = resolve(target);
  const configPath = join(root, ".seamshield", "config.yaml");
  const privacy = buildPrivacyReport(root);
  const guard = buildGuardStatus(root);
  const ciStatus = buildCiStatus(root);
  const agents = agentContextStatus(root);
  const artifacts = ruleArtifactStatus(root);
  const release = packageReleaseStatus();
  const checks = {
    package_scope: pkg.version.length > 0,
    package_homepage_ok: release.homepage_ok,
    config_exists: existsSync(configPath),
    offline_default: privacy.source_upload === false && privacy.static_scan.uploads_source === false,
    node_20_or_newer: Number(process.versions.node.split(".")[0]) >= 20,
    writable_target: (() => { try { accessSync(root, fsConstants.W_OK); return true; } catch { return false; } })(),
    package_manager_detected: ["pnpm-lock.yaml", "package-lock.json", "yarn.lock", "bun.lockb", "bun.lock"].some((file) => existsSync(join(root, file))),
    connection_setup: existsSync(join(root, ".seamshield", "connection.json")),
    guard_installed: guard.status === "installed",
    ci_installed: ciStatus.status === "installed",
    agent_context_any: agents.present > 0,
    rule_artifacts_clean: artifacts.duplicate_rule_files.length === 0,
  };
  const required = [
    checks.package_scope,
    checks.package_homepage_ok,
    checks.offline_default,
    checks.rule_artifacts_clean,
  ];
  return {
    schema: "seamshield.doctor/v1",
    target: root,
    package: {
      name: "@seamshield/cli",
      version: pkg.version,
      scope_ok: checks.package_scope,
      homepage: release.homepage,
      homepage_ok: release.homepage_ok,
      npm_latest_version: release.npm_latest_version,
      npm_latest_status: release.npm_latest_status,
    },
    checks,
    details: {
      config_path: configPath,
      guard,
      ci: ciStatus,
      agent_context: agents,
      rule_artifacts: artifacts,
    },
    status: required.every(Boolean) ? "ok" : "needs_attention",
    next: [
      ...(!checks.config_exists ? ["Run `seamshield config init .` to add local scanner config only."] : []),
      ...(!checks.guard_installed ? ["Run `seamshield guard install .` if this repo uses Claude Code."] : []),
      ...(!checks.ci_installed ? ["Run `seamshield ci install .` to add the Community offline ship check."] : []),
      ...(!checks.agent_context_any ? ["Run `seamshield agent-context . --all` or a specific agent target."] : []),
      ...(!checks.rule_artifacts_clean ? ["Run `pnpm run build` to regenerate package rule artifacts cleanly."] : []),
      ...(!checks.package_homepage_ok ? ["Set @seamshield/cli package homepage to https://seamshield.com."] : []),
      ...(!checks.node_20_or_newer ? ["Install Node.js 20 or newer before using the Community CLI."] : []),
      ...(!checks.writable_target ? ["Run SeamShield from a writable repository directory."] : []),
      ...(!checks.package_manager_detected ? ["Add or restore a package manager lockfile so dependency inventory is reproducible."] : []),
      ...(!checks.connection_setup ? ["Generate a project connection command in Console and run `seamshield connect . --token ...`."] : []),
    ],
  };
}

function renderDoctorTable(report: ReturnType<typeof buildDoctorReport>): string {
  const row = (label: string, ok: boolean) => `${ok ? "OK" : "WARN"}  ${label}`;
  return [
    "SeamShield Doctor",
    "",
    `Target: ${report.target}`,
    `Package: ${report.package.name}@${report.package.version}`,
    `Npm latest: ${report.package.npm_latest_status}${report.package.npm_latest_version ? ` (${report.package.npm_latest_version})` : ""}`,
    `Status: ${report.status}`,
    "",
    row("official package scope", report.checks.package_scope),
    row("npm package homepage", report.checks.package_homepage_ok),
    row("config exists", report.checks.config_exists),
    row("offline/source-private default", report.checks.offline_default),
    row("Node.js 20+", report.checks.node_20_or_newer),
    row("target writable", report.checks.writable_target),
    row("package manager detected", report.checks.package_manager_detected),
    row("project connection setup", report.checks.connection_setup),
    row("guard installed", report.checks.guard_installed),
    row("CI installed", report.checks.ci_installed),
    row("agent context present", report.checks.agent_context_any),
    row("rule artifacts clean", report.checks.rule_artifacts_clean),
    "",
    "Next:",
    ...(report.next.length > 0 ? report.next.map((item) => `- ${item}`) : ["- No required Community health issues found."]),
  ].join("\n");
}

function buildStatusReport(target: string) {
  const root = resolve(target);
  const connection = readLocalConnection(root);
  const configPath = join(root, ".seamshield", "config.yaml");
  const capabilities = collectInventory(root, { profile: "community" }).capabilities;
  const next = connection?.ci?.status === "configured" && connection.ci.provider === "github"
    ? "Ensure .github/workflows/seamshield.yml is committed and pushed. GitHub Actions then refreshes Build, Guard, Fix Plans, Test Plans, Learn, and Console on push or merge."
    : connection
      ? "Connection is persistent. `seamshield sync .` refreshes Build, Guard, Fix Plans, Test Plans, Learn, and Console; CI does this automatically after its provider workflow is committed and verified."
    : "Run `seamshield init .`, then generate a project connection command in the customer Console.";
  return { schema: "seamshield.status/v1", target: root, local_scan: { config_exists: existsSync(configPath), investigation_dir: existsSync(join(root, ".seamshield", "investigations")) }, capabilities, connection, next };
}

function renderStatusTable(report: ReturnType<typeof buildStatusReport>): string {
  const c = report.connection;
  const ci = c?.ci?.status === "configured" ? `${c.ci.provider} OIDC configured · workflow present locally` : c?.ci?.status || "not configured";
  const languages = report.capabilities.languages.map((language) => language.id).join(", ") || "not detected";
  const adapters = report.capabilities.coverage.deep_access_lane_adapters.join(", ") || "baseline coverage only";
  return ["SeamShield Status", "", `Target: ${report.target}`, `Languages: ${languages}`, `Deep access-lane adapters: ${adapters}`, `Local config: ${report.local_scan.config_exists ? "present" : "missing"}`, `Connected project: ${c?.project?.name || c?.project?.id || "not connected"}`, `Primary domain: ${c?.project?.primary_domain || "—"}`, `Last receipt: ${c?.last_sync_at || c?.connected_at || "—"}`, `CI: ${ci}`, "Source upload: false", "", `Next: ${report.next}`].join("\n");
}

async function offlineExport(target: string, outPath?: string): Promise<string> {
  const root = resolve(target);
  const result = await scanAsync(root, { network: "off", failOn: "never", profile: "community" });
  return JSON.stringify({ schema: "seamshield.offline-handoff/v1", profile: "community", exported_at: new Date().toISOString(), scan: result, inventory: collectInventory(root, { profile: "community" }), source_upload: false, metadata_only: true }, null, 2);
}

function offlineImport(target: string, file: string): string {
  const root = resolve(target);
  const parsed = JSON.parse(readFileSync(resolve(file), "utf8")) as Record<string, unknown>;
  const forbidden = ["source", "content", "diff", "secret", "secrets", "prompt", "raw", "reasoning", "model_output", "ast"];
  const serialized = JSON.stringify(parsed).toLowerCase();
  if (forbidden.some((key) => serialized.includes(`\"${key}\"`))) throw new Error("offline handoff contains forbidden source-shaped fields");
  if (parsed.schema !== "seamshield.offline-handoff/v1") throw new Error("unsupported offline handoff schema");
  const out = join(root, ".seamshield", "offline-handoff.json");
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(parsed, null, 2)}\n`);
  return out;
}

async function initProject(
  path: string,
  opts: { online?: boolean; offline?: boolean; agentContext?: boolean; agents?: string; guard?: boolean; ci?: boolean },
) {
  const target = resolve(path);
  if (!existsSync(target)) {
    console.error(`seamshield: path not found: ${path}`);
    process.exitCode = 2;
    return;
  }
  if (opts.agentContext === false && opts.agents) {
    console.error("seamshield: choose --agents or --no-agent-context, not both");
    process.exitCode = 2;
    return;
  }
  const selectedAgents = parseContextAgents(opts.agents);
  if (opts.agents && !selectedAgents) return;

  const wrote: string[] = [];
  wrote.push(ensureConfig(target));
  const inspection = writeRepositoryInspection(target);
  wrote.push(inspection.assessmentPath, inspection.manifestPath);
  if (opts.agentContext !== false) wrote.push(...writeAgentContexts(target, selectedAgents ?? CONTEXT_AGENTS));
  if (opts.guard !== false) wrote.push(installGuard(target));
  if (opts.ci !== false) wrote.push(writeGithubAction(target));
  if (opts.ci !== false) wrote.push(writeGitlabCi(target));

  const result = await scanAsync(target, {
    failOn: "never",
    network: opts.online && !opts.offline ? "on" : "off",
  });
  const investigation = writeInvestigationMarkdown(result);
  const verdict = buildShipVerdict(result);

  console.log("SeamShield Init");
  console.log("");
  console.log("Wrote:");
  for (const out of [...wrote, investigation]) console.log(`- ${out}`);
  console.log("");
  console.log(renderShipTable(verdict));
  console.log("");
  console.log("Next: open .seamshield/repository-assessment.md with your local coding agent before enabling runtime enforcement.");
  console.log("Then run: seamshield status .");
  process.exitCode = verdict.exitCode;
}

async function writeTriageSuppressions(
  path: string,
  opts: { rule?: string; reason?: string; includeBlock?: boolean; online?: boolean },
) {
  const target = resolve(path);
  const result = await readScanForCommand(target, !opts.online);
  if (!result) return;
  const config = readTriageConfig(target);
  const suppress = config.suppress ?? [];
  const existing = new Set(suppress.map((s) => `${s.rule}\0${s.file}\0${s.line ?? ""}`));
  const candidates = result.findings.filter((finding) => {
    if (opts.rule && finding.finding.rule_id !== opts.rule) return false;
    if (!opts.includeBlock && finding.finding.severity === "block") return false;
    return true;
  });
  for (const finding of candidates) {
    const entry = {
      rule: finding.finding.rule_id,
      file: finding.finding.file,
      line: finding.finding.line,
      reason: opts.reason ?? "triaged false positive",
    };
    const key = `${entry.rule}\0${entry.file}\0${entry.line}`;
    if (existing.has(key)) continue;
    suppress.push(entry);
    existing.add(key);
  }
  config.suppress = suppress;
  const out = writeTriageConfig(target, config);
  console.log(out);
  console.log(`Suppressed ${candidates.length} current finding(s).`);
}

function currentBin(): string {
  return fileURLToPath(import.meta.url);
}

function installGuard(target: string): string {
  const settingsPath = join(target, ".claude", "settings.json");
  mkdirSync(dirname(settingsPath), { recursive: true });
  const settings = existsSync(settingsPath)
    ? (JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>)
    : {};
  const hooks = (settings.hooks && typeof settings.hooks === "object" ? settings.hooks : {}) as Record<
    string,
    unknown
  >;
  const command = `${process.execPath} ${JSON.stringify(currentBin())} guard check`;
  hooks.PreToolUse = [
    {
      matcher: "Write|Edit|MultiEdit|Bash",
      hooks: [{ type: "command", command }],
    },
  ];
  settings.hooks = hooks;
  writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
  return settingsPath;
}

function guardPolicyPath(target: string): string {
  return join(resolve(target), ".seamshield", "guard-policy.json");
}

async function syncGuardPolicy(target: string, projectId: string, apiUrl: string): Promise<string> {
  const serverKey = process.env.SEAMSHIELD_SERVER_KEY;
  if (!serverKey) throw new Error("SEAMSHIELD_SERVER_KEY is required for guard sync");
  if (!projectId) throw new Error("SEAMSHIELD_PROJECT_ID is required for guard sync");
  const response = await fetch(`${apiUrl.replace(/\/$/, "")}/v1/projects/${encodeURIComponent(projectId)}/guard/policy`, {
    headers: { accept: "application/json", "x-seamshield-server-key": serverKey },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.guard_policy) throw new Error(String(body.error || `guard_policy_${response.status}`));
  const policy = body.guard_policy as Record<string, unknown>;
  const out = guardPolicyPath(target);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(policy, null, 2)}\n`);
  return out;
}

function readJsonFile(path: string): Record<string, unknown> | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function buildGuardStatus(target: string) {
  const root = resolve(target);
  const settingsPath = join(root, ".claude", "settings.json");
  const settings = readJsonFile(settingsPath);
  const hooks = settings?.hooks && typeof settings.hooks === "object" ? settings.hooks as Record<string, unknown> : {};
  const preToolUse = Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : [];
  const commandText = JSON.stringify(preToolUse);
  const installed = preToolUse.length > 0 && commandText.includes("guard check");
  const matcher = commandText.includes("Write|Edit|MultiEdit|Bash")
    ? "Write|Edit|MultiEdit|Bash"
    : preToolUse.length > 0 ? "custom" : "missing";
  const currentBinaryReferenced = commandText.includes(currentBin());
  const policy = readJsonFile(guardPolicyPath(root));
  return {
    schema: "seamshield.guard-status/v1",
    target: root,
    supported_agents: ["claude"],
    checks: {
      claude_settings_exists: existsSync(settingsPath),
      claude_settings_parseable: settings !== null,
      pre_tool_use_hook_installed: installed,
      matcher,
      current_binary_referenced: currentBinaryReferenced,
      signed_policy_cached: !!policy?.digest && policy?.schema === "seamshield.guard-policy/v1",
      fail_open_logging_path: ".seamshield/guard.log",
    },
    status: installed ? "installed" : "not_installed",
    next: installed
      ? "Run `seamshield guard check` through the configured Claude Code hook event."
      : "Run `seamshield guard install .` to add the Claude Code PreToolUse hook.",
  };
}

function renderGuardStatusTable(status: ReturnType<typeof buildGuardStatus>): string {
  return [
    "SeamShield Guard Status",
    "",
    `Target: ${status.target}`,
    `Status: ${status.status}`,
    `Supported agents: ${status.supported_agents.join(", ")}`,
    "",
    `Claude settings: ${status.checks.claude_settings_exists ? "found" : "missing"}`,
    `Settings parseable: ${status.checks.claude_settings_parseable ? "yes" : "no"}`,
    `PreToolUse hook: ${status.checks.pre_tool_use_hook_installed ? "installed" : "missing"}`,
    `Matcher: ${status.checks.matcher}`,
    `Current binary referenced: ${status.checks.current_binary_referenced ? "yes" : "no"}`,
    `Fail-open log: ${status.checks.fail_open_logging_path}`,
    "",
    `Next: ${status.next}`,
  ].join("\n");
}

function hookDeny(reason: string) {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

function hookAllow(additionalContext?: string) {
  return additionalContext
    ? { hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext } }
    : {};
}

function readStdin(): string {
  return readFileSync(0, "utf8");
}

function extractToolPayload(input: Record<string, unknown>) {
  const tool = String(input.tool_name ?? input.toolName ?? "");
  const raw = (input.tool_input ?? input.toolInput ?? input) as Record<string, unknown>;
  return { tool, raw };
}

function contentFromTool(tool: string, raw: Record<string, unknown>): { rel: string; content: string } | null {
  if (!/Write|Edit|MultiEdit/.test(tool)) return null;
  const rel = String(raw.file_path ?? raw.path ?? "proposed.txt");
  const candidate =
    raw.content ??
    raw.new_string ??
    raw.newStr ??
    (Array.isArray(raw.edits) ? raw.edits.map((e) => (e as { new_string?: string }).new_string ?? "").join("\n") : "");
  return typeof candidate === "string" && candidate.length > 0 ? { rel, content: candidate } : null;
}

function bashDecision(command: string): string | null {
  if (/git\s+add\s+\.env/.test(command)) return "ss/secrets/env-file-committed: do not stage dotenv files.";
  if (/curl\b[\s\S]*\|\s*(?:sh|bash)/.test(command)) return "ss/agent/overbroad-permissions: do not pipe curl directly to a shell.";
  if (/npm\s+(?:i|install|add)\s+(@?[\w.-]+\/?[\w.-]*)/.test(command)) {
    const name = command.match(/npm\s+(?:i|install|add)\s+(@?[\w.-]+\/?[\w.-]*)/)?.[1];
    if (name) {
      const encoded = name.startsWith("@") ? name.replace("/", "%2F") : name;
      const res = spawnSync("curl", ["-fsSI", `https://registry.npmjs.org/${encoded}`], {
        encoding: "utf8",
        timeout: 750,
      });
      if (res.status !== 0) return `ss/deps/hallucinated-package: npm package "${name}" did not resolve.`;
    }
  }
  return null;
}

function guardCheck(): void {
  try {
    const parsed = JSON.parse(readStdin()) as Record<string, unknown>;
    const { tool, raw } = extractToolPayload(parsed);
    if (/Bash/.test(tool)) {
      const command = String(raw.command ?? "");
      const deny = bashDecision(command);
      console.log(JSON.stringify(deny ? hookDeny(deny) : hookAllow()));
      return;
    }
    const proposed = contentFromTool(tool, raw);
    if (!proposed) {
      console.log(JSON.stringify(hookAllow()));
      return;
    }
    const tempRoot = mkdtempSync(join(tmpdir(), "seamshield-guard-"));
    const abs = resolve(tempRoot, proposed.rel);
    const tempRelative = relative(tempRoot, abs);
    if (!tempRelative || tempRelative.startsWith("..") || resolve(tempRoot, tempRelative) !== abs) {
      rmSync(tempRoot, { recursive: true, force: true });
      console.log(JSON.stringify(hookDeny("ss/guard/unsafe-file-path: proposed edit path must remain inside the Guard sandbox.")));
      return;
    }
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, proposed.content);
    const result = scan(tempRoot, { network: "off" });
    rmSync(tempRoot, { recursive: true, force: true });
    const block = result.findings.find((f: Finding) => f.finding.severity === "block");
    if (block) {
      console.log(
        JSON.stringify(
          hookDeny(`${block.finding.rule_id}: ${block.finding.title}. ${block.finding.fix.summary}`),
        ),
      );
      return;
    }
    console.log(JSON.stringify(hookAllow()));
  } catch (error) {
    const logPath = join(process.cwd(), ".seamshield", "guard.log");
    try {
      mkdirSync(dirname(logPath), { recursive: true });
      writeFileSync(logPath, `${new Date().toISOString()} ${String(error)}\n`, { flag: "a" });
    } catch {
      // fail-open even if logging fails
    }
    console.log(JSON.stringify(hookAllow("SeamShield guard failed open; run seamshield scan.")));
  }
}

function runSelftest(): void {
  const dir = mkdtempSync(join(tmpdir(), "seamshield-selftest-"));
  try {
    const secret = `sk_live_${"S".repeat(24)}`;
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify(
        {
          name: "seamshield-selftest",
          scripts: { postinstall: "node install.js" },
          dependencies: { "bumblebee-selftest-evil": "0.0.0" },
        },
        null,
        2,
      ),
    );
    writeFileSync(join(dir, "index.ts"), `const k = "${secret}";\n`);
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { local: { env: { API_KEY: "secret" } } } }));

    const result = scan(dir, { network: "off" });
    const access = buildAccessMap(result);
    const inventory = collectInventory(dir);
    const investigation = writeInvestigationMarkdown(result);
    const investigationText = readFileSync(investigation, "utf8");
    const checks = [
      result.findings.some((finding: Finding) => finding.finding.rule_id === "ss/secrets/hardcoded-provider-key"),
      result.findings.some((finding: Finding) => finding.finding.rule_id === "ss/deps/postinstall-script"),
      access.lanes.some((lane: AccessLane) => /^lane:[a-f0-9]{16}$/.test(lane.lane_id)),
      inventory.components.some((component: InventoryComponent) => component.ecosystem === "mcp"),
      !JSON.stringify(result).includes(secret),
      !investigationText.includes(secret),
    ];
    if (checks.every(Boolean)) {
      console.log(`selftest OK (${result.findings.length} findings, ${inventory.components.length} inventory records)`);
      process.exitCode = 0;
      return;
    }
    console.error("selftest failed: expected embedded fixture detections were missing");
    process.exitCode = 1;
  } catch (error) {
    console.error(`selftest error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const program = new Command();

program
  .name("seamshield")
  .description("Security scanner for AI-built repositories: baseline controls for every repo, deeper analysis for detected adapters.")
  .version(pkg.version);

program
  .command("scan")
  .description("Scan a project directory and report findings")
  .argument("[path]", "directory to scan", ".")
  .option("--format <format>", "output format: table | json | sarif | ndjson", "table")
  .option("--fail-on <severity>", "exit 1 at or above: block | high | warn | never", "block")
  .option("--offline", "skip npm registry and OSV network checks")
  .option("--no-investigation", "do not write .seamshield/investigations/*.md")
  .option("--profile <profile>", "scan profile: community | workspace | incident", "community")
  .option("--root <path>", "explicit root for workspace or incident profiles", collectRoot, [])
  .action((path: string, opts: { format: string; failOn: string; offline?: boolean; investigation?: boolean; profile?: string; root?: string[] }) => {
    return runScan(path, opts);
  });

program
  .command("inspect")
  .description("Map local runtime, auth, CI, deployment, server, and AI-agent surfaces before connecting a project")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json", "table")
  .option("--write", "write local assessment and bounded protection manifest", false)
  .action((path: string, opts: { format: string; write?: boolean }) => {
    if (!assertChoice(opts.format, INSPECT_FORMATS, "format")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const output: { report: RepositoryInspection; assessmentPath?: string; manifestPath?: string } = opts.write
      ? writeRepositoryInspection(path)
      : { report: buildRepositoryInspection(path) };
    console.log(opts.format === "json" ? `${JSON.stringify(output.report, null, 2)}\n` : renderRepositoryInspection(output.report));
    if (opts.write && opts.format !== "json" && output.assessmentPath && output.manifestPath) {
      console.log(`\nAssessment: ${output.assessmentPath}`);
      console.log(`Protection manifest: ${output.manifestPath}`);
    }
    process.exitCode = 0;
  });

program
  .command("ship")
  .description("Give a deploy verdict from dangerous access lanes")
  .argument("[path]", "directory to scan", ".")
  .option("--offline", "keep dependency intelligence offline (default)")
  .option("--online", "include network-backed dependency intelligence")
  .option("--profile <profile>", "scan profile: community | workspace | incident", "community")
  .option("--root <path>", "explicit root for workspace or incident profiles", collectRoot, [])
  .action(async (path: string, opts: { online?: boolean; offline?: boolean; profile?: string; root?: string[] }) => {
    if (!assertProfile(opts.profile, opts.root ?? [])) return;
    const result = await readScanForCommand(opts.root?.[0] ?? path, !(opts.online && !opts.offline), (opts.profile as ScanProfile | undefined) ?? "community");
    if (!result) return;
    maybeWriteInvestigation(result, true);
    const verdict = buildShipVerdict(result);
    console.log(renderShipTable(verdict));
    process.exitCode = verdict.exitCode;
  });

program
  .command("init")
  .description("Bootstrap SeamShield in a repo: config, agents, guard, CI, first ship check")
  .argument("[path]", "project directory", ".")
  .option("--online", "include network-backed dependency intelligence in the first ship check")
  .option("--offline", "keep dependency intelligence offline (default)")
  .option("--no-agent-context", "skip agent context files")
  .option("--agents <list>", `agent context targets: ${CONTEXT_AGENTS.join(", ")}, all`)
  .option("--no-guard", "skip Claude Code guard installation")
  .option("--no-ci", "skip GitHub Actions workflow")
  .action(
    (
      path: string,
      opts: { online?: boolean; offline?: boolean; agentContext?: boolean; agents?: string; guard?: boolean; ci?: boolean },
    ) => initProject(path, opts),
  );

const config = program
  .command("config")
  .description("Local SeamShield configuration utilities");

config
  .command("init")
  .description("Write .seamshield/config.yaml without agent, guard, CI, or scan side effects")
  .argument("[path]", "project directory", ".")
  .action((path: string) => {
    const target = resolve(path);
    if (!existsSync(target)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const out = ensureConfig(target);
    console.log(out);
    process.exitCode = 0;
  });

program
  .command("investigate")
  .description("Write a Markdown investigation for current access-lane findings")
  .argument("[path]", "directory to scan", ".")
  .option("--online", "include network-backed dependency intelligence")
  .action(async (path: string, opts: { online?: boolean }) => {
    const result = await readScanForCommand(path, !opts.online);
    if (!result) return;
    console.log(writeInvestigationMarkdown(result));
    process.exitCode = 0;
  });

program
  .command("audit")
  .description("Write a local audit bundle: architecture, report, detail, schema, and findings JSON")
  .argument("[path]", "directory to scan", ".")
  .option("--format <format>", "output format: table | json", "table")
  .option("--online", "include network-backed dependency intelligence")
  .option("--out <dir>", "output directory")
  .action(async (path: string, opts: { format: string; online?: boolean; out?: string }) => {
    if (!assertChoice(opts.format, AUDIT_FORMATS, "format")) return;
    const result = await readScanForCommand(path, !opts.online);
    if (!result) return;
    const outDir = opts.out ? resolve(opts.out) : auditDirFor(path);
    const report = buildAuditBundle(result, outDir);
    console.log(opts.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderAuditTable(report));
    process.exitCode = 0;
  });

program
  .command("privacy")
  .description("Explain SeamShield local execution, network behavior, redaction, and files written")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json", "table")
  .action((path: string, opts: { format: string }) => {
    if (!assertChoice(opts.format, PRIVACY_FORMATS, "format")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const report = buildPrivacyReport(path);
    console.log(opts.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderPrivacyTable(report));
    process.exitCode = 0;
  });

program
  .command("access")
  .description("Show the normalized Actor -> Lane -> Asset -> Permission -> Condition -> Risk access map")
  .argument("[path]", "directory to scan", ".")
  .option("--format <format>", "output format: table | json | ndjson", "table")
  .option("--online", "include network-backed dependency intelligence")
  .option("--profile <profile>", "scan profile: community | workspace | incident", "community")
  .option("--root <path>", "explicit root for workspace or incident profiles", collectRoot, [])
  .action(async (path: string, opts: { format: string; online?: boolean; profile?: string; root?: string[] }) => {
    if (!assertChoice(opts.format, ACCESS_FORMATS, "format")) return;
    if (!assertProfile(opts.profile, opts.root ?? [])) return;
    const result = await readScanForCommand(opts.root?.[0] ?? path, !opts.online, (opts.profile as ScanProfile | undefined) ?? "community");
    if (!result) return;
    const access = buildAccessMap(result);
    console.log(opts.format === "json" ? renderAccessJson(access) : opts.format === "ndjson" ? renderAccessNdjson(result) : renderAccessTable(access));
    process.exitCode = 0;
  });

program
  .command("inventory")
  .description("Read local repository capabilities, package, MCP, agent, extension, and deploy metadata without source upload")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json | ndjson", "table")
  .option("--profile <profile>", "inventory profile: community | workspace | incident", "community")
  .option("--root <path>", "explicit root for workspace or incident profiles", collectRoot, [])
  .option("--findings-only", "reserved for future signed exposure catalogs", false)
  .action((path: string, opts: { format: string; profile?: string; root?: string[]; findingsOnly?: boolean }) => {
    if (!assertChoice(opts.format, INVENTORY_FORMATS, "format")) return;
    if (!assertProfile(opts.profile, opts.root ?? [])) return;
    const target = opts.root?.[0] ?? path;
    if (!existsSync(target)) {
      console.error(`seamshield: path not found: ${target}`);
      process.exitCode = 2;
      return;
    }
    if (opts.findingsOnly) {
      console.error("seamshield: --findings-only requires future signed exposure catalog support");
      process.exitCode = 2;
      return;
    }
    const inventory = collectInventory(target, { profile: (opts.profile as ScanProfile | undefined) ?? "community" });
    console.log(opts.format === "json" ? renderInventoryJson(inventory) : opts.format === "ndjson" ? renderInventoryNdjson(inventory) : renderInventoryTable(inventory));
    process.exitCode = 0;
  });

program
  .command("connect")
  .description("Connect a local project to a provisioned SeamShield project using metadata-only receipts")
  .argument("[path]", "directory to scan", ".")
  .option("--project-id <id>", "provisioned project id", process.env.SEAMSHIELD_PROJECT_ID)
  .option("--token <token>", "short-lived one-time Platform connection token")
  .option("--api-url <url>", "SeamShield backend base URL (defaults to SeamShield production)", process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL)
  .option("--ci-provider <provider>", "CI provider override: github | gitlab | bitbucket | azure | circleci | generic")
  .option("--ci-repository-id <id>", "provider repository/project identity when the provider does not assert its repository path")
  .option("--ci-issuer <url>", "provider OIDC issuer for Azure, CircleCI, or generic CI")
  .option("--ci-jwks-uri <url>", "provider OIDC JWKS endpoint when discovery is unavailable")
  .option("--ci-audience <audience>", "provider OIDC audience for Bitbucket, Azure, CircleCI, or generic CI")
  .option("--offline", "skip network-backed dependency intelligence")
  .action(async (path: string, opts: { projectId?: string; token?: string; apiUrl?: string; offline?: boolean; ciProvider?: string; ciRepositoryId?: string; ciIssuer?: string; ciJwksUri?: string; ciAudience?: string }) => {
    process.exitCode = await connectProject(resolve(path), opts);
  });

program
  .command("sync")
  .description("Refresh a persisted paid-project connection with bounded scan, Guard, dependency, and release receipts")
  .argument("[path]", "directory to scan", ".")
  .option("--api-url <url>", "SeamShield backend base URL")
  .option("--offline", "skip network-backed dependency intelligence")
  .option("--ci", "mark this refresh as a CI run")
  .option("--ci-provider <provider>", "CI provider override", process.env.SEAMSHIELD_CI_PROVIDER)
  .option("--ci-audience <audience>", "provider OIDC audience", process.env.SEAMSHIELD_CI_AUDIENCE)
  .action(async (path: string, opts: { apiUrl?: string; offline?: boolean; ci?: boolean; ciProvider?: string; ciAudience?: string }) => {
    process.exitCode = await connectProject(resolve(path), opts);
  });

const sentinel = program
  .command("sentinel")
  .description("Paid runtime infrastructure observation utilities");

sentinel
  .command("enroll")
  .description("Save the opaque tenant-scoped Sentinel runtime id locally; keep the enrollment key in your server or CI secret store")
  .argument("[path]", "directory holding the local Sentinel state", ".")
  .requiredOption("--runtime-id <id>", "opaque Sentinel runtime id from the Console")
  .option("--api-url <url>", "SeamShield backend base URL", process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL)
  .action(async (path: string, opts: { apiUrl?: string; runtimeId?: string }) => {
    process.exitCode = await enrollSentinel(resolve(path), opts);
  });

sentinel
  .command("observe")
  .description("Submit bounded server listener and posture metadata without source, logs, hostnames, or IP addresses")
  .argument("[path]", "directory holding the protected project connection", ".")
  .option("--api-url <url>", "SeamShield backend base URL", process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL)
  .option("--runtime-id <id>", "opaque tenant-scoped Sentinel runtime id", process.env.SEAMSHIELD_SENTINEL_RUNTIME_ID)
  .option("--environment <name>", "deployment environment label", process.env.SEAMSHIELD_ENVIRONMENT || "production")
  .action(async (path: string, opts: { apiUrl?: string; runtimeId?: string; environment?: string }) => {
    try {
      process.exitCode = await observeSentinel(resolve(path), opts);
    } catch (error) {
      console.error(`seamshield sentinel observe: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    }
  });

sentinel
  .command("cloudflare")
  .description("Read Cloudflare posture locally with a scoped customer token and submit only opaque edge metadata")
  .argument("[path]", "directory holding the protected project connection", ".")
  .option("--api-url <url>", "SeamShield backend base URL", process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL)
  .option("--edge-attachment-id <id...>", "opaque Sentinel edge attachment id from the Console")
  .action(async (path: string, opts: { apiUrl?: string; edgeAttachmentId?: string[] }) => {
    process.exitCode = await observeCloudflare(resolve(path), { apiUrl: opts.apiUrl, edgeAttachmentIds: opts.edgeAttachmentId });
  });

sentinel
  .command("install")
  .description("Install a Linux systemd user timer for continuous server and optional Cloudflare observations")
  .argument("[path]", "directory holding the protected project connection", ".")
  .action((path: string) => {
    process.exitCode = installSentinelSchedule(resolve(path));
  });

program
  .command("fix-plan")
  .description("Write agent-ready fix prompts for dangerous access lanes")
  .argument("[path]", "directory to scan", ".")
  .option("--offline", "skip npm registry and OSV network checks")
  .option("--agent <agent>", "target agent: claude | cursor | codex | generic", "generic")
  .action(async (path: string, opts: { offline?: boolean; agent: string }) => {
    if (!assertChoice(opts.agent, FIX_AGENTS, "agent")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const result = await scanAsync(path, { network: opts.offline ? "off" : "on" });
    const out = join(resolve(path), ".seamshield", "fix-plan.json");
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify(buildFixPlan(result, { agent: opts.agent as FixPlanAgent }), null, 2)}\n`);
    const markdownOut = writeMarkdownFixPlan(result, { agent: opts.agent as FixPlanAgent });
    console.log(out);
    console.log(markdownOut);
    process.exitCode = result.exitCode;
  });

program
  .command("test-plan")
  .description("Write regression-test prompts for risky access lanes")
  .argument("[path]", "directory to scan", ".")
  .option("--offline", "skip npm registry and OSV network checks")
  .option("--agent <agent>", "target agent: codex | generic", "generic")
  .action(async (path: string, opts: { offline?: boolean; agent: string }) => {
    if (!assertChoice(opts.agent, TEST_PLAN_AGENTS, "agent")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const result = await scanAsync(path, { network: opts.offline ? "off" : "on" });
    const out = writeTestPlan(result, { agent: opts.agent as TestPlanAgent });
    console.log(out.jsonPath);
    console.log(out.markdownPath);
    process.exitCode = result.exitCode;
  });

program
  .command("learn")
  .description("Update local controls from vulnerability intelligence without uploading source")
  .option("--source <path-or-url>", "future rule/control bundle source")
  .action((opts: { source?: string }) => {
    console.log("SeamShield Learn");
    console.log("Status: local rule/control updates are not wired yet.");
    console.log("Privacy: no source code was read or uploaded.");
    if (opts.source) console.log(`Requested source: ${opts.source}`);
    process.exitCode = 0;
  });

program
  .command("selftest")
  .description("Run embedded local fixtures to verify the installed scanner without network calls")
  .action(runSelftest);

program
  .command("triage")
  .description("Persist current false-positive decisions into .seamshield/config.yaml")
  .argument("[path]", "directory to scan", ".")
  .option("--rule <rule-id>", "only suppress current findings from one rule")
  .option("--reason <text>", "suppression reason", "triaged false positive")
  .option("--include-block", "also suppress block findings", false)
  .option("--online", "include network-backed dependency intelligence")
  .action(
    (
      path: string,
      opts: { rule?: string; reason?: string; includeBlock?: boolean; online?: boolean },
    ) => writeTriageSuppressions(path, opts),
  );

program
  .command("offline")
  .description("Create or accept local-only Community handoff files")
  .addCommand(new Command("export")
    .description("Export a source-private scan and inventory handoff")
    .argument("[path]", "project directory", ".")
    .requiredOption("--out <file>", "local JSON output file")
    .action(async (path: string, opts: { out: string }) => {
      if (!existsSync(path)) { console.error(`seamshield: path not found: ${path}`); process.exitCode = 2; return; }
      writeFileSync(resolve(opts.out), `${await offlineExport(path, opts.out)}\n`);
      console.log(`Offline handoff written: ${resolve(opts.out)}`);
      console.log("Source upload: false · network: off");
    }))
  .addCommand(new Command("import")
    .description("Import a local-only scan handoff without network access")
    .argument("[path]", "project directory", ".")
    .requiredOption("--file <file>", "local handoff JSON file")
    .action((path: string, opts: { file: string }) => {
      try { console.log(`Offline handoff imported: ${offlineImport(path, opts.file)}`); console.log("Source upload: false · network: off"); } catch (error) { console.error(`seamshield: offline import failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 2; }
    }));

program
  .command("status")
  .description("Show local scan, connection, receipt, and next-action status")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json", "table")
  .action((path: string, opts: { format: string }) => {
    if (!assertChoice(opts.format, STATUS_FORMATS, "format")) return;
    if (!existsSync(path)) { console.error(`seamshield: path not found: ${path}`); process.exitCode = 2; return; }
    const report = buildStatusReport(path);
    console.log(opts.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderStatusTable(report));
  });

program
  .command("doctor")
  .description("Run a local Community SeamShield health check")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json", "table")
  .action((path: string, opts: { format: string }) => {
    if (!assertChoice(opts.format, STATUS_FORMATS, "format")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const report = buildDoctorReport(path);
    console.log(opts.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderDoctorTable(report));
    process.exitCode = report.status === "ok" ? 0 : 1;
  });

const release = program
  .command("release")
  .description("Release verification utilities for the official Community package");

release
  .command("verify")
  .description("Inspect package metadata, dry-run pack contents, and npm dist-tags before publish")
  .argument("[path]", "repo root", ".")
  .option("--format <format>", "output format: table | json", "table")
  .action((path: string, opts: { format: string }) => {
    if (!assertChoice(opts.format, STATUS_FORMATS, "format")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const report = buildReleaseVerifyReport(path);
    console.log(opts.format === "json" ? `${JSON.stringify(report, null, 2)}\n` : renderReleaseVerifyTable(report));
    process.exitCode = report.status === "ok" ? 0 : 1;
  });

program
  .command("agent-context")
  .description("Write SeamShield agent instructions for Codex, Claude, Cursor, Gemini, Cline, Windsurf, Copilot, or OpenCode")
  .argument("[path]", "project directory", ".")
  .option("--claude", "write CLAUDE.md", false)
  .option("--cursor", "write .cursor/rules/seamshield.mdc", false)
  .option("--codex", "write AGENTS.md", false)
  .option("--gemini", "write GEMINI.md", false)
  .option("--cline", "write .clinerules/seamshield.md", false)
  .option("--windsurf", "write .windsurf/rules/seamshield.md", false)
  .option("--copilot", "write .github/copilot-instructions.md", false)
  .option("--opencode", "write .opencode/AGENTS.md", false)
  .option("--all", "write all supported agent context files", false)
  .action((path: string, opts: Record<string, boolean | undefined>) => {
    const selected = [
      opts.claude ? "claude" : null,
      opts.cursor ? "cursor" : null,
      opts.codex ? "codex" : null,
      opts.gemini ? "gemini" : null,
      opts.cline ? "cline" : null,
      opts.windsurf ? "windsurf" : null,
      opts.copilot ? "copilot" : null,
      opts.opencode ? "opencode" : null,
    ].filter(Boolean) as ContextAgent[];
    if (opts.all && selected.length > 0) {
      console.error(`seamshield: choose --all or one agent context (${CONTEXT_AGENTS.join(", ")})`);
      process.exitCode = 2;
      return;
    }
    const target = resolve(path);
    const kinds = opts.all ? CONTEXT_AGENTS : [selected[0] ?? "codex"];
    for (const out of writeAgentContexts(target, kinds)) console.log(out);
  });

const guard = program
  .command("guard")
  .description("Claude Code guard utilities");

guard
  .command("check")
  .description("Read a Claude Code hook event from stdin and allow or deny")
  .action(guardCheck);

guard
  .command("install")
  .description("Install SeamShield Claude Code PreToolUse hooks")
  .argument("[path]", "project directory", ".")
  .action((path: string) => {
    console.log(installGuard(resolve(path)));
  });

guard
  .command("status")
  .description("Report SeamShield guard installation status")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json", "table")
  .action((path: string, opts: { format: string }) => {
    if (!assertChoice(opts.format, STATUS_FORMATS, "format")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const status = buildGuardStatus(path);
    console.log(opts.format === "json" ? `${JSON.stringify(status, null, 2)}\n` : renderGuardStatusTable(status));
    process.exitCode = 0;
  });

guard
  .command("sync")
  .description("Fetch a signed metadata-only project Guard policy")
  .argument("[path]", "project directory", ".")
  .requiredOption("--project-id <id>", "SeamShield project id (or SEAMSHIELD_PROJECT_ID)", process.env.SEAMSHIELD_PROJECT_ID)
  .option("--api-url <url>", "SeamShield backend base URL", process.env.SEAMSHIELD_API_URL || "")
  .action(async (path: string, opts: { projectId?: string; apiUrl: string }) => {
    try {
      if (!existsSync(path)) throw new Error(`path not found: ${path}`);
      console.log(await syncGuardPolicy(path, opts.projectId || "", opts.apiUrl));
      process.exitCode = 0;
    } catch (error) {
      console.error(`seamshield: guard sync failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 2;
    }
  });

const ci = program
  .command("ci")
  .description("CI enforcement utilities");

ci
  .command("install")
  .description("Install the detected provider's SeamShield Build and Guard pipeline")
  .argument("[path]", "project directory", ".")
  .option("--provider <provider>", "CI provider override")
  .option("--repository-id <id>", "immutable provider repository/project id")
  .option("--issuer <url>", "provider OIDC issuer")
  .option("--jwks-uri <url>", "provider OIDC JWKS endpoint")
  .option("--audience <audience>", "provider OIDC audience")
  .action((path: string, opts: { provider?: string; repositoryId?: string; issuer?: string; jwksUri?: string; audience?: string }) => {
    const target = resolve(path);
    if (!existsSync(target)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const connection = readLocalConnection(target);
    if (!connection?.project.id) {
      console.log(writeGithubAction(target));
      process.exitCode = 0;
    } else {
      const plan = buildCiPlan(target, { ciProvider: opts.provider, ciRepositoryId: opts.repositoryId, ciIssuer: opts.issuer, ciJwksUri: opts.jwksUri, ciAudience: opts.audience });
      const installed = installCiAutomation(target, { projectId: connection.project.id, apiUrl: connection.api_url, provider: plan.provider }, plan);
      console.log(installed.status === "configured" ? `${installed.provider}: configured` : installed.reason || `${installed.provider}: setup required`);
      process.exitCode = installed.status === "configured" ? 0 : 2;
    }
  });

ci
  .command("status")
  .description("Report SeamShield CI enforcement status")
  .argument("[path]", "project directory", ".")
  .option("--format <format>", "output format: table | json", "table")
  .action((path: string, opts: { format: string }) => {
    if (!assertChoice(opts.format, STATUS_FORMATS, "format")) return;
    if (!existsSync(path)) {
      console.error(`seamshield: path not found: ${path}`);
      process.exitCode = 2;
      return;
    }
    const status = buildCiStatus(path);
    console.log(opts.format === "json" ? `${JSON.stringify(status, null, 2)}\n` : renderCiStatusTable(status));
    process.exitCode = 0;
  });

const deploymentGate = program
  .command("deploy-gate")
  .description("Fail closed unless this exact deployment commit has a signed passing SeamShield receipt");

deploymentGate
  .command("verify")
  .description("Verify a signed Build and Guard receipt before a production deployment")
  .option("--project-id <id>", "SeamShield project id (or SEAMSHIELD_PROJECT_ID)", process.env.SEAMSHIELD_PROJECT_ID)
  .option("--commit <sha>", "commit being deployed (or SEAMSHIELD_DEPLOY_COMMIT)")
  .option("--branch <name>", "branch being deployed (or SEAMSHIELD_DEPLOY_BRANCH)")
  .option("--environment <name>", "deployment environment", "production")
  .option("--api-url <url>", "SeamShield backend base URL", process.env.SEAMSHIELD_API_URL || DEFAULT_CONNECTED_API_URL)
  .action(async (opts: { projectId?: string; commit?: string; environment: string; apiUrl: string }) => {
    try {
      await verifyDeploymentGate(opts);
      process.exitCode = 0;
    } catch (error) {
      console.error(`seamshield: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    }
  });

program.parse();
