import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { rulesDir as defaultRulesDir } from "@seamshield/rules";
import { isIgnored, isSuppressedByConfig, loadConfig } from "./config.js";
import { checkConvexPublicFunctions, checkConvexTenantBoundWrites } from "./convexAdapter.js";
import { checkHallucinatedPackages, checkKnownVulnerabilities } from "./dependencyChecks.js";
import { runAbsenceRule, runRegexRule } from "./engine.js";
import { checkEnvFileCommitted } from "./envFileCommitted.js";
import { checkNextServerActionTrustedClient } from "./nextAdapter.js";
import { checkNoLockfile, checkPackageManagerDrift } from "./noLockfile.js";
import { checkServerGroupedRouters, checkWebhookSignatureBoundary } from "./serverAdapter.js";
import { checkVercelConfig } from "./vercelAdapter.js";
import { loadRules } from "./loadRules.js";
import {
  SEVERITY_RANK,
  type FailOn,
  type Finding,
  type ScanContext,
  type ScanOptions,
  type ScanResult,
} from "./types.js";
import { FileCache, walk } from "./walker.js";

const corePkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version: string };

export function scan(target: string, options: ScanOptions = {}): ScanResult {
  const root = resolve(target);
  const { rules, policyBundleDigest } = loadRules(options.rulesDir ?? defaultRulesDir);
  const config = loadConfig(root);
  const ctx: ScanContext = { root, policyBundleDigest, engineVersion: corePkg.version };

  const files = walk(root).filter((f) => !isIgnored(f.rel, config.ignorePrefixes));
  const cache = new FileCache();

  let findings: Finding[] = [];
  for (const rule of rules) {
    if (config.disabledRules.has(rule.id)) continue;
    if (rule.check.type === "regex") {
      findings.push(...runRegexRule(rule, files, cache, ctx));
    } else if (rule.check.type === "absence") {
      findings.push(...runAbsenceRule(rule, files, cache, ctx));
    } else if (rule.check.builtin === "env-file-committed") {
      findings.push(...checkEnvFileCommitted(rule, ctx));
    } else if (rule.check.builtin === "no-lockfile") {
      findings.push(...checkNoLockfile(rule, ctx));
    } else if (rule.check.builtin === "package-manager-drift") {
      findings.push(...checkPackageManagerDrift(rule, ctx));
    } else if (rule.check.builtin === "convex-public-function-no-auth") {
      findings.push(...checkConvexPublicFunctions(rule, files, cache, ctx));
    } else if (rule.check.builtin === "convex-tenant-bound-write") {
      findings.push(...checkConvexTenantBoundWrites(rule, files, cache, ctx));
    } else if (rule.check.builtin === "next-server-action-trusted-client") {
      findings.push(...checkNextServerActionTrustedClient(rule, files, cache, ctx));
    } else if (rule.check.builtin === "server-grouped-router-boundary") {
      findings.push(...checkServerGroupedRouters(rule, files, cache, ctx));
    } else if (rule.check.builtin === "webhook-signature-boundary") {
      findings.push(...checkWebhookSignatureBoundary(rule, files, cache, ctx));
    } else if (rule.check.builtin === "vercel-config") {
      findings.push(...checkVercelConfig(rule, files, cache, ctx));
    } else if (
      rule.check.builtin === "hallucinated-package" ||
      rule.check.builtin === "known-vuln"
    ) {
      // Network-backed dependency checks are handled by scanAsync(). The sync
      // scanner remains deterministic for tests and editor guard hot paths.
      continue;
    } else {
      throw new Error(`${rule.id}: unknown builtin check "${rule.check.builtin}"`);
    }
  }

  // Builtin checks discover paths outside the walker, so config ignores are
  // applied to their findings here as well.
  findings = findings
    .filter((f) => !isIgnored(f.finding.file, config.ignorePrefixes))
    .filter(
      (f) =>
        !isSuppressedByConfig(
          f.finding.rule_id,
          f.finding.file,
          f.finding.line,
          config.suppressions,
        ),
    )
    .map((f) => refineFinding(f, cache, files));

  findings.sort(
    (a, b) =>
      SEVERITY_RANK[a.finding.severity] - SEVERITY_RANK[b.finding.severity] ||
      a.finding.file.localeCompare(b.finding.file) ||
      a.finding.line - b.finding.line ||
      a.finding.rule_id.localeCompare(b.finding.rule_id),
  );

  return {
    target: root,
    profile: options.profile ?? "community",
    findings,
    exitCode: computeExitCode(findings, options.failOn ?? "block"),
    filesScanned: files.length,
    rulesLoaded: rules.length,
    policyBundleDigest,
    engineVersion: corePkg.version,
    networkSkipped: true,
  };
}

export async function scanAsync(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const result = scan(target, options);
  if (options.network === "off") return result;

  const root = resolve(target);
  const { rules } = loadRules(options.rulesDir ?? defaultRulesDir);
  const config = loadConfig(root);
  const ctx: ScanContext = {
    root,
    policyBundleDigest: result.policyBundleDigest,
    engineVersion: result.engineVersion,
  };
  const files = walk(root).filter((f) => !isIgnored(f.rel, config.ignorePrefixes));
  const dependencyFindings: Finding[] = [];
  for (const rule of rules) {
    if (config.disabledRules.has(rule.id)) continue;
    if (rule.check.builtin === "hallucinated-package") {
      dependencyFindings.push(
        ...(await checkHallucinatedPackages(rule, ctx, files, {
          fetchImpl: options.fetchImpl,
          timeoutMs: options.networkTimeoutMs,
        })),
      );
    }
    if (rule.check.builtin === "known-vuln") {
      dependencyFindings.push(
        ...(await checkKnownVulnerabilities(rule, ctx, files, {
          fetchImpl: options.fetchImpl,
          timeoutMs: options.networkTimeoutMs,
        })),
      );
    }
  }

  result.findings = [...result.findings, ...dependencyFindings].filter(
    (f) =>
      !isIgnored(f.finding.file, config.ignorePrefixes) &&
      !isSuppressedByConfig(
        f.finding.rule_id,
        f.finding.file,
        f.finding.line,
        config.suppressions,
      ),
  );
  result.findings.sort(
    (a, b) =>
      SEVERITY_RANK[a.finding.severity] - SEVERITY_RANK[b.finding.severity] ||
      a.finding.file.localeCompare(b.finding.file) ||
      a.finding.line - b.finding.line ||
      a.finding.rule_id.localeCompare(b.finding.rule_id),
  );
  result.exitCode = computeExitCode(result.findings, options.failOn ?? "block");
  result.networkSkipped = false;
  return result;
}

function refineFinding(finding: Finding, cache: FileCache, files: { abs: string; rel: string }[]): Finding {
  if (finding.finding.rule_id !== "ss/auth/client-only-guard") return finding;
  const file = files.find((candidate) => candidate.rel === finding.finding.file);
  if (!file) return finding;
  const content = cache.read(file.abs);
  if (!content) return finding;
  const hasServerDataBoundary =
    /\b(?:fetch|axios|useQuery|useMutation|useAction|api\.|convex|server action|route\.ts|\/api\/)\b/i.test(
      content,
    );
  if (hasServerDataBoundary) return finding;
  return {
    ...finding,
    finding: { ...finding.finding, severity: "info" },
    decision: "scan",
  };
}

function computeExitCode(findings: Finding[], failOn: FailOn): number {
  if (failOn === "never") return 0;
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((f) => SEVERITY_RANK[f.finding.severity] <= threshold) ? 1 : 0;
}
