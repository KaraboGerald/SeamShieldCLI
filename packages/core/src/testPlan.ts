import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildAccessMap } from "./access.js";
import type { AccessLane, ScanResult } from "./types.js";

export type TestPlanAgent = "codex" | "generic";

interface TestCase {
  rule_id: string;
  severity: AccessLane["severity"];
  provider: string;
  risk: AccessLane["risk"];
  file: string;
  line: number;
  title: string;
  test_type: string;
  assertion: string;
  suggested_location: string;
  agent_prompt: string;
}

function dateStamp(now = new Date()): string {
  return now.toISOString().slice(0, 10);
}

function suggestedLocation(lane: AccessLane): string {
  if (lane.provider === "convex") return "convex/**/*.test.ts or the repo's Convex function test harness";
  if (lane.provider === "vercel" || lane.lane === "deploy_config") return "tests/deploy-config.test.ts";
  if (lane.provider === "supabase") return "tests/database-policy.test.ts";
  if (lane.provider === "firebase") return "tests/firestore-rules.test.ts";
  if (lane.provider === "agent") return "tests/agent-guard.test.ts";
  if (lane.provider === "self-hosted") return "tests/server-routes.test.ts";
  if (lane.provider === "nextjs" || lane.provider === "web") return "tests/access-routes.test.ts";
  if (lane.provider === "dependency") return "tests/dependency-policy.test.ts";
  return "tests/seamshield-access.test.ts";
}

function testType(lane: AccessLane): string {
  if (lane.risk.includes("secret")) return "secret-boundary regression";
  if (lane.risk === "anonymous_write" || lane.risk === "public_database_access") return "unauthenticated write denial";
  if (lane.risk === "anonymous_execute") return "unauthenticated route denial";
  if (lane.risk === "client_to_admin" || lane.risk === "untrusted_admin_surface") return "server-side authorization";
  if (lane.risk === "dependency_to_shell" || lane.lane === "package_install") return "dependency policy";
  if (lane.risk === "cors_credential_theft") return "CORS policy";
  return "access-lane regression";
}

function assertionFor(lane: AccessLane): string {
  if (lane.risk === "client_to_server_secret") {
    return "Client bundles and NEXT_PUBLIC/public env surfaces must not contain server credentials or secret-like values.";
  }
  if (lane.risk === "server_secret_exposure") {
    return "Secrets are loaded from the server environment or secret manager and are never hardcoded or committed.";
  }
  if (lane.risk === "agent_to_secret") {
    return "Agent instructions, MCP config, and dotenv changes do not expose secrets or grant broad secret access.";
  }
  if (lane.risk === "public_database_access") {
    return "Anonymous callers cannot read or write private database records; ownership/tenant policy is enforced.";
  }
  if (lane.risk === "public_storage_access") {
    return "Anonymous callers cannot write private storage objects; ownership/tenant policy is enforced.";
  }
  if (lane.risk === "anonymous_write") {
    return "Public mutations/actions reject unauthenticated callers or are explicitly safe, rate-limited, and side-effect bounded.";
  }
  if (lane.risk === "anonymous_execute") {
    return "Protected routes reject unauthenticated callers or require a valid signed webhook/API credential.";
  }
  if (lane.risk === "client_to_admin" || lane.risk === "untrusted_admin_surface") {
    return "Admin actions and pages require server-side authentication plus role or tenant authorization.";
  }
  if (lane.risk === "deploy_secret_exposure") {
    return "Deploy config does not expose secret env vars, privileged routes, or public admin surfaces.";
  }
  if (lane.risk === "dependency_to_shell") {
    return "Dependency changes cannot add install-time shell execution without explicit review.";
  }
  if (lane.risk === "known_vulnerable_dependency") {
    return "Known vulnerable dependency versions are rejected or pinned to a reviewed patched version.";
  }
  if (lane.risk === "unknown_package") {
    return "New dependencies resolve to real maintained packages before install or commit.";
  }
  if (lane.risk === "unreproducible_dependency") {
    return "The project keeps a lockfile so installs are reproducible.";
  }
  if (lane.risk === "cors_credential_theft") {
    return "Credentialed CORS responses never use wildcard origins.";
  }
  return "The risky access lane is covered by a regression test that fails if reopened.";
}

function promptFor(lane: AccessLane, agent: TestPlanAgent): string {
  const prefix =
    agent === "codex"
      ? "Add the smallest focused regression test using this repo's existing test framework."
      : "Add a focused regression test using the repo's existing test framework.";
  return [
    prefix,
    `Risk: ${lane.risk}`,
    `Source: ${lane.source.file}:${lane.source.line} (${lane.source.rule_id})`,
    `Expected assertion: ${assertionFor(lane)}`,
    "Do not expose secret values in fixtures, snapshots, logs, or test names.",
  ].join(" ");
}

function caseFor(lane: AccessLane, agent: TestPlanAgent): TestCase {
  return {
    rule_id: lane.source.rule_id,
    severity: lane.severity,
    provider: lane.provider,
    risk: lane.risk,
    file: lane.source.file,
    line: lane.source.line,
    title: lane.source.title,
    test_type: testType(lane),
    assertion: assertionFor(lane),
    suggested_location: suggestedLocation(lane),
    agent_prompt: promptFor(lane, agent),
  };
}

function markdownCase(item: TestCase): string {
  return [
    `## ${item.rule_id} (${item.severity})`,
    "",
    `Source: \`${item.file}:${item.line}\``,
    `Provider: \`${item.provider}\``,
    `Risk: \`${item.risk}\``,
    `Test type: ${item.test_type}`,
    `Suggested location: \`${item.suggested_location}\``,
    "",
    "Assertion:",
    "",
    `- ${item.assertion}`,
    "",
    "Agent prompt:",
    "",
    "```txt",
    item.agent_prompt,
    "```",
    "",
  ].join("\n");
}

export function buildTestPlan(result: ScanResult, options: { agent?: TestPlanAgent } = {}) {
  const agent = options.agent ?? "generic";
  const access = buildAccessMap(result);
  const critical = access.lanes.filter((lane) => lane.severity === "block" || lane.severity === "high");
  const warnings = access.lanes.filter((lane) => lane.severity === "warn");
  const cases = [...critical, ...warnings].map((lane) => caseFor(lane, agent));

  return {
    schema: "seamshield.test-plan/v1",
    target: result.target,
    agent,
    policy_bundle_digest: result.policyBundleDigest,
    summary: {
      access_lanes_total: access.lanes.length,
      test_cases_total: cases.length,
      critical_cases_total: critical.length,
      warning_cases_total: warnings.length,
    },
    cases,
    agent_markdown: [
      "# SeamShield Test Plan",
      "",
      "Add regression coverage for the access lanes SeamShield found. These tests should prove the lane stays closed after the fix.",
      "",
      "- Do not include real secrets in tests.",
      "- Prefer the repo's existing test runner, helpers, and fixtures.",
      "- Cover server-side authorization, database/storage policies, deploy config, agent guardrails, and dependency policy where applicable.",
      "- Re-run `npx @seamshield/cli ship --offline` after tests and fixes.",
      "",
      cases.length === 0 ? "_No block, high, or warning access lanes need regression tests._" : cases.map(markdownCase).join("\n"),
      "",
    ].join("\n"),
  };
}

export function writeTestPlan(
  result: ScanResult,
  options: { agent?: TestPlanAgent; now?: Date } = {},
): { jsonPath: string; markdownPath: string } {
  const root = join(result.target, ".seamshield");
  const markdownDir = join(root, "test-plans");
  mkdirSync(markdownDir, { recursive: true });
  const plan = buildTestPlan(result, { agent: options.agent });
  const jsonPath = join(root, "test-plan.json");
  const markdownPath = join(markdownDir, `${dateStamp(options.now)}-access-regression-tests.md`);
  writeFileSync(jsonPath, `${JSON.stringify(plan, null, 2)}\n`);
  writeFileSync(markdownPath, plan.agent_markdown);
  return { jsonPath, markdownPath };
}
