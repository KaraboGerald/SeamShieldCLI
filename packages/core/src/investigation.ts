import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildAccessMap, buildShipVerdict } from "./access.js";
import type { AccessLane, ScanResult, Severity } from "./types.js";

const SEVERITIES: Severity[] = ["block", "high", "warn", "info"];

function dateStamp(now = new Date()): string {
  return now.toISOString().slice(0, 10);
}

function countBy<T extends string>(items: AccessLane[], pick: (item: AccessLane) => T): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) counts[pick(item)] = (counts[pick(item)] ?? 0) + 1;
  return counts;
}

function table(counts: Record<string, number>): string[] {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (entries.length === 0) return ["_None._"];
  return ["| Item | Count |", "| --- | ---: |", ...entries.map(([key, value]) => `| \`${key}\` | ${value} |`)];
}

function laneLine(lane: AccessLane): string {
  return [
    `- \`${lane.severity}\` \`${lane.source.rule_id}\``,
    `  ${lane.actor} -> ${lane.lane} -> ${lane.asset} -> ${lane.permission}`,
    `  (${lane.condition}, ${lane.risk})`,
    `  at \`${lane.source.file}:${lane.source.line}\``,
  ].join(" ");
}

function checklistLine(lane: AccessLane): string {
  return [
    `- [ ] \`${lane.source.rule_id}\``,
    `at \`${lane.source.file}:${lane.source.line}\`:`,
    `verify ${lane.actor} cannot reach ${lane.asset} with ${lane.permission} unless the intended server-side condition is enforced.`,
  ].join(" ");
}

function rootCauseFor(lane: AccessLane): string {
  if (lane.risk.includes("secret")) return "secret exposure";
  if (lane.risk.includes("anonymous") || lane.risk.includes("trusted_client")) return "missing server-side authorization";
  if (lane.provider === "supabase" || lane.provider === "firebase") return "provider access policy";
  if (lane.provider === "convex") return "public backend function boundary";
  if (lane.provider === "vercel" || lane.provider === "deploy") return "deploy configuration boundary";
  if (lane.risk.includes("dependency") || lane.provider === "package") return "dependency supply-chain boundary";
  if (lane.provider === "agent") return "agent/tooling boundary";
  return "access boundary review";
}

function analystReport(critical: AccessLane[], warnings: AccessLane[], info: AccessLane[]): string[] {
  const lanes = [...critical, ...warnings, ...info];
  const rootCauses = countBy(lanes, rootCauseFor);
  return [
    "## Analyst Report",
    "",
    `Release decision: ${critical.length > 0 ? "block until critical lanes are fixed or explicitly accepted" : "no release blockers from the controls that ran"}.`,
    `Primary review focus: ${critical.length > 0 ? "critical lanes first, then warning clusters" : warnings.length > 0 ? "warning clusters and false-positive triage" : "informational hygiene"}.`,
    "",
    "Root-cause groups:",
    "",
    ...table(rootCauses),
    "",
    "Recommended analyst workflow:",
    "",
    "- Confirm whether each lane is reachable in production.",
    "- Confirm the enforcement point is server-side, provider-side, or internal-only.",
    "- Record false positives with narrow evidence; do not suppress whole rule families.",
    "- Re-run the ship check after code, config, provider-rule, or dependency changes.",
    "",
  ];
}

function evidenceTable(lanes: AccessLane[], limit: number): string[] {
  const shown = lanes.slice(0, limit);
  if (shown.length === 0) return ["## Evidence Table", "", "_None._", ""];
  const rows = shown.map((lane) =>
    [
      `\`${lane.severity}\``,
      `\`${lane.source.rule_id}\``,
      `\`${lane.provider}\``,
      `\`${rootCauseFor(lane)}\``,
      `\`${lane.actor} -> ${lane.asset} -> ${lane.permission}\``,
      `\`${lane.source.file}:${lane.source.line}\``,
    ].join(" | "),
  );
  return [
    "## Evidence Table",
    "",
    "| Severity | Rule | Provider | Root Cause | Lane | Location |",
    "| --- | --- | --- | --- | --- | --- |",
    ...rows.map((row) => `| ${row} |`),
    ...(lanes.length > shown.length ? [`| ... | ... | ... | ... | ${lanes.length - shown.length} more lane(s) not shown | ... |`] : []),
    "",
  ];
}

function verificationChecklist(critical: AccessLane[], warnings: AccessLane[]): string[] {
  const lanes = [...critical, ...warnings].slice(0, 20);
  return [
    "## Verification Checklist",
    "",
    ...(lanes.length > 0
      ? lanes.flatMap((lane) => [
          `- [ ] \`${lane.source.rule_id}\` at \`${lane.source.file}:${lane.source.line}\``,
          `  - Expected control: ${lane.actor} cannot ${lane.permission} ${lane.asset} unless \`${lane.condition}\` is true.`,
          "  - Evidence to attach: server/provider policy, middleware, internal function marker, route guard, or dependency lockfile proof.",
        ])
      : ["- [x] No block/high/warn access lanes require verification from the controls that ran."]),
    "- [ ] Re-run `seamshield ship . --offline` and keep the new investigation if the release decision changes.",
    "",
  ];
}

function remediationChecklist(critical: AccessLane[], warnings: AccessLane[], limit: number): string[] {
  const criticalShown = critical.slice(0, limit);
  const warningShown = warnings.slice(0, Math.min(limit, 20));
  return [
    "## Remediation Checklist",
    "",
    "### Release Blockers",
    "",
    ...(criticalShown.length > 0 ? criticalShown.map(checklistLine) : ["- [x] No block/high access lanes found by the controls that ran."]),
    ...(critical.length > criticalShown.length ? [`- [ ] Review ${critical.length - criticalShown.length} additional blocker(s) in the access map.`] : []),
    "",
    "### Warnings",
    "",
    ...(warningShown.length > 0 ? warningShown.map(checklistLine) : ["- [x] No warning access lanes found by the controls that ran."]),
    ...(warnings.length > warningShown.length ? [`- [ ] Review ${warnings.length - warningShown.length} additional warning(s) in the access map.`] : []),
    "",
    "### Before Shipping",
    "",
    "- [ ] Re-run `seamshield ship . --offline` after fixes.",
    "- [ ] Commit only intentional config or source changes; do not commit local secret files.",
    "- [ ] Keep this investigation with the remediation notes if it documents a release decision.",
    "",
  ];
}

function triagePrompts(): string[] {
  return [
    "## False-Positive Triage Prompts",
    "",
    "Use these prompts before suppressing a finding:",
    "",
    "- Is the file reachable in production, or is it test/demo/dead code?",
    "- Is access enforced on the server or provider side, not only in client UI state?",
    "- Is the secret/value actually public by design, or is it a credential with write/admin power?",
    "- Is the route, mutation, bucket, table, cron, or deploy endpoint intentionally public?",
    "- What evidence proves the lane is safe: middleware, provider rules, RLS policy, internal function marker, token check, or deployment boundary?",
    "",
    "When the answer is a confirmed false positive, add a narrow suppression:",
    "",
    "```bash",
    "seamshield triage . --rule <rule-id> --reason \"validated false positive: <evidence>\"",
    "```",
    "",
  ];
}

function copyPasteCommands(verdict: ReturnType<typeof buildShipVerdict>): string[] {
  const commands = [
    "## Copy-Paste Commands",
    "",
    "```bash",
    "seamshield access . --format table",
    "seamshield fix-plan . --agent codex --offline",
    "seamshield test-plan . --agent codex --offline",
    "seamshield ship . --offline",
    "```",
    "",
  ];
  if (verdict.verdict !== "SAFE TO SHIP") {
    commands.push(
      "For release blockers, start with:",
      "",
      "```bash",
      "seamshield access . --format json",
      "seamshield fix-plan . --agent codex --offline",
      "```",
      "",
    );
  }
  return commands;
}

function sectionFor(title: string, lanes: AccessLane[], limit: number): string[] {
  if (lanes.length === 0) return [`## ${title}`, "", "_None._", ""];
  const shown = lanes.slice(0, limit);
  const remaining = lanes.length - shown.length;
  return [
    `## ${title}`,
    "",
    ...shown.map(laneLine),
    ...(remaining > 0 ? [`- ... ${remaining} more not shown in this summary.`] : []),
    "",
  ];
}

export function renderInvestigationMarkdown(
  result: ScanResult,
  options: { now?: Date; itemLimit?: number } = {},
): string {
  const access = buildAccessMap(result);
  const verdict = buildShipVerdict(result);
  const lanes = access.lanes;
  const limit = options.itemLimit ?? 80;
  const bySeverity = countBy(lanes, (lane) => lane.severity);
  const byProvider = countBy(lanes, (lane) => lane.provider);
  const byRisk = countBy(lanes, (lane) => lane.risk);
  const critical = lanes.filter((lane) => lane.severity === "block" || lane.severity === "high");
  const warnings = lanes.filter((lane) => lane.severity === "warn");
  const info = lanes.filter((lane) => lane.severity === "info");

  return [
    "# SeamShield Investigation",
    "",
    `Date: ${dateStamp(options.now)}`,
    `Target: \`${result.target}\``,
    `Verdict: **${verdict.verdict}**`,
    `Policy bundle: \`${result.policyBundleDigest}\``,
    "",
    "## What This Means",
    "",
    verdict.verdict === "SAFE TO SHIP"
      ? "No block or high unsafe-to-ship access lanes were found by the controls that ran. Warnings still deserve triage."
      : "One or more block/high access lanes were found. Treat these as release blockers until fixed or explicitly triaged.",
    "",
    "SeamShield reports access-lane risk. It does not claim that the whole app has no vulnerabilities.",
    "",
    ...copyPasteCommands(verdict),
    "## Summary",
    "",
    `- Files scanned: ${result.filesScanned}`,
    `- Rules loaded: ${result.rulesLoaded}`,
    `- Findings: ${result.findings.length}`,
    `- Access lanes: ${lanes.length}`,
    "",
    "### By Severity",
    "",
    ...table(Object.fromEntries(SEVERITIES.map((severity) => [severity, bySeverity[severity] ?? 0]))),
    "",
    "### By Provider",
    "",
    ...table(byProvider),
    "",
    "### By Risk",
    "",
    ...table(byRisk),
    "",
    ...analystReport(critical, warnings, info),
    ...evidenceTable(lanes, Math.min(limit, 50)),
    ...remediationChecklist(critical, warnings, limit),
    ...verificationChecklist(critical, warnings),
    ...triagePrompts(),
    ...sectionFor("Critical Access Lanes", critical, limit),
    ...sectionFor("Warnings To Triage", warnings, limit),
    ...sectionFor("Informational Findings", info, Math.min(limit, 30)),
    "## Suggested Next Steps",
    "",
    "- Run `seamshield access --format table` to inspect normalized lanes.",
    "- Run `seamshield fix-plan --agent codex` to generate provider-aware remediation prompts.",
    "- Use `seamshield triage --rule <rule-id>` only after validating a false positive or accepted risk.",
    "",
  ].join("\n");
}

export function writeInvestigationMarkdown(
  result: ScanResult,
  options: { now?: Date; itemLimit?: number } = {},
): string {
  const dir = join(result.target, ".seamshield", "investigations");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${dateStamp(options.now)}-access-lanes.md`);
  writeFileSync(path, renderInvestigationMarkdown(result, options));
  return path;
}
