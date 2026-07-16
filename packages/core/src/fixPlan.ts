import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildAccessMap } from "./access.js";
import type { AccessLane, Finding, ScanResult } from "./types.js";

export type FixPlanAgent = "claude" | "cursor" | "codex" | "generic";

function promptFor(finding: Finding): string {
  return [
    `### ${finding.finding.rule_id} (${finding.finding.severity})`,
    `File: ${finding.finding.file}:${finding.finding.line}`,
    `Issue: ${finding.finding.title}`,
    `Fix: ${finding.finding.fix.agent_prompt}`,
  ].join("\n");
}

function rulesForAgent(agent: FixPlanAgent): string[] {
  const base = [
    "Do not print, rename, commit, or expose secret values.",
    "Do not move server credentials into public/client env names.",
    "Do not weaken authentication, authorization, database rules, storage rules, or CORS.",
    "Preserve current user-facing behavior unless the risky access lane requires a safer boundary.",
    "Re-run `npx @seamshield/cli ship --offline` after changes.",
  ];
  if (agent === "codex") return [...base, "Use focused edits and run the repo's typecheck/tests before claiming done."];
  if (agent === "claude") return [...base, "Respect existing CLAUDE.md project instructions and tool hooks."];
  if (agent === "cursor") return [...base, "Respect existing Cursor rules and keep generated code inside the intended files."];
  return base;
}

function lanePrompt(lane: AccessLane): string {
  return [
    `## Issue`,
    `${lane.actor} can ${lane.permission} ${lane.asset} through ${lane.lane}.`,
    "",
    `Risk: ${lane.risk}`,
    `Condition: ${lane.condition}`,
    `Source: ${lane.source.file}:${lane.source.line} (${lane.source.rule_id})`,
    "",
    `## Goal`,
    lane.fix.summary,
    "",
    `## Steps`,
    lane.fix.agent_prompt,
  ].join("\n");
}

export function buildFixPlan(result: ScanResult, options: { agent?: FixPlanAgent } = {}) {
  const agent = options.agent ?? "generic";
  const access = buildAccessMap(result);
  const items = result.findings.map((finding) => ({
    rule_id: finding.finding.rule_id,
    severity: finding.finding.severity,
    title: finding.finding.title,
    file: finding.finding.file,
    line: finding.finding.line,
    evidence: finding.spans[0]?.evidence ?? "",
    fix: finding.finding.fix,
    agent_prompt: promptFor(finding),
  }));
  return {
    schema: "seamshield.fix-plan/v1",
    target: result.target,
    agent,
    policy_bundle_digest: result.policyBundleDigest,
    summary: { findings_total: result.findings.length, access_lanes_total: access.lanes.length },
    items,
    access_lanes: access.lanes,
    agent_markdown: [
      "# SeamShield Fix Plan",
      "",
      ...rulesForAgent(agent).map((rule) => `- ${rule}`),
      "",
      ...access.lanes.map(lanePrompt),
      "",
    ].join("\n"),
  };
}

export function writeFixPlan(result: ScanResult): string {
  const dir = join(result.target, ".seamshield");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "fix-plan.json");
  writeFileSync(path, `${JSON.stringify(buildFixPlan(result), null, 2)}\n`);
  return path;
}

function dateStamp(now = new Date()): string {
  return now.toISOString().slice(0, 10);
}

export function writeMarkdownFixPlan(
  result: ScanResult,
  options: { agent?: FixPlanAgent; now?: Date } = {},
): string {
  const dir = join(result.target, ".seamshield", "fix-plans");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${dateStamp(options.now)}-critical-access-risks.md`);
  writeFileSync(path, buildFixPlan(result, { agent: options.agent }).agent_markdown);
  return path;
}
