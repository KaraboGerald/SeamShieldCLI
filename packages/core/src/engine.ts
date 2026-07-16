import { randomUUID } from "node:crypto";
import { fileMatchesRule } from "./matchers.js";
import { redactSecret } from "./redact.js";
import type { Finding, Rule, ScanContext } from "./types.js";
import type { FileCache, WalkedFile } from "./walker.js";

export function buildFinding(
  rule: Rule,
  file: string,
  line: number,
  evidence: string,
  ctx: ScanContext,
): Finding {
  return {
    event_id: randomUUID(),
    event_type: "scan.finding",
    time: new Date().toISOString(),
    tenant: "local",
    decision: rule.severity === "block" ? "deny" : "scan",
    route: { plane: "evidence", lane: "cpu", reason: [rule.id] },
    engines: [{ name: "seamshield", version: ctx.engineVersion, role: "scanner" }],
    provenance: { policy_bundle_digest: ctx.policyBundleDigest },
    spans: [{ start: line, end: line, label: file, evidence }],
    finding: {
      rule_id: rule.id,
      severity: rule.severity,
      title: rule.title,
      file,
      line,
      fix: rule.fix,
    },
  };
}

const IGNORE_RE = /seamshield-ignore(?:[ \t]+([\w/,\- \t]+))?/;

/**
 * A finding is suppressed when the matched line, or the line directly above
 * it, carries `seamshield-ignore` (bare = all rules) or `seamshield-ignore
 * <rule-id>[, <rule-id>...]`.
 */
export function isSuppressed(lines: string[], index: number, ruleId: string): boolean {
  const candidates = [lines[index], index > 0 ? lines[index - 1] : undefined];
  for (const line of candidates) {
    if (!line) continue;
    const match = IGNORE_RE.exec(line);
    if (!match) continue;
    if (!match[1]) return true;
    if (match[1].split(/[\s,]+/).filter(Boolean).includes(ruleId)) return true;
  }
  return false;
}

export function runRegexRule(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  const patterns = rule.check.patterns ?? [];
  const gate = rule.check.file_contains ? new RegExp(rule.check.file_contains) : null;
  for (const file of files) {
    if (!fileMatchesRule(file, rule.check)) continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    if (gate && !gate.test(content)) continue;
    const lines = content.split(/\r?\n/);
    const matchedLines = new Set<number>();
    for (const pattern of patterns) {
      const re = new RegExp(pattern.regex);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line === undefined || matchedLines.has(i)) continue;
        const match = re.exec(line);
        if (!match) continue;
        if (isSuppressed(lines, i, rule.id)) continue;
        matchedLines.add(i);
        const evidence = rule.check.redact
          ? `${pattern.name}: ${redactSecret(match[0])}`
          : match[0].slice(0, 120);
        findings.push(buildFinding(rule, file.rel, i + 1, evidence, ctx));
      }
    }
  }
  return findings;
}

/**
 * Absence rules fire when a file in scope (include/exclude + file_contains
 * gate) contains NO line matching any pattern — e.g. an admin page with no
 * recognizable auth check. The finding is anchored to line 1. A
 * `seamshield-ignore <rule-id>` anywhere in the file suppresses it.
 */
export function runAbsenceRule(
  rule: Rule,
  files: WalkedFile[],
  cache: FileCache,
  ctx: ScanContext,
): Finding[] {
  const findings: Finding[] = [];
  const patterns = (rule.check.patterns ?? []).map((p) => new RegExp(p.regex));
  const gate = rule.check.file_contains ? new RegExp(rule.check.file_contains) : null;
  for (const file of files) {
    if (!fileMatchesRule(file, rule.check)) continue;
    const content = cache.read(file.abs);
    if (content === null) continue;
    if (gate && !gate.test(content)) continue;
    const lines = content.split(/\r?\n/);
    if (patterns.some((re) => lines.some((line) => re.test(line)))) continue;
    if (lines.some((_, i) => isSuppressed(lines, i, rule.id))) continue;
    findings.push(
      buildFinding(rule, file.rel, 1, "no recognized safeguard found in this file", ctx),
    );
  }
  return findings;
}
