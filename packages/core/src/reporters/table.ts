import pc from "picocolors";
import type { ScanResult, Severity } from "../types.js";

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  block: (s) => pc.red(s),
  high: (s) => pc.magenta(s),
  warn: (s) => pc.yellow(s),
  info: (s) => pc.dim(s),
};

export function renderTable(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(
    `${pc.bold(`SeamShield v${result.engineVersion}`)}${pc.dim(
      ` — ${result.filesScanned} files, ${result.rulesLoaded} rules`,
    )}`,
  );
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(pc.green("✓ No findings."));
  } else {
    for (const f of result.findings) {
      const sev = SEVERITY_COLOR[f.finding.severity](
        f.finding.severity.toUpperCase().padEnd(5),
      );
      lines.push(`${sev} ${f.finding.rule_id}  ${pc.bold(`${f.finding.file}:${f.finding.line}`)}`);
      lines.push(`      ${f.finding.title}`);
      const evidence = f.spans[0]?.evidence;
      if (evidence) lines.push(pc.dim(`      evidence: ${evidence}`));
      lines.push(`      ${pc.cyan("fix:")} ${f.finding.fix.summary}`);
      lines.push("");
    }
    const counts = new Map<Severity, number>();
    for (const f of result.findings) {
      counts.set(f.finding.severity, (counts.get(f.finding.severity) ?? 0) + 1);
    }
    const parts = [...counts.entries()].map(([sev, n]) => SEVERITY_COLOR[sev](`${n} ${sev}`));
    lines.push(`${pc.bold(`${result.findings.length} findings`)} (${parts.join(", ")})`);
  }

  lines.push(pc.dim(`policy bundle ${result.policyBundleDigest.slice(0, 12)}`));
  return lines.join("\n");
}
