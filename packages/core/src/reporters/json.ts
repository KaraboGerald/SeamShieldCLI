import type { ScanResult } from "../types.js";

export function renderJson(result: ScanResult): string {
  const bySeverity: Record<string, number> = {};
  for (const f of result.findings) {
    bySeverity[f.finding.severity] = (bySeverity[f.finding.severity] ?? 0) + 1;
  }
  return JSON.stringify(
    {
      schema: "seamshield.findings/v1",
      engine: { name: "seamshield", version: result.engineVersion },
      policy_bundle_digest: result.policyBundleDigest,
      summary: {
        files_scanned: result.filesScanned,
        rules_loaded: result.rulesLoaded,
        findings_total: result.findings.length,
        by_severity: bySeverity,
      },
      findings: result.findings,
    },
    null,
    2,
  );
}
