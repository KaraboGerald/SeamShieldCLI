import type { Finding, ScanResult } from "../types.js";

function level(finding: Finding): "error" | "warning" | "note" {
  if (finding.finding.severity === "block" || finding.finding.severity === "high") {
    return "error";
  }
  if (finding.finding.severity === "warn") return "warning";
  return "note";
}

export function renderSarif(result: ScanResult): string {
  const ruleIds = [...new Set(result.findings.map((f) => f.finding.rule_id))].sort();
  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "SeamShield",
              informationUri: "https://seamshield.dev",
              semanticVersion: result.engineVersion,
              rules: ruleIds.map((id) => {
                const sample = result.findings.find((f) => f.finding.rule_id === id);
                return {
                  id,
                  shortDescription: { text: sample?.finding.title ?? id },
                  help: { text: sample?.finding.fix.summary ?? "" },
                };
              }),
            },
          },
          results: result.findings.map((finding) => ({
            ruleId: finding.finding.rule_id,
            level: level(finding),
            message: { text: `${finding.finding.title}: ${finding.finding.fix.summary}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: finding.finding.file },
                  region: { startLine: finding.finding.line },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}
