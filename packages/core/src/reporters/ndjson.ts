import { buildAccessMap } from "../access.js";
import { stableId } from "../ids.js";
import type { ScanResult } from "../types.js";

export function renderScanNdjson(result: ScanResult): string {
  const lines = result.findings.map((finding) =>
    JSON.stringify({
      record_type: "finding",
      record_id: stableId("finding", [
        finding.finding.rule_id,
        finding.finding.file,
        finding.finding.line,
        finding.finding.severity,
      ]),
      schema_version: "seamshield.findings/v1",
      scanner_name: "seamshield",
      scanner_version: result.engineVersion,
      profile: result.profile,
      target: result.target,
      finding,
    }),
  );
  lines.push(JSON.stringify(scanSummaryRecord(result)));
  return `${lines.join("\n")}\n`;
}

export function renderAccessNdjson(result: ScanResult): string {
  const access = buildAccessMap(result);
  const lines = access.lanes.map((lane) =>
    JSON.stringify({
      record_type: "access_lane",
      record_id: lane.lane_id,
      schema_version: "seamshield.access-map/v1",
      scanner_name: "seamshield",
      scanner_version: result.engineVersion,
      profile: result.profile,
      target: result.target,
      ...lane,
    }),
  );
  lines.push(JSON.stringify(scanSummaryRecord(result)));
  return `${lines.join("\n")}\n`;
}

function scanSummaryRecord(result: ScanResult) {
  const bySeverity: Record<string, number> = {};
  for (const f of result.findings) {
    bySeverity[f.finding.severity] = (bySeverity[f.finding.severity] ?? 0) + 1;
  }
  return {
    record_type: "scan_summary",
    schema_version: "seamshield.findings/v1",
    scanner_name: "seamshield",
    scanner_version: result.engineVersion,
    profile: result.profile,
    target: result.target,
    files_scanned: result.filesScanned,
    rules_loaded: result.rulesLoaded,
    findings_total: result.findings.length,
    by_severity: bySeverity,
    exit_code: result.exitCode,
    policy_bundle_digest: result.policyBundleDigest,
  };
}
