import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const cliPath = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fixtureDir = fileURLToPath(
  new URL("../../../examples/vulnerable-next-app", import.meta.url),
);
const providerFixtureDir = fileURLToPath(
  new URL("../../../examples/community-provider-fixtures", import.meta.url),
);
const corePackageDir = fileURLToPath(new URL("../../core", import.meta.url));
const cliPackageDir = fileURLToPath(new URL("..", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

function runCli(args: string[]) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: "utf8" });
}

function runCliEnv(args: string[], env: Record<string, string>) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
}

function runCliWithInput(args: string[], input: string) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: "utf8", input });
}

const tempDirs: string[] = [];
function tempProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "seamshield-cli-"));
  tempDirs.push(dir);
  writeFileSync(join(dir, "package.json"), `{"name":"x"}\n`);
  writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("seamshield scan (built CLI)", () => {
  it("ships the repository connection command in the built artifact", () => {
    const result = runCli(["--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("connect [options] [path]");
    expect(result.stdout).toContain("sync [options] [path]");
  });

  it("covers the Community provider fixtures", () => {
    const result = runCli(["scan", providerFixtureDir, "--format", "json", "--offline", "--no-investigation"]);
    expect(result.status).toBe(1);
    const parsed = JSON.parse(result.stdout) as { findings: Array<{ finding?: { rule_id?: string }; rule_id?: string }> };
    const rules = new Set(parsed.findings.map((item) => item.finding?.rule_id || item.rule_id));
    for (const rule of [
      "ss/convex/mutation-no-auth",
      "ss/vercel/config-access-risk",
      "ss/firebase/open-rules",
      "ss/supabase/permissive-policy",
      "ss/server/route-no-auth",
    ]) expect(rules.has(rule)).toBe(true);
  });

  it("provides local status and offline handoff commands", () => {
    const dir = tempProject();
    const status = runCli(["status", dir, "--format", "json"]);
    expect(status.status).toBe(0);
    expect(JSON.parse(status.stdout).next).toContain("seamshield init");
    const handoff = join(dir, "handoff.json");
    const exported = runCli(["offline", "export", dir, "--out", handoff]);
    expect(exported.status).toBe(0);
    expect(JSON.parse(readFileSync(handoff, "utf8")).schema).toBe("seamshield.offline-handoff/v1");
    const imported = runCli(["offline", "import", dir, "--file", handoff]);
    expect(imported.status).toBe(0);
    expect(existsSync(join(dir, ".seamshield", "offline-handoff.json"))).toBe(true);
  }, 120_000);

  it("does not include duplicate iCloud-generated rule files in the package artifact", () => {
    const ruleFiles = readdirSync(join(cliPackageDir, "rules"));
    expect(ruleFiles.filter((file) => / 2\.ya?ml$/.test(file))).toEqual([]);
  });

  it("scans the seeded fixture: 17 findings (8 block), exit 1, valid JSON", () => {
    const result = runCli(["scan", fixtureDir, "--format", "json", "--offline", "--no-investigation"]);
    expect(result.status).toBe(1);
    const parsed = JSON.parse(result.stdout) as {
      schema: string;
      summary: { findings_total: number; by_severity: Record<string, number> };
      policy_bundle_digest: string;
    };
    expect(parsed.schema).toBe("seamshield.findings/v1");
    expect(parsed.summary.findings_total).toBe(17);
    expect(parsed.summary.by_severity["block"]).toBe(8);
    expect(parsed.policy_bundle_digest).toMatch(/^[a-f0-9]{64}$/);
  }, 120_000);

  it("self-scan of packages/core exits 0", () => {
    const result = runCli(["scan", corePackageDir, "--offline", "--no-investigation"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("No findings");
  });

  it("renders a table by default with rule ids and fix lines", () => {
    const result = runCli(["scan", fixtureDir, "--offline", "--no-investigation"]);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("ss/secrets/hardcoded-provider-key");
    expect(result.stdout).toContain("fix:");
  });

  it("exits 2 on a missing path and bad flags", () => {
    expect(runCli(["scan", "/nonexistent/definitely-not-here"]).status).toBe(2);
    expect(runCli(["scan", ".", "--format", "xml", "--no-investigation"]).status).toBe(2);
    expect(runCli(["scan", ".", "--fail-on", "sometimes", "--no-investigation"]).status).toBe(2);
  });

  it("respects --fail-on never on the fixture", () => {
    expect(runCli(["scan", fixtureDir, "--fail-on", "never", "--offline", "--no-investigation"]).status).toBe(0);
  });

  it("renders SARIF", () => {
    const result = runCli(["scan", fixtureDir, "--format", "sarif", "--offline", "--no-investigation"]);
    expect(result.status).toBe(1);
    const parsed = JSON.parse(result.stdout) as { version: string; runs: unknown[] };
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs).toHaveLength(1);
  });

  it("renders scan findings as NDJSON with a final scan summary", () => {
    const result = runCli(["scan", fixtureDir, "--format", "ndjson", "--offline", "--no-investigation"]);
    expect(result.status).toBe(1);
    const lines = result.stdout.trim().split("\n").map((line) => JSON.parse(line));
    expect(lines[0]).toEqual(expect.objectContaining({ record_type: "finding", record_id: expect.stringMatching(/^finding:/) }));
    expect(lines.at(-1)).toEqual(expect.objectContaining({ record_type: "scan_summary", findings_total: 17 }));
  }, 120_000);

  it("writes a markdown investigation by default and supports opt-out", () => {
    const dir = tempProject();
    writeFileSync(join(dir, "index.ts"), `const k = "sk_live_${"I".repeat(24)}";\n`);

    const scan = runCli(["scan", dir, "--offline"]);
    expect(scan.status).toBe(1);
    expect(scan.stderr).toContain("Investigation written:");
    const investigation = join(dir, ".seamshield", "investigations");
    const path = join(investigation, `${new Date().toISOString().slice(0, 10)}-access-lanes.md`);
    expect(existsSync(path)).toBe(true);
    const markdown = readFileSync(path, "utf8");
    expect(markdown).toContain("# SeamShield Investigation");
    expect(markdown).toContain("Verdict: **UNSAFE TO SHIP**");
    expect(markdown).toContain("ss/secrets/hardcoded-provider-key");
    expect(markdown).toContain("## Remediation Checklist");
    expect(markdown).toContain("## Analyst Report");
    expect(markdown).toContain("## Evidence Table");
    expect(markdown).toContain("## Verification Checklist");
    expect(markdown).toContain("## False-Positive Triage Prompts");
    expect(markdown).toContain("## Copy-Paste Commands");
    expect(markdown).toContain("seamshield fix-plan . --agent codex --offline");
    expect(markdown).toContain("seamshield triage . --rule <rule-id>");
    expect(markdown).not.toContain(`sk_live_${"I".repeat(24)}`);

    rmSync(join(dir, ".seamshield"), { recursive: true, force: true });
    const optedOut = runCli(["scan", dir, "--offline", "--no-investigation"]);
    expect(optedOut.stderr).not.toContain("Investigation written:");
    expect(existsSync(path)).toBe(false);
  });

  it("writes an investigation from the explicit investigate command", () => {
    const dir = tempProject();
    writeFileSync(join(dir, "index.ts"), `const k = "sk_live_${"J".repeat(24)}";\n`);

    const result = runCli(["investigate", dir]);
    expect(result.status).toBe(0);
    const out = result.stdout.trim();
    expect(out).toContain(".seamshield/investigations/");
    const markdown = readFileSync(out, "utf8");
    expect(markdown).toContain("SeamShield reports access-lane risk");
    expect(markdown).toContain("Root-cause groups");
    expect(markdown).toContain("Use these prompts before suppressing a finding");
  });

  it("writes a local audit bundle with structured findings", () => {
    const dir = tempProject();
    const secret = `sk_live_${"A".repeat(24)}`;
    writeFileSync(join(dir, "index.ts"), `const k = "${secret}";\n`);

    const outDir = join(dir, ".seamshield", "audits", "test-audit");
    const result = runCli(["audit", dir, "--out", outDir]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("SeamShield Audit");
    expect(result.stdout).toContain("Source upload: no");
    for (const file of ["architecture.md", "REPORT.md", "FINDINGS-DETAIL.md", "findings.json", "report-schema.json"]) {
      expect(existsSync(join(outDir, file))).toBe(true);
    }
    const report = readFileSync(join(outDir, "REPORT.md"), "utf8");
    expect(report).toContain("This audit reports access-lane risk.");
    const findingsText = readFileSync(join(outDir, "findings.json"), "utf8");
    expect(findingsText).not.toContain(secret);
    const findings = JSON.parse(findingsText) as Array<{ verdict: string; trace: unknown[]; seamshield: { source_upload: boolean } }>;
    expect(findings[0]?.verdict).toBe("confirmed");
    expect(findings[0]?.trace.length).toBeGreaterThanOrEqual(2);
    expect(findings[0]?.seamshield.source_upload).toBe(false);
  });

  it("renders audit command metadata as JSON", () => {
    const dir = tempProject();
    writeFileSync(join(dir, "index.ts"), `const k = "sk_live_${"B".repeat(24)}";\n`);
    const outDir = join(dir, ".seamshield", "audits", "json-audit");
    const result = runCli(["audit", dir, "--out", outDir, "--format", "json"]);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as {
      schema: string;
      source_upload: boolean;
      files: Record<string, string>;
      findings_total: number;
    };
    expect(parsed.schema).toBe("seamshield.audit/v1");
    expect(parsed.source_upload).toBe(false);
    expect(parsed.findings_total).toBeGreaterThan(0);
    expect(parsed.files.findings).toBe(join(outDir, "findings.json"));
    expect(runCli(["audit", dir, "--format", "xml"]).status).toBe(2);
  });

  it("renders a privacy report without scanning or uploading source", () => {
    const dir = tempProject();
    const result = runCli(["privacy", dir]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("SeamShield Privacy Report");
    expect(result.stdout).toContain("Source upload: no");
    expect(result.stdout).toContain("Community scanning does not upload source code or findings.");
    expect(result.stdout).toContain("scan, fix-plan, and test-plan use network dependency checks unless --offline is passed");
    expect(result.stdout).toContain(".seamshield/test-plan.json and .seamshield/test-plans/*.md for test-plan");
    expect(result.stdout).toContain("Automatic untrusted updates: no");
  });

  it("renders a privacy report as JSON", () => {
    const dir = tempProject();
    const result = runCli(["privacy", dir, "--format", "json"]);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as {
      schema: string;
      tier: string;
      source_upload: boolean;
      default_network: string;
      static_scan: { uploads_source: boolean };
      files_written: string[];
      commercial_boundary: { pro: string; enterprise: string };
    };
    expect(parsed.schema).toBe("seamshield.privacy/v1");
    expect(parsed.tier).toBe("Community");
    expect(parsed.source_upload).toBe(false);
    expect(parsed.default_network).toContain("test-plan use network dependency checks unless --offline is passed");
    expect(parsed.static_scan.uploads_source).toBe(false);
    expect(parsed.files_written).toContain(".seamshield/test-plan.json and .seamshield/test-plans/*.md for test-plan");
    expect(parsed.commercial_boundary.pro).toContain("100k MAU");
    expect(parsed.commercial_boundary.enterprise).toContain("usage-based SeamShield Auth");
    expect(runCli(["privacy", dir, "--format", "xml"]).status).toBe(2);
  });

  it("writes a fix plan", () => {
    const dir = tempProject();
    writeFileSync(join(dir, "index.ts"), `const k = "sk_live_${"D".repeat(24)}";\n`);
    const result = runCli(["fix-plan", dir, "--offline", "--agent", "codex"]);
    expect(result.status).toBe(1);
    const path = join(dir, ".seamshield", "fix-plan.json");
    expect(existsSync(path)).toBe(true);
    const markdownDir = join(dir, ".seamshield", "fix-plans");
    const parsed = JSON.parse(readFileSync(path, "utf8")) as {
      schema: string;
      agent: string;
      items: Array<{ rule_id: string }>;
      agent_markdown: string;
    };
    expect(parsed.schema).toBe("seamshield.fix-plan/v1");
    expect(parsed.agent).toBe("codex");
    expect(parsed.items[0]?.rule_id).toBe("ss/secrets/hardcoded-provider-key");
    expect(parsed.agent_markdown).toContain("SeamShield Fix Plan");
    expect(existsSync(markdownDir)).toBe(true);
  });

  it("writes a test plan", () => {
    const dir = tempProject();
    writeFileSync(join(dir, "index.ts"), `const k = "sk_live_${"K".repeat(24)}";\n`);
    const result = runCli(["test-plan", dir, "--offline", "--agent", "codex"]);
    expect(result.status).toBe(1);
    const path = join(dir, ".seamshield", "test-plan.json");
    const markdownDir = join(dir, ".seamshield", "test-plans");
    expect(existsSync(path)).toBe(true);
    const parsed = JSON.parse(readFileSync(path, "utf8")) as {
      schema: string;
      agent: string;
      cases: Array<{ rule_id: string; assertion: string; suggested_location: string; agent_prompt: string }>;
      agent_markdown: string;
    };
    expect(parsed.schema).toBe("seamshield.test-plan/v1");
    expect(parsed.agent).toBe("codex");
    expect(parsed.cases[0]?.rule_id).toBe("ss/secrets/hardcoded-provider-key");
    expect(parsed.cases[0]?.assertion).toContain("Secrets are loaded from the server environment");
    expect(parsed.cases[0]?.suggested_location).toContain("seamshield-access");
    expect(parsed.cases[0]?.agent_prompt).toContain("Do not expose secret values");
    expect(parsed.agent_markdown).toContain("SeamShield Test Plan");
    expect(existsSync(markdownDir)).toBe(true);
    expect(runCli(["test-plan", dir, "--agent", "claude"]).status).toBe(2);
  });

  it("renders ship and access commands from normalized lanes", () => {
    const ship = runCli(["ship", fixtureDir]);
    expect(ship.status).toBe(1);
    expect(ship.stdout).toContain("SeamShield Ship Check");
    expect(ship.stdout).toContain("UNSAFE TO SHIP");
    expect(runCli(["ship", fixtureDir, "--offline"]).status).toBe(1);

    const access = runCli(["access", fixtureDir, "--format", "json"]);
    expect(access.status).toBe(0);
    const parsed = JSON.parse(access.stdout) as {
      schema: string;
      lanes: Array<{ lane_id: string; actor: string; risk: string; provider: string }>;
    };
    expect(parsed.schema).toBe("seamshield.access-map/v1");
    expect(parsed.lanes[0]?.lane_id).toMatch(/^lane:[a-f0-9]{16}$/);
    expect(parsed.lanes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ actor: "public_user", provider: "convex" }),
        expect.objectContaining({ risk: "client_to_server_secret" }),
      ]),
    );

    const accessNdjson = runCli(["access", fixtureDir, "--format", "ndjson"]);
    expect(accessNdjson.status).toBe(0);
    const lines = accessNdjson.stdout.trim().split("\n").map((line) => JSON.parse(line));
    expect(lines[0]).toEqual(expect.objectContaining({ record_type: "access_lane", lane_id: expect.stringMatching(/^lane:/) }));
    expect(lines.at(-1)).toEqual(expect.objectContaining({ record_type: "scan_summary" }));
  });

  it("renders read-only inventory in JSON and NDJSON", () => {
    const dir = tempProject();
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { db: { env: { API_KEY: "secret" } } } }));

    const json = runCli(["inventory", dir, "--format", "json"]);
    expect(json.status).toBe(0);
    const parsed = JSON.parse(json.stdout) as { schema: string; components: Array<{ ecosystem: string }> };
    expect(parsed.schema).toBe("seamshield.inventory/v1");
    expect(parsed.components).toEqual(expect.arrayContaining([expect.objectContaining({ ecosystem: "npm" })]));
    expect(json.stdout).not.toContain("secret");

    const ndjson = runCli(["inventory", dir, "--format", "ndjson"]);
    expect(ndjson.status).toBe(0);
    const lines = ndjson.stdout.trim().split("\n").map((line) => JSON.parse(line));
    expect(lines[0]).toEqual(expect.objectContaining({ record_type: "inventory_component" }));
    expect(lines.at(-1)).toEqual(expect.objectContaining({ record_type: "inventory_summary" }));
  });

  it("runs the built-in selftest without network", () => {
    const result = runCli(["selftest"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("selftest OK");
  });

  it("accepts known profiles and rejects invalid profiles", () => {
    const dir = tempProject();
    expect(runCli(["scan", dir, "--profile", "community", "--offline", "--no-investigation"]).status).toBe(0);
    expect(runCli(["inventory", dir, "--profile", "community"]).status).toBe(0);
    expect(runCli(["scan", dir, "--profile", "galaxy", "--offline", "--no-investigation"]).status).toBe(2);
    expect(runCli(["inventory", dir, "--profile", "galaxy"]).status).toBe(2);
  });

  it("initializes a repo with config, agents, guard, CI, and first investigation", () => {
    const dir = tempProject();
    const result = runCli(["init", dir]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("SeamShield Init");
    expect(result.stdout).toContain("SAFE TO SHIP");
    expect(readFileSync(join(dir, ".seamshield", "config.yaml"), "utf8")).toContain("node_modules/**");
    expect(readFileSync(join(dir, "AGENTS.md"), "utf8")).toContain("@seamshield/cli ship");
    expect(readFileSync(join(dir, "CLAUDE.md"), "utf8")).toContain("# SEAMSHIELD");
    expect(readFileSync(join(dir, ".cursor", "rules", "seamshield.mdc"), "utf8")).toContain(
      "# SEAMSHIELD",
    );
    expect(readFileSync(join(dir, ".claude", "settings.json"), "utf8")).toContain("guard check");
    expect(readFileSync(join(dir, ".github", "workflows", "seamshield.yml"), "utf8")).toContain(
      "npx @seamshield/cli ship . --offline",
    );
    expect(existsSync(join(dir, ".seamshield", "investigations"))).toBe(true);
  });

  it("initializes a repo with opt-outs", () => {
    const dir = tempProject();
    const result = runCli(["init", dir, "--no-agent-context", "--no-guard", "--no-ci"]);
    expect(result.status).toBe(0);
    expect(existsSync(join(dir, ".seamshield", "config.yaml"))).toBe(true);
    expect(existsSync(join(dir, "AGENTS.md"))).toBe(false);
    expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(false);
    expect(existsSync(join(dir, ".github", "workflows", "seamshield.yml"))).toBe(false);
  });

  it("initializes config only without side effects", () => {
    const dir = tempProject();
    const result = runCli(["config", "init", dir]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(join(dir, ".seamshield", "config.yaml"));
    expect(readFileSync(join(dir, ".seamshield", "config.yaml"), "utf8")).toContain("node_modules/**");
    expect(existsSync(join(dir, "AGENTS.md"))).toBe(false);
    expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(false);
    expect(existsSync(join(dir, ".github", "workflows", "seamshield.yml"))).toBe(false);
    expect(existsSync(join(dir, ".seamshield", "investigations"))).toBe(false);
    expect(runCli(["config", "init", "/nonexistent/definitely-not-here"]).status).toBe(2);
  });

  it("initializes only selected agent context targets", () => {
    const dir = tempProject();
    const result = runCli(["init", dir, "--agents", "codex,cursor", "--no-guard", "--no-ci"]);
    expect(result.status).toBe(0);
    expect(existsSync(join(dir, ".seamshield", "config.yaml"))).toBe(true);
    expect(readFileSync(join(dir, "AGENTS.md"), "utf8")).toContain("# SEAMSHIELD");
    expect(readFileSync(join(dir, ".cursor", "rules", "seamshield.mdc"), "utf8")).toContain("# SEAMSHIELD");
    expect(existsSync(join(dir, "CLAUDE.md"))).toBe(false);
    expect(existsSync(join(dir, "GEMINI.md"))).toBe(false);
    expect(existsSync(join(dir, ".github", "workflows", "seamshield.yml"))).toBe(false);
    expect(runCli(["init", dir, "--agents", "codex,unknown", "--no-guard", "--no-ci"]).status).toBe(2);
    expect(runCli(["init", dir, "--agents", "all,codex", "--no-guard", "--no-ci"]).status).toBe(2);
    expect(runCli(["init", dir, "--agents", "codex", "--no-agent-context", "--no-guard", "--no-ci"]).status).toBe(2);
  });

  it("installs the CI workflow without running init", () => {
    const dir = tempProject();
    const before = runCli(["ci", "status", dir, "--format", "json"]);
    expect(before.status).toBe(0);
    const missing = JSON.parse(before.stdout) as {
      schema: string;
      status: string;
      checks: { workflow_exists: boolean; offline_ship_check: boolean };
      diagnostics: Array<{ category: string; code: string }>;
    };
    expect(missing.schema).toBe("seamshield.ci-status/v1");
    expect(missing.status).toBe("not_installed");
    expect(missing.checks.workflow_exists).toBe(false);
    expect(missing.checks.offline_ship_check).toBe(false);
    expect(missing.diagnostics).toContainEqual(expect.objectContaining({ category: "workflow_installation", code: "workflow_missing" }));

    const result = runCli(["ci", "install", dir]);
    expect(result.status).toBe(0);
    const workflow = join(dir, ".github", "workflows", "seamshield.yml");
    expect(result.stdout.trim()).toBe(workflow);
    expect(readFileSync(workflow, "utf8")).toContain("npx @seamshield/cli ship . --offline");
    expect(readFileSync(workflow, "utf8")).not.toContain("npx @seamshield/cli sync . --ci");
    expect(readFileSync(workflow, "utf8")).not.toContain("SEAMSHIELD_SERVER_KEY");
    expect(readFileSync(workflow, "utf8")).toContain("seamshield-investigations");
    expect(existsSync(join(dir, "AGENTS.md"))).toBe(false);
    const after = runCli(["ci", "status", dir]);
    expect(after.status).toBe(0);
    expect(after.stdout).toContain("SeamShield CI Status");
    expect(after.stdout).toContain("Status: installed");
    expect(after.stdout).toContain("Offline ship check: yes");
    expect(after.stdout).toContain("Investigations uploaded on failure: yes");
    expect(runCli(["ci", "status", dir, "--format", "xml"]).status).toBe(2);
    expect(runCli(["ci", "status", "/nonexistent/definitely-not-here"]).status).toBe(2);
    expect(runCli(["ci", "install", "/nonexistent/definitely-not-here"]).status).toBe(2);
  });

  it("installs provider-native OIDC automation without a long-lived CI server key", () => {
    const connectedProject = (remote: string) => {
      const dir = tempProject();
      spawnSync("git", ["init"], { cwd: dir });
      spawnSync("git", ["remote", "add", "origin", remote], { cwd: dir });
      mkdirSync(join(dir, ".seamshield"), { recursive: true });
      writeFileSync(join(dir, ".seamshield", "connection.json"), `${JSON.stringify({
        schema: "seamshield.local-connection/v1",
        project: { id: "project_paid", name: "Paid project" },
        api_url: "https://platform.seamshield.com/api",
        source_upload: false,
      })}\n`);
      return dir;
    };

    const github = connectedProject("https://github.com/acme/widget.git");
    expect(runCli(["ci", "install", github, "--provider", "github"]).status).toBe(0);
    const githubWorkflow = readFileSync(join(github, ".github", "workflows", "seamshield.yml"), "utf8");
    expect(githubWorkflow).toContain("id-token: write");
    expect(githubWorkflow).toContain("npx @seamshield/cli sync . --ci --offline");
    expect(githubWorkflow).not.toContain("SEAMSHIELD_SERVER_KEY");
    const githubStatus = JSON.parse(runCli(["ci", "status", github, "--format", "json"]).stdout);
    expect(githubStatus.checks.continuous_sync).toBe(true);
    expect(githubStatus.checks.oidc_configured).toBe(true);
    expect(githubStatus.diagnostics).toEqual([]);

    const gitlab = connectedProject("https://gitlab.com/acme/widget.git");
    expect(runCli(["ci", "install", gitlab, "--provider", "gitlab"]).status).toBe(0);
    const gitlabWorkflow = readFileSync(join(gitlab, ".gitlab-ci.yml"), "utf8");
    expect(gitlabWorkflow).toContain("id_tokens");
    expect(gitlabWorkflow).toContain("SEAMSHIELD_ID_TOKEN");
    expect(gitlabWorkflow).toContain("sync . --ci --offline");

    const bitbucket = connectedProject("https://bitbucket.org/acme/widget.git");
    expect(runCliEnv(["ci", "install", bitbucket, "--provider", "bitbucket"], {
      SEAMSHIELD_CI_REPOSITORY_ID: "{repo-uuid}",
      SEAMSHIELD_CI_AUDIENCE: "ari:cloud:bitbucket::workspace/acme",
    }).status).toBe(0);
    const bitbucketWorkflow = readFileSync(join(bitbucket, "bitbucket-pipelines.yml"), "utf8");
    expect(bitbucketWorkflow).toContain("oidc: true");
    expect(bitbucketWorkflow).toContain("sync . --ci --offline");

    const azure = connectedProject("https://dev.azure.com/acme/core/_git/widget");
    expect(runCliEnv(["ci", "install", azure, "--provider", "azure"], {
      SEAMSHIELD_CI_REPOSITORY_ID: "azure-repo-id",
      SEAMSHIELD_CI_ISSUER: "https://vstoken.dev.azure.com/org-id/",
      SEAMSHIELD_CI_AUDIENCE: "api://AzureADTokenExchange",
    }).status).toBe(0);
    expect(readFileSync(join(azure, "azure-pipelines.yml"), "utf8")).toContain("SEAMSHIELD_ID_TOKEN");

    const circle = connectedProject("https://github.com/acme/circle-widget.git");
    expect(runCliEnv(["ci", "install", circle, "--provider", "circleci"], {
      SEAMSHIELD_CI_REPOSITORY_ID: "circle-project-id",
      SEAMSHIELD_CI_ISSUER: "https://oidc.circleci.com/org/org-id",
      SEAMSHIELD_CI_AUDIENCE: "org-id",
    }).status).toBe(0);
    expect(readFileSync(join(circle, ".circleci", "config.yml"), "utf8")).toContain("SEAMSHIELD_CI_PROVIDER: circleci");
  });

  it("exposes the one-time repository connection token flow", () => {
    const result = runCli(["connect", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--token <token>");
    const source = readFileSync(join(cliPackageDir, "src/index.ts"), "utf8");
    expect(source).toContain("absolute local path excluded");
    expect(source).toContain('DEFAULT_CONNECTED_API_URL = "https://platform.seamshield.com/api"');
    expect(source).toContain("Persistent enrollment:");
    expect(source).toContain("requireReceiptDigest");
    expect(source).toContain("The local connection was left unchanged.");
    expect(source).toContain("Generate a fresh connection command in Build → Platform");
    expect(source).toContain("Refreshed ${resolve(target)} for project");
    expect(source).toContain(".seamshield/connection.json");
    expect(source).toContain("SEAMSHIELD_SERVER_KEY");
    expect(source).toContain("ACTIONS_ID_TOKEN_REQUEST_URL");
    expect(source).toContain("BITBUCKET_STEP_OIDC_TOKEN");
    expect(source).toContain("CIRCLE_OIDC_TOKEN_V2");
    expect(source).toContain("ci/exchange");
    expect(source).toContain("branch_protection_present");
    expect(source).toContain("workflow_present");
    expect(source).toContain("duration_ms: Date.now() - startedAt");
    expect(source).toContain('filter((lane) => lane.severity === "block")');
    expect(source).toContain(".command(\"sync\")");
    expect(source).toContain("/agent/jobs");
    expect(source).toContain("/ci/bind");
    expect(source).toContain('new Set(["run_scan", "investigate_high_lanes", "install_ci_workflow", "repair_ci_automation", "apply_source_fix"])');
    expect(source).toContain("approval_gated_remediation_plan_prepared");
    expect(source).toContain('.command("sentinel")');
    expect(source).toContain('.command("enroll")');
    expect(source).toContain('.command("observe")');
    expect(source).toContain('.command("cloudflare")');
    expect(source).toContain('.command("install")');
    expect(source).toContain("CLOUDFLARE_API_TOKEN");
    expect(source).toContain("/v1/sentinel/edge/receipts");
    expect(source).toContain("OnUnitActiveSec=15min");
    expect(source).toContain("/v1/sentinel/runtimes/");
    expect(source).toContain(".seamshield/sentinel.json");
    expect(source).toContain("hostnames, IP addresses, logs, and credentials excluded");
    expect(source).not.toContain("raw repository text");
    expect(source).not.toContain("set SEAMSHIELD_API_URL or pass --api-url for connected mode");
  });

  it("exposes a source-private Sentinel server collector command", () => {
    const help = runCli(["sentinel", "observe", "--help"]);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("--runtime-id <id>");
    expect(help.stdout).toContain("hostnames, or IP addresses");

    const invalidEnrollment = runCli(["sentinel", "enroll", tempProject(), "--runtime-id", "host.example.com"]);
    expect(invalidEnrollment.status).toBe(2);
    expect(invalidEnrollment.stderr).toContain("opaque runtime id");
  });

  it("runs a Community doctor health check", () => {
    const dir = tempProject();
    const minimal = runCli(["doctor", dir, "--format", "json"]);
    expect(minimal.status).toBe(0);
    const minimalJson = JSON.parse(minimal.stdout) as {
      schema: string;
      status: string;
      package: { name: string; homepage: string; homepage_ok: boolean; npm_latest_status: string };
      checks: { offline_default: boolean; config_exists: boolean; guard_installed: boolean; ci_installed: boolean; package_homepage_ok: boolean };
      next: string[];
    };
    expect(minimalJson.schema).toBe("seamshield.doctor/v1");
    expect(minimalJson.package.name).toBe("@seamshield/cli");
    expect(minimalJson.package.homepage).toBe("https://seamshield.com");
    expect(minimalJson.package.homepage_ok).toBe(true);
    expect(["current", "behind", "unknown"]).toContain(minimalJson.package.npm_latest_status);
    expect(minimalJson.checks.package_homepage_ok).toBe(true);
    expect(minimalJson.checks.offline_default).toBe(true);
    expect(minimalJson.checks.config_exists).toBe(false);
    expect(minimalJson.checks.guard_installed).toBe(false);
    expect(minimalJson.checks.ci_installed).toBe(false);
    expect(minimalJson.next).toEqual(expect.arrayContaining([expect.stringContaining("seamshield config init")]));

    expect(runCli(["init", dir]).status).toBe(0);
    const bootstrapped = runCli(["doctor", dir]);
    expect(bootstrapped.status).toBe(0);
    expect(bootstrapped.stdout).toContain("SeamShield Doctor");
    expect(bootstrapped.stdout).toContain("OK  npm package homepage");
    expect(bootstrapped.stdout).toContain("OK  config exists");
    expect(bootstrapped.stdout).toContain("OK  guard installed");
    expect(bootstrapped.stdout).toContain("OK  CI installed");
    expect(bootstrapped.stdout).toContain("OK  agent context present");
    expect(runCli(["doctor", dir, "--format", "xml"]).status).toBe(2);
    expect(runCli(["doctor", "/nonexistent/definitely-not-here"]).status).toBe(2);
  }, 15_000);

  it("verifies release metadata and pack contents", () => {
    const result = runCli(["release", "verify", repoRoot, "--format", "json"]);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as {
      schema: string;
      status: string;
      package: { name: string; homepage: string; bin: { seamshield?: string } };
      checks: {
        official_scope: boolean;
        homepage_ok: boolean;
        bin_ok: boolean;
        files_ok: boolean;
        pack_dry_run_ok: boolean;
        pack_duplicate_rules_clean: boolean;
      };
      pack: { duplicate_rule_files: string[] };
    };
    expect(parsed.schema).toBe("seamshield.release-verify/v1");
    expect(parsed.status).toBe("ok");
    expect(parsed.package.name).toBe("@seamshield/cli");
    expect(parsed.package.homepage).toBe("https://seamshield.com");
    expect(parsed.package.bin.seamshield).toBe("dist/index.js");
    expect(parsed.checks.official_scope).toBe(true);
    expect(parsed.checks.homepage_ok).toBe(true);
    expect(parsed.checks.bin_ok).toBe(true);
    expect(parsed.checks.files_ok).toBe(true);
    expect(parsed.checks.pack_dry_run_ok).toBe(true);
    expect(parsed.checks.pack_duplicate_rules_clean).toBe(true);
    expect(parsed.pack.duplicate_rule_files).toEqual([]);

    const table = runCli(["release", "verify", repoRoot]);
    expect(table.status).toBe(0);
    expect(table.stdout).toContain("SeamShield Release Verify");
    expect(table.stdout).toContain("OK  official @seamshield/cli scope");
    expect(runCli(["release", "verify", repoRoot, "--format", "xml"]).status).toBe(2);
    expect(runCli(["release", "verify", "/nonexistent/definitely-not-here"]).status).toBe(2);
  }, 120_000);

  it("learn is local-only until update controls are wired", () => {
    const result = runCli(["learn"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("no source code was read or uploaded");
  });

  it("triage persists current warning suppressions into config", () => {
    const dir = tempProject();
    writeFileSync(
      join(dir, "profile.tsx"),
      `"use client";\nexport function Profile({ user }) { if (!user) return null; return <div />; }\n`,
    );

    const before = runCli(["scan", dir, "--format", "json", "--offline", "--fail-on", "never", "--no-investigation"]);
    expect(JSON.parse(before.stdout).summary.findings_total).toBe(1);

    const triage = runCli(["triage", dir, "--rule", "ss/auth/client-only-guard"]);
    expect(triage.status).toBe(0);
    expect(triage.stdout).toContain(".seamshield/config.yaml");
    expect(readFileSync(join(dir, ".seamshield", "config.yaml"), "utf8")).toContain(
      "ss/auth/client-only-guard",
    );

    const after = runCli(["scan", dir, "--format", "json", "--offline", "--fail-on", "never", "--no-investigation"]);
    expect(JSON.parse(after.stdout).summary.findings_total).toBe(0);
  });

  it("writes portable agent context for supported coding agents", () => {
    const dir = tempProject();
    expect(runCli(["agent-context", dir]).status).toBe(0);
    expect(readFileSync(join(dir, "AGENTS.md"), "utf8")).toContain("# SEAMSHIELD");
    expect(readFileSync(join(dir, "AGENTS.md"), "utf8")).toContain("@seamshield/cli ship");
    expect(runCli(["agent-context", dir, "--codex"]).status).toBe(0);
    expect(runCli(["agent-context", dir, "--claude"]).status).toBe(0);
    expect(readFileSync(join(dir, "CLAUDE.md"), "utf8")).toContain("# SEAMSHIELD");
    expect(runCli(["agent-context", dir, "--cursor"]).status).toBe(0);
    expect(readFileSync(join(dir, ".cursor", "rules", "seamshield.mdc"), "utf8")).toContain(
      "npx @seamshield/cli scan",
    );
    expect(runCli(["agent-context", dir, "--gemini"]).status).toBe(0);
    expect(readFileSync(join(dir, "GEMINI.md"), "utf8")).toContain("--agent generic");
    expect(runCli(["agent-context", dir, "--cline"]).status).toBe(0);
    expect(readFileSync(join(dir, ".clinerules", "seamshield.md"), "utf8")).toContain("# SEAMSHIELD");
    expect(runCli(["agent-context", dir, "--windsurf"]).status).toBe(0);
    expect(readFileSync(join(dir, ".windsurf", "rules", "seamshield.md"), "utf8")).toContain(
      "# SEAMSHIELD",
    );
    expect(runCli(["agent-context", dir, "--copilot"]).status).toBe(0);
    expect(readFileSync(join(dir, ".github", "copilot-instructions.md"), "utf8")).toContain(
      "@seamshield/cli ship",
    );
    expect(runCli(["agent-context", dir, "--opencode"]).status).toBe(0);
    expect(readFileSync(join(dir, ".opencode", "AGENTS.md"), "utf8")).toContain("# SEAMSHIELD");
    expect(runCli(["agent-context", dir, "--all"]).stdout.trim().split("\n")).toHaveLength(8);
    expect(runCli(["agent-context", dir, "--all", "--claude"]).status).toBe(2);
  });

  it("reports guard installation status", () => {
    const dir = tempProject();
    const before = runCli(["guard", "status", dir, "--format", "json"]);
    expect(before.status).toBe(0);
    const missing = JSON.parse(before.stdout) as {
      schema: string;
      status: string;
      checks: { pre_tool_use_hook_installed: boolean; claude_settings_exists: boolean };
    };
    expect(missing.schema).toBe("seamshield.guard-status/v1");
    expect(missing.status).toBe("not_installed");
    expect(missing.checks.claude_settings_exists).toBe(false);
    expect(missing.checks.pre_tool_use_hook_installed).toBe(false);

    expect(runCli(["guard", "install", dir]).status).toBe(0);
    const after = runCli(["guard", "status", dir]);
    expect(after.status).toBe(0);
    expect(after.stdout).toContain("SeamShield Guard Status");
    expect(after.stdout).toContain("Status: installed");
    expect(after.stdout).toContain("PreToolUse hook: installed");
    expect(after.stdout).toContain("Matcher: Write|Edit|MultiEdit|Bash");
    expect(runCli(["guard", "status", dir, "--format", "xml"]).status).toBe(2);
    expect(runCli(["guard", "status", "/nonexistent/definitely-not-here"]).status).toBe(2);
  });

  it("denies guard hook edits with block findings", () => {
    const input = JSON.stringify({
      tool_name: "Write",
      tool_input: {
        file_path: "app/page.tsx",
        content: `const k = "sk_live_${"E".repeat(24)}";\n`,
      },
    });
    const result = runCliWithInput(["guard", "check"], input);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as {
      hookSpecificOutput: { permissionDecision?: string; permissionDecisionReason?: string };
    };
    expect(parsed.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(parsed.hookSpecificOutput.permissionDecisionReason).toContain(
      "ss/secrets/hardcoded-provider-key",
    );
  });
});
