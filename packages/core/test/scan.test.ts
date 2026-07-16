import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { rulesDir } from "@seamshield/rules";
import { afterAll, describe, expect, it } from "vitest";
import { FindingSchema, loadRules, redactSecret, scan } from "../src/index.js";

const fixtureDir = fileURLToPath(
  new URL("../../../examples/vulnerable-next-app", import.meta.url),
);

const tempDirs: string[] = [];
const j = (...parts: string[]) => parts.join("");
const USE_CLIENT = j('"use ', 'client";');
const CLIENT_GUARD = j("if (!", "user");
const PUBLIC_SECRET_NAME = j("NEXT_PUBLIC_", "APP_SECRET");

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("loadRules", () => {
  it("loads the full 36-rule pack with a stable sha256 policy bundle digest", () => {
    const first = loadRules(rulesDir);
    const second = loadRules(rulesDir);
    expect(first.rules.map((r) => r.id).sort()).toEqual([
      "ss/agent/mcp-inline-credentials",
      "ss/agent/overbroad-permissions",
      "ss/agent/risky-filesystem-permissions",
      "ss/agent/secrets-in-agent-files",
      "ss/ai/public-provider-key",
      "ss/ai/untrusted-model-base-url",
      "ss/auth/admin-route-unprotected",
      "ss/auth/api-route-no-auth",
      "ss/auth/client-only-guard",
      "ss/auth/cors-wildcard-with-credentials",
      "ss/client/firebase-admin-in-client",
      "ss/client/next-public-secret",
      "ss/client/server-secret-env-in-client",
      "ss/client/supabase-service-role-in-client",
      "ss/convex/internal-not-internal",
      "ss/convex/mutation-no-auth",
      "ss/convex/public-function-no-auth",
      "ss/convex/tenant-bound-write",
      "ss/deploy/public-env-secret",
      "ss/deps/hallucinated-package",
      "ss/deps/known-vuln",
      "ss/deps/no-lockfile",
      "ss/deps/package-manager-drift",
      "ss/deps/postinstall-script",
      "ss/deps/unpinned-spec",
      "ss/firebase/open-rules",
      "ss/next/server-action-trusted-client",
      "ss/secrets/env-file-committed",
      "ss/secrets/generic-credential-assignment",
      "ss/secrets/hardcoded-provider-key",
      "ss/secrets/private-key-file",
      "ss/secrets/supabase-service-role-key",
      "ss/server/route-no-auth",
      "ss/server/webhook-missing-signature",
      "ss/supabase/permissive-policy",
      "ss/supabase/rls-disabled",
      "ss/vercel/config-access-risk",
    ]);
    expect(first.policyBundleDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(first.policyBundleDigest).toBe(second.policyBundleDigest);
  });

  it("merges shared patterns referenced via patterns_from", () => {
    const { rules } = loadRules(rulesDir);
    const keyRule = rules.find((r) => r.id === "ss/secrets/hardcoded-provider-key");
    expect(keyRule?.check.patterns?.length).toBeGreaterThanOrEqual(10);
  });
});

describe("redactSecret", () => {
  it("keeps only an 8-char prefix and the length", () => {
    const fake = "sk_live_" + "A".repeat(28);
    expect(redactSecret(fake)).toBe("sk_live_…(36 chars)");
  });
});

describe("scan of the seeded fixture", () => {
  const result = scan(fixtureDir);

  it("finds exactly the seeded violations and exits 1", () => {
    const located = result.findings
      .map((f) => `${f.finding.rule_id}@${f.finding.file}:${f.finding.line}`)
      .sort();
    expect(located).toEqual(
      [
        "ss/agent/mcp-inline-credentials@.mcp.json:7",
        "ss/auth/admin-route-unprotected@app/admin/page.jsx:1",
        "ss/auth/api-route-no-auth@app/api/upload/route.js:1",
        "ss/auth/client-only-guard@app/dashboard/page.jsx:4",
        "ss/client/firebase-admin-in-client@lib/firebase-client.js:3",
        "ss/client/next-public-secret@.env:3",
        "ss/client/next-public-secret@app/page.jsx:5",
        "ss/convex/mutation-no-auth@convex/messages.ts:1",
        "ss/convex/public-function-no-auth@convex/messages.ts:4",
        "ss/deploy/public-env-secret@.env:3",
        "ss/deps/unpinned-spec@package.json:13",
        "ss/firebase/open-rules@firestore.rules:5",
        "ss/secrets/env-file-committed@.env:1",
        "ss/secrets/hardcoded-provider-key@lib/ai.ts:2",
        "ss/secrets/supabase-service-role-key@lib/supabase-admin.js:6",
        "ss/supabase/permissive-policy@supabase/migrations/0001_init.sql:4",
        "ss/supabase/rls-disabled@supabase/migrations/0001_init.sql:3",
      ].sort(),
    );
    expect(result.exitCode).toBe(1);
    expect(
      result.findings.every((f) =>
        f.finding.severity === "block" ? f.decision === "deny" : f.decision === "scan",
      ),
    ).toBe(true);
    expect(result.findings.filter((f) => f.finding.severity === "block")).toHaveLength(8);
  });

  it("does not flag .env.example", () => {
    expect(result.findings.some((f) => f.finding.file === ".env.example")).toBe(false);
  });

  it("does not scan files ignored by .gitignore", () => {
    const dir = makeTempDir("seamshield-gitignore-");
    writeFileSync(join(dir, ".gitignore"), ".env.*\n*.pem\n");
    writeFileSync(dir + "/.env.local", `${PUBLIC_SECRET_NAME}=x\n`);
    writeFileSync(dir + "/dist.pem", `${j("-----BEGIN PRIVATE", " KEY-----")}\nMIIEFAKE\n`);

    const ignored = scan(dir);
    expect(ignored.findings.map((f) => f.finding.file)).toEqual([]);
  });

  it("emits findings that validate against the finding schema", () => {
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(() => FindingSchema.parse(finding)).not.toThrow();
    }
  });

  it("redacts matched secret values in evidence", () => {
    const serialized = JSON.stringify(result.findings);
    expect(serialized).not.toContain("FAKE4eC39");
    expect(serialized).not.toContain("FAKEFIXTUREKEY");
    expect(serialized).toContain("…(");
  });

  it("respects --fail-on never", () => {
    expect(scan(fixtureDir, { failOn: "never" }).exitCode).toBe(0);
  });
});

describe("scan of a clean directory", () => {
  it("returns zero findings and exit 0", () => {
    const dir = makeTempDir("seamshield-clean-");
    writeFileSync(join(dir, "index.ts"), "export const ok = true;\n");
    const result = scan(dir);
    expect(result.findings).toEqual([]);
    expect(result.exitCode).toBe(0);
  });
});

describe("signal refinement", () => {
  it("downgrades client-only guards without a nearby data boundary to info", () => {
    const dir = makeTempDir("seamshield-client-info-");
    writeFileSync(
      join(dir, "profile.tsx"),
      `${USE_CLIENT}\nexport function Profile({ user }) { ${CLIENT_GUARD}) return null; return <div />; }\n`,
    );
    const finding = scan(dir).findings.find(
      (f) => f.finding.rule_id === "ss/auth/client-only-guard",
    );
    expect(finding?.finding.severity).toBe("info");
  });

  it("keeps client-only guards with nearby data calls as warnings", () => {
    const dir = makeTempDir("seamshield-client-warn-");
    writeFileSync(
      join(dir, "profile.tsx"),
      `${USE_CLIENT}\nexport function Profile({ user }) { ${CLIENT_GUARD}) return null; fetch("/api/me"); return <div />; }\n`,
    );
    const finding = scan(dir).findings.find(
      (f) => f.finding.rule_id === "ss/auth/client-only-guard",
    );
    expect(finding?.finding.severity).toBe("warn");
  });
});

describe("default traversal skips generated agent worktrees", () => {
  it("does not scan duplicated files inside .claude/worktrees or .worktrees", () => {
    const dir = makeTempDir("seamshield-worktrees-");
    mkdirSync(join(dir, ".claude", "worktrees", "agent", "keys"), { recursive: true });
    mkdirSync(join(dir, ".worktrees", "copy", "keys"), { recursive: true });
    writeFileSync(
      join(dir, ".claude", "worktrees", "agent", "keys", "dev.pem"),
      `${"-----BEGIN PRIVATE"} KEY-----\nFAKE\n`,
    );
    writeFileSync(
      join(dir, ".worktrees", "copy", "keys", "dev.pem"),
      `${"-----BEGIN PRIVATE"} KEY-----\nFAKE\n`,
    );
    expect(scan(dir).findings).toEqual([]);
  });

  it("does not scan native build target directories", () => {
    const dir = makeTempDir("seamshield-target-");
    mkdirSync(join(dir, "desktop", "src-tauri", "target", "release", "keys"), {
      recursive: true,
    });
    writeFileSync(
      join(dir, "desktop", "src-tauri", "target", "release", "keys", "dev.pem"),
      `${"-----BEGIN PRIVATE"} KEY-----\nFAKE\n`,
    );
    expect(scan(dir).findings).toEqual([]);
  });
});

describe("inline suppression", () => {
  it("suppresses a finding when the line above carries seamshield-ignore <rule-id>", () => {
    const dir = makeTempDir("seamshield-suppress-");
    const fakeKey = "sk_live_" + "B".repeat(24);
    writeFileSync(
      join(dir, "pay.ts"),
      `// seamshield-ignore ss/secrets/hardcoded-provider-key\nconst k = "${fakeKey}";\n`,
    );
    expect(scan(dir).findings).toEqual([]);

    writeFileSync(join(dir, "pay.ts"), `const k = "${fakeKey}";\n`);
    const flagged = scan(dir);
    expect(flagged.findings).toHaveLength(1);
    expect(flagged.findings[0]?.finding.rule_id).toBe("ss/secrets/hardcoded-provider-key");
  });
});

describe(".seamshield/config.yaml", () => {
  it("supports disabling rules and ignoring paths", () => {
    const dir = makeTempDir("seamshield-config-");
    const fakeKey = "sk_live_" + "C".repeat(24);
    mkdirSync(join(dir, ".seamshield"));
    mkdirSync(join(dir, "vendored"));
    writeFileSync(join(dir, "vendored", "old.ts"), `const k = "${fakeKey}";\n`);
    // seamshield-ignore ss/client/next-public-secret
    writeFileSync(join(dir, "app.ts"), `export const name = "${PUBLIC_SECRET_NAME}";\n`);

    writeFileSync(
      join(dir, ".seamshield", "config.yaml"),
      "ignore:\n  - vendored/**\nrules:\n  disable:\n    - ss/client/next-public-secret\n",
    );
    expect(scan(dir).findings).toEqual([]);

    writeFileSync(join(dir, ".seamshield", "config.yaml"), "ignore: []\n");
    const flagged = scan(dir);
    expect(flagged.findings.map((f) => f.finding.rule_id).sort()).toEqual([
      "ss/client/next-public-secret",
      "ss/secrets/hardcoded-provider-key",
    ]);
  });

  it("supports exact finding suppressions", () => {
    const dir = makeTempDir("seamshield-config-suppress-");
    mkdirSync(join(dir, ".seamshield"));
    writeFileSync(join(dir, "app.ts"), `export const name = "${PUBLIC_SECRET_NAME}";\n`);
    writeFileSync(
      join(dir, ".seamshield", "config.yaml"),
      "suppress:\n  - rule: ss/client/next-public-secret\n    file: app.ts\n    line: 1\n    reason: release gate\n",
    );
    expect(scan(dir).findings).toEqual([]);
  });
});
