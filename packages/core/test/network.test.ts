import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { scanAsync } from "../src/index.js";

const tempDirs: string[] = [];

function makeProject(pkg: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "seamshield-network-"));
  tempDirs.push(dir);
  writeFileSync(join(dir, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
  writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("network dependency rules", () => {
  it("flags npm 404 packages and OSV vulnerable versions", async () => {
    const dir = makeProject({
      dependencies: {
        "made-up-ai-package": "1.0.0",
        lodash: "4.17.20",
      },
    });
    const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
      const href = String(url);
      if (href.includes("registry.npmjs.org/made-up-ai-package")) {
        return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
      }
      if (href.includes("registry.npmjs.org/lodash")) {
        return Response.json({ name: "lodash" });
      }
      if (href.includes("api.osv.dev")) {
        const body = JSON.parse(String(init?.body));
        if (body.package.name === "lodash") {
          return Response.json({ vulns: [{ id: "GHSA-test" }] });
        }
        return Response.json({ vulns: [] });
      }
      return Response.json({});
    }) as typeof fetch;

    const result = await scanAsync(dir, { fetchImpl, networkTimeoutMs: 50 });
    expect(result.findings.map((f) => f.finding.rule_id).sort()).toEqual([
      "ss/deps/hallucinated-package",
      "ss/deps/known-vuln",
    ]);
    expect(result.exitCode).toBe(1);
  });

  it("skips network failures without producing dependency findings", async () => {
    const dir = makeProject({ dependencies: { lodash: "4.17.20" } });
    const fetchImpl = (async () => {
      throw new Error("offline");
    }) as typeof fetch;
    const result = await scanAsync(dir, { fetchImpl, networkTimeoutMs: 1 });
    expect(result.findings.filter((f) => f.finding.rule_id.startsWith("ss/deps/"))).toEqual([]);
    expect(result.networkSkipped).toBe(false);
  });
});
