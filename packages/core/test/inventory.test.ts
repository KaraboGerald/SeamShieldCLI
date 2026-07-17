import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { collectInventory, renderInventoryNdjson } from "../src/index.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("read-only inventory", () => {
  it("collects package, MCP, agent skill, and deploy metadata without source records", () => {
    const dir = makeTempDir("seamshield-inventory-");
    mkdirSync(join(dir, ".seamshield"), { recursive: true });
    mkdirSync(join(dir, ".cursor"), { recursive: true });

    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "inventory-fixture", dependencies: { zod: "^4.0.0" } }, null, 2),
    );
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
    writeFileSync(join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { db: { env: { API_KEY: "secret" } } } }));
    writeFileSync(join(dir, "skills-lock.json"), JSON.stringify({ skills: { guard: { version: "1.0.0" } } }));
    writeFileSync(join(dir, "vercel.json"), JSON.stringify({ crons: [{ path: "/api/cron" }] }));
    writeFileSync(join(dir, "app.ts"), "const source = true;\n");

    const inventory = collectInventory(dir);

    expect(inventory.schema).toBe("seamshield.inventory/v1");
    expect(inventory.components).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ ecosystem: "npm", source_type: "package-manifest", confidence: "medium" }),
        expect.objectContaining({ ecosystem: "npm", source_type: "pnpm-lockfile", confidence: "high" }),
        expect.objectContaining({ ecosystem: "mcp", source_type: "mcp-config", credential_fields_present: ["API_KEY"] }),
        expect.objectContaining({ ecosystem: "agent-skill", source_type: "skills-lock" }),
        expect.objectContaining({ ecosystem: "deploy", source_type: "vercel-config" }),
      ]),
    );
    expect(JSON.stringify(inventory)).not.toContain("secret");
    expect(inventory.components.some((component) => component.source_file === "app.ts")).toBe(false);
  });

  it("renders inventory as NDJSON ending with an inventory summary", () => {
    const dir = makeTempDir("seamshield-inventory-ndjson-");
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "ndjson-fixture" }));

    const lines = renderInventoryNdjson(collectInventory(dir)).trim().split("\n").map((line) => JSON.parse(line));

    expect(lines[0]).toEqual(expect.objectContaining({ record_type: "inventory_component" }));
    expect(lines.at(-1)).toEqual(expect.objectContaining({ record_type: "inventory_summary" }));
  });

  it("reports capability depth for non-JavaScript repository markers without inventing adapters", () => {
    const dir = makeTempDir("seamshield-inventory-capabilities-");
    writeFileSync(join(dir, "pyproject.toml"), "[project]\nname = 'example'\n");
    writeFileSync(join(dir, "go.mod"), "module example.com/service\n");
    writeFileSync(join(dir, "pom.xml"), "<project />\n");
    writeFileSync(join(dir, "service.csproj"), "<Project />\n");

    const inventory = collectInventory(dir);
    const languages = inventory.capabilities.languages.map((language) => language.id);

    expect(languages).toEqual(expect.arrayContaining(["python", "go", "java", "dotnet"]));
    expect(inventory.capabilities.coverage.deep_access_lane_adapters).toEqual([]);
    expect(inventory.capabilities.coverage.unknown_language_policy).toBe("baseline_only");
    expect(JSON.stringify(inventory.capabilities)).not.toContain("example.com");
  });
});
