import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildAccessMap, buildShipVerdict, scan } from "../src/index.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: 9\n");
  return dir;
}

function publicSecretName(prefix: "ADMIN_API_KEY" | "APP_SECRET"): string {
  return `NEXT_PUBLIC_${prefix}`;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("access lane mapping", () => {
  it("maps provider and platform findings into normalized access lanes", () => {
    const dir = makeTempDir("seamshield-access-");
    mkdirSync(join(dir, "convex"), { recursive: true });
    mkdirSync(join(dir, "server"), { recursive: true });

    writeFileSync(
      join(dir, "convex", "messages.ts"),
      "export const save = mutation({ handler: async (ctx) => ctx.db.insert('messages', {}) });\n",
    );
    writeFileSync(
      join(dir, "coolify.yaml"),
      `environment:\n  ${publicSecretName("ADMIN_API_KEY")}: fake\n`,
    );
    writeFileSync(
      join(dir, "vercel.json"),
      JSON.stringify({ rewrites: [{ source: "/admin/:path*", destination: "/api/admin/:path*" }] }),
    );
    writeFileSync(
      join(dir, "server", "index.ts"),
      "app.post('/admin/delete-user', async (req, res) => res.send('ok'));\n",
    );
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify(
        {
          name: "access-fixture",
          scripts: { postinstall: "node scripts/install.js" },
          dependencies: { leftpad: "latest" },
        },
        null,
        2,
      ),
    );

    const access = buildAccessMap(scan(dir));
    expect(access.schema).toBe("seamshield.access-map/v1");
    expect(access.lanes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          actor: "public_user",
          provider: "convex",
          risk: "anonymous_write",
        }),
        expect.objectContaining({
          actor: "deploy_platform",
          provider: "deploy",
          risk: "deploy_secret_exposure",
        }),
        expect.objectContaining({
          actor: "deploy_platform",
          provider: "vercel",
          risk: "deploy_secret_exposure",
        }),
        expect.objectContaining({
          actor: "public_user",
          provider: "self-hosted",
          risk: "anonymous_execute",
        }),
        expect.objectContaining({
          actor: "dependency",
          risk: "dependency_to_shell",
        }),
      ]),
    );
  });

  it("builds an unsafe ship verdict when high or block lanes exist", () => {
    const dir = makeTempDir("seamshield-ship-");
    writeFileSync(join(dir, ".env"), `${publicSecretName("APP_SECRET")}=x\n`);

    const verdict = buildShipVerdict(scan(dir));
    expect(verdict.schema).toBe("seamshield.ship/v1");
    expect(verdict.verdict).toBe("UNSAFE TO SHIP");
    expect(verdict.exitCode).toBe(1);
    expect(verdict.critical.some((lane) => lane.risk === "deploy_secret_exposure")).toBe(true);
  });

  it("generates stable lane IDs across repeated scans", () => {
    const dir = makeTempDir("seamshield-stable-lanes-");
    writeFileSync(join(dir, "index.ts"), `const k = "sk_live_${"A".repeat(24)}";\n`);

    const first = buildAccessMap(scan(dir));
    const second = buildAccessMap(scan(dir));

    expect(first.lanes[0]?.lane_id).toMatch(/^lane:[a-f0-9]{16}$/);
    expect(first.lanes.map((lane) => lane.lane_id)).toEqual(second.lanes.map((lane) => lane.lane_id));
  });
});
