import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { afterAll, describe, expect, it } from "vitest";
import { scan, verifyRulepack } from "../src/index.js";

// Trigger strings are assembled from parts so the scanner never matches this
// test file itself during self-scans.
const j = (...parts: string[]) => parts.join("");
const publicSecretName = (suffix: "APP_SECRET" | "ADMIN_API_KEY") => `NEXT_PUBLIC_${suffix}`;
const USE_CLIENT = j('"use ', 'client";');
const FAKE_JWT = j(
  "eyJhbGciOiJIUzI1NiJ9",
  ".",
  "eyJyb2xlIjoic2VydmljZV9yb2xlIn0",
  ".",
  "TESTSIGNATURE",
);
const PEM_HEADER = j("-----BEGIN PRIVATE", " KEY-----");

const tempDirs: string[] = [];
function scanFiles(files: Record<string, string>): string[] {
  const dir = mkdtempSync(join(tmpdir(), "seamshield-rule-"));
  tempDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return scan(dir)
    .findings.map((f) => `${f.finding.rule_id}@${f.finding.file}`)
    .sort();
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function packDigest(rulesDir: string): string {
  const name = "commercial.yaml";
  const content = readFileSync(join(rulesDir, name), "utf8");
  return createHash("sha256").update(name).update("\n").update(content).update("\n").digest("hex");
}

it("verifies signed commercial rulepacks and rejects tampering, tier, channel, and rollback mismatches", () => {
  const root = mkdtempSync(join(tmpdir(), "seamshield-rulepack-")); tempDirs.push(root);
  const rulesDir = join(root, "rules"); mkdirSync(rulesDir);
  writeFileSync(join(rulesDir, "commercial.yaml"), `id: ss/pro/example\nseverity: warn\ntitle: Example\ndescription: Example rule\nframework_ref: example\ncheck:\n  type: regex\n  patterns:\n    - name: example\n      regex: example\nfix:\n  summary: Fix\n  agent_prompt: Fix it\n`);
  const keys = generateKeyPairSync("ed25519");
  const unsigned = { schema: "seamshield.rulepack-manifest/v1", tier: "pro", channel: "stable", version: "2026.07.24", rules_digest: packDigest(rulesDir), previous_rules_digest: "previous", signing_key_id: "test-key" };
  const manifest = { ...unsigned, signature: sign(null, Buffer.from(canonicalJson(unsigned)), keys.privateKey).toString("base64url") };
  const manifestPath = join(root, "manifest.json"); writeFileSync(manifestPath, JSON.stringify(manifest));
  const options = { rulesDir, manifestPath, publicKey: keys.publicKey.export({ type: "spki", format: "pem" }).toString(), entitlementTier: "pro" as const, allowedChannels: ["stable"] as const, previousRulesDigest: "previous" };
  expect(verifyRulepack(options).manifest.version).toBe("2026.07.24");
  expect(scan(root, { rulesDir, rulepack: options }).rulesLoaded).toBe(1);
  expect(() => verifyRulepack({ ...options, entitlementTier: "enterprise" })).toThrow("rulepack_entitlement_mismatch");
  expect(() => verifyRulepack({ ...options, allowedChannels: ["preview"] })).toThrow("rulepack_channel_not_allowed");
  expect(() => verifyRulepack({ ...options, previousRulesDigest: "other" })).toThrow("rulepack_rollback_lineage_mismatch");
  writeFileSync(join(rulesDir, "commercial.yaml"), "tampered\n");
  expect(() => verifyRulepack(options)).toThrow("rulepack_digest_mismatch");
});

interface Case {
  rule: string;
  tp: Record<string, string>[];
  tn: Record<string, string>[];
}

const LOCK = { "pnpm-lock.yaml": "lockfileVersion: 9\n" };

const cases: Case[] = [
  {
    rule: "ss/server/webhook-missing-signature",
    tp: [
      { "api/webhooks.ts": 'import express from "express";\nconst app = express();\napp.post("/webhook/stripe", async (req, res) => { await processEvent(req.body); res.sendStatus(200); });\n' },
    ],
    tn: [
      { "api/webhooks.ts": 'import express from "express";\nconst app = express();\napp.post("/webhook/stripe", async (req, res) => { const event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret); await processEvent(event); res.sendStatus(200); });\n' },
    ],
  },
  {
    rule: "ss/secrets/supabase-service-role-key",
    tp: [
      { "lib/db.ts": `const key = "${FAKE_JWT}";\n` },
      { "config.yaml": `supabase_key: "${FAKE_JWT}"\n` },
    ],
    tn: [
      // anon-role JWT (payload says "anon", not service_role)
      { "lib/db.ts": `const key = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.SIG";\n` },
      { ".env": `SUPABASE_SERVICE_ROLE_KEY=${FAKE_JWT}\n` },
    ],
  },
  {
    rule: "ss/secrets/private-key-file",
    tp: [
      { "keys/server.pem": `${PEM_HEADER}\nMIIEFAKE\n` },
      { "deploy/id_rsa": `${j("-----BEGIN OPENSSH PRIVATE", " KEY-----")}\nFAKE\n` },
    ],
    tn: [
      { "keys/server.pub": `${PEM_HEADER}\n` },
      { ".env.local": `${PEM_HEADER}\nMIIEFAKE\n` },
      { "README.md": "Generate a private key with openssl genrsa.\n" },
    ],
  },
  {
    rule: "ss/secrets/generic-credential-assignment",
    tp: [
      { "src/config.ts": `const apiToken = "${"Ab1".repeat(12)}";\n` },
      { "src/settings.py": `PASSWORD = "${"Zx9".repeat(12)}"\n` },
    ],
    tn: [
      { "src/config.ts": `const apiToken = process.env.API_TOKEN;\n` },
      { "src/config.ts": `const tokenName = "short-value";\n` },
    ],
  },
  {
    rule: "ss/client/next-public-secret",
    tp: [
      { ".env": `${publicSecretName("APP_SECRET")}=x\n` },
      { "app/page.tsx": `const key = "${publicSecretName("ADMIN_API_KEY")}";\n` },
    ],
    tn: [
      {
        "scripts/seamshield-release-gate.mjs":
          `if (process.env.${publicSecretName("APP_SECRET")}) throw new Error("bad public env");\n`,
      },
      { "app/page.tsx": `const key = "NEXT_PUBLIC_BASE_URL";\n` },
    ],
  },
  {
    rule: "ss/client/firebase-admin-in-client",
    tp: [
      { "app/page.tsx": `${USE_CLIENT}\nimport admin from ${j('"firebase-', 'admin"')};\n` },
      { "c.jsx": `${USE_CLIENT}\nconst admin = require(${j('"firebase-', 'admin"')});\n` },
    ],
    tn: [
      { "app/api/route.ts": `import admin from ${j('"firebase-', 'admin"')};\n` },
      { "app/page.tsx": `${USE_CLIENT}\nimport { initializeApp } from "firebase/app";\n` },
    ],
  },
  {
    rule: "ss/client/server-secret-env-in-client",
    tp: [
      { "app/p.tsx": `${USE_CLIENT}\nconst s = process.env.STRIPE_SECRET_KEY;\n` },
      { "app/q.jsx": `${USE_CLIENT}\nfetch(process.env.ADMIN_API_KEY);\n` },
    ],
    tn: [
      { "app/p.tsx": `const s = process.env.STRIPE_SECRET_KEY;\n` },
      { "app/p.tsx": `${USE_CLIENT}\nconst s = process.env.NEXT_PUBLIC_BASE_URL;\n` },
    ],
  },
  {
    rule: "ss/client/supabase-service-role-in-client",
    tp: [
      { "app/p.tsx": `${USE_CLIENT}\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n` },
      { "hooks/u.jsx": `${USE_CLIENT}\ncreateClient(url, env.SUPABASE_SERVICE_ROLE);\n` },
    ],
    tn: [
      { "server/db.ts": `const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n` },
      { "app/p.tsx": `${USE_CLIENT}\nconst k = process.env.NEXT_PUBLIC_SUPABASE_URL;\n` },
    ],
  },
  {
    rule: "ss/auth/admin-route-unprotected",
    tp: [
      { "app/admin/page.tsx": "export default function P() { return <div>hi</div>; }\n" },
      { "pages/admin/index.jsx": "export default () => <div>panel</div>;\n" },
    ],
    tn: [
      {
        "app/admin/page.tsx":
          'import { getServerSession } from "next-auth";\nexport default async function P() { return null; }\n',
      },
      { "app/blog/page.tsx": "export default function P() { return <div>post</div>; }\n" },
    ],
  },
  {
    rule: "ss/auth/api-route-no-auth",
    tp: [
      { "app/api/items/route.ts": "export async function GET() { return Response.json([]); }\n" },
      { "pages/api/items.ts": "export default function handler(req, res) { res.json([]); }\n" },
    ],
    tn: [
      {
        "app/api/items/route.ts":
          'import { auth } from "@/lib";\nexport async function GET() { await auth(); return Response.json([]); }\n',
      },
      { "app/api/_internal.ts": "export function internalToken() { return process.env.CONVEX_INTERNAL_TOKEN; }\n" },
      { "app/api/_convexApiAny.ts": "export const convexApiAny = {} as any;\n" },
      { "app/api/resend/waitlist/route.ts": "export async function POST() { return new Response('Gone', { status: 410 }); }\n" },
      { "app/items/page.tsx": "export default function P() { return null; }\n" },
    ],
  },
  {
    rule: "ss/auth/client-only-guard",
    tp: [
      { "app/d.tsx": `${USE_CLIENT}\nexport function D({ user }) { if (!user) return null; return <p>x</p>; }\n` },
      { "app/e.jsx": `${USE_CLIENT}\nif (!isAuthenticated) { redirectHome(); }\n` },
    ],
    tn: [
      { "app/d.tsx": `export function D({ user }) { if (!user) return null; return null; }\n` },
      { "app/d.tsx": `${USE_CLIENT}\nif (!data) return null;\n` },
    ],
  },
  {
    rule: "ss/auth/cors-wildcard-with-credentials",
    tp: [
      {
        "server.js": `res.setHeader("${j("Access-Control-Allow-", "Origin")}", "*");\nres.setHeader("${j("Access-Control-Allow-", "Credentials")}", "true");\n`,
      },
      {
        "api.py": `headers = {"${j("Access-Control-Allow-", "Origin")}": "*", "${j("Access-Control-Allow-", "Credentials")}": "true"}\n`,
      },
    ],
    tn: [
      { "server.js": `res.setHeader("${j("Access-Control-Allow-", "Origin")}", "*");\n` },
      {
        "server.js": `res.setHeader("${j("Access-Control-Allow-", "Origin")}", origin);\nres.setHeader("${j("Access-Control-Allow-", "Credentials")}", "true");\n`,
      },
    ],
  },
  {
    rule: "ss/server/route-no-auth",
    tp: [
      {
        "server/routes/admin.ts":
          'import { Router } from "express";\nconst adminRouter = Router();\nadminRouter.post("/delete-user", async (req, res) => { await deleteUser(req.body.userId); res.json({ ok: true }); });\napp.use("/admin", adminRouter);\n',
      },
      {
        "server/index.ts":
          'import express from "express";\nconst app = express();\nconst publicRouter = express.Router();\nconst adminRouter = express.Router();\npublicRouter.get("/health", (_req, res) => res.send("ok"));\nadminRouter.post("/users/:id/delete", async (req, res) => { await db.user.delete({ where: { id: req.params.id } }); res.json({ ok: true }); });\napp.use("/public", publicRouter);\napp.use("/admin", adminRouter);\n',
      },
      {
        "server/hono.ts":
          'import { Hono } from "hono";\nconst admin = new Hono();\nadmin.post("/impersonate", async (c) => c.json(await impersonate(c.req.param("id"))));\napp.route("/admin", admin);\n',
      },
    ],
    tn: [
      {
        "server/routes/admin.ts":
          'import { Router } from "express";\nconst adminRouter = Router();\nadminRouter.use(requireAuth);\nadminRouter.post("/delete-user", async (req, res) => { await deleteUser(req.body.userId); res.json({ ok: true }); });\napp.use("/admin", adminRouter);\n',
      },
      {
        "server/index.ts":
          'import express from "express";\nconst app = express();\nconst adminRouter = express.Router();\napp.use("/admin", requireAuth, adminRouter);\nadminRouter.post("/users/:id/delete", async (req, res) => { await db.user.delete({ where: { id: req.params.id } }); res.json({ ok: true }); });\n',
      },
      {
        "server/hono.ts":
          'import { Hono } from "hono";\nconst admin = new Hono();\nadmin.use("*", requireAuth);\nadmin.post("/impersonate", async (c) => c.json(await impersonate(c.req.param("id"))));\napp.route("/admin", admin);\n',
      },
      {
        "server/health.ts":
          'const router = express.Router();\nrouter.get("/health", (_req, res) => res.send("ok"));\napp.use("/health", router);\n',
      },
    ],
  },
  {
    rule: "ss/supabase/rls-disabled",
    tp: [
      { "migrations/1.sql": "alter table t disable row level security;\n" },
      { "schema.sql": "ALTER TABLE users DISABLE ROW LEVEL SECURITY;\n" },
    ],
    tn: [
      { "migrations/1.sql": "alter table t enable row level security;\n" },
      { "notes.md": "Never disable row level security in production.\n" },
    ],
  },
  {
    rule: "ss/supabase/permissive-policy",
    tp: [
      { "migrations/1.sql": 'create policy "p" on t for all using (true);\n' },
      { "migrations/2.sql": 'create policy "p" on t with check (true);\n' },
    ],
    tn: [
      { "migrations/1.sql": 'create policy "p" on t using (auth.uid() = user_id);\n' },
      { "migrations/1.sql": "select * from t where active = true;\n" },
    ],
  },
  {
    rule: "ss/convex/mutation-no-auth",
    tp: [
      {
        "convex/items.ts":
          'import { mutation } from "./_generated/server";\nexport const add = mutation({ handler: async (ctx) => ctx.db.insert("t", {}) });\n',
      },
      {
        "convex/notes.js":
          'import { mutation } from "./_generated/server";\nexport const save = mutation({ handler: async (ctx) => ctx.db.insert("n", {}) });\n',
      },
    ],
    tn: [
      {
        "convex/items.ts":
          'import { mutation } from "./_generated/server";\nexport const add = mutation({ handler: async (ctx) => { const id = await ctx.auth.getUserIdentity(); } });\n',
      },
      {
        "convex/teams.ts":
          'import { mutation } from "./_generated/server";\nimport { requireInternalToken } from "./lib/internal_token";\nexport const upsertTeam = mutation({ handler: async (ctx, args) => { requireInternalToken(args.token); } });\n',
      },
      {
        "convex/features.ts":
          'import { mutation } from "./_generated/server";\nexport const update = mutation({ handler: async (ctx) => { const caller = await getCaller(ctx); } });\n',
      },
      {
        "convex/waitlist.ts":
          'import { mutation } from "./_generated/server";\nexport const join = mutation({ handler: async (ctx, args) => { const emailHash = normalizeEmail(args.email); await rateLimit(ctx, emailHash); } });\n',
      },
      {
        "convex/public.ts":
          'import { mutation } from "./_generated/server";\nexport const ping = mutation({ handler: async (ctx) => { /* seamshield-public */ await ctx.db.insert("events", {}); } });\n',
      },
      {
        "convex/public.ts":
          'import { mutation } from "./_generated/server";\nexport const join = mutation({ handler: async (ctx, args) => { await rateLimit(ctx, args.email); await ctx.db.insert("teamInvites", { teamId: args.teamId }); } });\n',
      },
      { "convex/queries.ts": 'import { query } from "./_generated/server";\nexport const list = query({});\n' },
    ],
  },
  {
    rule: "ss/convex/public-function-no-auth",
    tp: [
      {
        "convex/tasks.ts":
          'import { action } from "./_generated/server";\nexport const recomputeForDay = action({ handler: async (ctx, args) => { await ctx.db.patch(args.id, { done: true }); } });\n',
      },
      {
        "convex/teams.ts":
          'import { mutation } from "./_generated/server";\nexport const invite = mutation({ handler: async (ctx, args) => { await ctx.db.insert("teamInvites", { teamId: args.teamId }); } });\n',
      },
      {
        "convex/audit.ts":
          'import { query } from "./_generated/server";\nexport const noteTenantMismatch = query({ handler: async (ctx, args) => ctx.db.query("tenant").collect() });\n',
      },
    ],
    tn: [
      {
        "convex/tasks.ts":
          'import { action } from "./_generated/server";\nexport const recomputeForDay = action({ handler: async (ctx, args) => { /* seamshield-public */ return null; } });\n',
      },
      {
        "convex/waitlist.ts":
          'import { mutation } from "./_generated/server";\nexport const join = mutation({ handler: async (ctx, args) => { const emailHash = normalizeEmail(args.email); await rateLimit(ctx, emailHash); await ctx.db.insert("waitlist", { emailHash }); } });\n',
      },
      {
        "convex/teams.ts":
          'import { mutation } from "./_generated/server";\nexport const invite = mutation({ handler: async (ctx, args) => { const identity = await ctx.auth.getUserIdentity(); await ctx.db.insert("teamInvites", {}); } });\n',
      },
      {
        "convex/helpers.ts":
          'export async function listTeams(ctx) { return ctx.db.query("teams").collect(); }\n',
      },
      {
        "convex/internal.ts":
          'import { internalMutation } from "./_generated/server";\nexport const sync = internalMutation({ handler: async (ctx) => ctx.db.insert("jobs", {}) });\n',
      },
    ],
  },
  {
    rule: "ss/convex/tenant-bound-write",
    tp: [
      {
        "convex/teams.ts":
          'import { mutation } from "./_generated/server";\nexport const invite = mutation({ handler: async (ctx, args) => { await ctx.db.insert("teamInvites", { teamId: args.teamId, email: args.email }); } });\n',
      },
      {
        "convex/projects.ts":
          'import { mutation } from "./_generated/server";\nexport const rename = mutation({ handler: async (ctx, args) => { await ctx.db.patch(args.projectId, { orgId: args.orgId, name: args.name }); } });\n',
      },
    ],
    tn: [
      {
        "convex/teams.ts":
          'import { mutation } from "./_generated/server";\nexport const invite = mutation({ handler: async (ctx, args) => { const identity = await ctx.auth.getUserIdentity(); await requireTeamMember(ctx, identity.subject, args.teamId); await ctx.db.insert("teamInvites", { teamId: args.teamId }); } });\n',
      },
      {
        "convex/internal.ts":
          'import { internalMutation } from "./_generated/server";\nexport const sync = internalMutation({ handler: async (ctx, args) => ctx.db.insert("teams", { teamId: args.teamId }) });\n',
      },
    ],
  },
  {
    rule: "ss/convex/internal-not-internal",
    tp: [
      { "convex/jobs.ts": "export const internalCleanup = mutation({});\n" },
      { "convex/sync.ts": "const internalSync = action({});\n" },
    ],
    tn: [
      { "convex/jobs.ts": "export const internalCleanup = internalMutation({});\n" },
      { "src/jobs.ts": "export const internalCleanup = mutation({});\n" },
    ],
  },
  {
    rule: "ss/vercel/config-access-risk",
    tp: [
      {
        "vercel.json": JSON.stringify({
          env: { [j("NEXT_PUBLIC_", "ADMIN_API_KEY")]: "x" },
        }),
      },
      {
        "vercel.json": JSON.stringify({
          headers: [
            {
              source: "/api/(.*)",
              headers: [
                { key: "Access-Control-Allow-Origin", value: "*" },
                { key: "Access-Control-Allow-Credentials", value: "true" },
              ],
            },
          ],
        }),
      },
      {
        "vercel.json": JSON.stringify({
          rewrites: [{ source: "/admin/:path*", destination: "/api/admin/:path*" }],
        }),
      },
      {
        "vercel.json": JSON.stringify({
          rewrites: [{ source: "/admin/:path*", destination: "/api/admin/:path*" }],
        }),
        "middleware.ts":
          'import { auth } from "@clerk/nextjs/server";\nexport const config = { matcher: ["/dashboard/:path*"] };\nexport default function middleware() { auth(); }\n',
      },
      {
        "vercel.json": JSON.stringify({
          crons: [{ path: "/api/internal/recompute", schedule: "0 0 * * *" }],
        }),
      },
    ],
    tn: [
      {
        "vercel.json": JSON.stringify({
          env: { SERVER_ADMIN_API_KEY: "x" },
        }),
      },
      {
        "vercel.json": JSON.stringify({
          rewrites: [{ source: "/admin/:path*", destination: "/api/admin/:path*" }],
          headers: [{ source: "/admin/:path*", headers: [{ key: "Authorization", value: "required" }] }],
        }),
      },
      {
        "vercel.json": JSON.stringify({
          rewrites: [{ source: "/admin/:path*", destination: "/api/admin/:path*" }],
        }),
        "middleware.ts":
          'import { auth } from "@clerk/nextjs/server";\nexport const config = { matcher: ["/admin/:path*", "/api/admin/:path*"] };\nexport default function middleware() { auth(); }\n',
      },
    ],
  },
  {
    rule: "ss/next/server-action-trusted-client",
    tp: [
      {
        "app/actions.ts":
          "'use server';\nexport async function deleteUser(formData) { const role = formData.get('role'); const userId = formData.get('userId'); if (role === 'admin') await db.user.delete({ where: { id: userId } }); }\n",
      },
      {
        "app/team/actions.ts":
          "'use server';\nexport async function invite(data) { await prisma.invite.create({ data: { orgId: data.orgId, role: data.role } }); }\n",
      },
    ],
    tn: [
      {
        "app/actions.ts":
          "'use server';\nexport async function deleteUser(formData) { const caller = await auth(); await requireAdmin(caller.userId); const userId = formData.get('userId'); await db.user.delete({ where: { id: userId } }); }\n",
      },
      {
        "app/actions.ts":
          "'use server';\nexport async function updateName(formData) { const name = formData.get('name'); await db.profile.update({ data: { name } }); }\n",
      },
    ],
  },
  {
    rule: "ss/firebase/open-rules",
    tp: [
      { "firestore.rules": "match /{d=**} {\n  allow read, write: if true;\n}\n" },
      { "storage.rules": "allow write: if true;\n" },
    ],
    tn: [
      { "firestore.rules": "allow read: if request.auth != null;\n" },
      { "rules.md": "allow read, write: if true;\n" },
    ],
  },
  {
    rule: "ss/agent/secrets-in-agent-files",
    tp: [
      { "CLAUDE.md": `Key: ${j("sk-ant-", "api03-TESTAGENTKEY0000000000")}\n` },
      { ".cursor/rules/main.mdc": `token ${j("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")}\n` },
    ],
    tn: [
      { "CLAUDE.md": "Read the key from the ANTHROPIC_API_KEY env var.\n" },
      { "notes.txt": `Key: ${j("sk-ant-", "api03-TESTAGENTKEY0000000000")}\n` },
    ],
  },
  {
    rule: "ss/agent/mcp-inline-credentials",
    tp: [
      { ".mcp.json": `{ "env": { "GITHUB_TOKEN": "inline-literal-value-123" } }\n` },
      { "claude_desktop_config.json": `{ "env": { "API_KEY": "another-literal-cred-456" } }\n` },
      { ".mcp.json": `{ "mcpServers": { "demo": { "args": ["--api-key=inline-literal-value-123456"] } } }\n` },
      { "mcp.json": `{ "mcpServers": { "demo": { "args": ["API_TOKEN=inline-literal-value-123456"] } } }\n` },
    ],
    tn: [
      { ".mcp.json": `{ "env": { "GITHUB_TOKEN": "\${GITHUB_TOKEN}" } }\n` },
      { ".mcp.json": `{ "mcpServers": { "demo": { "args": ["--api-key=\${GITHUB_TOKEN}", "API_TOKEN=\${API_TOKEN}"] } } }\n` },
      { "config.json": `{ "env": { "GITHUB_TOKEN": "inline-literal-value-123" } }\n` },
    ],
  },
  {
    rule: "ss/agent/overbroad-permissions",
    tp: [
      { ".claude/settings.json": `{ "permissions": { "allow": ["Bash(*)"] } }\n` },
      { ".claude/settings.local.json": `{ "defaultMode": "bypassPermissions" }\n` },
    ],
    tn: [
      { ".claude/settings.json": `{ "permissions": { "allow": ["Bash(npm test:*)"] } }\n` },
      { "settings.json": `{ "permissions": { "allow": ["Bash(*)"] } }\n` },
    ],
  },
  {
    rule: "ss/agent/risky-filesystem-permissions",
    tp: [
      { ".mcp.json": `{ "filesystem": { "write": [".env.local"] } }\n` },
      { ".cursor/rules/tools.mdc": `{ "roots": ["**"] }\n` },
      { ".claude/settings.json": `{ "paths": ["~/.ssh"] }\n` },
    ],
    tn: [
      { ".mcp.json": `{ "filesystem": { "write": ["src/generated"] } }\n` },
      { "tools.json": `{ "roots": ["**"] }\n` },
    ],
  },
  {
    rule: "ss/ai/public-provider-key",
    tp: [
      { ".env": `${j("NEXT_PUBLIC_", "OPENAI_API_KEY")}=sk-test\n` },
      { "src/config.ts": `const key = "${j("VITE_", "ANTHROPIC_API_KEY")}";\n` },
      { "vercel.json": `{ "env": { "${j("NEXT_PUBLIC_", "GEMINI_API_KEY")}": "x" } }\n` },
    ],
    tn: [
      { ".env": `${j("OPENAI_", "API_KEY")}=sk-test\n` },
      { "src/config.ts": `const name = "NEXT_PUBLIC_BASE_URL";\n` },
    ],
  },
  {
    rule: "ss/ai/untrusted-model-base-url",
    tp: [
      { ".env": `${j("OPENAI_", "BASE_URL")}=${j("https://models", ".example.test/v1")}\n` },
      { "src/ai.ts": `const client = new OpenAI({ ${j("base", "URL")}: "${j("https://proxy", ".example.test/v1")}" });\n` },
    ],
    tn: [
      { ".env": `${j("OPENAI_", "BASE_URL")}=https://api.openai.com/v1\n` },
      { "src/ai.ts": `const client = new OpenAI({ ${j("base", "URL")}: "https://api.openai.com/v1" });\n` },
      { "src/ai.ts": `const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n` },
    ],
  },
  {
    rule: "ss/deps/unpinned-spec",
    tp: [
      { "package.json": `{ "dependencies": { "left-pad": "latest" } }\n`, ...LOCK },
      { "package.json": `{ "dependencies": { "lodash": "*" } }\n`, ...LOCK },
    ],
    tn: [
      { "package.json": `{ "dependencies": { "lodash": "^4.17.21" } }\n`, ...LOCK },
      { "deps.json": `{ "lodash": "latest" }\n` },
    ],
  },
];

describe.each(cases)("$rule", ({ rule, tp, tn }) => {
  it("fires on true positives", () => {
    for (const files of tp) {
      const hits = scanFiles(files).filter((h) => h.startsWith(rule));
      expect(hits, `expected ${rule} in ${Object.keys(files).join(",")}`).not.toEqual([]);
    }
  });
  it("stays quiet on true negatives", () => {
    for (const files of tn) {
      const hits = scanFiles(files).filter((h) => h.startsWith(rule));
      expect(hits, `unexpected ${rule} in ${Object.keys(files).join(",")}`).toEqual([]);
    }
  });
});

describe("ss/deps/no-lockfile", () => {
  it("fires when package.json has no lockfile anywhere up the tree", () => {
    const hits = scanFiles({ "package.json": `{ "name": "x" }\n` });
    expect(hits).toContain("ss/deps/no-lockfile@package.json");
  });
  it("stays quiet when a lockfile is present", () => {
    const hits = scanFiles({ "package.json": `{ "name": "x" }\n`, ...LOCK });
    expect(hits.filter((h) => h.startsWith("ss/deps/no-lockfile"))).toEqual([]);
  });
});

describe("ss/deps/package-manager-drift", () => {
  it("fires when packageManager and lockfile disagree", () => {
    const hits = scanFiles({
      "package.json": '{\n  "packageManager": "pnpm@11.6.0",\n  "dependencies": { "left-pad": "^1.3.0" }\n}\n',
      "package-lock.json": "{}\n",
    });
    expect(hits).toContain("ss/deps/package-manager-drift@package.json");
  });

  it("fires when multiple root lockfiles compete", () => {
    const hits = scanFiles({
      "package.json": '{ "dependencies": { "left-pad": "^1.3.0" } }\n',
      "pnpm-lock.yaml": "lockfileVersion: 9\n",
      "package-lock.json": "{}\n",
    });
    expect(hits).toContain("ss/deps/package-manager-drift@package.json");
  });

  it("stays quiet for a matching declared manager and lockfile", () => {
    const hits = scanFiles({
      "package.json": '{ "packageManager": "pnpm@11.6.0", "dependencies": { "left-pad": "^1.3.0" } }\n',
      "pnpm-lock.yaml": "lockfileVersion: 9\n",
    });
    expect(hits.filter((h) => h.startsWith("ss/deps/package-manager-drift"))).toEqual([]);
  });
});
