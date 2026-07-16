# SeamShield Build Checklist

This checklist tracks the next product build steps for the Community scanner
and the open-core boundary. Website, console, and commercial product surfaces
are tracked separately in `docs/PLATFORM_BUILD_CHECKLIST.md`; do not ship Pro
or Enterprise controls inside the Community npm package.

## Current Baseline

- [x] Access-lane scan engine
- [x] `ship`
- [x] `access`
- [x] `fix-plan`
- [x] `test-plan`
- [x] `privacy`
- [x] `investigate`
- [x] `audit`
- [x] `init`
- [x] `ci install`
- [x] `guard install`
- [x] Portable agent context for Codex, Claude, Cursor, Gemini, Cline,
  Windsurf, GitHub Copilot, and OpenCode
- [x] Convex and Vercel Community adapters
- [x] Open-core docs and Community / Pro / Enterprise boundary

## Next Community Builds

These items are Community-safe: they inspect or generate local scanner,
guard, CI, config, and report artifacts. Do not add paid control feeds,
premium rules, managed dashboards, policy servers, or Auth runtime features to
the Community package.

- [x] `guard status`: report installed guard coverage, supported agent hooks,
  and whether local guard files point at the current SeamShield binary.
- [x] `ci status`: report whether `.github/workflows/seamshield.yml` exists,
  whether it runs `npx @seamshield/cli ship . --offline`, and whether
  investigations are uploaded on failure.
- [x] `doctor`: combined local health check for package version, config,
  offline behavior, guard, CI, agent context, rule artifact integrity, and npm
  package scope.
- [x] `init --agents <list>`: allow targeted agent context generation instead
  of always writing all supported adapters.
- [x] Better investigation markdown: add remediation checklist sections,
  false-positive triage prompts, and copy-paste next commands.
- [x] Standalone `config init`: write `.seamshield/config.yaml` without agent,
  guard, CI, or scan side effects.
- [x] Release verification command: inspect installed package metadata, tarball
  contents, and official package scope.

## Adapter Depth

Adapter depth must stay split by tier. Community can improve deterministic
local checks that do not require paid intelligence feeds. Pro-only work covers
premium rules, advanced scoring, and CVE-to-control updates. Enterprise-only
work covers policy servers, approvals, audit workflows, internal mirrors, and
organization governance.

- [x] Convex: detect tenant-bound writes that trust caller-provided tenant/org
  IDs without server-side membership proof.
- [x] Convex: distinguish intentionally public, rate-limited, low-risk
  mutations from privileged public mutations more precisely.
- [x] Vercel: detect protected route gaps between middleware matchers,
  rewrites, and privileged app/API paths.
- [x] Next.js: detect server actions trusting role, tenant, org, or user ID from
  form data or client state.
- [x] Self-hosted servers: improve Express/Fastify/Hono middleware boundary
  detection for grouped routers.
- [x] Dependencies: add stronger lockfile and package-manager drift checks.

## Release Discipline

- [x] Keep package publishing only under `@seamshield/cli`.
- [x] Keep npm README focused on the Community scanner; product tier strategy
  stays in repo docs, not the package README.
- [x] Before every publish, verify `pnpm pack --dry-run` has no duplicate
  generated rule files.
- [x] After every publish, verify `npm dist-tag ls @seamshield/cli` and smoke
  the exact published version from `/tmp`.
- [x] Automate Community CLI releases from `cli-v<version>` tags through GitHub
  Actions. The workflow builds, tests, verifies package contents and scope,
  publishes only `@seamshield/cli` with npm provenance, and smoke-tests the
  exact published version. Manual dispatch supports a non-publishing dry run;
  publishing requires explicit confirmation.
