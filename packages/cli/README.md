# SeamShield

Community local access-lane scanner/control engine for AI-built repositories.

SeamShield maps who or what can reach sensitive assets before you ship:
`Actor -> Lane -> Asset -> Permission -> Condition -> Risk`.

The CLI is the open-source Community surface. Run it locally, inspect it, block
network access, and verify source code does not leave your machine. Pro adds
the continuously updated intelligence layer and SeamShield Auth up to 100k MAU.
Enterprise adds private enforcement, governance, auditability, and usage-based
Auth. Website and platform UIs are outside this npm package.

## Install

```bash
npx @seamshield/cli init .
npx @seamshield/cli ship .
```

Or install globally:

```bash
npm install -g @seamshield/cli
seamshield ship .
```

Requires Node.js 20 or newer.

## Repository Coverage

SeamShield runs baseline local controls on every repository, regardless of the
language an AI IDE used to create it. Baseline coverage includes repository-wide
credential controls, AI-agent and MCP configuration checks, deployment metadata,
and JSON, SARIF, and NDJSON evidence output.

`seamshield inventory .` and `seamshield status .` detect repository markers
for JavaScript/TypeScript, Python, Go, Java, .NET, Ruby, PHP, and Rust. They
report the deeper access-lane adapters that actually ran. Framework-specific
analysis is currently deepest for Next.js, Convex, and generic Node servers.
An unfamiliar language remains protected by baseline controls; SeamShield does
not invent routes, authorization findings, or coverage it has not verified.

## Commands

```bash
seamshield init .
seamshield ship .
seamshield access . --format table
seamshield access . --format json
seamshield access . --format ndjson
seamshield scan . --offline
seamshield scan . --format ndjson --offline
seamshield inventory . --format json
seamshield inventory . --format ndjson
seamshield selftest
seamshield status .
seamshield status . --format json
seamshield offline export . --out /tmp/seamshield-handoff.json
seamshield offline import . --file /tmp/seamshield-handoff.json
seamshield investigate .
seamshield audit .
seamshield config init .
seamshield privacy .
seamshield privacy . --format json
seamshield fix-plan . --agent codex
seamshield test-plan . --agent codex
seamshield agent-context . --all
seamshield triage . --rule ss/auth/client-only-guard
seamshield agent-context . --codex
seamshield agent-context . --claude
seamshield agent-context . --cursor
seamshield guard install .
seamshield guard status .
seamshield ci install .
seamshield ci status .
seamshield deploy-gate verify --commit "$SEAMSHIELD_DEPLOY_COMMIT"
seamshield doctor .
seamshield release verify .
seamshield learn
```

## Init

```bash
seamshield init .
seamshield init . --agents codex,cursor
seamshield init . --no-agent-context --no-guard --no-ci
```

Bootstraps SeamShield in a repo. It writes `.seamshield/config.yaml`, generates
portable agent context for every supported AI IDE with `agent-context --all` by
default, installs the native Claude Code guard when that hook is configured,
writes GitHub and GitLab CI templates, runs the first offline ship check,
writes a Markdown investigation, and prints the next command to run.

Use `--agents <list>` to write only selected local agent context files. Supported
values are `codex`, `claude`, `cursor`, `gemini`, `cline`, `windsurf`,
`copilot`, `opencode`, or `all`. This only controls Community agent instruction
files; it does not enable Pro rulepacks or Enterprise policy services.

The GitHub Actions workflow runs:

```bash
npx @seamshield/cli ship . --offline
```

and uploads `.seamshield/investigations/` as an artifact on failure.

Install or refresh just the CI workflow without changing agent context or guard
files:

```bash
seamshield ci install .
seamshield ci status . --format json
```

`ci status` reports whether the Community GitHub Actions workflow exists, runs
the offline ship check, and uploads SeamShield investigations on failure.

`status` shows local setup, the connected project and primary domain when a
connection has been made, the latest metadata receipt, and the next action.
`offline export` and `offline import` move local scan/inventory handoffs without
network access. They are local files only and are separate from the primary
authenticated project connection.

## Connect A Provisioned Project

In Platform Build, create a project and generate its one-time connection
command. Run that command from the repository root:

```bash
npx @seamshield/cli connect . --token ssconn_...
```

The command defaults to the SeamShield production API. Set
`SEAMSHIELD_API_URL` or pass `--api-url` only when connecting to a self-hosted,
staging, or other non-production deployment. It sends bounded scan and package
metadata only; source, secrets, diffs, and absolute paths stay local.

For paid and trial projects, the same one-time command also detects GitHub
Actions, GitLab CI, Bitbucket Pipelines, Azure Pipelines, or CircleCI and
installs a continuous Build and Guard job. CI uses its provider OIDC identity
to obtain a ten-minute metadata-only SeamShield credential; it does not store a
long-lived SeamShield server key. GitHub and gitlab.com activate directly.
Bitbucket, Azure, CircleCI, and generic CI activate after their provider
integration supplies the immutable project identity, issuer, and audience.

The generated paid job writes local fix and test plans, runs the ship gate, and
synchronizes bounded scan, dependency, release, and Guard metadata. Critical
lanes fail the job. Remediation is agent-assisted and still requires customer
approval before code is merged.

### Private GitHub repositories without branch protection

GitHub Actions and OIDC work on private repositories without an upgraded plan.
Some GitHub plans cannot enforce required status checks on a private default
branch; SeamShield does not claim that those merges are blocked. Instead, the
generated `.github/workflows/seamshield.yml` is a reusable deployment gate.
Make the production deploy job depend on it:

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  seamshield:
    uses: ./.github/workflows/seamshield.yml
  deploy:
    needs: seamshield
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy-production.sh
```

The gate records a short-lived OIDC-backed receipt for the commit. A blocked
SeamShield job prevents the dependent deploy job from running. This protects
production deployment, but cannot stop someone from merging directly into an
unprotected branch.

### Coolify and DevPush deployment gate

For a host that deploys directly from GitHub, add one pre-deployment command to
the host configuration. Store these values in the host's encrypted secret
manager, never in repository files:

```text
SEAMSHIELD_API_URL=https://platform.seamshield.com/api
SEAMSHIELD_PROJECT_ID=project_...
SEAMSHIELD_SERVER_KEY=sssk_...
SEAMSHIELD_DEPLOY_COMMIT=<the deployment provider's immutable commit SHA>
SEAMSHIELD_DEPLOY_BRANCH=main
```

Use this pre-deploy command:

```bash
npx @seamshield/cli deploy-gate verify --environment production --commit "$SEAMSHIELD_DEPLOY_COMMIT" --branch "$SEAMSHIELD_DEPLOY_BRANCH"
```

The command checks a signed passing Build and Guard receipt for that exact
commit and fails closed for a missing, blocked, branch-mismatched, or expired
receipt. It returns only receipt metadata. Coolify or DevPush must expose their
immutable deployment commit as `SEAMSHIELD_DEPLOY_COMMIT` and branch as
`SEAMSHIELD_DEPLOY_BRANCH`; do not substitute a branch name or a mutable tag for
the commit. This protects a deployment even when GitHub cannot enforce branch
checks for a private repository.

Connected paid and trial syncs also check for signed Security Agent jobs. The
CLI accepts only project-scoped, short-lived jobs from a fixed operation
allowlist, prepares approved remediation locally, and returns metadata-only
receipts for later verification. Repository source, diffs, secrets, prompts,
and model output remain on the customer machine.

## Config

```bash
seamshield config init .
```

Writes only `.seamshield/config.yaml`. It does not write agent files, install
guard hooks, add CI, run a scan, or create investigations.

## Doctor

```bash
seamshield doctor .
seamshield doctor . --format json
```

Runs a local Community health check for official package scope, config,
source-private defaults, guard status, CI status, agent context, and package
rule artifact integrity. It does not call paid intelligence feeds or managed
policy services.

## Release Verify

```bash
seamshield release verify .
seamshield release verify . --format json
```

Checks Community package release hygiene before publish: official
`@seamshield/cli` scope, `https://seamshield.com` homepage, `bin.seamshield`,
package file allowlist, duplicate generated rule files, `npm pack --dry-run`,
and npm dist-tags when the registry is reachable. It does not publish or enable
Pro/Enterprise distribution.

## Ship Verdict

```bash
seamshield ship .
seamshield ship . --offline
```

Runs locally and prints `SAFE TO SHIP` only when there are no block or high
unsafe-to-ship access-lane risks found by the controls that ran. Use this
before deploys; it does not replace a security review.

By default, `ship` also writes a Markdown investigation under
`.seamshield/investigations/` so new repos have a durable review artifact.

## Access Map

```bash
seamshield access . --format json
```

Outputs normalized access lanes while preserving provider-specific evidence.
Supported surfaces include Next.js/API routes, Supabase, Firebase/Firestore,
Convex, Vercel/Coolify/self-hosted deploy config, generic Node servers, AI
agent config, and package supply-chain risks.

Community checks stay local/offline and include suspicious MCP or agent
permissions, exposed public AI provider keys, unofficial model base URLs,
dangerous install lifecycle scripts, and risky agent filesystem access. Signed
intelligence feeds, advisory-to-control updates, and organization policy
rollouts remain Pro or Enterprise surfaces.

Convex coverage includes public function checks for sensitive queries,
mutations, and actions without recognized auth/internal guards, tenant/org
writes that trust caller-provided ids without membership proof, and safer
handling for explicitly public low-risk mutations. Vercel coverage includes
`vercel.json` public env secrets, wildcard credentialed CORS, privileged route
and cron surfaces, and middleware matcher gaps for admin/internal rewrites.
Next.js coverage includes server actions that trust role, tenant, org, team,
workspace, account, or user id values from client-controlled input.

## Scan

```bash
seamshield scan .
seamshield scan . --format json
seamshield scan . --format sarif
seamshield scan . --format ndjson
seamshield scan . --fail-on high
seamshield scan . --offline
seamshield scan . --no-investigation
seamshield scan . --profile community
```

Exit codes:

- `0` - no findings at or above the selected threshold.
- `1` - findings at or above the selected threshold.
- `2` - CLI usage or scanner failure.

`--offline` disables npm registry and OSV checks. Static rules still run.

`--profile community` is the default current-project scan. `workspace` and
`incident` require explicit `--root` paths so the Community CLI never broadens
scope into a home-directory sweep by accident.

NDJSON output emits one record per line and ends with a `scan_summary` record
for CI and collectors.

By default, `scan` writes `.seamshield/investigations/<date>-access-lanes.md`
and prints the path to stderr so JSON/SARIF stdout remains parseable. Use
`--no-investigation` for CI jobs that should not write files.

## Investigations

```bash
seamshield investigate .
```

Writes a Markdown investigation summarizing the ship verdict, severity/provider
breakdowns, normalized access lanes, and suggested next commands. This is meant
to make findings understandable in a fresh repo without uploading source code.

## Audit Bundle

```bash
seamshield audit .
seamshield audit . --format json
```

Writes `.seamshield/audits/<date>-local-audit/` with `architecture.md`,
`REPORT.md`, `FINDINGS-DETAIL.md`, `findings.json`, and `report-schema.json`.
Community audit bundles are local and source-private. They structure current
access-lane findings for human review; Pro and Enterprise verification,
approval, signed custody, and audit workflows stay outside the Community
package.

## Inventory

```bash
seamshield inventory .
seamshield inventory . --format json
seamshield inventory . --format ndjson
```

Reads local metadata only: package manifests/lockfiles, supported MCP JSON
configs, agent skill lock files, editor extension manifests, and deploy config.
It does not execute package managers, install dependencies, read arbitrary
source files, upload source, or emit credential values from MCP/env blocks.

Inventory records include confidence:

- `high` - lockfile or installed metadata.
- `medium` - manifest package/version metadata.
- `low` - config/path reference.

## Selftest

```bash
seamshield selftest
```

Runs embedded fake fixtures in a temporary directory with no network calls. It
verifies access-lane detection, dependency lifecycle detection, redaction,
inventory records, and investigation-safe output for the installed CLI.

## Triage

```bash
seamshield triage . --rule ss/auth/client-only-guard
```

Persists current false-positive decisions into `.seamshield/config.yaml` as
exact rule/file/line suppressions. Block findings are not triaged unless
`--include-block` is provided.

## Fix Plans

```bash
seamshield fix-plan . --agent claude
seamshield fix-plan . --agent cursor
seamshield fix-plan . --agent codex
seamshield fix-plan . --agent generic
```

Writes `.seamshield/fix-plan.json` and a Markdown plan under
`.seamshield/fix-plans/` with redacted findings and provider-aware prompts.

## Test Plans

```bash
seamshield test-plan . --agent codex
seamshield test-plan . --agent generic
```

Writes `.seamshield/test-plan.json` and a Markdown plan under
`.seamshield/test-plans/` with regression-test prompts for risky access lanes.
Use this after `fix-plan` so repaired auth, database, deploy, dependency, and
agent guard boundaries do not reopen.

## Agent Guard

```bash
seamshield agent-context . --codex
seamshield agent-context . --claude
seamshield agent-context . --cursor
seamshield agent-context . --gemini
seamshield agent-context . --cline
seamshield agent-context . --windsurf
seamshield agent-context . --copilot
seamshield agent-context . --opencode
seamshield agent-context . --all
seamshield guard install .
seamshield guard status . --format json
```

`agent-context --codex` writes `AGENTS.md`. `--claude` writes `CLAUDE.md`.
`--cursor` writes `.cursor/rules/seamshield.mdc`. Additional adapters write
`GEMINI.md`, `.clinerules/seamshield.md`,
`.windsurf/rules/seamshield.md`, `.github/copilot-instructions.md`, and
`.opencode/AGENTS.md`. Use `--all` to generate every supported adapter from
the same SeamShield rule body.

`guard install` adds the currently supported native Claude Code `PreToolUse`
hook that blocks
high-confidence risky edits such as committed dotenv files, exposed server
secrets, public database/storage writes, unsafe `.env` edits, dangerous shell
installs, and obvious privileged route exposure.

Guard behavior is fail-open: if the hook errors, it allows the tool call and
appends diagnostics to `.seamshield/guard.log`.

`guard status` reports whether the native Claude Code hook is installed,
whether it is parseable, which matcher is configured, and whether the hook
points at the current SeamShield binary.

## Configuration

Create `.seamshield/config.yaml`:

```yaml
ignore:
  - vendored/**
suppress:
  - rule: ss/auth/client-only-guard
    file: app/dashboard/page.tsx
    line: 42
    reason: server-side route enforces auth
rules:
  disable:
    - ss/auth/client-only-guard
```

Suppress a single finding inline:

```ts
// seamshield-ignore ss/secrets/hardcoded-provider-key
const fixtureKey = "sk_live_test_fixture_only";
```

## Privacy

```bash
seamshield privacy .
seamshield privacy . --format json
```

SeamShield runs locally. Static scanning does not transmit source code.

Network dependency checks send package names and versions to the npm registry
and OSV. Use `--offline` or avoid `--online` on `ship` and `access` to keep the
run fully local.

Secret evidence is redacted before findings, JSON, SARIF, and fix plans are
emitted.

`learn` is currently a no-upload stub. SeamShield does not auto-update or run
untrusted community rules.

## Release Trust

Install from the official npm package:

```bash
npx @seamshield/cli ship .
npm install -g @seamshield/cli
```

For release audits, use npm tarball integrity/checksum metadata and prefer the
documented package entrypoint over forks or republished packages. Signed
rulepack distribution is reserved for a future commercial/control-plane layer.
