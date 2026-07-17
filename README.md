# SeamShield Community CLI

The local-first, open-source access-lane scanner for AI-built repositories.

```bash
npx @seamshield/cli init .
npx @seamshield/cli ship .
```

The CLI maps `Actor -> Lane -> Asset -> Permission -> Condition`, writes local fix plans, and does not upload source code. The commercial Platform, Console, runtime services, customer data, and infrastructure are intentionally not part of this repository.

SeamShield applies baseline local controls to every repository and reports the
language and framework adapters it actually detects. It does not claim equal
semantic access-lane coverage across every ecosystem.

## Repository layout

- `packages/cli`: published `@seamshield/cli` package.
- `packages/core`: scan engine.
- `packages/rules`: open YAML rules and schemas.
- `examples`: deliberately vulnerable, fake-only test fixtures.

## Development

```bash
pnpm install
pnpm test
```

## Releases

Trusted publishing runs from `.github/workflows/release-cli.yml` on tags named `cli-v<package-version>`. Configure npm's trusted publisher for this repository and workflow before creating a release tag.

## Security boundary

Never add customer source, logs, credentials, private server configuration, deployment files, or commercial control-plane code here. Report security issues privately to `security@seamshield.com`.
