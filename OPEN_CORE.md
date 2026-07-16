# SeamShield Open-Core Boundary

SeamShield uses open source as a trust surface. The local scanner/control engine
is intended to be inspectable, runnable offline, and verifiable by users who do
not want to send source code anywhere.

SeamShield has three product tiers:

```txt
Community
Pro
Enterprise
```

Community is the open local trust layer. Pro is the continuously updated
intelligence layer. Enterprise is private enforcement, governance, and
auditability.

## Community Open Source

The open-source scanner includes:

- CLI commands such as `ship`, `access`, `scan`, `inventory`, `selftest`,
  `fix-plan`, `triage`, `agent-context`, `guard`, `privacy`, and the
  local-only `learn` stub.
- Local scan engine, file walker, rule loader, finding IR, reporters, and
  redaction.
- Access-lane IR:
  `Actor -> Lane -> Asset -> Permission -> Condition -> Risk`.
- Basic controls and rule authoring format.
- Starter provider adapters for Next.js/API routes, Supabase,
  Firebase/Firestore, Convex, Vercel/Coolify/self-hosted deploy config, generic
  Node servers, agent config, secrets, and package supply-chain surfaces.
- JSON, SARIF, table, and NDJSON output.
- Read-only local inventory for package metadata, lockfiles, supported MCP
  configs, agent skill locks, editor extension manifests, and deploy metadata.
- Embedded self-test fixtures that verify the installed scanner without network
  calls.
- Offline mode and source-private default behavior.
- Local agent guard integrations.

## Pro

Pro layers are not part of the open-source scanner contract:

- Advanced controls and premium provider/framework adapters.
- CVE-to-control intelligence feeds.
- Advanced fix-plan templates and agent guard policies.
- Weekly rule updates and private local rule bundles.
- Deeper dependency risk checks and more precise access-risk scoring.
- SeamShield Auth up to `100k MAU`.

## Enterprise

Enterprise layers are not part of the open-source scanner contract:

- Private deployment and organization policy management.
- CI/CD enforcement, signed internal rule distribution, and internal mirrors.
- Shared suppressions, approval workflows, audit trails, and compliance
  exports.
- SSO/SAML, role-based access control, custom controls, and priority support.
- Usage-based SeamShield Auth.
- Platform and website UIs supplied outside this package.

## Language Contract

SeamShield should not claim that a project is secure. Use precise language:

- Good: `No critical unsafe-to-ship access lanes found.`
- Good: `SAFE TO SHIP means no block or high access-lane risks were found by the controls that ran.`
- Bad: broad whole-application safety claims.
- Bad: broad claims that no vulnerabilities exist.

## Rule Governance

Public rules are accepted only when they include:

- A clear access-lane failure model.
- True-positive and true-negative fixtures.
- Provider-specific evidence without exposing secrets.
- A fix prompt that does not weaken auth or move secrets into client-reachable
  code.

Community rules must not auto-update into user projects. Future signed rulepack
distribution must verify origin and integrity before local use.

## Release Trust

Users should install the official npm package and verify npm integrity/checksum
metadata when auditing a release. Forks can remove protections; the official
distribution should remain the documented installation path.
