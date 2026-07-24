# SeamShield Product Strategy

**Product:** SeamShield, the access-risk control layer for AI-built software.

SeamShield protects access lanes across the full lifecycle of AI-built
software: while code is being written, before it ships, while agents change it,
while users and services interact with it, and after real-world incidents reveal
new control patterns.

The product is not a scanner, auth provider, CVE tracker, fraud dashboard, or
agent plugin. Those are surfaces. SeamShield is the shared access-risk control
layer behind them.

Core primitive:

```txt
Actor -> Device -> Session -> Lane -> Asset -> Action -> Condition -> Evidence -> Trust -> Decision
```

This repository contains the Community local scanner/control engine and the
framework contracts that guide the broader product. Website and platform UIs
are separate product surfaces and are not built in this package.

## Product Modules

**SeamShield Build** is build-time access-risk analysis. It maps dangerous lanes
in code, config, dependencies, auth logic, database rules, storage rules,
deploy settings, and agent config before release. Community commands include
`ship`, `access`, `fix-plan`, `test-plan`, `scan`, `investigate`, `inventory`,
`selftest`, and `privacy`.

**SeamShield Guard** is AI-agent edit-time enforcement. It asks whether an
agent change creates a new dangerous access lane, then allows, warns, blocks, or
feeds back a fix plan.

**SeamShield Auth** is runtime access provenance, device/session trust, and
fraud control. It sits beside existing auth providers first, consumes access and
session events, and decides whether to allow, step up, limit, revoke, or
investigate. SeamShield Auth is available in Pro up to `100k MAU` and in
Enterprise on usage-based terms.

**SeamShield Learn** converts CVEs, breaches, advisories, and abuse patterns
into local controls, guard rules, fix plans, and runtime decision rules. The
Community CLI exposes `learn` only as a local/no-upload stub. Commercial local
packs require an explicit signed manifest, trusted public key, entitlement,
channel, digest, and rollback-lineage verification before activation; the
hosted control plane records only distribution and rotation custody metadata.

**SeamShield Console** is the local, self-hosted, or enterprise control surface
for access maps, guard decisions, runtime trails, suppressions, policies,
control updates, and audit evidence. Console implementation is outside this
repo; the website and platform UI will be supplied separately.

## Tier Framework

Use only three product tiers:

```txt
Community
Pro
Enterprise
```

**Community** gives builders the local open-source safety check.

Included:

```txt
open-source CLI
local scan engine
access-lane IR
basic access map
basic ship check
basic fix-plan
basic test-plan
read-only inventory
embedded self-test
basic guard
offline mode
JSON/SARIF/table/NDJSON output
basic adapters
basic controls
privacy report
```

Best for:

```txt
Am I about to ship something obviously unsafe?
```

**Pro** gives serious builders the continuously updated intelligence layer.

Included:

```txt
everything in Community
advanced control packs
CVE-to-control intelligence feed
premium framework/provider rules
advanced fix-plan templates
advanced agent guard policies
weekly rule updates
private local rule bundles
deeper dependency risk checks
more precise access-risk scoring
SeamShield Auth up to 100k MAU
```

Best for:

```txt
I ship real products with AI and want stronger protection before users touch them.
```

**Enterprise** gives organizations private enforcement, governance, and
auditability.

Included:

```txt
everything in Pro
organization policy management
CI/CD enforcement
private rule mirrors
signed internal rule distribution
shared suppressions
approval workflows
audit logs
SSO/SAML
role-based access control
custom control packs
internal advisory mirrors
deployment inside customer infrastructure
compliance exports
priority support
usage-based SeamShield Auth
```

Best for:

```txt
We need AI-generated code security controls across the organization.
```

Product ladder:

```txt
Community = open local trust layer
Pro = paid local intelligence layer
Enterprise = private governance and enforcement layer
```

## Open-Core Boundary

Open source:

```txt
Community CLI
core engine
access-lane IR
basic adapters
basic controls
basic guard
privacy/offline mode
rule authoring format
SARIF/JSON output
```

Paid Pro:

```txt
advanced controls
CVE-to-control updates
premium adapters
advanced guard rules
advanced fix plans
local premium rulepacks
SeamShield Auth up to 100k MAU
```

Paid Enterprise:

```txt
private deployment
policy server
internal mirrors
CI enforcement
audit trails
SSO/RBAC
custom controls
compliance workflows
usage-based SeamShield Auth
```

Community runs locally by default. Static scanning does not upload source code.
Network-backed dependency intelligence is explicit and can be disabled with
offline mode.

## Positioning

Final tier language:

> Community gives you the local open-source safety check.
> Pro gives you the continuously updated intelligence layer.
> Enterprise gives your organization private enforcement, governance, and auditability.

Public claims should stay precise:

```txt
NO CRITICAL ACCESS RISKS FOUND
NEEDS REVIEW
UNSAFE TO SHIP
```

Do not claim broad whole-application protection. A clean ship verdict only means
no block or high unsafe-to-ship access lanes were found by the controls that
ran.

## Operating Principles

1. Keep source-private trust central: run locally, inspect the package, block
   network, and verify source never leaves the machine during Community scans.
2. Keep the repo boundary clear: scanner/control engine and framework contracts
   live here; commercial rulepacks, policy servers, and platform UIs live
   outside the npm scanner contract.
3. Keep controls agent-ready: findings should map to access lanes and generate
   safe prompts that do not weaken auth, database rules, storage rules, CORS, or
   secret handling.
4. Keep Auth adjacent first: SeamShield Auth consumes runtime events from
   existing identity systems before acting as a deeper access provenance layer.
5. Keep rule updates trustworthy: no automatic untrusted rule execution; signed
   distribution and private mirrors belong to paid product layers.
