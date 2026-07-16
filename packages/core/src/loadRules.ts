import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { z } from "zod";
import type { Rule } from "./types.js";

const PatternSchema = z.object({
  name: z.string().min(1),
  regex: z.string().min(1),
});

const BuiltinSchema = z.enum([
  "env-file-committed",
  "no-lockfile",
  "package-manager-drift",
  "hallucinated-package",
  "known-vuln",
  "convex-public-function-no-auth",
  "convex-tenant-bound-write",
  "next-server-action-trusted-client",
  "server-grouped-router-boundary",
  "webhook-signature-boundary",
  "vercel-config",
]);

const RuleSchema = z.object({
  id: z.string().regex(/^ss\/[a-z-]+\/[a-z0-9-]+$/),
  severity: z.enum(["block", "high", "warn", "info"]),
  title: z.string().min(1),
  description: z.string().min(1),
  framework_ref: z.string().min(1),
  check: z.object({
    type: z.enum(["regex", "absence", "builtin"]),
    builtin: BuiltinSchema.optional(),
    include: z
      .object({
        extensions: z.array(z.string()).optional(),
        basenames: z.array(z.string()).optional(),
        path_contains: z.array(z.string()).optional(),
      })
      .optional(),
    exclude: z
      .object({
        basenames: z.array(z.string()).optional(),
        dirs: z.array(z.string()).optional(),
      })
      .optional(),
    file_contains: z.string().optional(),
    patterns: z.array(PatternSchema).optional(),
    patterns_from: z.string().optional(),
    redact: z.boolean().optional(),
  }),
  fix: z.object({
    summary: z.string().min(1),
    agent_prompt: z.string().min(1),
    doc_url: z.string().optional(),
  }),
});

const PatternFileSchema = z.object({ patterns: z.array(PatternSchema).min(1) });

export interface LoadedRules {
  rules: Rule[];
  /** sha256 over the sorted filenames + contents of every rule YAML in the pack. */
  policyBundleDigest: string;
}

export function loadRules(rulesDir: string): LoadedRules {
  const yamlFiles = readdirSync(rulesDir)
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))
    .sort();
  if (yamlFiles.length === 0) {
    throw new Error(`no rule YAML files found in ${rulesDir}`);
  }

  const hash = createHash("sha256");
  const contents = new Map<string, string>();
  for (const name of yamlFiles) {
    const text = readFileSync(join(rulesDir, name), "utf8");
    contents.set(name, text);
    hash.update(name);
    hash.update("\n");
    hash.update(text);
    hash.update("\n");
  }

  const rules: Rule[] = [];
  for (const [name, text] of contents) {
    const doc: unknown = parse(text);
    // Files without an `id` key (e.g. shared pattern packs) are not rules.
    if (typeof doc !== "object" || doc === null || !("id" in doc)) continue;
    const rule = RuleSchema.parse(doc);
    if (rule.check.patterns_from) {
      const source = contents.get(rule.check.patterns_from);
      if (!source) {
        throw new Error(
          `${name}: patterns_from references missing file ${rule.check.patterns_from}`,
        );
      }
      const shared = PatternFileSchema.parse(parse(source));
      rule.check.patterns = [...shared.patterns, ...(rule.check.patterns ?? [])];
    }
    if ((rule.check.type === "regex" || rule.check.type === "absence") && !rule.check.patterns?.length) {
      throw new Error(`${name}: ${rule.check.type} rule has no patterns`);
    }
    rules.push(rule);
  }
  return { rules, policyBundleDigest: hash.digest("hex") };
}
