import { z } from "zod";
import type { Finding } from "./types.js";

/**
 * Runtime mirror of the Finding interface (and of
 * packages/rules/schemas/finding.schema.json). Tests validate every emitted
 * finding against this schema.
 */
export const FindingSchema = z.object({
  event_id: z.string().min(8),
  event_type: z.literal("scan.finding"),
  time: z.string().min(20),
  tenant: z.string().min(1),
  decision: z.enum(["deny", "scan"]),
  route: z.object({
    plane: z.literal("evidence"),
    lane: z.literal("cpu"),
    reason: z.array(z.string()).min(1),
  }),
  engines: z
    .array(
      z.object({
        name: z.string().min(1),
        version: z.string().min(1),
        role: z.string().optional(),
      }),
    )
    .min(1),
  provenance: z.object({
    policy_bundle_digest: z.string().regex(/^[a-f0-9]{64}$/),
  }),
  spans: z.array(
    z.object({
      start: z.number().int().min(1),
      end: z.number().int().min(1),
      label: z.string().min(1),
      evidence: z.string().min(1),
    }),
  ),
  finding: z.object({
    rule_id: z.string().regex(/^ss\/[a-z-]+\/[a-z0-9-]+$/),
    severity: z.enum(["block", "high", "warn", "info"]),
    title: z.string().min(1),
    file: z.string().min(1),
    line: z.number().int().min(1),
    fix: z.object({
      summary: z.string().min(1),
      agent_prompt: z.string().min(1),
      doc_url: z.string().optional(),
    }),
  }),
});

export function validateFinding(value: unknown): Finding {
  return FindingSchema.parse(value) as Finding;
}
