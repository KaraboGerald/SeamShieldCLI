import { z } from "zod";

const CoverageStateSchema = z.enum(["supported", "review_required", "unknown"]);

export const CoverageContractSchema = z.object({
  schema: z.literal("seamshield.coverage-contract/v1"),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, "coverage_contract_invalid_version"),
  source_upload: z.literal(false),
  adapters: z.array(z.object({
    id: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, "coverage_contract_invalid_adapter_id"),
    languages: z.array(z.string()).min(1),
    checks: z.array(z.string()).min(1),
    confidence: z.enum(["high", "medium", "low"]),
    ship_suitability: CoverageStateSchema,
  })).min(1).superRefine((adapters, context) => {
    const ids = new Set<string>();
    for (const [index, adapter] of adapters.entries()) {
      if (ids.has(adapter.id)) {
        context.addIssue({ code: "custom", message: "coverage_contract_duplicate_adapter_id", path: [index, "id"] });
      }
      ids.add(adapter.id);
    }
  }),
  states: z.record(CoverageStateSchema, z.string().min(1)),
}).superRefine((contract, context) => {
  for (const state of CoverageStateSchema.options) {
    if (!contract.states[state]) {
      context.addIssue({ code: "custom", message: `coverage_contract_missing_${state}_state`, path: ["states", state] });
    }
  }
});

export type CoverageContract = z.infer<typeof CoverageContractSchema>;

/** Parse a public coverage claim before it is presented or released. */
export function parseCoverageContract(input: unknown): CoverageContract {
  return CoverageContractSchema.parse(input);
}
