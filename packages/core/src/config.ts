import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { z } from "zod";

const ConfigSchema = z.object({
  ignore: z.array(z.string()).optional(),
  suppress: z
    .array(
      z.object({
        rule: z.string().min(1),
        file: z.string().min(1),
        line: z.number().int().positive().optional(),
        reason: z.string().optional(),
      }),
    )
    .optional(),
  rules: z.object({ disable: z.array(z.string()).optional() }).optional(),
});

export interface ScanConfig {
  ignorePrefixes: string[];
  disabledRules: Set<string>;
  suppressions: ConfigSuppression[];
}

export interface ConfigSuppression {
  rule: string;
  file: string;
  line?: number;
  reason?: string;
}

const EMPTY: ScanConfig = { ignorePrefixes: [], disabledRules: new Set(), suppressions: [] };

/** Reads `.seamshield/config.yaml` from the scan root, if present. */
export function loadConfig(root: string): ScanConfig {
  let text: string;
  try {
    text = readFileSync(join(root, ".seamshield", "config.yaml"), "utf8");
  } catch {
    return EMPTY;
  }
  const parsed = ConfigSchema.parse(parse(text) ?? {});
  return {
    ignorePrefixes: (parsed.ignore ?? []).map((p) =>
      p.replace(/\/\*{1,2}$/, "").replace(/\/$/, ""),
    ),
    disabledRules: new Set(parsed.rules?.disable ?? []),
    suppressions: parsed.suppress ?? [],
  };
}

/** Prefix match on path segments: `examples` ignores `examples/anything`. */
export function isIgnored(rel: string, prefixes: string[]): boolean {
  return prefixes.some((p) => rel === p || rel.startsWith(`${p}/`));
}

export function isSuppressedByConfig(
  ruleId: string,
  rel: string,
  line: number,
  suppressions: ConfigSuppression[],
): boolean {
  return suppressions.some(
    (s) => s.rule === ruleId && s.file === rel && (s.line === undefined || s.line === line),
  );
}
