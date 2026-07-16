import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Absolute path to the directory of YAML rule files shipped with this
 * package. Resolves correctly from both src/ (tests) and dist/ (published).
 */
export const rulesDir = join(dirname(fileURLToPath(import.meta.url)), "..", "rules");

/** Absolute path to the derived finding JSON schema. */
export const findingSchemaPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "schemas",
  "finding.schema.json",
);
