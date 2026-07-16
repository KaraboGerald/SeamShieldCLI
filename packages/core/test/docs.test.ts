import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
const docs = [
  "README.md",
  "OPEN_CORE.md",
  "docs/BUILD_CHECKLIST.md",
  "docs/PRODUCT_STRATEGY.md",
  "packages/cli/README.md",
];
const bannedClaims = [
  ["your app", " is secure"].join(""),
  ["no vulnerabilities", " found"].join(""),
  ["protected from", " hackers"].join(""),
];
const bannedProductLanguage = [
  "mvp",
  "roadmap",
  "timeline",
  "seamshield cloud",
  "npx seamshield",
  "teams",
];

describe("public docs language", () => {
  it("does not promise general app security", () => {
    for (const rel of docs) {
      const text = readFileSync(join(repoRoot, rel), "utf8").toLowerCase();
      for (const claim of bannedClaims) {
        expect(text, `${rel} must not include "${claim}"`).not.toContain(claim);
      }
    }
  });

  it("uses full-product tier language instead of staged or old package language", () => {
    for (const rel of docs) {
      const text = readFileSync(join(repoRoot, rel), "utf8").toLowerCase();
      for (const phrase of bannedProductLanguage) {
        expect(text, `${rel} must not include "${phrase}"`).not.toContain(phrase);
      }
    }
  });
});
