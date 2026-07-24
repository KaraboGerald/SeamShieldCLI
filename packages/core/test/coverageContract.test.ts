import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCoverageContract } from "../src/index.js";

const contractPath = fileURLToPath(new URL("../../../docs/COVERAGE_CONTRACT.v1.json", import.meta.url));

describe("coverage contract", () => {
  it("validates the published adapter matrix and its capability identifiers", () => {
    const contract = parseCoverageContract(JSON.parse(readFileSync(contractPath, "utf8")));

    expect(contract.version).toBe("1.0.0");
    expect(contract.source_upload).toBe(false);
    expect(contract.adapters.map((adapter) => adapter.id)).toEqual(expect.arrayContaining([
      "generic-server", "nextjs", "convex",
    ]));
  });

  it("rejects duplicate adapters and incomplete public state definitions", () => {
    expect(() => parseCoverageContract({
      schema: "seamshield.coverage-contract/v1",
      version: "1.0.0",
      source_upload: false,
      adapters: [
        { id: "nextjs", languages: ["TypeScript"], checks: ["middleware"], confidence: "high", ship_suitability: "supported" },
        { id: "nextjs", languages: ["TypeScript"], checks: ["actions"], confidence: "high", ship_suitability: "supported" },
      ],
      states: { supported: "A check exists." },
    })).toThrow();
  });
});
