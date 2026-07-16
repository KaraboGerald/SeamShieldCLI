import { createHash } from "node:crypto";

export function stableId(prefix: string, parts: unknown[]): string {
  const canonical = JSON.stringify(parts);
  const digest = createHash("sha256").update(canonical).digest("hex").slice(0, 16);
  return `${prefix}:${digest}`;
}
