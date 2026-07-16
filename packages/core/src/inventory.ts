import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { stableId } from "./ids.js";
import type {
  InventoryComponent,
  InventoryConfidence,
  InventoryResult,
  ScanProfile,
} from "./types.js";
import { walk } from "./walker.js";

const LOCKFILES: Record<string, { manager: string; sourceType: string }> = {
  "package-lock.json": { manager: "npm", sourceType: "npm-lockfile" },
  "npm-shrinkwrap.json": { manager: "npm", sourceType: "npm-shrinkwrap" },
  "pnpm-lock.yaml": { manager: "pnpm", sourceType: "pnpm-lockfile" },
  "yarn.lock": { manager: "yarn", sourceType: "yarn-lockfile" },
  "bun.lock": { manager: "bun", sourceType: "bun-lockfile" },
};

const MCP_CONFIGS = new Set([
  "mcp.json",
  ".mcp.json",
  "claude_desktop_config.json",
  "mcp_config.json",
  "mcp_settings.json",
  "cline_mcp_settings.json",
]);

const AGENT_SKILL_LOCKS = new Set(["skills-lock.json", ".skill-lock.json"]);
const EDITOR_EXTENSION_MANIFEST = /(?:^|\/)\.(?:vscode|cursor|windsurf|vscodium)\/extensions\/[^/]+\/package\.json$/;
const DEPLOY_CONFIGS = new Set(["vercel.json", "coolify.yaml", "coolify.yml", "docker-compose.yml", "docker-compose.yaml"]);

function readJson(path: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function addRecordId(component: Omit<InventoryComponent, "record_id">): InventoryComponent {
  return {
    record_id: stableId("inventory", [
      component.ecosystem,
      component.name,
      component.version ?? "",
      component.source_type,
      component.source_file,
    ]),
    ...component,
  };
}

function countBy<T extends string>(items: InventoryComponent[], pick: (item: InventoryComponent) => T): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) counts[pick(item)] = (counts[pick(item)] ?? 0) + 1;
  return counts;
}

function packageManifestComponents(abs: string, rel: string): InventoryComponent[] {
  const pkg = readJson(abs);
  if (!pkg) return [];
  const components: InventoryComponent[] = [];
  const name = typeof pkg.name === "string" ? pkg.name : basename(rel.replace(/\/package\.json$/, ""));
  const version = typeof pkg.version === "string" ? pkg.version : undefined;
  components.push(
    addRecordId({
      ecosystem: "npm",
      name,
      version,
      source_type: "package-manifest",
      source_file: rel,
      package_manager: "npm",
      confidence: "medium",
    }),
  );
  for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
    const deps = pkg[field];
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;
    for (const [depName, spec] of Object.entries(deps as Record<string, unknown>)) {
      components.push(
        addRecordId({
          ecosystem: "npm",
          name: depName,
          version: typeof spec === "string" ? spec : undefined,
          source_type: "package-manifest",
          source_file: rel,
          package_manager: "npm",
          confidence: "medium",
        }),
      );
    }
  }
  return components;
}

function lockfileComponent(rel: string): InventoryComponent | null {
  const lock = LOCKFILES[basename(rel)];
  if (!lock) return null;
  return addRecordId({
    ecosystem: "npm",
    name: basename(rel),
    source_type: lock.sourceType,
    source_file: rel,
    package_manager: lock.manager,
    confidence: "high",
  });
}

function credentialKeys(value: unknown): string[] {
  const keys = new Set<string>();
  const visit = (node: unknown): void => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      if (key === "env" && child && typeof child === "object" && !Array.isArray(child)) {
        for (const envKey of Object.keys(child as Record<string, unknown>)) keys.add(envKey);
      } else {
        visit(child);
      }
    }
  };
  visit(value);
  return [...keys].sort();
}

function mcpComponent(abs: string, rel: string): InventoryComponent | null {
  if (!MCP_CONFIGS.has(basename(rel))) return null;
  const parsed = readJson(abs);
  return addRecordId({
    ecosystem: "mcp",
    name: basename(rel),
    source_type: "mcp-config",
    source_file: rel,
    credential_fields_present: parsed ? credentialKeys(parsed) : [],
    confidence: "low",
  });
}

function agentSkillComponent(abs: string, rel: string): InventoryComponent | null {
  if (!AGENT_SKILL_LOCKS.has(basename(rel))) return null;
  const parsed = readJson(abs);
  const skillCount =
    parsed && typeof parsed.skills === "object" && parsed.skills && !Array.isArray(parsed.skills)
      ? Object.keys(parsed.skills as Record<string, unknown>).length
      : undefined;
  return addRecordId({
    ecosystem: "agent-skill",
    name: skillCount === undefined ? basename(rel) : `${basename(rel)}:${skillCount}`,
    source_type: "skills-lock",
    source_file: rel,
    confidence: "high",
  });
}

function editorExtensionComponent(abs: string, rel: string): InventoryComponent | null {
  if (!EDITOR_EXTENSION_MANIFEST.test(rel)) return null;
  const parsed = readJson(abs);
  return addRecordId({
    ecosystem: "editor-extension",
    name: typeof parsed?.name === "string" ? parsed.name : basename(rel),
    version: typeof parsed?.version === "string" ? parsed.version : undefined,
    source_type: "editor-extension-manifest",
    source_file: rel,
    confidence: "medium",
  });
}

function deployComponent(rel: string): InventoryComponent | null {
  if (!DEPLOY_CONFIGS.has(basename(rel))) return null;
  return addRecordId({
    ecosystem: "deploy",
    name: basename(rel),
    source_type: basename(rel) === "vercel.json" ? "vercel-config" : "deploy-config",
    source_file: rel,
    confidence: "low",
  });
}

function dedupe(components: InventoryComponent[]): InventoryComponent[] {
  const seen = new Set<string>();
  return components.filter((component) => {
    if (seen.has(component.record_id)) return false;
    seen.add(component.record_id);
    return true;
  });
}

export function collectInventory(target: string, options: { profile?: ScanProfile } = {}): InventoryResult {
  const root = resolve(target);
  const components: InventoryComponent[] = [];
  for (const file of walk(root)) {
    if (basename(file.rel) === "package.json") components.push(...packageManifestComponents(file.abs, file.rel));
    const lock = lockfileComponent(file.rel);
    if (lock) components.push(lock);
    const mcp = mcpComponent(file.abs, file.rel);
    if (mcp) components.push(mcp);
    const skill = agentSkillComponent(file.abs, file.rel);
    if (skill) components.push(skill);
    const extension = editorExtensionComponent(file.abs, file.rel);
    if (extension) components.push(extension);
    const deploy = deployComponent(file.rel);
    if (deploy) components.push(deploy);
  }
  const unique = dedupe(components).sort(
    (a, b) =>
      a.ecosystem.localeCompare(b.ecosystem) ||
      a.source_file.localeCompare(b.source_file) ||
      a.name.localeCompare(b.name),
  );
  return {
    schema: "seamshield.inventory/v1",
    target: root,
    profile: options.profile ?? "community",
    generated_at: new Date().toISOString(),
    components: unique,
    summary: {
      components_total: unique.length,
      by_ecosystem: countBy(unique, (component) => component.ecosystem),
      by_confidence: countBy(unique, (component) => component.confidence as InventoryConfidence),
    },
  };
}

export function renderInventoryJson(inventory: InventoryResult): string {
  return JSON.stringify(inventory, null, 2);
}

export function renderInventoryTable(inventory: InventoryResult): string {
  const lines = [
    "SeamShield Inventory",
    "",
    `Target: ${inventory.target}`,
    `Profile: ${inventory.profile}`,
    `Components: ${inventory.summary.components_total}`,
    "",
  ];
  for (const component of inventory.components) {
    lines.push(
      `${component.ecosystem.padEnd(16)} ${component.name}${component.version ? `@${component.version}` : ""}`,
      `  ${component.source_type} ${component.source_file} (${component.confidence})`,
    );
    if (component.credential_fields_present?.length) {
      lines.push(`  credential fields present: ${component.credential_fields_present.join(", ")}`);
    }
  }
  return lines.join("\n");
}

export function renderInventoryNdjson(inventory: InventoryResult): string {
  const lines = inventory.components.map((component) =>
    JSON.stringify({
      record_type: "inventory_component",
      schema_version: "seamshield.inventory/v1",
      scanner_name: "seamshield",
      profile: inventory.profile,
      target: inventory.target,
      ...component,
    }),
  );
  lines.push(
    JSON.stringify({
      record_type: "inventory_summary",
      schema_version: "seamshield.inventory/v1",
      target: inventory.target,
      profile: inventory.profile,
      components_total: inventory.summary.components_total,
      by_ecosystem: inventory.summary.by_ecosystem,
      by_confidence: inventory.summary.by_confidence,
    }),
  );
  return `${lines.join("\n")}\n`;
}
