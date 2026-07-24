import { basename } from "node:path";
import type { InventoryConfidence, RepositoryCapabilities, RepositoryCapability } from "./types.js";
import type { WalkedFile } from "./walker.js";

type Marker = { id: string; files: string[]; confidence?: InventoryConfidence };

const LANGUAGE_MARKERS: Marker[] = [
  { id: "typescript", files: ["tsconfig.json", "tsconfig.base.json"] },
  { id: "javascript", files: ["package.json"] },
  { id: "python", files: ["pyproject.toml", "requirements.txt", "pipfile", "poetry.lock"] },
  { id: "go", files: ["go.mod"] },
  { id: "java", files: ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"] },
  { id: "dotnet", files: [".csproj", ".fsproj", ".vbproj", "packages.lock.json"] },
  { id: "ruby", files: ["gemfile", "gemfile.lock"] },
  { id: "php", files: ["composer.json", "composer.lock"] },
  { id: "rust", files: ["cargo.toml", "cargo.lock"] },
];

const FRAMEWORK_MARKERS: Marker[] = [
  { id: "nextjs", files: ["next.config.js", "next.config.mjs", "next.config.ts"] },
  { id: "convex", files: ["convex.json"] },
  { id: "vercel", files: ["vercel.json"] },
  { id: "coolify", files: ["coolify.yaml", "coolify.yml"] },
  { id: "docker", files: ["dockerfile", "docker-compose.yml", "docker-compose.yaml"] },
  { id: "kubernetes", files: ["kustomization.yaml", "kustomization.yml"] },
];

function matchedCapabilities(files: WalkedFile[], markers: Marker[]): RepositoryCapability[] {
  const names = files.map((file) => ({ rel: file.rel, base: basename(file.rel).toLowerCase() }));
  return markers.flatMap((marker) => {
    const signals = names
      .filter((file) => marker.files.some((name) => name.startsWith(".") ? file.base.endsWith(name) : file.base === name))
      .map((file) => file.rel)
      .slice(0, 8);
    return signals.length ? [{ id: marker.id, confidence: marker.confidence ?? "high", signals }] : [];
  });
}

export function detectRepositoryCapabilities(files: WalkedFile[]): RepositoryCapabilities {
  const languages = matchedCapabilities(files, LANGUAGE_MARKERS);
  const frameworks = matchedCapabilities(files, FRAMEWORK_MARKERS);
  const languageIds = new Set(languages.map((language) => language.id));
  const frameworkIds = new Set(frameworks.map((framework) => framework.id));
  const deepAccessLaneAdapters = [
    ...(frameworkIds.has("nextjs") ? ["nextjs"] : []),
    ...(frameworkIds.has("convex") ? ["convex"] : []),
    ...(languageIds.has("javascript") || languageIds.has("typescript") ? ["generic-server"] : []),
  ];
  const dependencyEcosystems = [
    ...(languageIds.has("javascript") || languageIds.has("typescript") ? ["npm"] : []),
    ...(languageIds.has("python") ? ["pypi"] : []),
    ...(languageIds.has("go") ? ["go"] : []),
    ...(languageIds.has("java") ? ["maven-or-gradle"] : []),
    ...(languageIds.has("dotnet") ? ["nuget"] : []),
    ...(languageIds.has("ruby") ? ["rubygems"] : []),
    ...(languageIds.has("php") ? ["composer"] : []),
    ...(languageIds.has("rust") ? ["cargo"] : []),
  ];
  return {
    schema: "seamshield.repository-capabilities/v1",
    languages,
    frameworks,
    coverage: {
      baseline: ["repository-wide credential controls", "AI agent and MCP configuration checks", "deployment metadata", "SARIF and NDJSON output"],
      deep_access_lane_adapters: deepAccessLaneAdapters,
      dependency_ecosystems: dependencyEcosystems,
      unknown_language_policy: "baseline_only",
    },
  };
}
