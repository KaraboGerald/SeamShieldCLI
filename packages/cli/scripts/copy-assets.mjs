import { cpSync, existsSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const rulesPackageRoot = join(packageRoot, "..", "rules");

const copies = [
  [join(rulesPackageRoot, "rules"), join(packageRoot, "rules")],
  [join(rulesPackageRoot, "schemas"), join(packageRoot, "schemas")],
];

for (const [, destination] of copies) {
  rmSync(destination, { recursive: true, force: true });
}

for (const [source, destination] of copies) {
  if (!existsSync(source)) {
    throw new Error(`Missing CLI asset source: ${source}`);
  }

  cpSync(source, destination, { recursive: true });
}

removeDuplicateYamlFiles(join(packageRoot, "rules"));

function removeDuplicateYamlFiles(directory) {
  if (!existsSync(directory)) {
    return;
  }

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const entryPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      removeDuplicateYamlFiles(entryPath);
      continue;
    }

    if (entry.name.endsWith(" 2.yaml")) {
      rmSync(entryPath, { force: true });
    }
  }
}
