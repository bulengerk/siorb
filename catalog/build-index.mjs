import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifests, parseManifest } from "./lib/manifest.mjs";

const catalogRoot = dirname(fileURLToPath(import.meta.url));
const metadata = parseManifest(await readFile(resolve(catalogRoot, "catalog.toml"), "utf8"), "catalog/catalog.toml");
const entries = await loadManifests(resolve(catalogRoot, "packages"));
const packages = entries.map(({ manifest }) => manifest);
const mappings = packages.reduce((count, pkg) => count + pkg.sources.length, 0);
const generatedNotice = "Generated from catalog/packages/*.toml. DO NOT EDIT; regenerate with: node catalog/build-index.mjs";

const index = {
  _generated: generatedNotice,
  schema_version: "1",
  catalog: {
    id: metadata.id,
    version: metadata.version,
    generated_at: metadata.generated_at,
    signature_status: metadata.signature_status,
  },
  counts: { packages: packages.length, mappings },
  packages,
};

const runtime = {
  _generated: generatedNotice,
  schema_version: "1.0",
  catalog_version: metadata.version_number,
  generated_at: metadata.generated_at,
  expires_unix: null,
  packages,
};

const outputs = [
  [resolve(catalogRoot, "index.json"), `${JSON.stringify(index)}\n`],
  [resolve(catalogRoot, "generated/catalog.json"), `${JSON.stringify(runtime)}\n`],
];

if (process.argv.includes("--check")) {
  const stale = [];
  for (const [path, expected] of outputs) {
    let actual = "";
    try {
      actual = await readFile(path, "utf8");
    } catch {
      // A missing generated file is stale by definition.
    }
    if (actual !== expected) stale.push(path);
  }
  if (stale.length > 0) {
    console.error(`generated catalog output is stale:\n${stale.join("\n")}`);
    process.exitCode = 1;
  } else {
    console.log(`catalog index is current (${packages.length} packages, ${mappings} mappings)`);
  }
} else {
  for (const [path, contents] of outputs) {
    await mkdir(dirname(path), { recursive: true });
    const temporary = `${path}.tmp`;
    await writeFile(temporary, contents);
    await rename(temporary, path);
  }
  console.log(`generated catalog indexes (${packages.length} packages, ${mappings} mappings)`);
}
