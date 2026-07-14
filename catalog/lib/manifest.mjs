import { readFile, readdir } from "node:fs/promises";
import { basename, join } from "node:path";

function parseValue(raw, path, lineNumber) {
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+$/.test(raw)) return Number(raw);
  if (raw.startsWith('"') || raw.startsWith("[")) {
    try {
      return JSON.parse(raw);
    } catch (error) {
      throw new Error(`${path}:${lineNumber}: invalid TOML value: ${error.message}`);
    }
  }
  throw new Error(`${path}:${lineNumber}: unsupported TOML value ${raw}`);
}

export function parseManifest(text, path = "<manifest>") {
  const manifest = {};
  let target = manifest;
  const lines = text.replaceAll("\r\n", "\n").split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line === "[[sources]]") {
      manifest.sources ??= [];
      target = {};
      manifest.sources.push(target);
      continue;
    }
    if (line === "[sources.verification]") {
      const source = manifest.sources?.at(-1);
      if (!source) throw new Error(`${path}:${index + 1}: verification has no source`);
      if (Object.hasOwn(source, "verification")) {
        throw new Error(`${path}:${index + 1}: duplicate source verification`);
      }
      target = {};
      source.verification = target;
      continue;
    }
    const table = /^\[([a-z][a-z0-9_]*)\]$/.exec(line);
    if (table) {
      const key = table[1];
      if (Object.hasOwn(manifest, key)) throw new Error(`${path}:${index + 1}: duplicate table ${key}`);
      target = {};
      manifest[key] = target;
      continue;
    }
    const match = /^([a-z][a-z0-9_]*)\s*=\s*(.+)$/.exec(line);
    if (!match) throw new Error(`${path}:${index + 1}: unsupported TOML syntax`);
    const [, key, rawValue] = match;
    if (Object.hasOwn(target, key)) throw new Error(`${path}:${index + 1}: duplicate key ${key}`);
    target[key] = parseValue(rawValue, path, index + 1);
  }
  return manifest;
}

export async function loadManifests(root) {
  const names = (await readdir(root)).filter((name) => name.endsWith(".toml")).sort();
  return Promise.all(
    names.map(async (name) => {
      const path = join(root, name);
      const manifest = parseManifest(await readFile(path, "utf8"), path);
      return { manifest, path, filename: basename(path) };
    }),
  );
}
