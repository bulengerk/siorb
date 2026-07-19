import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadManifests, parseManifest } from "./lib/manifest.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const entries = await loadManifests(resolve(root, "packages"));
const policies = await loadManifests(resolve(root, "policies"));
const catalog = parseManifest(await readFile(resolve(root, "catalog.toml"), "utf8"), "catalog/catalog.toml");
const errors = [];
const identifiers = new Map();
const sourceIds = new Set();
const requiredFields = [
  "schema_version", "id", "name", "description", "aliases", "deprecated_aliases", "search_terms",
  "homepage", "upstream", "license", "categories", "capabilities", "risk", "channels", "conflicts",
  "replacements", "dependencies", "optional_relationships", "version_normalization", "verification",
  "evidence", "reviewed_at", "deprecated", "maintainers", "sources",
];
const sourceFields = [
  "id", "platform", "backend", "package_id", "trust", "scope", "channel", "architectures", "priority",
  "requires_privilege", "provenance", "evidence", "reviewed_at",
];
const platforms = new Set(["windows", "macos", "debian", "fedora", "arch", "opensuse", "alpine", "linux"]);
const backends = new Set(["winget", "scoop", "chocolatey", "homebrew-formula", "homebrew-cask", "macports", "apt", "dnf", "yum", "pacman", "zypper", "apk", "flatpak", "snap", "artifact"]);
const trusts = new Set(["native", "sandboxed", "verified-upstream"]);
const scopes = new Set(["user", "system", "auto"]);
const channels = new Set(["stable", "beta", "nightly", "custom"]);
const architectures = new Set(["x86_64", "aarch64"]);
const artifactKinds = new Map([
  ["zip", "portable-archive"], ["tar", "portable-archive"], ["tar.gz", "portable-archive"],
  ["appimage", "portable-executable"],
  ["msi", "native-installer"], ["msix", "native-installer"], ["exe", "native-installer"],
  ["pkg", "native-installer"], ["dmg", "native-installer"], ["deb", "native-installer"],
  ["rpm", "native-installer"],
]);
const artifactPlatforms = new Map([
  ["zip", new Set(["windows", "macos"])],
  ["tar", new Set(["macos", "linux", "debian", "fedora", "arch", "opensuse", "alpine"])],
  ["tar.gz", new Set(["macos", "linux", "debian", "fedora", "arch", "opensuse", "alpine"])],
  ["msi", new Set(["windows"])], ["msix", new Set(["windows"])], ["exe", new Set(["windows"])],
  ["pkg", new Set(["macos"])], ["dmg", new Set(["macos"])], ["deb", new Set(["debian"])],
  ["rpm", new Set(["fedora", "opensuse"])],
  ["appimage", new Set(["linux", "debian", "fedora", "arch", "opensuse"])],
]);
const installerFlags = new Set(["/S", "/silent", "/verysilent", "/quiet", "/norestart", "--silent", "--quiet"]);
const reserved = new Set(["install", "remove", "upgrade", "search", "info", "list", "plan", "why", "doctor", "adopt", "reconcile", "repair", "migrate", "bundle", "pin", "unpin", "hold", "unhold", "backend", "source", "catalog", "audit", "verify", "self", "completion", "version", "policy"]);

function fail(path, message) {
  errors.push(`${path}: ${message}`);
}

function validHttps(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && publicNetworkHost(url.hostname)
      && url.username === ""
      && url.password === "";
  } catch {
    return false;
  }
}

function publicNetworkHost(rawHost) {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || host === "localhost" || !host.includes(".")) return false;
  if ([".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".example", ".onion"].some((suffix) => host.endsWith(suffix))) return false;
  if (isIP(host) === 4) {
    const octets = host.split(".").map(Number);
    const [a, b] = octets;
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0)
      || (a === 192 && b === 168)
      || (a === 192 && b === 88)
      || (a === 198 && (b === 18 || b === 19 || b === 51))
      || (a === 203 && b === 0));
  }
  if (isIP(host) === 6) {
    return !(host === "::" || host === "::1" || host.startsWith("fc")
      || host.startsWith("fd") || /^fe[89ab]/.test(host)
      || host.startsWith("ff") || host.startsWith("2001:db8:"));
  }
  return true;
}

function registerIdentifier(value, owner, path) {
  if (!/^[a-z0-9][a-z0-9]*(?:-[a-z0-9]+)*$/.test(value)) fail(path, `unsafe identifier ${value}`);
  if (reserved.has(value)) fail(path, `identifier shadows reserved command ${value}`);
  const previous = identifiers.get(value);
  if (previous && previous !== owner) fail(path, `identifier ${value} collides with package ${previous}`);
  identifiers.set(value, owner);
}

for (const { manifest, path, filename } of entries) {
  for (const field of requiredFields) if (!Object.hasOwn(manifest, field)) fail(path, `missing field ${field}`);
  if (!manifest.id) continue;
  if (filename !== `${manifest.id}.toml`) fail(path, `filename must match canonical id ${manifest.id}`);
  registerIdentifier(manifest.id, manifest.id, path);
  if (new Set(manifest.aliases ?? []).size !== (manifest.aliases ?? []).length) fail(path, "aliases must be unique");
  for (const alias of manifest.aliases ?? []) registerIdentifier(alias, manifest.id, path);
  for (const alias of manifest.deprecated_aliases ?? []) registerIdentifier(alias, manifest.id, path);
  if (typeof manifest.description !== "string" || manifest.description.length < 20 || manifest.description.length > 180) fail(path, "description must contain 20-180 characters");
  if (!validHttps(manifest.homepage)) fail(path, "homepage must be an absolute credential-free HTTPS URL");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(manifest.reviewed_at)) fail(path, "reviewed_at must be YYYY-MM-DD");
  if (!Array.isArray(manifest.sources) || manifest.sources.length === 0) fail(path, "at least one source mapping is required");
  for (const source of manifest.sources ?? []) {
    for (const field of sourceFields) if (!Object.hasOwn(source, field)) fail(path, `source ${source.id ?? "<unknown>"} missing field ${field}`);
    if (!/^[a-z0-9][a-z0-9]*(?:-[a-z0-9]+)*$/.test(source.id)) fail(path, `unsafe source identifier ${source.id}`);
    if (sourceIds.has(source.id)) fail(path, `duplicate global source id ${source.id}`);
    sourceIds.add(source.id);
    if (!platforms.has(source.platform)) fail(path, `unknown platform ${source.platform}`);
    if (!backends.has(source.backend)) fail(path, `unknown backend ${source.backend}`);
    if (!trusts.has(source.trust)) fail(path, `unknown trust level ${source.trust}`);
    if (!scopes.has(source.scope)) fail(path, `unknown scope ${source.scope}`);
    if (!channels.has(source.channel)) fail(path, `unknown channel ${source.channel}`);
    if (!Array.isArray(source.architectures) || source.architectures.length === 0 || source.architectures.some((arch) => !architectures.has(arch))) fail(path, `invalid architectures for ${source.id}`);
    if (typeof source.package_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._@/+:-]*$/.test(source.package_id)) fail(path, `unsafe exact package id ${source.package_id}`);
    if (!validHttps(source.evidence)) fail(path, `source ${source.id} evidence must be an absolute credential-free HTTPS URL`);
    if (!(manifest.evidence ?? []).includes(source.evidence)) fail(path, `source ${source.id} evidence missing from package evidence list`);
    if (source.backend === "artifact") {
      const verification = source.verification;
      if (!validHttps(source.package_id)) fail(path, `artifact ${source.id} must use credential-free HTTPS`);
      if (!verification || !/^[a-f0-9]{64}$/.test(verification.sha256 ?? "")) fail(path, `artifact ${source.id} must pin SHA-256`);
      if (!Number.isInteger(verification?.max_bytes) || verification.max_bytes < 1 || verification.max_bytes > 16 * 1024 * 1024 * 1024) fail(path, `artifact ${source.id} has invalid size bound`);
      if (typeof verification?.content_type !== "string" || !verification.content_type.includes("/")) fail(path, `artifact ${source.id} has invalid content type`);
      if (!artifactKinds.has(verification?.format)) fail(path, `artifact ${source.id} has unknown typed format`);
      if (artifactKinds.get(verification?.format) !== verification?.kind) fail(path, `artifact ${source.id} kind does not match format`);
      if (!artifactPlatforms.get(verification?.format)?.has(source.platform)) fail(path, `artifact ${source.id} format is unsupported on ${source.platform}`);
      if (verification?.kind === "portable-archive" && verification.archive_format !== verification.format) fail(path, `artifact ${source.id} has mismatched archive format`);
      if (verification?.kind === "portable-executable" && verification.format !== "appimage") fail(path, `artifact ${source.id} has invalid portable executable format`);
      if (["msi", "msix", "exe", "pkg", "dmg"].includes(verification?.format) && !verification?.signer) fail(path, `artifact ${source.id} must pin its signer`);
      if (verification?.format === "dmg" && (typeof verification?.payload_path !== "string" || !/^[A-Za-z0-9+._ -]+(?:\/[A-Za-z0-9+._ -]+)*\.pkg$/i.test(verification.payload_path))) fail(path, `artifact ${source.id} has invalid DMG PKG payload path`);
      if (verification?.format !== "dmg" && verification?.payload_path !== undefined) fail(path, `artifact ${source.id} has an unexpected payload path`);
      if (!Array.isArray(verification?.install_arguments) || verification.install_arguments.length > 4 || verification.install_arguments.some((argument) => verification.format !== "exe" || !installerFlags.has(argument))) fail(path, `artifact ${source.id} has non-allowlisted installer flags`);
      if (!Array.isArray(verification?.allowed_redirect_hosts) || verification.allowed_redirect_hosts.some((host) => !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host) || !publicNetworkHost(host))) fail(path, `artifact ${source.id} has invalid redirect hosts`);
    }
  }
}

for (const { manifest, path, filename } of policies) {
  if (filename !== `${manifest.id}.toml`) fail(path, `filename must match policy id ${manifest.id}`);
  for (const field of [
    "schema_version", "id", "allow_packages", "deny_packages", "allow_categories", "deny_categories",
    "allow_sources", "deny_sources", "allow_backends", "deny_backends", "allow_channels", "deny_channels",
    "allow_scopes", "deny_scopes", "allow_licenses", "deny_licenses", "preferred_backends",
    "require_signatures", "require_digests", "trusted_publishers", "forbid_artifacts", "forbid_prerelease",
    "require_confirmation", "require_dry_run", "network_domains", "prevent_downgrade", "prevent_uninstall",
  ]) {
    if (!Object.hasOwn(manifest, field)) fail(path, `policy missing field ${field}`);
  }
  for (const field of [
    "allow_packages", "deny_packages", "allow_categories", "deny_categories", "allow_sources", "deny_sources",
    "allow_backends", "deny_backends", "allow_channels", "deny_channels", "allow_scopes", "deny_scopes",
    "allow_licenses", "deny_licenses", "preferred_backends", "trusted_publishers", "network_domains",
  ]) {
    if (!Array.isArray(manifest[field])) fail(path, `${field} must be an array`);
  }
  for (const field of ["allow_backends", "deny_backends", "preferred_backends"]) {
    for (const backend of manifest[field] ?? []) if (!backends.has(backend)) fail(path, `${field} uses unknown backend ${backend}`);
  }
  for (const field of ["allow_channels", "deny_channels"]) {
    for (const channel of manifest[field] ?? []) if (!channels.has(channel)) fail(path, `${field} uses unknown channel ${channel}`);
  }
  for (const field of ["allow_scopes", "deny_scopes"]) {
    for (const scope of manifest[field] ?? []) if (!scopes.has(scope)) fail(path, `${field} uses unknown scope ${scope}`);
  }
  for (const field of ["require_signatures", "require_digests", "forbid_artifacts", "forbid_prerelease", "require_confirmation", "require_dry_run", "prevent_downgrade", "prevent_uninstall"]) {
    if (typeof manifest[field] !== "boolean") fail(path, `${field} must be a boolean`);
  }
  if (Object.hasOwn(manifest, "freshness_days") && (!Number.isInteger(manifest.freshness_days) || manifest.freshness_days < 1)) fail(path, "freshness_days must be positive");
  for (const domain of manifest.network_domains ?? []) {
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) fail(path, `invalid exact network domain ${domain}`);
  }
}

const mappings = entries.reduce((total, entry) => total + (entry.manifest.sources?.length ?? 0), 0);
if (entries.length < 100) fail("catalog/packages", `requires at least 100 packages, found ${entries.length}`);
if (mappings < 250) fail("catalog/packages", `requires at least 250 mappings, found ${mappings}`);
for (const id of catalog.top_packages ?? []) {
  const entry = entries.find(({ manifest }) => manifest.id === id);
  if (!entry) {
    fail("catalog/catalog.toml", `top package ${id} is missing`);
    continue;
  }
  const packagePlatforms = new Set(entry.manifest.sources.map((source) => source.platform));
  for (const platform of catalog.required_top_platforms ?? []) {
    if (!packagePlatforms.has(platform)) fail(entry.path, `curated top package lacks required ${platform} mapping`);
  }
}

if (errors.length > 0) {
  console.error(errors.join("\n"));
  console.error(`catalog validation failed with ${errors.length} error(s)`);
  process.exitCode = 1;
} else {
  console.log(`catalog valid: ${entries.length} packages, ${mappings} mappings, ${identifiers.size - entries.length} aliases, ${policies.length} policies`);
}
