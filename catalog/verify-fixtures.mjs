import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const fixtureRoot = resolve(root, "fixtures/tuf");
const evaluationTime = Date.parse("2026-07-13T00:00:00Z");
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const loadJson = async (path) => JSON.parse(await readFile(path, "utf8"));

const trustedRoot = await loadJson(resolve(root, "trusted-root/root.json"));
const runtimeRoot = await loadJson(resolve(root, "trusted-root/runtime-root.json"));

function verifyRole(envelope, role) {
  const definition = trustedRoot.signed.roles[role];
  let valid = 0;
  const seen = new Set();
  for (const signature of envelope.signatures) {
    if (!definition.keyids.includes(signature.keyid) || seen.has(signature.keyid)) continue;
    const key = trustedRoot.signed.keys[signature.keyid];
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.keyval.public, "hex")]);
    const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    if (verify(null, Buffer.from(canonical(envelope.signed)), publicKey, Buffer.from(signature.sig, "hex"))) {
      seen.add(signature.keyid);
      valid += 1;
    }
  }
  if (valid < definition.threshold) throw new Error(`${role} threshold not met: ${valid}/${definition.threshold}`);
}

verifyRole(trustedRoot, "root");
const runtimeRootBytes = Buffer.from(JSON.stringify(runtimeRoot.signed));
const runtimeRole = runtimeRoot.signed.roles.root;
let runtimeSignatures = 0;
for (const signature of runtimeRoot.signatures) {
  if (!runtimeRole.key_ids.includes(signature.key_id)) continue;
  const publicBytes = Buffer.from(runtimeRoot.signed.keys[signature.key_id].public, "base64");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicBytes]);
  const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
  if (verify(null, runtimeRootBytes, publicKey, Buffer.from(signature.signature, "base64"))) runtimeSignatures += 1;
}
if (runtimeSignatures < runtimeRole.threshold) throw new Error(`runtime root threshold not met: ${runtimeSignatures}/${runtimeRole.threshold}`);
const metadataDir = resolve(fixtureRoot, "valid/metadata");
const targets = await loadJson(resolve(metadataDir, "targets.json"));
const snapshot = await loadJson(resolve(metadataDir, "snapshot.json"));
const timestamp = await loadJson(resolve(metadataDir, "timestamp.json"));
for (const [role, envelope] of [["targets", targets], ["snapshot", snapshot], ["timestamp", timestamp]]) {
  verifyRole(envelope, role);
  if (Date.parse(envelope.signed.expires) <= evaluationTime) throw new Error(`${role} unexpectedly expired at fixture evaluation time`);
}

const targetsBytes = await readFile(resolve(metadataDir, "targets.json"));
const snapshotBytes = await readFile(resolve(metadataDir, "snapshot.json"));
const catalogBytes = await readFile(resolve(fixtureRoot, "valid/targets/catalog.json"));
const generatedCatalogBytes = await readFile(resolve(root, "generated/catalog.json"));
const fixtureCatalog = JSON.parse(catalogBytes);
const generatedCatalog = JSON.parse(generatedCatalogBytes);
const timestampSnapshot = timestamp.signed.meta["snapshot.json"];
if (timestampSnapshot.length !== snapshotBytes.length || timestampSnapshot.hashes.sha256 !== sha256(snapshotBytes)) throw new Error("timestamp-to-snapshot binding failed");
const snapshotTargets = snapshot.signed.meta["targets.json"];
if (snapshotTargets.length !== targetsBytes.length || snapshotTargets.hashes.sha256 !== sha256(targetsBytes)) throw new Error("snapshot-to-targets binding failed");
const catalogTarget = targets.signed.targets["catalog.json"];
if (catalogTarget.length !== catalogBytes.length || catalogTarget.hashes.sha256 !== sha256(catalogBytes)) throw new Error("targets-to-catalog binding failed");
if (generatedCatalog._generated !== "Generated from catalog/packages/*.toml. DO NOT EDIT; regenerate with: node catalog/build-index.mjs") throw new Error("generated catalog notice is missing or stale");
// The signed fixture is intentionally immutable; require compatibility and reject a current-catalog rollback without forcing fixture re-signing.
if (generatedCatalog.schema_version !== fixtureCatalog.schema_version) throw new Error("static signed fixture and generated catalog use different schemas");
if (!Number.isSafeInteger(fixtureCatalog.catalog_version) || fixtureCatalog.catalog_version > generatedCatalog.catalog_version) throw new Error("static signed fixture is newer than the generated catalog");

const negativeChecks = [];
const expired = await loadJson(resolve(fixtureRoot, "expired/metadata/timestamp.json"));
negativeChecks.push(Date.parse(expired.signed.expires) <= evaluationTime);
const rollback = await loadJson(resolve(fixtureRoot, "rollback/metadata/snapshot.json"));
negativeChecks.push(rollback.signed.version < snapshot.signed.version);
const insufficient = await loadJson(resolve(fixtureRoot, "invalid-threshold/metadata/root.json"));
negativeChecks.push(insufficient.signatures.length < trustedRoot.signed.roles.root.threshold);
const changed = await loadJson(resolve(fixtureRoot, "changed-root/metadata/2.root.json"));
negativeChecks.push(changed.signatures.every((signature) => !trustedRoot.signed.roles.root.keyids.includes(signature.keyid)));
let truncatedRejected = false;
try { await loadJson(resolve(fixtureRoot, "truncated/metadata/snapshot.json")); } catch { truncatedRejected = true; }
negativeChecks.push(truncatedRejected);
const mismatchedBytes = await readFile(resolve(fixtureRoot, "hash-mismatch/targets/catalog.json"));
negativeChecks.push(sha256(mismatchedBytes) !== catalogTarget.hashes.sha256);
const inconsistent = await loadJson(resolve(fixtureRoot, "mirror-inconsistency/metadata/snapshot.json"));
negativeChecks.push(inconsistent.signed.meta["targets.json"].hashes.sha256 !== sha256(targetsBytes));
const interrupted = await loadJson(resolve(fixtureRoot, "interrupted-update/state.json"));
negativeChecks.push(interrupted.staged_complete === false && interrupted.expected_result === "retain-current");
if (negativeChecks.some((result) => !result)) throw new Error("one or more adversarial fixtures do not express their intended failure");

console.log(`TUF fixtures valid: standard and runtime root thresholds 2, 3 delegated roles, ${negativeChecks.length} adversarial cases`);
