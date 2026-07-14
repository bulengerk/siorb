import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const catalogRoot = dirname(fileURLToPath(import.meta.url));
const fixtureRoot = resolve(catalogRoot, "fixtures/runtime-tuf");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function failure(code, detail) {
  const error = new Error(detail);
  error.code = code;
  throw error;
}

async function decode(path, role) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    failure("update.metadata.invalid", `${role} metadata is invalid JSON: ${error.message}`);
  }
}

function roleType(value, expected) {
  if (value !== expected) failure("update.role.type", `expected ${expected}, observed ${value}`);
}

function verifyRole(envelope, role, root) {
  const definition = root.roles[role];
  if (!definition || definition.threshold === 0 || definition.threshold > definition.key_ids.length) failure("update.threshold.invalid", `${role} threshold is invalid`);
  const bytes = Buffer.from(JSON.stringify(envelope.signed));
  const valid = new Set();
  for (const signature of envelope.signatures) {
    if (!definition.key_ids.includes(signature.key_id) || valid.has(signature.key_id)) continue;
    const key = root.keys[signature.key_id];
    if (!key) failure("update.key.missing", `${role} references missing key ${signature.key_id}`);
    if (key.scheme !== "ed25519") continue;
    const publicBytes = Buffer.from(key.public, "base64");
    if (publicBytes.length !== 32) continue;
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicBytes]);
    const publicKey = createPublicKey({ key: spki, format: "der", type: "spki" });
    if (verify(null, bytes, publicKey, Buffer.from(signature.signature, "base64"))) valid.add(signature.key_id);
  }
  if (valid.size < definition.threshold) failure("update.threshold.not_met", `${role} has ${valid.size}/${definition.threshold} valid signatures`);
}

function notExpired(expires, now, role) {
  if (expires <= now) failure("update.metadata.expired", `${role} expired at ${expires}`);
}

function noRollback(observed, trusted, role) {
  if (observed < trusted) failure("update.rollback.detected", `${role} ${observed} is older than ${trusted}`);
}

function verifyDescription(bytes, description, role) {
  if (bytes.length !== description.length) failure("update.length.mismatch", `${role} length mismatch`);
  if (sha256(bytes) !== description.sha256) failure("update.hash.mismatch", `${role} hash mismatch`);
}

async function verifyRepository(directory, fixture) {
  const rootEnvelope = await decode(resolve(directory, "runtime-root.json"), "root");
  roleType(rootEnvelope.signed.type, "root");
  if (rootEnvelope.signed.spec_version !== "1.0") failure("update.spec.unsupported", "unsupported root spec");
  verifyRole(rootEnvelope, "root", rootEnvelope.signed);

  const timestamp = await decode(resolve(directory, "timestamp.json"), "timestamp");
  roleType(timestamp.signed.type, "timestamp");
  verifyRole(timestamp, "timestamp", rootEnvelope.signed);
  notExpired(timestamp.signed.expires_unix, fixture.at_time_unix, "timestamp");
  noRollback(timestamp.signed.version, fixture.rollback_state.timestamp, "timestamp");

  const snapshotPath = resolve(directory, `${timestamp.signed.snapshot.version}.snapshot.json`);
  const snapshotBytes = await readFile(snapshotPath);
  verifyDescription(snapshotBytes, timestamp.signed.snapshot, "snapshot");
  const snapshot = await decode(snapshotPath, "snapshot");
  roleType(snapshot.signed.type, "snapshot");
  verifyRole(snapshot, "snapshot", rootEnvelope.signed);
  notExpired(snapshot.signed.expires_unix, fixture.at_time_unix, "snapshot");
  if (snapshot.signed.version !== timestamp.signed.snapshot.version) failure("update.snapshot.mix_match", "snapshot version differs from timestamp");
  noRollback(snapshot.signed.version, fixture.rollback_state.snapshot, "snapshot");

  const targetsDescription = snapshot.signed.meta["targets.json"];
  if (!targetsDescription) failure("update.snapshot.targets_missing", "snapshot omits targets.json");
  const targetsPath = resolve(directory, `${targetsDescription.version}.targets.json`);
  const targetsBytes = await readFile(targetsPath);
  verifyDescription(targetsBytes, targetsDescription, "targets");
  const targets = await decode(targetsPath, "targets");
  roleType(targets.signed.type, "targets");
  verifyRole(targets, "targets", rootEnvelope.signed);
  notExpired(targets.signed.expires_unix, fixture.at_time_unix, "targets");
  if (targets.signed.version !== targetsDescription.version) failure("update.targets.mix_match", "targets version differs from snapshot");
  noRollback(targets.signed.version, fixture.rollback_state.targets, "targets");
  return { rootEnvelope, timestamp, snapshot, targets };
}

async function verifyTarget(directory, repository) {
  const bytes = await readFile(resolve(directory, "catalog.json"));
  const target = repository.targets.signed.targets["catalog.json"];
  if (!target) failure("update.target.missing", "targets omits catalog.json");
  verifyDescription(bytes, target, "target");
  return bytes;
}

async function runFixture(directory) {
  const fixture = await decode(resolve(directory, "fixture.json"), "fixture");
  try {
    const repository = await verifyRepository(directory, fixture);
    if (fixture.expected_stage === "target") await verifyTarget(directory, repository);
    else if (fixture.expected === "success") {
      const target = await verifyTarget(directory, repository);
      const current = await readFile(resolve(catalogRoot, "generated/catalog.json"));
      if (!target.equals(current)) failure("fixture.catalog.stale", "valid runtime target differs from generated catalog");
    }
    if (fixture.expected !== "success") failure("fixture.unexpected_success", `expected ${fixture.expected}`);
  } catch (error) {
    if (fixture.expected === "success") throw error;
    if (error.code !== fixture.expected) throw new Error(`${directory}: expected ${fixture.expected}, observed ${error.code ?? error.message}`);
    return fixture.expected;
  }
  return "success";
}

const validResult = await runFixture(resolve(fixtureRoot, "valid"));
if (validResult !== "success") throw new Error("valid runtime repository did not succeed");
const attacksRoot = resolve(fixtureRoot, "attacks");
const attacks = (await readdir(attacksRoot, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
const results = [];
for (const attack of attacks) results.push([attack, await runFixture(resolve(attacksRoot, attack))]);

console.log(`runtime TUF valid: transport chain and catalog target verified; ${results.length} attacks rejected`);
for (const [attack, reason] of results) console.log(`  ${attack}: ${reason}`);
