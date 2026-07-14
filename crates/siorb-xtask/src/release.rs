use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use siorb_update::{
    MetadataDescription, RepositoryVerifier, RollbackState, RootMetadata, Signed, SnapshotMetadata,
    TargetDescription, TargetsMetadata, TimestampMetadata, public_key, sign,
};
use walkdir::WalkDir;

use crate::benchmark;
use crate::repository;
use crate::support::{
    atomic_json, atomic_write, capture, copy_regular_file, executable_name, host_target, message,
    prepare_empty_directory, run, sha256_bytes, sha256_file, source_epoch, target_directory,
};
use crate::{Result, SigningRole};

const SPEC_VERSION: &str = "1.0";
const DAY: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ArtifactRecord {
    path: String,
    length: u64,
    sha256: String,
    kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ArtifactManifest {
    schema_version: String,
    version: String,
    target: String,
    signing_status: String,
    artifacts: Vec<ArtifactRecord>,
}

pub fn package(root: &Path, out: &Path, target: Option<&str>, verify: Option<&Path>) -> Result<()> {
    if let Some(directory) = verify {
        return verify_package(root, directory);
    }
    let target = target.map_or_else(|| host_target(root), |value| Ok(value.to_owned()))?;
    build_package(root, out, &target)
}

fn build_package(root: &Path, out: &Path, target: &str) -> Result<()> {
    validate_safe_name(target, "target triple")?;
    prepare_empty_directory(out)?;
    let native_target = host_target(root)?;
    let mut build_arguments = vec![
        "build".to_owned(),
        "--locked".to_owned(),
        "--release".to_owned(),
    ];
    if target != native_target {
        build_arguments.extend(["--target".to_owned(), target.to_owned()]);
    }
    build_arguments.extend(["-p".to_owned(), "siorb-cli".to_owned()]);
    run(root, "cargo", build_arguments)?;
    let mut binary_directory = target_directory(root)?;
    if target != native_target {
        binary_directory.push(target);
    }
    let binary = binary_directory
        .join("release")
        .join(executable_name("siorb"));
    if !binary.is_file() || binary.is_symlink() {
        return Err(message(format!(
            "release build did not create a regular binary at {}",
            binary.display()
        )));
    }
    let version = env!("CARGO_PKG_VERSION");
    let arguments = vec![
        "scripts/release/package_archive.py".into(),
        "--binary".into(),
        binary.into_os_string(),
        "--target".into(),
        target.into(),
        "--version".into(),
        version.into(),
        "--output-dir".into(),
        out.as_os_str().to_owned(),
    ];
    run(root, "python3", arguments)?;

    let generated_at = catalog_generated_at(root)?;
    write_sbom(root, out, version, target, &generated_at)?;
    atomic_write(
        &out.join("UNSIGNED.txt"),
        b"Secret-free local candidate. No production Authenticode, Apple, Sigstore, or catalog trust is claimed.\n",
    )?;
    write_provenance(root, out, version, target, &generated_at)?;
    write_artifact_manifest(out, version, target, "unsigned-local")?;
    generate_checksums(root, out)?;
    verify_package(root, out)?;
    println!("packaged local {target} candidate in {}", out.display());
    Ok(())
}

pub fn release_local(root: &Path, out: &Path) -> Result<()> {
    prepare_empty_directory(out)?;
    repository::verify(root)?;
    repository::test_catalog(root)?;
    repository::test_docs(root)?;
    repository::build_site(root)?;
    benchmark::run(root, true)?;

    let target = host_target(root)?;
    let artifacts = out.join("release-artifacts");
    build_package(root, &artifacts, &target)?;
    let catalog = out.join("catalog");
    prepare_catalog(root, Some(&artifacts), &catalog)?;
    for role in [
        SigningRole::Targets,
        SigningRole::Snapshot,
        SigningRole::Timestamp,
    ] {
        let secret = development_secret(role);
        sign_metadata_with_secret(&catalog, role, &secret)?;
    }
    verify_prepared_catalog(&catalog)?;
    atomic_json(
        &out.join("RELEASE.json"),
        &json!({
            "schema_version": "1.0",
            "version": env!("CARGO_PKG_VERSION"),
            "target": target,
            "candidate": "local-development",
            "production_signing": false,
            "catalog_signing": "deterministic-compromised-development-fixture",
            "artifacts": "release-artifacts/ARTIFACTS.json",
            "catalog": "catalog/timestamp.json"
        }),
    )?;
    generate_checksums(root, out)?;
    verify_package(root, out)?;
    println!(
        "secret-free local release candidate created and verified at {}",
        out.display()
    );
    Ok(())
}

pub fn verify_package(root: &Path, directory: &Path) -> Result<()> {
    if !directory.is_dir() || directory.is_symlink() {
        return Err(message(format!(
            "package verification input must be a real directory: {}",
            directory.display()
        )));
    }
    let checksums = directory.join("SHA256SUMS");
    if !checksums.is_file() || checksums.is_symlink() {
        return Err(message(format!(
            "package has no regular SHA256SUMS: {}",
            directory.display()
        )));
    }
    run(
        root,
        "python3",
        [
            "scripts/release/verify_release.py".into(),
            "--directory".into(),
            directory.as_os_str().to_owned(),
            "--checksums".into(),
            checksums.into_os_string(),
            "--inspect-archives".into(),
        ],
    )?;

    let files = regular_files(directory)?;
    for suffix in [".spdx.json", ".provenance.json"] {
        if !files
            .iter()
            .any(|path| path.to_string_lossy().ends_with(suffix))
        {
            return Err(message(format!(
                "release candidate is missing required `{suffix}` evidence"
            )));
        }
    }
    let manifests: Vec<_> = files
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "ARTIFACTS.json")
        })
        .collect();
    if manifests.is_empty() {
        return Err(message("release candidate contains no ARTIFACTS.json"));
    }
    for manifest_path in manifests {
        verify_artifact_manifest(directory, manifest_path)?;
    }
    let has_sigstore_evidence = files
        .iter()
        .any(|path| path.to_string_lossy().ends_with(".sigstore.json"));
    let has_catalog_signature = files
        .iter()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "timestamp.json")
        })
        .any(|path| {
            read_json::<Signed<TimestampMetadata>>(path)
                .is_ok_and(|metadata| !metadata.signatures.is_empty())
        });
    let has_signature_evidence = has_sigstore_evidence || has_catalog_signature;
    let explicitly_unsigned = files
        .iter()
        .any(|path| path.file_name().is_some_and(|name| name == "UNSIGNED.txt"));
    if !has_signature_evidence && !explicitly_unsigned {
        return Err(message(
            "candidate has neither signature evidence nor an explicit UNSIGNED.txt marker",
        ));
    }
    println!("release package verified: {} files", files.len());
    Ok(())
}

fn verify_artifact_manifest(root: &Path, path: &Path) -> Result<()> {
    let bytes = fs::read(path)
        .map_err(|error| message(format!("cannot read {}: {error}", path.display())))?;
    let manifest: ArtifactManifest = serde_json::from_slice(&bytes)
        .map_err(|error| message(format!("invalid {}: {error}", path.display())))?;
    if manifest.schema_version != "1.0" || manifest.artifacts.is_empty() {
        return Err(message(format!(
            "artifact manifest has unsupported schema or no subjects: {}",
            path.display()
        )));
    }
    let base = path
        .parent()
        .ok_or_else(|| message("artifact manifest has no parent"))?;
    for artifact in &manifest.artifacts {
        validate_relative_path(&artifact.path)?;
        let subject = base.join(&artifact.path);
        let metadata = fs::symlink_metadata(&subject).map_err(|error| {
            message(format!(
                "artifact manifest references missing {}: {error}",
                subject.display()
            ))
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(message(format!(
                "artifact manifest subject is not a regular file: {}",
                subject.display()
            )));
        }
        if metadata.len() != artifact.length || sha256_file(&subject)? != artifact.sha256 {
            return Err(message(format!(
                "artifact manifest digest/length mismatch: {} (verification root {})",
                subject.display(),
                root.display()
            )));
        }
    }
    Ok(())
}

fn write_artifact_manifest(
    out: &Path,
    version: &str,
    target: &str,
    signing_status: &str,
) -> Result<()> {
    let mut records = Vec::new();
    for path in regular_files(out)? {
        if path
            .file_name()
            .is_some_and(|name| name == "ARTIFACTS.json" || name == "SHA256SUMS")
        {
            continue;
        }
        let relative = path
            .strip_prefix(out)
            .map_err(|error| message(format!("cannot relativize artifact: {error}")))?
            .to_string_lossy()
            .replace('\\', "/");
        let length = fs::metadata(&path)
            .map_err(|error| message(format!("cannot inspect {}: {error}", path.display())))?
            .len();
        let lowercase = relative.to_ascii_lowercase();
        let is_zip = Path::new(&relative)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"));
        let kind = if lowercase.ends_with(".tar.gz") || is_zip {
            "native-archive"
        } else if relative.ends_with(".spdx.json") {
            "sbom"
        } else if relative.ends_with(".provenance.json") {
            "provenance"
        } else {
            "release-evidence"
        };
        records.push(ArtifactRecord {
            path: relative,
            length,
            sha256: sha256_file(&path)?,
            kind: kind.to_owned(),
        });
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    atomic_json(
        &out.join("ARTIFACTS.json"),
        &ArtifactManifest {
            schema_version: "1.0".to_owned(),
            version: version.to_owned(),
            target: target.to_owned(),
            signing_status: signing_status.to_owned(),
            artifacts: records,
        },
    )?;
    Ok(())
}

fn write_sbom(
    root: &Path,
    out: &Path,
    version: &str,
    target: &str,
    generated_at: &str,
) -> Result<()> {
    let output = capture(
        root,
        Path::new("cargo"),
        ["metadata", "--locked", "--format-version", "1"],
    )?;
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| message(format!("cargo metadata returned invalid JSON: {error}")))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| message("cargo metadata omitted packages"))?;
    let mut sbom_packages: Vec<_> = packages
        .iter()
        .filter_map(|package| {
            let name = package["name"].as_str()?;
            let package_version = package["version"].as_str()?;
            Some(json!({
                "name": name,
                "SPDXID": format!("SPDXRef-Package-{}-{}", spdx_component(name), spdx_component(package_version)),
                "versionInfo": package_version,
                "downloadLocation": package["source"].as_str().unwrap_or("NOASSERTION"),
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": package["license"].as_str().unwrap_or("NOASSERTION"),
                "copyrightText": "NOASSERTION"
            }))
        })
        .collect();
    sbom_packages.sort_by(|left, right| left["SPDXID"].as_str().cmp(&right["SPDXID"].as_str()));
    let relationships: Vec<_> = sbom_packages
        .iter()
        .filter_map(|package| package["SPDXID"].as_str())
        .map(|id| {
            json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": id
            })
        })
        .collect();
    let sbom = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("siorb-{version}-{target}"),
        "documentNamespace": format!("https://github.com/bulengerk/siorb/sbom/{version}/{target}/local"),
        "creationInfo": {
            "created": generated_at,
            "creators": [format!("Tool: siorb-xtask-{}", env!("CARGO_PKG_VERSION"))]
        },
        "packages": sbom_packages,
        "relationships": relationships
    });
    atomic_json(
        &out.join(format!("siorb-{version}-{target}.spdx.json")),
        &sbom,
    )?;
    Ok(())
}

fn write_provenance(
    root: &Path,
    out: &Path,
    version: &str,
    target: &str,
    generated_at: &str,
) -> Result<()> {
    let mut subjects = Vec::new();
    for path in regular_files(out)? {
        if !(path.to_string_lossy().ends_with(".tar.gz")
            || path.to_string_lossy().ends_with(".zip"))
        {
            continue;
        }
        subjects.push(json!({
            "name": path.file_name().and_then(|value| value.to_str()).unwrap_or("artifact"),
            "digest": { "sha256": sha256_file(&path)? }
        }));
    }
    if subjects.is_empty() {
        return Err(message("packaging created no native archive subject"));
    }
    let provenance = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/bulengerk/siorb/buildtypes/cargo-release/v1",
                "externalParameters": { "target": target, "profile": "release", "version": version },
                "internalParameters": { "production_signing": false },
                "resolvedDependencies": [
                    { "uri": "git+https://github.com/bulengerk/siorb", "digest": { "sha256": sha256_file(&root.join("Cargo.lock"))? } },
                    { "uri": "file:catalog/generated/catalog.json", "digest": { "sha256": sha256_file(&root.join("catalog/generated/catalog.json"))? } }
                ]
            },
            "runDetails": {
                "builder": { "id": "https://github.com/bulengerk/siorb/siorb-xtask/local" },
                "metadata": { "invocationId": "local-secret-free", "startedOn": generated_at, "finishedOn": generated_at }
            }
        }
    });
    atomic_json(
        &out.join(format!("siorb-{version}-{target}.provenance.json")),
        &provenance,
    )?;
    Ok(())
}

fn generate_checksums(root: &Path, directory: &Path) -> Result<()> {
    run(
        root,
        "python3",
        [
            "scripts/release/checksums.py".into(),
            "--directory".into(),
            directory.as_os_str().to_owned(),
            "--output".into(),
            directory.join("SHA256SUMS").into_os_string(),
        ],
    )
}

pub fn prepare_catalog(root: &Path, artifacts: Option<&Path>, out: &Path) -> Result<()> {
    prepare_empty_directory(out)?;
    let catalog_source = root.join("catalog/generated/catalog.json");
    let catalog_bytes = fs::read(&catalog_source)
        .map_err(|error| message(format!("cannot read {}: {error}", catalog_source.display())))?;
    let catalog: Value = serde_json::from_slice(&catalog_bytes)
        .map_err(|error| message(format!("generated catalog is invalid: {error}")))?;
    let version = catalog["catalog_version"]
        .as_u64()
        .ok_or_else(|| message("generated catalog has no integer catalog_version"))?;
    let schema_version = catalog["schema_version"]
        .as_str()
        .ok_or_else(|| message("generated catalog has no schema_version"))?;
    let generated_at = catalog["generated_at"]
        .as_str()
        .ok_or_else(|| message("generated catalog has no generated_at"))?;
    let base_epoch = match source_epoch()? {
        0 => parse_rfc3339_utc(generated_at)?,
        value => value,
    };

    atomic_write(&out.join("catalog.json"), &catalog_bytes)?;
    copy_regular_file(
        &root.join("catalog/trusted-root/runtime-root.json"),
        &out.join("runtime-root.json"),
    )?;
    copy_regular_file(
        &root.join("catalog/trusted-root/root.json"),
        &out.join("root.json"),
    )?;

    let mut targets = BTreeMap::from([(
        "catalog.json".to_owned(),
        TargetDescription {
            length: catalog_bytes.len() as u64,
            sha256: sha256_bytes(&catalog_bytes),
            custom: BTreeMap::from([
                ("kind".to_owned(), "siorb-catalog".to_owned()),
                ("catalog_version".to_owned(), version.to_string()),
                ("schema_version".to_owned(), schema_version.to_owned()),
            ]),
        },
    )]);
    if let Some(artifacts) = artifacts {
        add_artifact_targets(artifacts, out, &mut targets)?;
    }
    let targets_envelope = Signed {
        signed: TargetsMetadata {
            role_type: "targets".to_owned(),
            spec_version: SPEC_VERSION.to_owned(),
            version,
            expires_unix: base_epoch.saturating_add(365 * DAY),
            targets,
        },
        signatures: Vec::new(),
    };
    let targets_bytes = write_role(out, "targets", version, &targets_envelope)?;
    let snapshot_envelope = Signed {
        signed: SnapshotMetadata {
            role_type: "snapshot".to_owned(),
            spec_version: SPEC_VERSION.to_owned(),
            version,
            expires_unix: base_epoch.saturating_add(30 * DAY),
            meta: BTreeMap::from([(
                "targets.json".to_owned(),
                metadata_description(version, &targets_bytes),
            )]),
        },
        signatures: Vec::new(),
    };
    let snapshot_bytes = write_role(out, "snapshot", version, &snapshot_envelope)?;
    let timestamp_envelope = Signed {
        signed: TimestampMetadata {
            role_type: "timestamp".to_owned(),
            spec_version: SPEC_VERSION.to_owned(),
            version,
            expires_unix: base_epoch.saturating_add(7 * DAY),
            snapshot: metadata_description(version, &snapshot_bytes),
        },
        signatures: Vec::new(),
    };
    write_timestamp(out, &timestamp_envelope)?;
    println!(
        "prepared unsigned catalog metadata version {version} with {} target(s) at {}",
        targets_envelope.signed.targets.len(),
        out.display()
    );
    Ok(())
}

pub fn sign_metadata(out: &Path, role: SigningRole, key: &Path) -> Result<()> {
    let secret = read_secret_key(key)?;
    sign_metadata_with_secret(out, role, &secret)
}

fn sign_metadata_with_secret(out: &Path, role: SigningRole, secret: &[u8; 32]) -> Result<()> {
    if !out.is_dir() || out.is_symlink() {
        return Err(message(format!(
            "metadata output must be a real directory: {}",
            out.display()
        )));
    }
    let root_bytes = fs::read(out.join("runtime-root.json"))
        .map_err(|error| message(format!("cannot read runtime root: {error}")))?;
    let root: Signed<RootMetadata> = serde_json::from_slice(&root_bytes)
        .map_err(|error| message(format!("runtime root is invalid: {error}")))?;
    let key_id = signing_key_id(&root.signed, role, secret)?;
    match role {
        SigningRole::Targets => {
            let mut envelope: Signed<TargetsMetadata> = read_json(&out.join("targets.json"))?;
            add_signature(&mut envelope, &key_id, secret)?;
            let version = envelope.signed.version;
            let bytes = write_role(out, "targets", version, &envelope)?;
            let mut snapshot: Signed<SnapshotMetadata> = read_json(&out.join("snapshot.json"))?;
            snapshot.signed.meta.insert(
                "targets.json".to_owned(),
                metadata_description(version, &bytes),
            );
            snapshot.signatures.clear();
            let snapshot_version = snapshot.signed.version;
            write_role(out, "snapshot", snapshot_version, &snapshot)?;
            clear_timestamp_signature(out, snapshot_version)?;
        }
        SigningRole::Snapshot => {
            let mut envelope: Signed<SnapshotMetadata> = read_json(&out.join("snapshot.json"))?;
            add_signature(&mut envelope, &key_id, secret)?;
            let version = envelope.signed.version;
            let bytes = write_role(out, "snapshot", version, &envelope)?;
            let mut timestamp: Signed<TimestampMetadata> = read_json(&out.join("timestamp.json"))?;
            timestamp.signed.snapshot = metadata_description(version, &bytes);
            timestamp.signatures.clear();
            write_timestamp(out, &timestamp)?;
        }
        SigningRole::Timestamp => {
            let mut envelope: Signed<TimestampMetadata> = read_json(&out.join("timestamp.json"))?;
            add_signature(&mut envelope, &key_id, secret)?;
            write_timestamp(out, &envelope)?;
        }
    }
    println!(
        "added key `{key_id}` signature for {} metadata in {}",
        role.as_str(),
        out.display()
    );
    Ok(())
}

fn clear_timestamp_signature(out: &Path, snapshot_version: u64) -> Result<()> {
    let snapshot_bytes = fs::read(out.join(format!("{snapshot_version}.snapshot.json")))
        .map_err(|error| message(format!("cannot read updated snapshot: {error}")))?;
    let mut timestamp: Signed<TimestampMetadata> = read_json(&out.join("timestamp.json"))?;
    timestamp.signed.snapshot = metadata_description(snapshot_version, &snapshot_bytes);
    timestamp.signatures.clear();
    write_timestamp(out, &timestamp)?;
    Ok(())
}

fn add_signature<T: Serialize + Clone>(
    envelope: &mut Signed<T>,
    key_id: &str,
    secret: &[u8; 32],
) -> Result<()> {
    let generated = sign(envelope.signed.clone(), key_id, secret)?;
    let signature = generated
        .signatures
        .into_iter()
        .next()
        .ok_or_else(|| message("signer returned no signature"))?;
    envelope
        .signatures
        .retain(|existing| existing.key_id != key_id);
    envelope.signatures.push(signature);
    envelope
        .signatures
        .sort_by(|left, right| left.key_id.cmp(&right.key_id));
    Ok(())
}

fn signing_key_id(root: &RootMetadata, role: SigningRole, secret: &[u8; 32]) -> Result<String> {
    let public = public_key(secret).ok_or_else(|| message("invalid Ed25519 secret key"))?;
    let definition = root.roles.get(role.as_str()).ok_or_else(|| {
        message(format!(
            "runtime root does not define role `{}`",
            role.as_str()
        ))
    })?;
    definition
        .key_ids
        .iter()
        .find(|key_id| {
            root.keys
                .get(*key_id)
                .is_some_and(|key| key.scheme == "ed25519" && key.public == public)
        })
        .cloned()
        .ok_or_else(|| {
            message(format!(
                "provided key is not authorized for `{}` by runtime-root.json",
                role.as_str()
            ))
        })
}

fn read_secret_key(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| message(format!("cannot inspect signing key: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(message("signing key must be a regular non-symlink file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(message(
                "signing key permissions are too broad; restrict the file to its owner (for example, chmod 600)",
            ));
        }
    }
    let bytes =
        fs::read(path).map_err(|error| message(format!("cannot read signing key: {error}")))?;
    if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
        return Ok(secret);
    }
    let text = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|_| message("signing key must contain 32 raw bytes or 64 hexadecimal digits"))?;
    let decoded = hex::decode(text)
        .map_err(|_| message("signing key must contain 32 raw bytes or 64 hexadecimal digits"))?;
    <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| message("signing key must contain exactly 32 secret bytes"))
}

fn development_secret(role: SigningRole) -> [u8; 32] {
    let label = format!(
        "PUBLIC SIORB DEVELOPMENT FIXTURE KEY: dev-{}",
        role.as_str()
    );
    Sha256::digest(label.as_bytes()).into()
}

fn verify_prepared_catalog(directory: &Path) -> Result<()> {
    let root: Signed<RootMetadata> = read_json(&directory.join("runtime-root.json"))?;
    let timestamp = fs::read(directory.join("timestamp.json"))?;
    let timestamp_value: Signed<TimestampMetadata> = serde_json::from_slice(&timestamp)?;
    let snapshot_version = timestamp_value.signed.snapshot.version;
    let snapshot = fs::read(directory.join(format!("{snapshot_version}.snapshot.json")))?;
    let snapshot_value: Signed<SnapshotMetadata> = serde_json::from_slice(&snapshot)?;
    let targets_version = snapshot_value
        .signed
        .meta
        .get("targets.json")
        .ok_or_else(|| message("snapshot omits targets.json"))?
        .version;
    let targets = fs::read(directory.join(format!("{targets_version}.targets.json")))?;
    let repository = RepositoryVerifier::new(root, RollbackState::default())?
        .verify(&timestamp, &snapshot, &targets)?;
    let catalog = fs::read(directory.join("catalog.json"))?;
    repository.verify_target("catalog.json", &catalog)?;
    println!("prepared catalog signature chain verified");
    Ok(())
}

fn add_artifact_targets(
    artifacts: &Path,
    out: &Path,
    targets: &mut BTreeMap<String, TargetDescription>,
) -> Result<()> {
    if !artifacts.is_dir() || artifacts.is_symlink() {
        return Err(message(format!(
            "--artifacts must name a real directory: {}",
            artifacts.display()
        )));
    }
    let artifacts_canonical = artifacts.canonicalize()?;
    let out_canonical = out.canonicalize()?;
    if artifacts_canonical.starts_with(&out_canonical)
        || out_canonical.starts_with(&artifacts_canonical)
    {
        return Err(message(
            "artifact input and catalog output directories must not contain one another",
        ));
    }
    let entries = WalkDir::new(artifacts)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut files = Vec::new();
    for entry in entries {
        if entry.file_type().is_symlink() {
            return Err(message(format!(
                "artifact directory contains a symlink: {}",
                entry.path().display()
            )));
        }
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();
    for source in files {
        let relative = source
            .strip_prefix(artifacts)
            .map_err(|error| message(format!("cannot relativize artifact: {error}")))?;
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        validate_relative_path(&relative_text)?;
        let target_name = format!("artifacts/{relative_text}");
        let destination = out.join(&target_name);
        copy_regular_file(&source, &destination)?;
        let bytes = fs::read(&destination)?;
        targets.insert(
            target_name,
            TargetDescription {
                length: bytes.len() as u64,
                sha256: sha256_bytes(&bytes),
                custom: artifact_custom(&relative_text),
            },
        );
    }
    Ok(())
}

fn artifact_custom(name: &str) -> BTreeMap<String, String> {
    let file_name = Path::new(name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(name);
    let mut custom = BTreeMap::from([("kind".to_owned(), "release-artifact".to_owned())]);
    let (stem, format) = if let Some(value) = file_name.strip_suffix(".tar.gz") {
        (value, "tar.gz")
    } else if let Some(value) = file_name.strip_suffix(".zip") {
        (value, "zip")
    } else {
        return custom;
    };
    let Some(body) = stem.strip_prefix("siorb-") else {
        return custom;
    };
    let marker = ["-x86_64-", "-aarch64-", "-i686-", "-armv7-"]
        .into_iter()
        .find_map(|candidate| body.find(candidate).map(|index| (candidate, index)));
    let Some((_, index)) = marker else {
        return custom;
    };
    let version = &body[..index];
    let target = &body[index + 1..];
    let architecture = target.split('-').next().unwrap_or("unknown");
    let os = if target.contains("windows") {
        "windows"
    } else if target.contains("apple-darwin") {
        "macos"
    } else if target.contains("linux") {
        "linux"
    } else {
        "unknown"
    };
    custom.extend([
        ("kind".to_owned(), "siorb-binary".to_owned()),
        ("version".to_owned(), version.to_owned()),
        ("target".to_owned(), target.to_owned()),
        ("os".to_owned(), os.to_owned()),
        ("architecture".to_owned(), architecture.to_owned()),
        ("archive_format".to_owned(), format.to_owned()),
    ]);
    custom
}

fn write_role<T: Serialize>(
    out: &Path,
    role: &str,
    version: u64,
    envelope: &Signed<T>,
) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec_pretty(envelope)
        .map_err(|error| message(format!("cannot encode {role} metadata: {error}")))?;
    let mut bytes_with_newline = bytes;
    bytes_with_newline.push(b'\n');
    atomic_write(&out.join(format!("{role}.json")), &bytes_with_newline)?;
    atomic_write(
        &out.join(format!("{version}.{role}.json")),
        &bytes_with_newline,
    )?;
    Ok(bytes_with_newline)
}

fn write_timestamp(out: &Path, envelope: &Signed<TimestampMetadata>) -> Result<Vec<u8>> {
    atomic_json(&out.join("timestamp.json"), envelope)
}

fn metadata_description(version: u64, bytes: &[u8]) -> MetadataDescription {
    MetadataDescription {
        version,
        length: bytes.len() as u64,
        sha256: sha256_bytes(bytes),
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)
        .map_err(|error| message(format!("cannot read {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| message(format!("invalid JSON {}: {error}", path.display())))
}

fn regular_files(root: &Path) -> Result<Vec<PathBuf>> {
    let entries = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut files = Vec::new();
    for entry in entries {
        if entry.file_type().is_symlink() {
            return Err(message(format!(
                "release directory contains a symlink: {}",
                entry.path().display()
            )));
        }
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();
    Ok(files)
}

fn catalog_generated_at(root: &Path) -> Result<String> {
    let bytes = fs::read(root.join("catalog/generated/catalog.json"))?;
    let value: Value = serde_json::from_slice(&bytes)?;
    value["generated_at"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| message("generated catalog has no generated_at timestamp"))
}

fn spdx_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn validate_safe_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        return Err(message(format!("unsafe {label}: `{value}`")));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value.contains('\\')
    {
        return Err(message(format!("unsafe relative path `{value}`")));
    }
    Ok(())
}

fn parse_rfc3339_utc(value: &str) -> Result<u64> {
    if value.len() != 20 || !value.is_ascii() || !value.ends_with('Z') {
        return Err(message(format!(
            "generated_at must use YYYY-MM-DDTHH:MM:SSZ: `{value}`"
        )));
    }
    let number = |start: usize, end: usize| -> Result<i64> {
        value[start..end]
            .parse::<i64>()
            .map_err(|error| message(format!("invalid generated_at `{value}`: {error}")))
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    };
    if &value[4..5] != "-"
        || &value[7..8] != "-"
        || &value[10..11] != "T"
        || &value[13..14] != ":"
        || &value[16..17] != ":"
        || maximum_day == 0
        || !(1..=maximum_day).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return Err(message(format!("invalid generated_at `{value}`")));
    }
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|base| base.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| message("generated_at is outside the supported range"))?;
    u64::try_from(seconds).map_err(|_| message("generated_at predates the Unix epoch"))
}

const fn days_from_civil(mut year: i64, month: i64, day: i64) -> i64 {
    year -= if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::repository_root;

    #[test]
    fn parses_catalog_timestamp() -> Result<()> {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z")?, 0);
        assert_eq!(parse_rfc3339_utc("2026-07-13T00:00:00Z")?, 1_783_900_800);
        Ok(())
    }

    #[test]
    fn extracts_typed_binary_target_metadata() {
        let custom = artifact_custom("siorb-0.1.0-aarch64-apple-darwin.tar.gz");
        assert_eq!(custom.get("kind").map(String::as_str), Some("siorb-binary"));
        assert_eq!(custom.get("os").map(String::as_str), Some("macos"));
        assert_eq!(
            custom.get("architecture").map(String::as_str),
            Some("aarch64")
        );
    }

    #[test]
    fn rejects_parent_paths() {
        assert!(validate_relative_path("../escape").is_err());
        assert!(validate_relative_path("ok/file").is_ok());
    }

    #[test]
    fn prepared_catalog_signatures_round_trip() -> Result<()> {
        let root = repository_root()?;
        let out =
            std::env::temp_dir().join(format!("siorb-xtask-signing-test-{}", std::process::id()));
        if out.exists() {
            fs::remove_dir_all(&out)?;
        }
        prepare_catalog(&root, None, &out)?;
        for role in [
            SigningRole::Targets,
            SigningRole::Snapshot,
            SigningRole::Timestamp,
        ] {
            sign_metadata_with_secret(&out, role, &development_secret(role))?;
        }
        verify_prepared_catalog(&out)?;
        fs::remove_dir_all(out)?;
        Ok(())
    }
}
