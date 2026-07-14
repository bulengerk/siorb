//! Threshold-signed static metadata with rollback, freeze, and mix-and-match resistance.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::read::GzDecoder;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(not(windows))]
use siorb_core::correlation_id;
use siorb_core::{
    Architecture, ErrorKind, OsFamily, Result, SiorbError, unix_timestamp,
    validate_public_network_host,
};
use url::Url;
use zip::ZipArchive;

pub const MAX_RELEASE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RELEASE_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RELEASE_ENTRIES: usize = 1_024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signed<T> {
    pub signed: T,
    pub signatures: Vec<MetadataSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetadataSignature {
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub scheme: String,
    pub public: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub key_ids: Vec<String>,
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootMetadata {
    #[serde(rename = "type")]
    pub role_type: String,
    pub spec_version: String,
    pub version: u64,
    pub expires_unix: u64,
    pub consistent_snapshot: bool,
    pub keys: BTreeMap<String, PublicKey>,
    pub roles: BTreeMap<String, RoleDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(rename = "type")]
    pub role_type: String,
    pub spec_version: String,
    pub version: u64,
    pub expires_unix: u64,
    pub targets: BTreeMap<String, TargetDescription>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    #[serde(rename = "type")]
    pub role_type: String,
    pub spec_version: String,
    pub version: u64,
    pub expires_unix: u64,
    pub meta: BTreeMap<String, MetadataDescription>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampMetadata {
    #[serde(rename = "type")]
    pub role_type: String,
    pub spec_version: String,
    pub version: u64,
    pub expires_unix: u64,
    pub snapshot: MetadataDescription,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MetadataDescription {
    pub version: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetDescription {
    pub length: u64,
    pub sha256: String,
    #[serde(default)]
    pub custom: BTreeMap<String, String>,
}

/// A release archive selected exclusively from authenticated targets metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseTarget {
    pub name: String,
    pub version: Version,
    pub target: String,
    pub os: OsFamily,
    pub architecture: Architecture,
    pub archive_format: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUpdateDisposition {
    Replaced,
    ScheduledAfterExit,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackState {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedRepository {
    pub root: Signed<RootMetadata>,
    pub timestamp: Signed<TimestampMetadata>,
    pub snapshot: Signed<SnapshotMetadata>,
    pub targets: Signed<TargetsMetadata>,
    pub state: RollbackState,
}

impl VerifiedRepository {
    pub fn verify_target(&self, name: &str, bytes: &[u8]) -> Result<()> {
        validate_target_name(name)?;
        let target = self.targets.signed.targets.get(name).ok_or_else(|| {
            update_error(
                "update.target.missing",
                format!("signed targets metadata has no `{name}`"),
            )
        })?;
        verify_description(bytes, target.length, &target.sha256, "target")
    }
}

/// Select the newest compatible release newer than the running version.
/// Every decision field comes from threshold-verified targets metadata.
pub fn select_release_target(
    repository: &VerifiedRepository,
    current_version: &str,
    os: OsFamily,
    architecture: Architecture,
) -> Result<Option<ReleaseTarget>> {
    let current = Version::parse(current_version).map_err(|error| {
        update_error(
            "update.release.current_version",
            format!("running version `{current_version}` is not semantic: {error}"),
        )
    })?;
    let mut candidates = Vec::new();
    for (name, description) in &repository.targets.signed.targets {
        if description.custom.get("kind").map(String::as_str) != Some("siorb-binary") {
            continue;
        }
        let version_text = release_field(description, name, "version")?;
        let target = release_field(description, name, "target")?;
        let os_text = release_field(description, name, "os")?;
        let architecture_text = release_field(description, name, "architecture")?;
        let archive_format = release_field(description, name, "archive_format")?;
        let release_os = match os_text {
            "windows" => OsFamily::Windows,
            "macos" => OsFamily::Macos,
            "linux" => OsFamily::Linux,
            _ => {
                return Err(update_error(
                    "update.release.os",
                    format!("release target `{name}` has unsupported OS `{os_text}`"),
                ));
            }
        };
        let release_architecture = Architecture::normalize(architecture_text);
        if release_architecture == Architecture::Unknown {
            return Err(update_error(
                "update.release.architecture",
                format!(
                    "release target `{name}` has unsupported architecture `{architecture_text}`"
                ),
            ));
        }
        if !matches!(archive_format, "zip" | "tar.gz") {
            return Err(update_error(
                "update.release.archive_format",
                format!("release target `{name}` uses unsupported format `{archive_format}`"),
            ));
        }
        if description.length == 0 || description.length > MAX_RELEASE_ARCHIVE_BYTES {
            return Err(update_error(
                "update.release.size",
                format!("release target `{name}` exceeds the archive size boundary"),
            ));
        }
        let version = Version::parse(version_text).map_err(|error| {
            update_error(
                "update.release.version",
                format!("release target `{name}` has invalid version: {error}"),
            )
        })?;
        if release_os == os && release_architecture == architecture && version > current {
            candidates.push(ReleaseTarget {
                name: name.clone(),
                version,
                target: target.to_owned(),
                os: release_os,
                architecture: release_architecture,
                archive_format: archive_format.to_owned(),
                length: description.length,
                sha256: description.sha256.clone(),
            });
        }
    }
    candidates.sort_by(|left, right| {
        left.version
            .cmp(&right.version)
            .then_with(|| right.name.cmp(&left.name))
    });
    Ok(candidates.pop())
}

fn release_field<'a>(
    description: &'a TargetDescription,
    name: &str,
    field: &str,
) -> Result<&'a str> {
    description
        .custom
        .get(field)
        .map(String::as_str)
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| {
            update_error(
                "update.release.metadata",
                format!("release target `{name}` has no valid `{field}` field"),
            )
        })
}

/// Extract the one expected Siorb executable while rejecting unsafe archive
/// paths, links, special files, duplicate binaries, and decompression bombs.
pub fn extract_release_binary(archive_bytes: &[u8], target: &ReleaseTarget) -> Result<Vec<u8>> {
    if archive_bytes.len() as u64 != target.length {
        return Err(update_error(
            "update.release.length",
            "release archive length changed after verification".to_owned(),
        ));
    }
    let binary = match target.archive_format.as_str() {
        "zip" => extract_zip_binary(archive_bytes, target.os)?,
        "tar.gz" => extract_tar_binary(archive_bytes, target.os)?,
        format => {
            return Err(update_error(
                "update.release.archive_format",
                format!("unsupported release archive format `{format}`"),
            ));
        }
    };
    validate_executable_header(&binary, target.os)?;
    Ok(binary)
}

fn extract_zip_binary(archive_bytes: &[u8], os: OsFamily) -> Result<Vec<u8>> {
    let cursor = Cursor::new(archive_bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|error| {
        update_error(
            "update.release.archive",
            format!("release ZIP is invalid: {error}"),
        )
    })?;
    if archive.len() > MAX_RELEASE_ENTRIES {
        return Err(update_error(
            "update.release.archive_entries",
            "release ZIP contains too many entries".to_owned(),
        ));
    }
    let expected = executable_name(os);
    let mut unpacked = 0_u64;
    let mut binary = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            update_error(
                "update.release.archive",
                format!("cannot inspect release ZIP: {error}"),
            )
        })?;
        let path = entry.enclosed_name().ok_or_else(|| {
            update_error(
                "update.release.archive_path",
                format!("release ZIP contains unsafe path `{}`", entry.name()),
            )
        })?;
        validate_archive_path(&path)?;
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170_000;
            if kind != 0 && kind != 0o040_000 && kind != 0o100_000 {
                return Err(update_error(
                    "update.release.archive_type",
                    format!("release ZIP entry `{}` is not a regular file", entry.name()),
                ));
            }
        }
        if entry.is_dir() {
            continue;
        }
        unpacked = unpacked.checked_add(entry.size()).ok_or_else(|| {
            update_error(
                "update.release.archive_size",
                "release ZIP expanded size overflowed".to_owned(),
            )
        })?;
        if unpacked > MAX_RELEASE_UNPACKED_BYTES || entry.size() > MAX_RELEASE_ARCHIVE_BYTES {
            return Err(update_error(
                "update.release.archive_size",
                "release ZIP exceeds the expanded size boundary".to_owned(),
            ));
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(expected) {
            if binary.is_some() {
                return Err(update_error(
                    "update.release.binary_duplicate",
                    "release archive contains more than one Siorb executable".to_owned(),
                ));
            }
            let capacity = usize::try_from(entry.size()).map_err(|_| {
                update_error(
                    "update.release.binary_size",
                    "release executable cannot fit in this process address space".to_owned(),
                )
            })?;
            let mut bytes = Vec::with_capacity(capacity);
            entry
                .by_ref()
                .take(MAX_RELEASE_ARCHIVE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    update_error(
                        "update.release.archive_read",
                        format!("cannot read release executable: {error}"),
                    )
                })?;
            if bytes.len() as u64 > MAX_RELEASE_ARCHIVE_BYTES {
                return Err(update_error(
                    "update.release.binary_size",
                    "release executable exceeds the size boundary".to_owned(),
                ));
            }
            binary = Some(bytes);
        }
    }
    binary.ok_or_else(|| {
        update_error(
            "update.release.binary_missing",
            format!("release ZIP contains no `{expected}` executable"),
        )
    })
}

fn extract_tar_binary(archive_bytes: &[u8], os: OsFamily) -> Result<Vec<u8>> {
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|error| {
        update_error(
            "update.release.archive",
            format!("release tar archive is invalid: {error}"),
        )
    })?;
    let expected = executable_name(os);
    let mut entry_count = 0_usize;
    let mut unpacked = 0_u64;
    let mut binary = None;
    for entry in entries {
        entry_count += 1;
        if entry_count > MAX_RELEASE_ENTRIES {
            return Err(update_error(
                "update.release.archive_entries",
                "release tar archive contains too many entries".to_owned(),
            ));
        }
        let mut entry = entry.map_err(|error| {
            update_error(
                "update.release.archive",
                format!("cannot inspect release tar archive: {error}"),
            )
        })?;
        let path = entry.path().map_err(|error| {
            update_error(
                "update.release.archive_path",
                format!("release tar path is invalid: {error}"),
            )
        })?;
        validate_archive_path(&path)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err(update_error(
                "update.release.archive_type",
                format!(
                    "release tar entry `{}` is not a regular file",
                    path.display()
                ),
            ));
        }
        let size = entry.size();
        unpacked = unpacked.checked_add(size).ok_or_else(|| {
            update_error(
                "update.release.archive_size",
                "release tar expanded size overflowed".to_owned(),
            )
        })?;
        if unpacked > MAX_RELEASE_UNPACKED_BYTES || size > MAX_RELEASE_ARCHIVE_BYTES {
            return Err(update_error(
                "update.release.archive_size",
                "release tar archive exceeds the expanded size boundary".to_owned(),
            ));
        }
        if path.file_name().and_then(|name| name.to_str()) == Some(expected) {
            if binary.is_some() {
                return Err(update_error(
                    "update.release.binary_duplicate",
                    "release archive contains more than one Siorb executable".to_owned(),
                ));
            }
            let capacity = usize::try_from(size).map_err(|_| {
                update_error(
                    "update.release.binary_size",
                    "release executable cannot fit in this process address space".to_owned(),
                )
            })?;
            let mut bytes = Vec::with_capacity(capacity);
            entry
                .by_ref()
                .take(MAX_RELEASE_ARCHIVE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    update_error(
                        "update.release.archive_read",
                        format!("cannot read release executable: {error}"),
                    )
                })?;
            binary = Some(bytes);
        }
    }
    binary.ok_or_else(|| {
        update_error(
            "update.release.binary_missing",
            format!("release tar archive contains no `{expected}` executable"),
        )
    })
}

fn validate_archive_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text.is_empty()
        || text.contains('\\')
        || text.chars().any(char::is_control)
        || path.is_absolute()
        || path.components().count() > 16
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(update_error(
            "update.release.archive_path",
            format!("release archive contains unsafe path `{text}`"),
        ));
    }
    Ok(())
}

fn executable_name(os: OsFamily) -> &'static str {
    if os == OsFamily::Windows {
        "siorb.exe"
    } else {
        "siorb"
    }
}

fn validate_executable_header(bytes: &[u8], os: OsFamily) -> Result<()> {
    let valid = match os {
        OsFamily::Windows => bytes.starts_with(b"MZ"),
        OsFamily::Linux => bytes.starts_with(b"\x7fELF"),
        OsFamily::Macos => {
            bytes.len() >= 4
                && matches!(
                    &bytes[..4],
                    [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                        | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                        | [0xca, 0xfe, 0xba, 0xbe]
                        | [0xbe, 0xba, 0xfe, 0xca]
                )
        }
        OsFamily::Unknown => false,
    };
    if !valid {
        return Err(update_error(
            "update.release.binary_format",
            format!("release executable is not a valid {os} binary"),
        ));
    }
    Ok(())
}

/// Atomically replace the running executable on Unix, or schedule a fixed
/// post-exit replacement helper on Windows where a running image is locked.
pub fn install_current_executable(binary: &[u8]) -> Result<SelfUpdateDisposition> {
    let current = std::env::current_exe().map_err(|error| {
        update_error(
            "update.self.current_executable",
            format!("cannot locate the running executable: {error}"),
        )
    })?;
    install_executable_at(&current, binary)
}

fn install_executable_at(current: &Path, binary: &[u8]) -> Result<SelfUpdateDisposition> {
    let metadata = fs::symlink_metadata(current).map_err(|error| {
        update_error(
            "update.self.current_executable",
            format!("cannot inspect {}: {error}", current.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(update_error(
            "update.self.current_executable",
            "the running executable is not a regular non-symlink file".to_owned(),
        ));
    }
    let parent = current.parent().ok_or_else(|| {
        update_error(
            "update.self.current_executable",
            "the running executable has no parent directory".to_owned(),
        )
    })?;
    let name = current
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            update_error(
                "update.self.current_executable",
                "the running executable has a non-Unicode file name".to_owned(),
            )
        })?;
    let staged = parent.join(format!(
        ".{name}.siorb-update-{}-{}",
        std::process::id(),
        unix_timestamp()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options.open(&staged).map_err(|error| {
        update_error(
            "update.self.stage",
            format!("cannot stage self-update beside the executable: {error}"),
        )
    })?;
    if let Err(error) = file.write_all(binary).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&staged);
        return Err(update_error(
            "update.self.stage",
            format!("cannot write staged self-update: {error}"),
        ));
    }
    drop(file);
    install_staged_executable(current, &staged)
}

#[cfg(unix)]
fn install_staged_executable(current: &Path, staged: &Path) -> Result<SelfUpdateDisposition> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(staged, fs::Permissions::from_mode(0o755)).map_err(|error| {
        let _ = fs::remove_file(staged);
        update_error(
            "update.self.permissions",
            format!("cannot secure the staged executable permissions: {error}"),
        )
    })?;
    if let Err(error) = fs::rename(staged, current) {
        let _ = fs::remove_file(staged);
        return Err(update_error(
            "update.self.replace",
            format!("cannot atomically replace {}: {error}", current.display()),
        ));
    }
    if let Some(parent) = current.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(SelfUpdateDisposition::Replaced)
}

#[cfg(windows)]
fn install_staged_executable(current: &Path, staged: &Path) -> Result<SelfUpdateDisposition> {
    use std::process::{Command, Stdio};

    let script = staged.with_extension("ps1");
    let script_body = r#"param([int]$WaitFor, [string]$Current, [string]$Staged)
Wait-Process -Id $WaitFor -ErrorAction SilentlyContinue
$Backup = "$Current.siorb-old"
Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue
try {
  Move-Item -LiteralPath $Current -Destination $Backup -Force -ErrorAction Stop
  Move-Item -LiteralPath $Staged -Destination $Current -Force -ErrorAction Stop
  Remove-Item -LiteralPath $Backup -Force -ErrorAction SilentlyContinue
} catch {
  if (Test-Path -LiteralPath $Backup) { Move-Item -LiteralPath $Backup -Destination $Current -Force }
  exit 1
}
Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
"#;
    let mut script_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&script)
        .map_err(|error| {
            let _ = fs::remove_file(staged);
            update_error(
                "update.self.helper",
                format!("cannot create the Windows replacement helper: {error}"),
            )
        })?;
    if let Err(error) = script_file
        .write_all(script_body.as_bytes())
        .and_then(|()| script_file.sync_all())
    {
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(&script);
        return Err(update_error(
            "update.self.helper",
            format!("cannot write the Windows replacement helper: {error}"),
        ));
    }
    drop(script_file);
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        update_error(
            "update.self.helper",
            "SystemRoot is unavailable for the fixed PowerShell path".to_owned(),
        )
    })?;
    let powershell =
        PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    validate_windows_system_program(&powershell)?;
    let spawned = Command::new(&powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .arg(std::process::id().to_string())
        .arg(current)
        .arg(staged)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Err(error) = spawned {
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(&script);
        return Err(update_error(
            "update.self.helper",
            format!("cannot start the Windows replacement helper: {error}"),
        ));
    }
    Ok(SelfUpdateDisposition::ScheduledAfterExit)
}

#[cfg(windows)]
fn validate_windows_system_program(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if !path.is_absolute() {
        return Err(update_error(
            "update.self.helper",
            "Windows helper path is not absolute".to_owned(),
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            update_error(
                "update.self.helper",
                format!("cannot inspect fixed Windows helper path: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(update_error(
                "update.self.helper",
                "Windows helper path crosses a reparse point".to_owned(),
            ));
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        update_error(
            "update.self.helper",
            format!("cannot inspect fixed PowerShell executable: {error}"),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(update_error(
            "update.self.helper",
            "fixed PowerShell executable is not a regular file".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RepositoryVerifier {
    trusted_root: Signed<RootMetadata>,
    state: RollbackState,
    now_unix: u64,
    allow_expired_offline: bool,
}

impl RepositoryVerifier {
    pub fn new(trusted_root: Signed<RootMetadata>, state: RollbackState) -> Result<Self> {
        validate_root_shape(&trusted_root.signed)?;
        verify_role(&trusted_root, "root", &trusted_root.signed)?;
        Ok(Self {
            trusted_root,
            state,
            now_unix: unix_timestamp(),
            allow_expired_offline: false,
        })
    }

    #[must_use]
    pub const fn at_time(mut self, now_unix: u64) -> Self {
        self.now_unix = now_unix;
        self
    }

    #[must_use]
    pub const fn allow_expired_offline(mut self, allow: bool) -> Self {
        self.allow_expired_offline = allow;
        self
    }

    pub fn rotate_root(&mut self, next_bytes: &[u8]) -> Result<()> {
        let next: Signed<RootMetadata> = decode_metadata(next_bytes, "root")?;
        if next.signed.version != self.trusted_root.signed.version + 1 {
            return Err(update_error(
                "update.root.version",
                "new root version must increment exactly by one".to_owned(),
            ));
        }
        verify_role(&next, "root", &self.trusted_root.signed)?;
        validate_root_shape(&next.signed)?;
        verify_role(&next, "root", &next.signed)?;
        ensure_not_expired(next.signed.expires_unix, self.now_unix, false, "root")?;
        self.state.root = next.signed.version;
        self.trusted_root = next;
        Ok(())
    }

    pub fn verify(
        self,
        timestamp_bytes: &[u8],
        snapshot_bytes: &[u8],
        targets_bytes: &[u8],
    ) -> Result<VerifiedRepository> {
        ensure_not_expired(
            self.trusted_root.signed.expires_unix,
            self.now_unix,
            false,
            "root",
        )?;
        reject_rollback("root", self.trusted_root.signed.version, self.state.root)?;
        let timestamp: Signed<TimestampMetadata> = decode_metadata(timestamp_bytes, "timestamp")?;
        role_type(&timestamp.signed.role_type, "timestamp")?;
        verify_role(&timestamp, "timestamp", &self.trusted_root.signed)?;
        ensure_not_expired(
            timestamp.signed.expires_unix,
            self.now_unix,
            self.allow_expired_offline,
            "timestamp",
        )?;
        reject_rollback("timestamp", timestamp.signed.version, self.state.timestamp)?;
        verify_description(
            snapshot_bytes,
            timestamp.signed.snapshot.length,
            &timestamp.signed.snapshot.sha256,
            "snapshot",
        )?;
        let snapshot: Signed<SnapshotMetadata> = decode_metadata(snapshot_bytes, "snapshot")?;
        role_type(&snapshot.signed.role_type, "snapshot")?;
        verify_role(&snapshot, "snapshot", &self.trusted_root.signed)?;
        ensure_not_expired(
            snapshot.signed.expires_unix,
            self.now_unix,
            self.allow_expired_offline,
            "snapshot",
        )?;
        if snapshot.signed.version != timestamp.signed.snapshot.version {
            return Err(update_error(
                "update.snapshot.mix_match",
                "snapshot version does not match timestamp metadata".to_owned(),
            ));
        }
        reject_rollback("snapshot", snapshot.signed.version, self.state.snapshot)?;
        let targets_description = snapshot.signed.meta.get("targets.json").ok_or_else(|| {
            update_error(
                "update.snapshot.targets_missing",
                "snapshot metadata does not describe targets.json".to_owned(),
            )
        })?;
        verify_description(
            targets_bytes,
            targets_description.length,
            &targets_description.sha256,
            "targets",
        )?;
        let targets: Signed<TargetsMetadata> = decode_metadata(targets_bytes, "targets")?;
        role_type(&targets.signed.role_type, "targets")?;
        verify_role(&targets, "targets", &self.trusted_root.signed)?;
        ensure_not_expired(
            targets.signed.expires_unix,
            self.now_unix,
            self.allow_expired_offline,
            "targets",
        )?;
        if targets.signed.version != targets_description.version {
            return Err(update_error(
                "update.targets.mix_match",
                "targets version does not match snapshot metadata".to_owned(),
            ));
        }
        reject_rollback("targets", targets.signed.version, self.state.targets)?;
        for name in targets.signed.targets.keys() {
            validate_target_name(name)?;
        }
        let state = RollbackState {
            root: self.trusted_root.signed.version,
            timestamp: timestamp.signed.version,
            snapshot: snapshot.signed.version,
            targets: targets.signed.version,
        };
        Ok(VerifiedRepository {
            root: self.trusted_root,
            timestamp,
            snapshot,
            targets,
            state,
        })
    }
}

pub fn sign<T: Serialize + Clone>(signed: T, key_id: &str, secret_key: &[u8]) -> Result<Signed<T>> {
    let secret: [u8; 32] = secret_key.try_into().map_err(|_| {
        update_error(
            "update.signing_key.length",
            "Ed25519 signing key must contain exactly 32 secret bytes".to_owned(),
        )
    })?;
    let signing_key = SigningKey::from_bytes(&secret);
    let bytes = canonical_bytes(&signed)?;
    let signature = signing_key.sign(&bytes);
    Ok(Signed {
        signed,
        signatures: vec![MetadataSignature {
            key_id: key_id.to_owned(),
            signature: BASE64.encode(signature.to_bytes()),
        }],
    })
}

#[must_use]
pub fn public_key(secret_key: &[u8]) -> Option<String> {
    let secret: [u8; 32] = secret_key.try_into().ok()?;
    Some(BASE64.encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes()))
}

pub fn load_rollback_state(path: &Path) -> Result<RollbackState> {
    if !path.exists() {
        return Ok(RollbackState::default());
    }
    let bytes =
        fs::read(path).map_err(|error| update_error("update.state.read", error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| update_error("update.state.invalid", error.to_string()))
}

pub fn store_rollback_state(path: &Path, state: &RollbackState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| update_error("update.state.encode", error.to_string()))?;
    atomic_write(path, &bytes)
}

pub trait StaticTransport: std::fmt::Debug {
    fn fetch_optional(&self, relative_path: &str, maximum_bytes: usize) -> Result<Option<Vec<u8>>>;

    fn fetch(&self, relative_path: &str, maximum_bytes: usize) -> Result<Vec<u8>> {
        self.fetch_optional(relative_path, maximum_bytes)?
            .ok_or_else(|| {
                update_error(
                    "update.transport.not_found",
                    format!("static repository has no `{relative_path}`"),
                )
            })
    }
}

#[derive(Clone, Debug)]
pub struct DirectoryTransport {
    root: PathBuf,
}

impl DirectoryTransport {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl StaticTransport for DirectoryTransport {
    fn fetch_optional(&self, relative_path: &str, maximum_bytes: usize) -> Result<Option<Vec<u8>>> {
        validate_target_name(relative_path)?;
        let path = self.root.join(relative_path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(update_error("update.transport.read", error.to_string()));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(update_error(
                "update.transport.file_type",
                format!("{} is not a regular non-symlink file", path.display()),
            ));
        }
        if metadata.len() > maximum_bytes as u64 {
            return Err(update_error(
                "update.transport.size",
                format!("{} exceeds the download bound", path.display()),
            ));
        }
        fs::read(path)
            .map(Some)
            .map_err(|error| update_error("update.transport.read", error.to_string()))
    }
}

/// Bounded HTTPS-only transport for replaceable static mirrors.
#[derive(Clone, Debug)]
pub struct HttpsTransport {
    base: Url,
    allowed_hosts: BTreeSet<String>,
    client: reqwest::blocking::Client,
}

impl HttpsTransport {
    pub fn new(base: &str, additional_redirect_hosts: &[String]) -> Result<Self> {
        let mut base = Url::parse(base).map_err(|error| {
            update_error(
                "update.transport.url",
                format!("invalid mirror URL: {error}"),
            )
        })?;
        let base_host = base
            .host_str()
            .and_then(|host| validate_public_network_host(host).ok());
        if base.scheme() != "https"
            || base_host.is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(update_error(
                "update.transport.url",
                "static mirror must be a credential-free HTTPS URL without query or fragment"
                    .to_owned(),
            ));
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let base_host = base_host.ok_or_else(|| {
            update_error(
                "update.transport.url",
                "static mirror host is not publicly routable".to_owned(),
            )
        })?;
        let mut allowed_hosts = BTreeSet::from([base_host]);
        for host in additional_redirect_hosts {
            let canonical = validate_public_network_host(host).map_err(|error| {
                update_error(
                    "update.transport.redirect_host",
                    format!("unsafe redirect host `{host}`: {error}"),
                )
            })?;
            allowed_hosts.insert(canonical);
        }
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .user_agent(concat!("siorb/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                update_error(
                    "update.transport.client",
                    format!("cannot initialize HTTPS client: {error}"),
                )
            })?;
        Ok(Self {
            base,
            allowed_hosts,
            client,
        })
    }

    fn validate_redirect(&self, current: &Url, location: &str) -> Result<Url> {
        let next = current.join(location).map_err(|error| {
            update_error(
                "update.transport.redirect",
                format!("invalid redirect target: {error}"),
            )
        })?;
        let host = next
            .host_str()
            .and_then(|host| validate_public_network_host(host).ok());
        if next.scheme() != "https"
            || host
                .as_ref()
                .is_none_or(|host| !self.allowed_hosts.contains(host))
            || !next.username().is_empty()
            || next.password().is_some()
            || next.fragment().is_some()
        {
            return Err(update_error(
                "update.transport.redirect",
                "redirect leaves the HTTPS/domain trust boundary".to_owned(),
            ));
        }
        Ok(next)
    }
}

impl StaticTransport for HttpsTransport {
    fn fetch_optional(&self, relative_path: &str, maximum_bytes: usize) -> Result<Option<Vec<u8>>> {
        validate_target_name(relative_path)?;
        let mut current = self.base.join(relative_path).map_err(|error| {
            update_error(
                "update.transport.url",
                format!("cannot construct mirror URL: {error}"),
            )
        })?;
        for redirect_count in 0..=5 {
            let mut response = self.client.get(current.clone()).send().map_err(|error| {
                update_error(
                    "update.transport.network",
                    format!("HTTPS mirror request failed: {error}"),
                )
            })?;
            if response.status().is_redirection() {
                if redirect_count == 5 {
                    return Err(update_error(
                        "update.transport.redirect_limit",
                        "HTTPS mirror exceeded five redirects".to_owned(),
                    ));
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        update_error(
                            "update.transport.redirect",
                            "redirect response has no valid Location header".to_owned(),
                        )
                    })?;
                current = self.validate_redirect(&current, location)?;
                continue;
            }
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                return Err(update_error(
                    "update.transport.status",
                    format!("HTTPS mirror returned status {}", response.status()),
                ));
            }
            if response
                .content_length()
                .is_some_and(|length| length > maximum_bytes as u64)
            {
                return Err(update_error(
                    "update.transport.size",
                    "HTTPS response exceeds the signed download bound".to_owned(),
                ));
            }
            let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
            response
                .by_ref()
                .take(maximum_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    update_error(
                        "update.transport.truncated",
                        format!("cannot read HTTPS response: {error}"),
                    )
                })?;
            if bytes.len() > maximum_bytes {
                return Err(update_error(
                    "update.transport.size",
                    "HTTPS response exceeds the download bound".to_owned(),
                ));
            }
            return Ok(Some(bytes));
        }
        Err(update_error(
            "update.transport.redirect_limit",
            "HTTPS redirect loop".to_owned(),
        ))
    }
}

pub fn verify_from_transport(
    transport: &dyn StaticTransport,
    trusted_root: Signed<RootMetadata>,
    state: RollbackState,
    now_unix: u64,
) -> Result<VerifiedRepository> {
    const MAX_ROOT_ROTATIONS: usize = 64;
    let mut verifier = RepositoryVerifier::new(trusted_root, state)?.at_time(now_unix);
    let mut reached_rotation_limit = true;
    for _ in 0..MAX_ROOT_ROTATIONS {
        let next_version = verifier.trusted_root.signed.version + 1;
        let name = format!("{next_version}.root.json");
        let Some(next_root) = transport.fetch_optional(&name, 1024 * 1024)? else {
            reached_rotation_limit = false;
            break;
        };
        verifier.rotate_root(&next_root)?;
    }
    if reached_rotation_limit
        && transport
            .fetch_optional(
                &format!("{}.root.json", verifier.trusted_root.signed.version + 1),
                1024 * 1024,
            )?
            .is_some()
    {
        return Err(update_error(
            "update.root.rotation_limit",
            "static repository exceeds 64 sequential root rotations".to_owned(),
        ));
    }
    let timestamp = transport.fetch("timestamp.json", 1024 * 1024)?;
    let timestamp_value: Signed<TimestampMetadata> = decode_metadata(&timestamp, "timestamp")?;
    let snapshot_name = if verifier.trusted_root.signed.consistent_snapshot {
        format!("{}.snapshot.json", timestamp_value.signed.snapshot.version)
    } else {
        "snapshot.json".to_owned()
    };
    let snapshot = transport.fetch(&snapshot_name, 4 * 1024 * 1024)?;
    let snapshot_value: Signed<SnapshotMetadata> = decode_metadata(&snapshot, "snapshot")?;
    let target_version = snapshot_value
        .signed
        .meta
        .get("targets.json")
        .map_or(0, |description| description.version);
    let targets_name = if verifier.trusted_root.signed.consistent_snapshot {
        format!("{target_version}.targets.json")
    } else {
        "targets.json".to_owned()
    };
    let targets = transport.fetch(&targets_name, 32 * 1024 * 1024)?;
    verifier.verify(&timestamp, &snapshot, &targets)
}

fn verify_role<T: Serialize>(metadata: &Signed<T>, role: &str, root: &RootMetadata) -> Result<()> {
    let definition = root.roles.get(role).ok_or_else(|| {
        update_error(
            "update.role.missing",
            format!("trusted root has no `{role}` role"),
        )
    })?;
    if definition.threshold == 0 || definition.threshold as usize > definition.key_ids.len() {
        return Err(update_error(
            "update.threshold.invalid",
            format!("role `{role}` has an invalid threshold"),
        ));
    }
    let bytes = canonical_bytes(&metadata.signed)?;
    let mut valid = BTreeMap::<String, bool>::new();
    for signature in &metadata.signatures {
        if !definition.key_ids.contains(&signature.key_id) || valid.contains_key(&signature.key_id)
        {
            continue;
        }
        let Some(key) = root.keys.get(&signature.key_id) else {
            continue;
        };
        if key.scheme != "ed25519" {
            continue;
        }
        if verify_ed25519(key, signature, &bytes) {
            valid.insert(signature.key_id.clone(), true);
        }
    }
    if valid.len() < definition.threshold as usize {
        return Err(update_error(
            "update.threshold.not_met",
            format!(
                "role `{role}` has {} valid signature(s), but requires {}",
                valid.len(),
                definition.threshold
            ),
        ));
    }
    Ok(())
}

fn verify_ed25519(key: &PublicKey, signature: &MetadataSignature, bytes: &[u8]) -> bool {
    let Ok(public) = BASE64.decode(&key.public) else {
        return false;
    };
    let Ok(public): std::result::Result<[u8; 32], _> = public.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    let Ok(signature) = BASE64.decode(&signature.signature) else {
        return false;
    };
    let Ok(signature) = Ed25519Signature::from_slice(&signature) else {
        return false;
    };
    verifying_key.verify(bytes, &signature).is_ok()
}

fn validate_root_shape(root: &RootMetadata) -> Result<()> {
    role_type(&root.role_type, "root")?;
    if root.spec_version != "1.0" {
        return Err(update_error(
            "update.spec.unsupported",
            format!("unsupported metadata specification `{}`", root.spec_version),
        ));
    }
    for role in ["root", "targets", "snapshot", "timestamp"] {
        let definition = root.roles.get(role).ok_or_else(|| {
            update_error("update.role.missing", format!("root omits role `{role}`"))
        })?;
        if definition.threshold == 0 || definition.threshold as usize > definition.key_ids.len() {
            return Err(update_error(
                "update.threshold.invalid",
                format!("role `{role}` threshold is invalid"),
            ));
        }
        for key_id in &definition.key_ids {
            if !root.keys.contains_key(key_id) {
                return Err(update_error(
                    "update.key.missing",
                    format!("role `{role}` refers to missing key `{key_id}`"),
                ));
            }
        }
    }
    Ok(())
}

fn ensure_not_expired(expires: u64, now: u64, offline_exception: bool, role: &str) -> Result<()> {
    if expires <= now && !offline_exception {
        return Err(update_error(
            "update.metadata.expired",
            format!("{role} metadata expired at {expires}"),
        ));
    }
    Ok(())
}

fn reject_rollback(role: &str, observed: u64, trusted: u64) -> Result<()> {
    if observed < trusted {
        return Err(update_error(
            "update.rollback.detected",
            format!("{role} version {observed} is older than trusted version {trusted}"),
        ));
    }
    Ok(())
}

fn verify_description(bytes: &[u8], length: u64, sha256: &str, role: &str) -> Result<()> {
    if bytes.len() as u64 != length {
        return Err(update_error(
            "update.length.mismatch",
            format!("{role} length does not match signed metadata"),
        ));
    }
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != sha256 {
        return Err(update_error(
            "update.hash.mismatch",
            format!("{role} hash does not match signed metadata"),
        ));
    }
    Ok(())
}

fn role_type(observed: &str, expected: &str) -> Result<()> {
    if observed != expected {
        return Err(update_error(
            "update.role.type",
            format!("expected `{expected}` metadata, observed `{observed}`"),
        ));
    }
    Ok(())
}

fn decode_metadata<T: DeserializeOwned>(bytes: &[u8], role: &str) -> Result<Signed<T>> {
    serde_json::from_slice(bytes).map_err(|error| {
        update_error(
            "update.metadata.invalid",
            format!("{role} metadata is invalid JSON: {error}"),
        )
    })
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|error| update_error("update.canonicalize", error.to_string()))
}

fn validate_target_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || name.starts_with('-')
        || name.contains('\\')
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(update_error(
            "update.target.path",
            format!("unsafe metadata target path `{name}`"),
        ));
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(windows)]
    {
        use atomicwrites::{AllowOverwrite, AtomicFile};

        AtomicFile::new(path, AllowOverwrite)
            .write(|file| {
                file.write_all(bytes)?;
                file.write_all(b"\n")?;
                file.sync_all()
            })
            .map_err(|error| {
                let error: std::io::Error = error.into();
                update_error("update.state.replace", error.to_string())
            })
    }
    #[cfg(not(windows))]
    {
        let temporary = path.with_extension(format!("tmp-{}", correlation_id()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| update_error("update.state.write", error.to_string()))?;
        if let Err(error) = file
            .write_all(bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
        {
            let _ = fs::remove_file(&temporary);
            return Err(update_error("update.state.write", error.to_string()));
        }
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(update_error("update.state.rename", error.to_string()));
        }
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| update_error("update.state.sync", error.to_string()))?;
        }
        Ok(())
    }
}

fn update_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::CatalogFailure,
        message,
        "Keep the last verified catalog, inspect mirror metadata, and retry without bypassing verification.",
    )
    .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;

    fn repository_with_release(bytes: &[u8], version: &str) -> VerifiedRepository {
        let description = TargetDescription {
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            custom: BTreeMap::from([
                ("kind".to_owned(), "siorb-binary".to_owned()),
                ("version".to_owned(), version.to_owned()),
                ("target".to_owned(), "x86_64-unknown-linux-gnu".to_owned()),
                ("os".to_owned(), "linux".to_owned()),
                ("architecture".to_owned(), "x86_64".to_owned()),
                ("archive_format".to_owned(), "zip".to_owned()),
            ]),
        };
        VerifiedRepository {
            root: Signed {
                signed: RootMetadata {
                    role_type: "root".to_owned(),
                    spec_version: "1.0".to_owned(),
                    version: 1,
                    expires_unix: u64::MAX,
                    consistent_snapshot: true,
                    keys: BTreeMap::new(),
                    roles: BTreeMap::new(),
                },
                signatures: Vec::new(),
            },
            timestamp: Signed {
                signed: TimestampMetadata {
                    role_type: "timestamp".to_owned(),
                    spec_version: "1.0".to_owned(),
                    version: 1,
                    expires_unix: u64::MAX,
                    snapshot: MetadataDescription {
                        version: 1,
                        length: 0,
                        sha256: String::new(),
                    },
                },
                signatures: Vec::new(),
            },
            snapshot: Signed {
                signed: SnapshotMetadata {
                    role_type: "snapshot".to_owned(),
                    spec_version: "1.0".to_owned(),
                    version: 1,
                    expires_unix: u64::MAX,
                    meta: BTreeMap::new(),
                },
                signatures: Vec::new(),
            },
            targets: Signed {
                signed: TargetsMetadata {
                    role_type: "targets".to_owned(),
                    spec_version: "1.0".to_owned(),
                    version: 1,
                    expires_unix: u64::MAX,
                    targets: BTreeMap::from([(
                        "artifacts/siorb-linux.zip".to_owned(),
                        description,
                    )]),
                },
                signatures: Vec::new(),
            },
            state: RollbackState::default(),
        }
    }

    fn zip_with_entry(name: &str, bytes: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .unix_permissions(0o755);
        assert!(writer.start_file(name, options).is_ok());
        assert!(writer.write_all(bytes).is_ok());
        writer.finish().map(Cursor::into_inner).unwrap_or_default()
    }

    fn root_payload(version: u64, key_id: &str, public: String) -> RootMetadata {
        let role = RoleDefinition {
            key_ids: vec![key_id.to_owned()],
            threshold: 1,
        };
        RootMetadata {
            role_type: "root".to_owned(),
            spec_version: "1.0".to_owned(),
            version,
            expires_unix: u64::MAX,
            consistent_snapshot: true,
            keys: BTreeMap::from([(
                key_id.to_owned(),
                PublicKey {
                    scheme: "ed25519".to_owned(),
                    public,
                },
            )]),
            roles: ["root", "targets", "snapshot", "timestamp"]
                .into_iter()
                .map(|name| (name.to_owned(), role.clone()))
                .collect(),
        }
    }

    #[cfg(unix)]
    fn metadata_description(version: u64, bytes: &[u8]) -> MetadataDescription {
        MetadataDescription {
            version,
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    #[cfg(unix)]
    fn write_signed_release_repository(
        root: &Path,
        archive: &[u8],
        secret: &[u8; 32],
    ) -> std::result::Result<Signed<RootMetadata>, Box<dyn std::error::Error>> {
        const KEY_ID: &str = "local-release";
        const TARGET_NAME: &str = "artifacts/siorb-linux.zip";

        let public = public_key(secret).ok_or("test signing key must be valid")?;
        let trusted_root = sign(root_payload(1, KEY_ID, public), KEY_ID, secret)?;
        let target = TargetDescription {
            length: archive.len() as u64,
            sha256: hex::encode(Sha256::digest(archive)),
            custom: BTreeMap::from([
                ("kind".to_owned(), "siorb-binary".to_owned()),
                ("version".to_owned(), "2.0.0".to_owned()),
                ("target".to_owned(), "x86_64-unknown-linux-gnu".to_owned()),
                ("os".to_owned(), "linux".to_owned()),
                ("architecture".to_owned(), "x86_64".to_owned()),
                ("archive_format".to_owned(), "zip".to_owned()),
            ]),
        };
        let targets = sign(
            TargetsMetadata {
                role_type: "targets".to_owned(),
                spec_version: "1.0".to_owned(),
                version: 1,
                expires_unix: u64::MAX,
                targets: BTreeMap::from([(TARGET_NAME.to_owned(), target)]),
            },
            KEY_ID,
            secret,
        )?;
        let targets_bytes = serde_json::to_vec(&targets)?;
        let snapshot = sign(
            SnapshotMetadata {
                role_type: "snapshot".to_owned(),
                spec_version: "1.0".to_owned(),
                version: 1,
                expires_unix: u64::MAX,
                meta: BTreeMap::from([(
                    "targets.json".to_owned(),
                    metadata_description(1, &targets_bytes),
                )]),
            },
            KEY_ID,
            secret,
        )?;
        let snapshot_bytes = serde_json::to_vec(&snapshot)?;
        let timestamp = sign(
            TimestampMetadata {
                role_type: "timestamp".to_owned(),
                spec_version: "1.0".to_owned(),
                version: 1,
                expires_unix: u64::MAX,
                snapshot: metadata_description(1, &snapshot_bytes),
            },
            KEY_ID,
            secret,
        )?;

        fs::create_dir_all(root.join("artifacts"))?;
        fs::write(root.join("timestamp.json"), serde_json::to_vec(&timestamp)?)?;
        fs::write(root.join("1.snapshot.json"), snapshot_bytes)?;
        fs::write(root.join("1.targets.json"), targets_bytes)?;
        fs::write(root.join(TARGET_NAME), archive)?;
        Ok(trusted_root)
    }

    #[test]
    fn target_traversal_is_rejected() {
        assert!(validate_target_name("../targets.json").is_err());
        assert!(validate_target_name("safe/catalog.json").is_ok());
    }

    #[test]
    fn https_transport_rejects_non_public_base_and_redirect_hosts() {
        for base in [
            "https://localhost/catalog/",
            "https://127.0.0.1/catalog/",
            "https://10.0.0.1/catalog/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/catalog/",
        ] {
            assert!(HttpsTransport::new(base, &[]).is_err(), "{base}");
        }
        assert!(
            HttpsTransport::new(
                "https://updates.example.org/catalog/",
                &["192.168.1.20".to_owned()]
            )
            .is_err()
        );

        let transport = HttpsTransport::new(
            "https://updates.example.org/catalog/",
            &["cdn.example.org".to_owned()],
        );
        assert!(transport.is_ok());
        let Some(transport) = transport.ok() else {
            return;
        };
        let current = Url::parse("https://updates.example.org/catalog/timestamp.json");
        assert!(current.is_ok());
        let Some(current) = current.ok() else { return };
        assert!(
            transport
                .validate_redirect(&current, "https://cdn.example.org/timestamp.json")
                .is_ok()
        );
        assert!(
            transport
                .validate_redirect(&current, "https://127.0.0.1/timestamp.json")
                .is_err()
        );
    }

    #[test]
    fn signing_and_public_key_are_consistent() {
        let secret = [7_u8; 32];
        let public = public_key(&secret);
        assert!(public.is_some());
        let signed = sign(BTreeMap::from([("a", 1)]), "dev", &secret);
        assert!(signed.is_ok());
    }

    #[test]
    fn newest_compatible_release_is_selected() {
        let repository = repository_with_release(b"archive", "1.2.3");
        let selected =
            select_release_target(&repository, "1.0.0", OsFamily::Linux, Architecture::X86_64);
        assert!(selected.is_ok());
        assert_eq!(
            selected
                .ok()
                .flatten()
                .map(|target| target.version.to_string()),
            Some("1.2.3".to_owned())
        );
        assert!(
            select_release_target(&repository, "1.2.3", OsFamily::Linux, Architecture::X86_64,)
                .is_ok_and(|target| target.is_none())
        );
    }

    #[test]
    fn verified_zip_yields_the_expected_binary() {
        let bytes = zip_with_entry("siorb", b"\x7fELF-test-binary");
        let repository = repository_with_release(&bytes, "1.2.3");
        let target =
            select_release_target(&repository, "1.0.0", OsFamily::Linux, Architecture::X86_64)
                .ok()
                .flatten();
        assert!(target.is_some());
        let extracted = target.and_then(|target| extract_release_binary(&bytes, &target).ok());
        assert_eq!(extracted, Some(b"\x7fELF-test-binary".to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn local_signed_update_verifies_and_replaces_only_a_temporary_executable()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let archive = zip_with_entry("siorb", b"\x7fELF-signed-local-update");
        let repository_path = directory.path().join("repository");
        let trusted_root =
            write_signed_release_repository(&repository_path, &archive, &[23_u8; 32])?;
        let transport = DirectoryTransport::new(repository_path);
        let repository =
            verify_from_transport(&transport, trusted_root, RollbackState::default(), 1)?;
        assert_eq!(repository.state.root, 1);
        assert_eq!(repository.state.timestamp, 1);
        assert_eq!(repository.state.snapshot, 1);
        assert_eq!(repository.state.targets, 1);

        let target =
            select_release_target(&repository, "1.0.0", OsFamily::Linux, Architecture::X86_64)?
                .ok_or("signed repository must contain a newer compatible release")?;
        let fetched = transport.fetch(&target.name, usize::try_from(target.length)?)?;
        repository.verify_target(&target.name, &fetched)?;
        let binary = extract_release_binary(&fetched, &target)?;

        let install_root = directory.path().join("installation");
        fs::create_dir(&install_root)?;
        let executable = install_root.join("siorb");
        fs::write(&executable, b"\x7fELF-old-test-binary")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        assert!(executable.starts_with(directory.path()));
        let disposition = install_executable_at(&executable, &binary)?;

        assert_eq!(disposition, SelfUpdateDisposition::Replaced);
        assert_eq!(fs::read(&executable)?, b"\x7fELF-signed-local-update");
        assert_eq!(
            fs::metadata(&executable)?.permissions().mode() & 0o777,
            0o755
        );
        let installed_entries =
            fs::read_dir(&install_root)?.collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(installed_entries.len(), 1);
        assert_eq!(installed_entries[0].path(), executable);
        Ok(())
    }

    #[test]
    fn archive_traversal_is_rejected() {
        let bytes = zip_with_entry("../siorb", b"\x7fELF-test-binary");
        let repository = repository_with_release(&bytes, "1.2.3");
        let target =
            select_release_target(&repository, "1.0.0", OsFamily::Linux, Architecture::X86_64)
                .ok()
                .flatten();
        assert!(target.is_some());
        assert!(target.is_some_and(|target| extract_release_binary(&bytes, &target).is_err()));
    }

    #[test]
    fn root_rotation_requires_old_and_new_authorization() {
        let old_secret = [11_u8; 32];
        let new_secret = [12_u8; 32];
        let Some(old_public) = public_key(&old_secret) else {
            return;
        };
        let Some(new_public) = public_key(&new_secret) else {
            return;
        };
        let Ok(old_root) = sign(root_payload(1, "old", old_public), "old", &old_secret) else {
            return;
        };
        let new_payload = root_payload(2, "new", new_public);
        let Ok(mut next_root) = sign(new_payload.clone(), "old", &old_secret) else {
            return;
        };
        let Ok(new_authorization) = sign(new_payload, "new", &new_secret) else {
            return;
        };
        next_root.signatures.extend(new_authorization.signatures);
        let Ok(next_bytes) = serde_json::to_vec(&next_root) else {
            return;
        };
        let Ok(mut verifier) = RepositoryVerifier::new(old_root, RollbackState::default()) else {
            return;
        };
        assert!(verifier.rotate_root(&next_bytes).is_ok());
        assert_eq!(verifier.trusted_root.signed.version, 2);
    }
}
