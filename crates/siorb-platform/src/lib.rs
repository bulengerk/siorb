//! Injectable host detection. Detection never mutates the machine.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use siorb_core::{
    Architecture, BackendInfo, ErrorKind, OsFamily, PlatformContext, Result, Scope, SiorbError,
    correlation_id,
};

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_PROBE_MAX_BYTES: usize = 16 * 1024;

/// Bounded result of a read-only host probe. Keeping the runner injectable makes
/// platform detection deterministic in tests and prevents tests from invoking
/// whatever happens to be installed on the build host.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProbeOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub truncated: bool,
}

pub trait ProbeRunner: Send + Sync + std::fmt::Debug {
    /// Run a read-only executable probe.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the executable cannot be started, observed, or
    /// terminated within the supplied bound.
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        timeout: Duration,
        max_output_bytes: usize,
    ) -> io::Result<ProbeOutput>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeProbeRunner;

impl ProbeRunner for NativeProbeRunner {
    fn run(
        &self,
        executable: &Path,
        arguments: &[&str],
        timeout: Duration,
        max_output_bytes: usize,
    ) -> io::Result<ProbeOutput> {
        if !executable.is_absolute()
            || arguments.len() > 16
            || !(256..=1024 * 1024).contains(&max_output_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe or unbounded platform probe",
            ));
        }
        let capture_id = correlation_id();
        let stdout_path = env::temp_dir().join(format!(".siorb-probe-{capture_id}-stdout"));
        let stderr_path = env::temp_dir().join(format!(".siorb-probe-{capture_id}-stderr"));
        let stdout = create_capture_file(&stdout_path)?;
        let stderr = match create_capture_file(&stderr_path) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_file(&stdout_path);
                return Err(error);
            }
        };
        let child = Command::new(executable)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&stdout_path);
                let _ = fs::remove_file(&stderr_path);
                return Err(error);
            }
        };
        let started = Instant::now();
        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait()? {
                break (status, false);
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                break (child.wait()?, true);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = File::open(&stdout_path).and_then(|file| read_bounded(file, max_output_bytes));
        let stderr = File::open(&stderr_path).and_then(|file| read_bounded(file, max_output_bytes));
        let _ = fs::remove_file(&stdout_path);
        let _ = fs::remove_file(&stderr_path);
        let (stdout, stdout_truncated) = stdout?;
        let (stderr, stderr_truncated) = stderr?;
        Ok(ProbeOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            timed_out,
            truncated: stdout_truncated || stderr_truncated,
        })
    }
}

fn create_capture_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn read_bounded(reader: impl Read, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    reader.take(limit).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok((bytes, truncated))
}

#[derive(Clone, Debug)]
pub struct SystemDetector {
    offline: bool,
    path: Option<String>,
    os_release_path: PathBuf,
    probe: Arc<dyn ProbeRunner>,
    os_override: Option<OsFamily>,
    architecture_override: Option<Architecture>,
    native_architecture_override: Option<Architecture>,
    os_version_override: Option<String>,
    libc_override: Option<String>,
    interactive_override: Option<bool>,
    elevation_override: Option<bool>,
    container_override: Option<bool>,
    compatibility_layer_override: Option<bool>,
}

impl Default for SystemDetector {
    fn default() -> Self {
        Self {
            offline: false,
            path: env::var("PATH").ok(),
            os_release_path: PathBuf::from("/etc/os-release"),
            probe: Arc::new(NativeProbeRunner),
            os_override: None,
            architecture_override: None,
            native_architecture_override: None,
            os_version_override: None,
            libc_override: None,
            interactive_override: None,
            elevation_override: None,
            container_override: None,
            compatibility_layer_override: None,
        }
    }
}

impl SystemDetector {
    #[must_use]
    pub const fn offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_os_release(mut self, path: impl Into<PathBuf>) -> Self {
        self.os_release_path = path.into();
        self
    }

    #[must_use]
    pub fn with_probe(mut self, probe: impl ProbeRunner + 'static) -> Self {
        self.probe = Arc::new(probe);
        self
    }

    /// Test-only-style injection is public so embedders can detect a remote or
    /// sandboxed host from fixtures without forging process-wide environment.
    #[must_use]
    pub const fn with_host(mut self, os: OsFamily, architecture: Architecture) -> Self {
        self.os_override = Some(os);
        self.architecture_override = Some(architecture);
        self
    }

    /// Supply the native CPU architecture independently of the process
    /// architecture (for example WOW64 or Rosetta fixtures).
    #[must_use]
    pub const fn with_native_architecture(mut self, architecture: Architecture) -> Self {
        self.native_architecture_override = Some(architecture);
        self
    }

    /// Supply the version returned by the host's native version provider.
    #[must_use]
    pub fn with_os_version(mut self, version: impl Into<String>) -> Self {
        self.os_version_override = Some(version.into());
        self
    }

    /// Supply the libc result of a remote/sandbox detector provider.
    #[must_use]
    pub fn with_libc(mut self, libc: impl Into<String>) -> Self {
        self.libc_override = Some(libc.into());
        self
    }

    /// Supply terminal capability input without depending on the test runner's
    /// own terminal.
    #[must_use]
    pub const fn with_interactive(mut self, interactive: bool) -> Self {
        self.interactive_override = Some(interactive);
        self
    }

    /// Supply Unix privilege-provider availability for remote/sandbox fixtures.
    /// Windows elevation remains disabled until the executor has a validated
    /// Windows broker.
    #[must_use]
    pub const fn with_elevation_available(mut self, available: bool) -> Self {
        self.elevation_override = Some(available);
        self
    }

    /// Supply container detection input for a remote/sandbox fixture.
    #[must_use]
    pub const fn with_container(mut self, container: bool) -> Self {
        self.container_override = Some(container);
        self
    }

    /// Supply compatibility-layer detection input for WSL-style fixtures.
    #[must_use]
    pub const fn with_compatibility_layer(mut self, compatibility_layer: bool) -> Self {
        self.compatibility_layer_override = Some(compatibility_layer);
        self
    }

    #[must_use]
    pub fn detect(&self) -> PlatformContext {
        let os = self.os_override.unwrap_or_else(current_os);
        let release = if os == OsFamily::Linux {
            fs::read_to_string(&self.os_release_path)
                .ok()
                .map(|content| parse_os_release(&content))
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };

        let distribution = release.get("ID").cloned();
        let distribution_version = release.get("VERSION_ID").cloned();
        let distribution_like: Vec<String> = release
            .get("ID_LIKE")
            .map(|value| value.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let process_architecture = self
            .architecture_override
            .unwrap_or_else(|| Architecture::normalize(env::consts::ARCH));
        let (architecture, translated) = self.native_architecture_override.map_or_else(
            || detect_native_architecture(os, process_architecture, self.probe.as_ref()),
            |native| (native, native != process_architecture),
        );

        let os_version = self
            .os_version_override
            .clone()
            .or_else(|| detect_os_version(os, &release, self.probe.as_ref()));
        let backends = detect_backends(
            os,
            distribution.as_deref(),
            &distribution_like,
            self.path.as_deref(),
            &self.probe,
        );

        let elevation_available = if os == OsFamily::Windows {
            false
        } else {
            self.elevation_override
                .unwrap_or_else(|| has_elevation(os, self.path.as_deref()))
        };

        let mut restrictions = Vec::new();
        restrictions.extend(classify_host_support(
            os,
            os_version.as_deref(),
            distribution.as_deref(),
            distribution_version.as_deref(),
            &distribution_like,
            architecture,
        ));
        let container = self
            .container_override
            .unwrap_or_else(|| os == OsFamily::Linux && Path::new("/.dockerenv").exists());
        if container {
            restrictions.push("container".to_owned());
        }
        let compatibility_layer = self.compatibility_layer_override.unwrap_or_else(|| {
            os == OsFamily::Linux
                && fs::read_to_string("/proc/version")
                    .is_ok_and(|value| value.to_ascii_lowercase().contains("microsoft"))
        });
        if compatibility_layer {
            restrictions.push("windows_compatibility_layer".to_owned());
        }
        if translated {
            restrictions.push("translated_process".to_owned());
        }
        if os == OsFamily::Windows {
            restrictions.push("external_elevation_unavailable".to_owned());
        } else if matches!(os, OsFamily::Linux | OsFamily::Macos) && !elevation_available {
            restrictions.push("missing_elevation".to_owned());
        }
        if os != OsFamily::Unknown && backends.iter().all(|backend| !backend.available) {
            restrictions.push("no_compatible_backend".to_owned());
        }

        PlatformContext {
            os,
            os_version,
            distribution,
            distribution_version,
            distribution_like,
            architecture,
            translated,
            libc: self.libc_override.clone().or_else(|| detect_libc(os)),
            backends,
            interactive: self.interactive_override.unwrap_or_else(|| {
                std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
            }),
            elevation_available,
            supported_scopes: if elevation_available {
                vec![Scope::User, Scope::System]
            } else {
                vec![Scope::User]
            },
            offline: self.offline,
            restrictions,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BackendDefinition {
    id: &'static str,
    executables: &'static [&'static str],
    version_arguments: &'static [&'static str],
    capabilities: &'static [&'static str],
    minimum_version: &'static [u64],
    maximum_major: u64,
}

const MUTATION_CAPABILITIES: &[&str] =
    &["query", "install", "remove", "upgrade", "repair", "verify"];
const NON_INTERACTIVE_CAPABILITIES: &[&str] = &[
    "query",
    "install",
    "remove",
    "upgrade",
    "repair",
    "verify",
    "non_interactive",
];
const NO_REPAIR_NON_INTERACTIVE_CAPABILITIES: &[&str] = &[
    "query",
    "install",
    "remove",
    "upgrade",
    "verify",
    "non_interactive",
];

fn backend_definitions(os: OsFamily) -> &'static [BackendDefinition] {
    const WINDOWS: &[BackendDefinition] = &[
        BackendDefinition {
            id: "winget",
            executables: &["winget.exe", "winget"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[1, 6],
            maximum_major: 1,
        },
        BackendDefinition {
            id: "scoop",
            executables: &["scoop.cmd", "scoop"],
            version_arguments: &["--version"],
            capabilities: MUTATION_CAPABILITIES,
            minimum_version: &[0, 4],
            maximum_major: 0,
        },
        BackendDefinition {
            id: "chocolatey",
            executables: &["choco.exe", "choco"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[2, 0],
            maximum_major: 2,
        },
    ];
    const MACOS: &[BackendDefinition] = &[
        BackendDefinition {
            id: "brew",
            executables: &["brew"],
            version_arguments: &["--version"],
            capabilities: MUTATION_CAPABILITIES,
            minimum_version: &[4, 0],
            maximum_major: 6,
        },
        BackendDefinition {
            id: "macports",
            executables: &["port"],
            version_arguments: &["version"],
            capabilities: MUTATION_CAPABILITIES,
            minimum_version: &[2, 8],
            maximum_major: 2,
        },
    ];
    const LINUX: &[BackendDefinition] = &[
        BackendDefinition {
            id: "apt",
            executables: &["apt-get"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[2, 0],
            maximum_major: 3,
        },
        BackendDefinition {
            id: "dnf",
            executables: &["dnf5", "dnf"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[4, 0],
            maximum_major: 5,
        },
        BackendDefinition {
            id: "yum",
            executables: &["yum"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[3, 4],
            maximum_major: 4,
        },
        BackendDefinition {
            id: "pacman",
            executables: &["pacman"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[6, 0],
            maximum_major: 7,
        },
        BackendDefinition {
            id: "flatpak",
            executables: &["flatpak"],
            version_arguments: &["--version"],
            capabilities: NO_REPAIR_NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[1, 12],
            maximum_major: 1,
        },
        BackendDefinition {
            id: "snap",
            executables: &["snap"],
            version_arguments: &["version"],
            capabilities: MUTATION_CAPABILITIES,
            minimum_version: &[2, 58],
            maximum_major: 2,
        },
        BackendDefinition {
            id: "zypper",
            executables: &["zypper"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[1, 14],
            maximum_major: 1,
        },
        BackendDefinition {
            id: "apk",
            executables: &["apk"],
            version_arguments: &["--version"],
            capabilities: NON_INTERACTIVE_CAPABILITIES,
            minimum_version: &[2, 14],
            maximum_major: 2,
        },
    ];
    match os {
        OsFamily::Windows => WINDOWS,
        OsFamily::Macos => MACOS,
        OsFamily::Linux => LINUX,
        OsFamily::Unknown => &[],
    }
}

fn detect_backend(
    definition: &BackendDefinition,
    path: Option<&str>,
    probe: &dyn ProbeRunner,
) -> Option<BackendInfo> {
    let executable = definition
        .executables
        .iter()
        .find_map(|name| find_executable(name, path))?;
    let version = {
        let output = probe
            .run(
                &executable,
                definition.version_arguments,
                VERSION_PROBE_TIMEOUT,
                VERSION_PROBE_MAX_BYTES,
            )
            .ok();
        let output = output.as_ref()?;
        if output.timed_out || output.truncated || output.exit_code != Some(0) {
            None
        } else {
            let bytes = if output.stdout.is_empty() {
                &output.stderr
            } else {
                &output.stdout
            };
            parse_backend_version(definition.id, bytes)
        }
    };
    let available = version
        .as_deref()
        .is_some_and(|version| backend_version_supported(definition, version));
    Some(BackendInfo {
        id: definition.id.to_owned(),
        executable: executable.display().to_string(),
        version,
        available,
        capabilities: if available {
            definition
                .capabilities
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            Vec::new()
        },
    })
}

fn detect_backends(
    os: OsFamily,
    distribution: Option<&str>,
    distribution_like: &[String],
    path: Option<&str>,
    probe: &Arc<dyn ProbeRunner>,
) -> Vec<BackendInfo> {
    let definitions: Vec<_> = backend_definitions(os)
        .iter()
        .copied()
        .filter(|definition| backend_applies(definition.id, os, distribution, distribution_like))
        .collect();
    let handles: Vec<_> = definitions
        .iter()
        .copied()
        .map(|definition| {
            let path = path.map(str::to_owned);
            let probe = Arc::clone(probe);
            thread::spawn(move || detect_backend(&definition, path.as_deref(), probe.as_ref()))
        })
        .collect();
    handles
        .into_iter()
        .zip(&definitions)
        .filter_map(|(handle, definition)| match handle.join() {
            Ok(info) => info,
            Err(_) => backend_without_version(definition, path),
        })
        .collect()
}

fn backend_without_version(
    definition: &BackendDefinition,
    path: Option<&str>,
) -> Option<BackendInfo> {
    let executable = definition
        .executables
        .iter()
        .find_map(|name| find_executable(name, path))?;
    Some(BackendInfo {
        id: definition.id.to_owned(),
        executable: executable.display().to_string(),
        version: None,
        available: false,
        capabilities: Vec::new(),
    })
}

fn backend_applies(
    backend: &str,
    os: OsFamily,
    distribution: Option<&str>,
    distribution_like: &[String],
) -> bool {
    if os != OsFamily::Linux || distribution.is_none() {
        return true;
    }
    let belongs_to = |family: &[&str]| {
        distribution
            .into_iter()
            .chain(distribution_like.iter().map(String::as_str))
            .any(|value| family.contains(&value))
    };
    match backend {
        "apt" | "snap" => belongs_to(&["debian", "ubuntu", "linuxmint", "pop"]),
        "dnf" | "yum" => belongs_to(&["fedora", "rhel", "centos", "rocky", "almalinux"]),
        "pacman" => belongs_to(&["arch", "archarm", "manjaro", "endeavouros"]),
        "zypper" => belongs_to(&["opensuse", "opensuse-leap", "suse", "sles"]),
        "apk" => belongs_to(&["alpine"]),
        "flatpak" => true,
        _ => false,
    }
}

fn backend_version_supported(definition: &BackendDefinition, version: &str) -> bool {
    let Some(components) = numeric_version(version) else {
        return false;
    };
    components.first().copied().is_some_and(|major| {
        major <= definition.maximum_major
            && compare_version_components(&components, definition.minimum_version)
                != std::cmp::Ordering::Less
    })
}

fn numeric_version(value: &str) -> Option<Vec<u64>> {
    let numeric = value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .next()?;
    if numeric.is_empty() {
        return None;
    }
    numeric
        .split('.')
        .take(4)
        .map(str::parse)
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()
        .filter(|components| !components.is_empty())
}

fn compare_version_components(left: &[u64], right: &[u64]) -> std::cmp::Ordering {
    let width = left.len().max(right.len());
    (0..width)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or_default()
                .cmp(&right.get(index).copied().unwrap_or_default())
        })
        .find(|ordering| *ordering != std::cmp::Ordering::Equal)
        .unwrap_or(std::cmp::Ordering::Equal)
}

/// Extract a printable version token from bounded backend output. The parser is
/// byte-oriented so invalid UTF-8 and terminal control bytes cannot alter the
/// decision or leak into serialized platform facts.
#[must_use]
pub fn parse_backend_version(_backend: &str, output: &[u8]) -> Option<String> {
    if output.len() > VERSION_PROBE_MAX_BYTES {
        return None;
    }
    output
        .split(|byte| byte.is_ascii_whitespace() || b":,()[]".contains(byte))
        .filter(|token| !token.is_empty() && token.len() <= 128)
        .find_map(|token| {
            let token = token.strip_prefix(b"v").unwrap_or(token);
            if !token.first().is_some_and(u8::is_ascii_digit)
                || !token
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._+-~".contains(byte))
            {
                return None;
            }
            String::from_utf8(token.to_vec()).ok()
        })
}

#[must_use]
pub fn find_executable(name: &str, path: Option<&str>) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') || name.starts_with('-') {
        return None;
    }
    path?
        .split(if cfg!(windows) { ';' } else { ':' })
        .filter(|part| !part.is_empty())
        .map(Path::new)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable_file(candidate))
        .and_then(|candidate| candidate.canonicalize().ok())
}

/// Canonicalize and validate a program that will cross a privilege boundary.
///
/// Normal user-scope tools may legitimately live below a user's home
/// directory. A program passed to an elevation broker may not: on Unix every
/// path component and the executable itself must be owned by root and must not
/// be group- or world-writable. The canonical path returned here is the only
/// path callers should execute.
pub fn trusted_privileged_executable(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(untrusted_privileged_executable(path));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let canonical =
            fs::canonicalize(path).map_err(|_| untrusted_privileged_executable(path))?;
        let executable =
            fs::symlink_metadata(&canonical).map_err(|_| untrusted_privileged_executable(path))?;
        if !executable.file_type().is_file()
            || executable.uid() != 0
            || executable.permissions().mode() & 0o022 != 0
            || executable.permissions().mode() & 0o111 == 0
        {
            return Err(untrusted_privileged_executable(path));
        }
        let Some(parent) = canonical.parent() else {
            return Err(untrusted_privileged_executable(path));
        };
        for directory in parent.ancestors() {
            let metadata = fs::symlink_metadata(directory)
                .map_err(|_| untrusted_privileged_executable(path))?;
            if !metadata.file_type().is_dir()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(untrusted_privileged_executable(path));
            }
        }
        Ok(canonical)
    }
    #[cfg(not(unix))]
    {
        // External elevation is disabled until the Windows implementation can
        // validate DACL ownership and every reparse-point component.
        Err(untrusted_privileged_executable(path))
    }
}

fn untrusted_privileged_executable(path: &Path) -> SiorbError {
    SiorbError::new(
        ErrorKind::PrivilegeDenied,
        format!(
            "{} is not a trusted system executable for privileged use",
            path.display()
        ),
        "Use a root-owned, non-writable system backend and the detected system privilege broker.",
    )
    .with_reason("privilege.executable.untrusted")
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[must_use]
pub fn parse_os_release(content: &str) -> BTreeMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (key, raw) = trimmed.split_once('=')?;
            if !key
                .chars()
                .all(|character| character.is_ascii_uppercase() || character == '_')
            {
                return None;
            }
            let value = raw.trim();
            let value = if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            Some((key.to_owned(), value.replace("\\\"", "\"")))
        })
        .collect()
}

fn classify_host_support(
    os: OsFamily,
    os_version: Option<&str>,
    distribution: Option<&str>,
    distribution_version: Option<&str>,
    distribution_like: &[String],
    architecture: Architecture,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if os == OsFamily::Unknown {
        reasons.push("unsupported_platform".to_owned());
        return reasons;
    }
    match architecture {
        Architecture::Unknown => reasons.push("architecture_unverified".to_owned()),
        Architecture::X86 | Architecture::Arm => {
            reasons.push("unsupported_architecture".to_owned());
        }
        Architecture::X86_64 | Architecture::Arm64 => {}
    }
    match os {
        OsFamily::Windows => classify_windows_version(os_version, &mut reasons),
        OsFamily::Macos => classify_bounded_major(os_version, 13, 26, &mut reasons),
        OsFamily::Linux => classify_linux_version(
            distribution,
            distribution_version,
            distribution_like,
            &mut reasons,
        ),
        OsFamily::Unknown => {}
    }
    reasons
}

fn classify_windows_version(version: Option<&str>, reasons: &mut Vec<String>) {
    let Some(components) = version.and_then(numeric_version) else {
        reasons.push("os_version_unverified".to_owned());
        return;
    };
    let compatible = components.first() == Some(&10)
        && components.get(1) == Some(&0)
        && components.get(2).is_some_and(|build| *build >= 17_763);
    if compatible {
        return;
    }
    let obsolete = components.first().is_some_and(|major| *major < 10)
        || (components.first() == Some(&10)
            && components.get(1) == Some(&0)
            && components.get(2).is_some_and(|build| *build < 17_763));
    reasons.push(
        if obsolete {
            "unsupported_os_version"
        } else {
            "os_version_unverified"
        }
        .to_owned(),
    );
}

fn classify_bounded_major(
    version: Option<&str>,
    minimum: u64,
    maximum: u64,
    reasons: &mut Vec<String>,
) {
    let Some(major) = version
        .and_then(numeric_version)
        .and_then(|components| components.first().copied())
    else {
        reasons.push("os_version_unverified".to_owned());
        return;
    };
    if major < minimum {
        reasons.push("unsupported_os_version".to_owned());
    } else if major > maximum {
        reasons.push("os_version_unverified".to_owned());
    }
}

fn classify_linux_version(
    distribution: Option<&str>,
    distribution_version: Option<&str>,
    distribution_like: &[String],
    reasons: &mut Vec<String>,
) {
    let Some(distribution) = distribution else {
        reasons.push("unsupported_distribution".to_owned());
        return;
    };
    let direct_range = match distribution {
        "debian" => Some((12, 13)),
        "ubuntu" => Some((22, 26)),
        "fedora" => Some((41, 43)),
        "rhel" | "centos" | "rocky" | "almalinux" => Some((9, 10)),
        "opensuse" | "opensuse-leap" | "suse" | "sles" => Some((15, 16)),
        "alpine" => Some((3, 3)),
        "arch" | "archarm" => return,
        _ => None,
    };
    if let Some((minimum, maximum)) = direct_range {
        if distribution == "alpine" {
            classify_alpine_version(distribution_version, reasons);
        } else {
            classify_bounded_major(distribution_version, minimum, maximum, reasons);
        }
        return;
    }
    let known_derivative = distribution_like.iter().any(|value| {
        matches!(
            value.as_str(),
            "debian" | "ubuntu" | "fedora" | "rhel" | "arch" | "opensuse" | "suse" | "alpine"
        )
    });
    reasons.push(
        if known_derivative {
            "distribution_version_unverified"
        } else {
            "unsupported_distribution"
        }
        .to_owned(),
    );
}

fn classify_alpine_version(version: Option<&str>, reasons: &mut Vec<String>) {
    let Some(components) = version.and_then(numeric_version) else {
        reasons.push("os_version_unverified".to_owned());
        return;
    };
    let major = components.first().copied().unwrap_or_default();
    let minor = components.get(1).copied().unwrap_or_default();
    if major < 3 || (major == 3 && minor < 20) {
        reasons.push("unsupported_os_version".to_owned());
    } else if major > 3 || minor > 23 {
        reasons.push("os_version_unverified".to_owned());
    }
}

const fn current_os() -> OsFamily {
    if cfg!(target_os = "windows") {
        OsFamily::Windows
    } else if cfg!(target_os = "macos") {
        OsFamily::Macos
    } else if cfg!(target_os = "linux") {
        OsFamily::Linux
    } else {
        OsFamily::Unknown
    }
}

fn detect_os_version(
    os: OsFamily,
    release: &BTreeMap<String, String>,
    probe: &dyn ProbeRunner,
) -> Option<String> {
    match os {
        OsFamily::Linux => release
            .get("VERSION_ID")
            .or_else(|| release.get("BUILD_ID"))
            .cloned(),
        OsFamily::Macos => {
            fixed_version_probe(probe, Path::new("/usr/bin/sw_vers"), &["-productVersion"])
        }
        OsFamily::Windows => fixed_version_probe(
            probe,
            Path::new(r"C:\Windows\System32\cmd.exe"),
            &["/d", "/c", "ver"],
        ),
        OsFamily::Unknown => None,
    }
}

fn fixed_version_probe(
    probe: &dyn ProbeRunner,
    executable: &Path,
    arguments: &[&str],
) -> Option<String> {
    let output = probe
        .run(
            executable,
            arguments,
            VERSION_PROBE_TIMEOUT,
            VERSION_PROBE_MAX_BYTES,
        )
        .ok()?;
    if output.exit_code != Some(0) || output.timed_out || output.truncated {
        return None;
    }
    parse_backend_version("host", &output.stdout)
}

fn detect_libc(os: OsFamily) -> Option<String> {
    if !matches!(os, OsFamily::Linux) {
        return None;
    }
    if cfg!(target_env = "musl") {
        Some("musl".to_owned())
    } else {
        Some("glibc".to_owned())
    }
}

fn detect_native_architecture(
    os: OsFamily,
    process_architecture: Architecture,
    probe: &dyn ProbeRunner,
) -> (Architecture, bool) {
    match os {
        OsFamily::Windows => {
            let native = env::var("PROCESSOR_ARCHITEW6432")
                .ok()
                .or_else(|| env::var("PROCESSOR_ARCHITECTURE").ok())
                .map_or(process_architecture, |value| {
                    Architecture::normalize(&value)
                });
            let native = if native == Architecture::Unknown {
                process_architecture
            } else {
                native
            };
            (native, native != process_architecture)
        }
        OsFamily::Macos if process_architecture == Architecture::X86_64 => {
            let translated = fixed_version_probe(
                probe,
                Path::new("/usr/sbin/sysctl"),
                &["-in", "sysctl.proc_translated"],
            )
            .as_deref()
                == Some("1");
            if translated {
                (Architecture::Arm64, true)
            } else {
                (process_architecture, false)
            }
        }
        _ => (process_architecture, false),
    }
}

fn has_elevation(os: OsFamily, path: Option<&str>) -> bool {
    match os {
        OsFamily::Windows | OsFamily::Unknown => false,
        OsFamily::Macos | OsFamily::Linux => find_executable("sudo", path)
            .or_else(|| find_executable("doas", path))
            .is_some_and(|candidate| trusted_privileged_executable(&candidate).is_ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[derive(Clone, Debug)]
    struct FixtureProbe {
        output: ProbeOutput,
    }

    impl ProbeRunner for FixtureProbe {
        fn run(
            &self,
            _executable: &Path,
            _arguments: &[&str],
            _timeout: Duration,
            _max_output_bytes: usize,
        ) -> io::Result<ProbeOutput> {
            Ok(self.output.clone())
        }
    }

    #[test]
    fn parses_quoted_os_release() {
        let parsed = parse_os_release(
            "ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=\"debian linux\"\n# ignored\n",
        );
        assert_eq!(parsed.get("ID").map(String::as_str), Some("ubuntu"));
        assert_eq!(parsed.get("VERSION_ID").map(String::as_str), Some("24.04"));
    }

    #[test]
    fn executable_lookup_rejects_relative_path_and_option() {
        assert!(find_executable("-evil", Some("/bin")).is_none());
        assert!(find_executable("tool", Some("relative")).is_none());
    }

    #[test]
    fn privileged_lookup_rejects_user_controlled_executable() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let executable = directory.path().join("apt-get");
        assert!(fs::write(&executable, "fixture").is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(fs::set_permissions(&executable, fs::Permissions::from_mode(0o777)).is_ok());
        }
        assert!(
            find_executable("apt-get", Some(directory.path().to_string_lossy().as_ref())).is_some()
        );
        let error = trusted_privileged_executable(&executable);
        assert!(error.is_err());
        assert_eq!(
            error.err().map(|value| value.reason_code),
            Some("privilege.executable.untrusted".to_owned())
        );
    }

    #[test]
    fn fixture_detection_is_injectable() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let release = directory.path().join("os-release");
        assert!(fs::write(&release, "ID=alpine\nVERSION_ID=3.21\n").is_ok());
        let context = SystemDetector::default()
            .with_os_release(release)
            .with_path("/no/such/directory")
            .offline(true)
            .detect();
        if cfg!(target_os = "linux") {
            assert_eq!(context.distribution.as_deref(), Some("alpine"));
        }
        assert!(context.offline);
    }

    #[test]
    fn backend_version_parser_is_bounded_and_byte_oriented() {
        assert_eq!(
            parse_backend_version("apt", b"apt 2.9.8 (amd64)\n"),
            Some("2.9.8".to_owned())
        );
        assert_eq!(parse_backend_version("winget", b"v1.10.340\xff\n"), None);
        assert!(parse_backend_version("apt", &vec![b'1'; 16 * 1024 + 1]).is_none());
    }

    #[test]
    fn reviewed_backend_ranges_are_bounded_and_search_is_not_advertised() {
        let apt = backend_definitions(OsFamily::Linux)
            .iter()
            .find(|definition| definition.id == "apt");
        assert!(apt.is_some());
        let Some(apt) = apt else { return };
        assert!(backend_version_supported(apt, "2.0.0"));
        assert!(backend_version_supported(apt, "3.1.0"));
        assert!(!backend_version_supported(apt, "1.9.9"));
        assert!(!backend_version_supported(apt, "4.0.0"));
        let yum = backend_definitions(OsFamily::Linux)
            .iter()
            .find(|definition| definition.id == "yum");
        assert!(yum.is_some_and(|definition| {
            backend_version_supported(definition, "3.4.3")
                && backend_version_supported(definition, "4.18.2")
                && !backend_version_supported(definition, "3.3.9")
                && !backend_version_supported(definition, "5.0.0")
        }));
        assert!(
            backend_definitions(OsFamily::Linux)
                .iter()
                .all(|definition| !definition.capabilities.contains(&"search"))
        );
        let flatpak = backend_definitions(OsFamily::Linux)
            .iter()
            .find(|definition| definition.id == "flatpak");
        assert!(flatpak.is_some_and(|definition| {
            !definition.capabilities.contains(&"repair")
                && definition.capabilities.contains(&"non_interactive")
        }));
    }

    #[test]
    fn probe_versions_are_injectable() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let executable = directory.path().join("apt-get");
        assert!(fs::write(&executable, "fixture").is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).is_ok());
        }
        let release = directory.path().join("os-release");
        assert!(fs::write(&release, "ID=debian\nVERSION_ID=13\n").is_ok());
        let context = SystemDetector::default()
            .with_host(OsFamily::Linux, Architecture::X86_64)
            .with_os_release(release)
            .with_path(directory.path().display().to_string())
            .with_probe(FixtureProbe {
                output: ProbeOutput {
                    exit_code: Some(0),
                    stdout: b"apt 2.9.8 (amd64)\n".to_vec(),
                    ..ProbeOutput::default()
                },
            })
            .detect();
        assert_eq!(
            context
                .backend("apt")
                .and_then(|backend| backend.version.as_deref()),
            Some("2.9.8")
        );
        let apt = context.backend("apt");
        assert!(apt.is_some());
        assert!(apt.is_some_and(|backend| {
            backend.capabilities.contains(&"repair".to_owned())
                && backend.capabilities.contains(&"non_interactive".to_owned())
                && !backend.capabilities.contains(&"search".to_owned())
        }));
    }

    #[test]
    fn incompatible_backend_version_is_visible_but_has_no_capabilities() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let executable = directory.path().join("apt-get");
        assert!(fs::write(&executable, "fixture").is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).is_ok());
        }
        let release = directory.path().join("os-release");
        assert!(fs::write(&release, "ID=ubuntu\nVERSION_ID=14.04\n").is_ok());
        let context = SystemDetector::default()
            .with_host(OsFamily::Linux, Architecture::X86_64)
            .with_os_release(release)
            .with_path(directory.path().display().to_string())
            .with_probe(FixtureProbe {
                output: ProbeOutput {
                    exit_code: Some(0),
                    stdout: b"apt 1.0.1ubuntu2\n".to_vec(),
                    ..ProbeOutput::default()
                },
            })
            .with_container(false)
            .with_compatibility_layer(false)
            .detect();
        let apt = context.backends.iter().find(|backend| backend.id == "apt");
        assert!(apt.is_some());
        assert!(apt.is_some_and(|backend| {
            !backend.available
                && backend.version.as_deref() == Some("1.0.1ubuntu2")
                && backend.capabilities.is_empty()
        }));
        assert_eq!(context.support(), siorb_core::PlatformSupport::Unsupported);
    }

    #[test]
    fn yum_is_detected_on_the_rhel_family_with_reviewed_capabilities() {
        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let executable = directory.path().join("yum");
        assert!(fs::write(&executable, "fixture").is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).is_ok());
        }
        let release = directory.path().join("os-release");
        assert!(
            fs::write(
                &release,
                "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=9.6\n"
            )
            .is_ok()
        );
        let context = SystemDetector::default()
            .with_host(OsFamily::Linux, Architecture::X86_64)
            .with_os_release(release)
            .with_path(directory.path().display().to_string())
            .with_probe(FixtureProbe {
                output: ProbeOutput {
                    exit_code: Some(0),
                    stdout: b"4.18.2\n".to_vec(),
                    ..ProbeOutput::default()
                },
            })
            .detect();
        assert!(context.backend("yum").is_some_and(|backend| {
            backend.available
                && backend.version.as_deref() == Some("4.18.2")
                && backend.capabilities.contains(&"non_interactive".to_owned())
                && backend.capabilities.contains(&"verify".to_owned())
        }));
    }

    #[test]
    fn windows_does_not_advertise_an_executor_elevation_path() {
        let context = SystemDetector::default()
            .with_host(OsFamily::Windows, Architecture::X86_64)
            .with_native_architecture(Architecture::X86_64)
            .with_os_version("10.0.26100")
            .with_path("/no/such/directory")
            .with_elevation_available(true)
            .with_container(false)
            .with_compatibility_layer(false)
            .detect();
        assert!(!context.elevation_available);
        assert_eq!(context.supported_scopes, vec![Scope::User]);
        assert!(
            context
                .restrictions
                .contains(&"external_elevation_unavailable".to_owned())
        );
    }

    #[test]
    fn support_boundaries_are_explicit_and_future_versions_are_unverified() {
        let classify = |os, version, distribution, distribution_version, architecture| {
            classify_host_support(
                os,
                version,
                distribution,
                distribution_version,
                &[],
                architecture,
            )
        };
        assert!(
            classify(
                OsFamily::Windows,
                Some("10.0.17763"),
                None,
                None,
                Architecture::X86_64
            )
            .is_empty()
        );
        assert!(
            classify(
                OsFamily::Windows,
                Some("10.0.14393"),
                None,
                None,
                Architecture::X86_64
            )
            .contains(&"unsupported_os_version".to_owned())
        );
        assert!(
            classify(
                OsFamily::Macos,
                Some("27.0"),
                None,
                None,
                Architecture::Arm64
            )
            .contains(&"os_version_unverified".to_owned())
        );
        assert!(
            classify(
                OsFamily::Linux,
                Some("14.04"),
                Some("ubuntu"),
                Some("14.04"),
                Architecture::X86_64
            )
            .contains(&"unsupported_os_version".to_owned())
        );
        assert!(
            classify(
                OsFamily::Linux,
                Some("27.04"),
                Some("ubuntu"),
                Some("27.04"),
                Architecture::X86_64
            )
            .contains(&"os_version_unverified".to_owned())
        );
        assert!(
            classify(
                OsFamily::Linux,
                Some("24.04"),
                Some("ubuntu"),
                Some("24.04"),
                Architecture::X86
            )
            .contains(&"unsupported_architecture".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_probe_enforces_wall_clock_timeout() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let executable = directory.path().join("slow-version");
        assert!(fs::write(&executable, "#!/bin/sh\nprintf '1.2.3\\n'\nexec sleep 10\n").is_ok());
        assert!(fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).is_ok());
        let started = Instant::now();
        let output =
            NativeProbeRunner.run(&executable, &["--version"], Duration::from_millis(50), 1024);
        assert!(output.is_ok());
        let Some(output) = output.ok() else { return };
        assert!(output.timed_out);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
