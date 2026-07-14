//! Typed native package-manager adapters. No shell strings are constructed here.

use std::path::Path;

use serde::{Deserialize, Serialize};
use siorb_catalog::PackageSource;
use siorb_core::{BackendInfo, ErrorKind, InstalledPackage, Operation, Result, Scope, SiorbError};
use siorb_resolver::VersionConstraint;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub executable: String,
    pub arguments: Vec<String>,
    pub redacted_arguments: Vec<String>,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    pub requires_privilege: bool,
    pub network: bool,
    pub environment: Vec<(String, String)>,
}

impl CommandSpec {
    pub fn validate(&self) -> Result<()> {
        let executable = Path::new(&self.executable);
        if !executable.is_absolute() || self.executable.chars().any(char::is_control) {
            return Err(adapter_error(
                "backend.executable.unsafe",
                "backend executable must be an absolute, printable path".to_owned(),
            ));
        }
        if self.arguments.len() > 128
            || self.arguments.iter().any(|argument| {
                argument.len() > 8_192
                    || argument.contains('\0')
                    || argument
                        .chars()
                        .any(|character| character.is_control() && character != '\t')
            })
        {
            return Err(adapter_error(
                "backend.arguments.unsafe",
                "backend arguments exceed safety bounds or contain control data".to_owned(),
            ));
        }
        if self.redacted_arguments.len() != self.arguments.len() {
            return Err(adapter_error(
                "backend.redaction.invalid",
                "redacted argument vector does not match execution arguments".to_owned(),
            ));
        }
        if !(1..=3_600).contains(&self.timeout_seconds)
            || !(1_024..=16 * 1024 * 1024).contains(&self.max_output_bytes)
        {
            return Err(adapter_error(
                "backend.bounds.invalid",
                "backend timeout or output bound is outside supported limits".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub search: bool,
    pub query_installed: bool,
    pub install: bool,
    pub remove: bool,
    pub upgrade: bool,
    pub verify: bool,
    pub non_interactive: bool,
    pub native_pin: bool,
    pub native_hold: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlanOptions {
    pub non_interactive: bool,
    pub accept_agreements: bool,
}

pub trait BackendAdapter: Send + Sync + std::fmt::Debug {
    fn id(&self) -> &'static str;
    fn capabilities(&self) -> AdapterCapabilities;
    fn command(
        &self,
        operation: Operation,
        backend: &BackendInfo,
        source: &PackageSource,
        options: PlanOptions,
    ) -> Result<CommandSpec>;

    fn command_with_version(
        &self,
        operation: Operation,
        backend: &BackendInfo,
        source: &PackageSource,
        options: PlanOptions,
        version: Option<&VersionConstraint>,
    ) -> Result<CommandSpec> {
        if version.is_some() {
            return Err(adapter_error(
                "backend.version.unsupported",
                format!(
                    "backend `{}` cannot express a version constraint",
                    self.id()
                ),
            ));
        }
        self.command(operation, backend, source, options)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionSupport {
    None,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Winget,
    Scoop,
    Chocolatey,
    BrewFormula,
    BrewCask,
    MacPorts,
    Apt,
    Dnf,
    Pacman,
    Flatpak,
    Snap,
    Zypper,
    Apk,
}

impl BackendKind {
    pub fn from_catalog(value: &str) -> Result<Self> {
        match value {
            "winget" => Ok(Self::Winget),
            "scoop" => Ok(Self::Scoop),
            "chocolatey" => Ok(Self::Chocolatey),
            "homebrew-formula" => Ok(Self::BrewFormula),
            "homebrew-cask" => Ok(Self::BrewCask),
            "macports" => Ok(Self::MacPorts),
            "apt" => Ok(Self::Apt),
            "dnf" => Ok(Self::Dnf),
            "pacman" => Ok(Self::Pacman),
            "flatpak" => Ok(Self::Flatpak),
            "snap" => Ok(Self::Snap),
            "zypper" => Ok(Self::Zypper),
            "apk" => Ok(Self::Apk),
            "artifact" => Err(adapter_error(
                "backend.artifact.separate_adapter",
                "verified artifacts use the isolated artifact executor".to_owned(),
            )),
            other => Err(adapter_error(
                "backend.unknown",
                format!("unknown backend `{other}`"),
            )),
        }
    }

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Winget => "winget",
            Self::Scoop => "scoop",
            Self::Chocolatey => "chocolatey",
            Self::BrewFormula | Self::BrewCask => "brew",
            Self::MacPorts => "macports",
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Flatpak => "flatpak",
            Self::Snap => "snap",
            Self::Zypper => "zypper",
            Self::Apk => "apk",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NativeAdapter {
    kind: BackendKind,
}

impl NativeAdapter {
    #[must_use]
    pub const fn new(kind: BackendKind) -> Self {
        Self { kind }
    }

    pub fn for_source(source: &PackageSource) -> Result<Self> {
        BackendKind::from_catalog(&source.backend).map(Self::new)
    }

    #[must_use]
    pub const fn version_support(&self) -> VersionSupport {
        match self.kind {
            BackendKind::Winget | BackendKind::Chocolatey | BackendKind::Apt | BackendKind::Apk => {
                VersionSupport::Exact
            }
            _ => VersionSupport::None,
        }
    }

    fn build_command(
        self,
        operation: Operation,
        backend: &BackendInfo,
        source: &PackageSource,
        options: PlanOptions,
        version: Option<&VersionConstraint>,
    ) -> Result<CommandSpec> {
        validate_package_id(&source.package_id)?;
        if !backend.available {
            return Err(SiorbError::new(
                ErrorKind::BackendAbsent,
                format!("backend `{}` is not available", backend.id),
                "Install the backend or choose another catalog source with `--via`.",
            )
            .with_reason("backend.absent"));
        }
        if backend.id != self.id() {
            return Err(adapter_error(
                "backend.identity.mismatch",
                format!(
                    "source requires `{}`, but detected `{}`",
                    self.id(),
                    backend.id
                ),
            ));
        }
        if matches!(self.kind, BackendKind::Winget)
            && options.non_interactive
            && !options.accept_agreements
            && matches!(operation, Operation::Install | Operation::Upgrade)
        {
            return Err(SiorbError::new(
                ErrorKind::InvalidInput,
                "WinGet agreements were not accepted for non-interactive execution",
                "Review the plan, then add `--accept-agreements` if permitted.",
            )
            .with_reason("backend.agreement.required"));
        }
        let arguments =
            arguments_with_version(self.kind, operation, &source.package_id, options, version)?;
        let command = CommandSpec {
            executable: backend.executable.clone(),
            redacted_arguments: arguments.clone(),
            arguments,
            timeout_seconds: 1_800,
            max_output_bytes: 1024 * 1024,
            requires_privilege: source.requires_privilege
                && !matches!(operation, Operation::Verify | Operation::Adopt),
            network: !matches!(operation, Operation::Verify | Operation::Adopt),
            environment: vec![
                ("LANG".to_owned(), "C.UTF-8".to_owned()),
                ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
            ],
        };
        command.validate()?;
        Ok(command)
    }
}

impl BackendAdapter for NativeAdapter {
    fn id(&self) -> &'static str {
        self.kind.id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            search: true,
            query_installed: true,
            install: true,
            remove: true,
            upgrade: true,
            verify: true,
            non_interactive: true,
            native_pin: matches!(
                self.kind,
                BackendKind::Apt | BackendKind::Dnf | BackendKind::Pacman
            ),
            native_hold: matches!(
                self.kind,
                BackendKind::Apt | BackendKind::Dnf | BackendKind::Pacman
            ),
        }
    }

    fn command(
        &self,
        operation: Operation,
        backend: &BackendInfo,
        source: &PackageSource,
        options: PlanOptions,
    ) -> Result<CommandSpec> {
        self.build_command(operation, backend, source, options, None)
    }

    fn command_with_version(
        &self,
        operation: Operation,
        backend: &BackendInfo,
        source: &PackageSource,
        options: PlanOptions,
        version: Option<&VersionConstraint>,
    ) -> Result<CommandSpec> {
        self.build_command(operation, backend, source, options, version)
    }
}

#[cfg(test)]
fn arguments(
    kind: BackendKind,
    operation: Operation,
    package: &str,
    options: PlanOptions,
) -> Result<Vec<String>> {
    arguments_with_version(kind, operation, package, options, None)
}

// Repeated argument shapes stay explicit so each backend/operation pair is
// independently reviewable instead of sharing accidental behavior.
#[allow(clippy::match_same_arms)]
fn arguments_with_version(
    kind: BackendKind,
    operation: Operation,
    package: &str,
    options: PlanOptions,
    constraint: Option<&VersionConstraint>,
) -> Result<Vec<String>> {
    let version = if let Some(constraint) = constraint {
        if !matches!(
            operation,
            Operation::Install | Operation::Upgrade | Operation::Repair
        ) {
            return Err(adapter_error(
                "backend.version.operation_unsupported",
                format!("version constraint is not meaningful for `{operation}`"),
            ));
        }
        let exact = constraint.exact().ok_or_else(|| {
            adapter_error(
                "backend.version.range_unsupported",
                format!("backend `{}` supports only exact versions", kind.id()),
            )
        })?;
        if !matches!(
            kind,
            BackendKind::Winget | BackendKind::Chocolatey | BackendKind::Apt | BackendKind::Apk
        ) {
            return Err(adapter_error(
                "backend.version.unsupported",
                format!("backend `{}` cannot select an exact version", kind.id()),
            ));
        }
        validate_version_argument(exact)?;
        Some(exact)
    } else {
        None
    };
    let package = package.to_owned();
    let values = match (kind, operation) {
        (BackendKind::Winget, Operation::Install) => {
            let mut args = vec!["install", "--id", package.as_str(), "--exact", "--silent"];
            if let Some(version) = version {
                args.extend(["--version", version]);
            }
            if options.accept_agreements {
                args.extend(["--accept-package-agreements", "--accept-source-agreements"]);
            }
            strings(args)
        }
        (BackendKind::Winget, Operation::Remove) => {
            strings(["uninstall", "--id", &package, "--exact", "--silent"])
        }
        (BackendKind::Winget, Operation::Upgrade) => {
            let mut args = vec!["upgrade", "--id", package.as_str(), "--exact", "--silent"];
            if let Some(version) = version {
                args.extend(["--version", version]);
            }
            if options.accept_agreements {
                args.extend(["--accept-package-agreements", "--accept-source-agreements"]);
            }
            strings(args)
        }
        (BackendKind::Scoop, Operation::Install) => strings(["install", &package]),
        (BackendKind::Scoop, Operation::Remove) => strings(["uninstall", &package]),
        (BackendKind::Scoop, Operation::Upgrade) => strings(["update", &package]),
        (BackendKind::Chocolatey, Operation::Install) => {
            let mut args = strings(["install", "--yes", "--no-progress", &package]);
            if let Some(version) = version {
                args.extend(strings(["--version", version]));
            }
            args
        }
        (BackendKind::Chocolatey, Operation::Remove) => {
            strings(["uninstall", "--yes", "--no-progress", &package])
        }
        (BackendKind::Chocolatey, Operation::Upgrade) => {
            let mut args = strings(["upgrade", "--yes", "--no-progress", &package]);
            if let Some(version) = version {
                args.extend(strings(["--version", version]));
            }
            args
        }
        (BackendKind::BrewFormula, Operation::Install) => strings(["install", &package]),
        (BackendKind::BrewFormula, Operation::Remove) => strings(["uninstall", &package]),
        (BackendKind::BrewFormula, Operation::Upgrade) => strings(["upgrade", &package]),
        (BackendKind::BrewCask, Operation::Install) => strings(["install", "--cask", &package]),
        (BackendKind::BrewCask, Operation::Remove) => strings(["uninstall", "--cask", &package]),
        (BackendKind::BrewCask, Operation::Upgrade) => strings(["upgrade", "--cask", &package]),
        (BackendKind::MacPorts, Operation::Install) => strings(["install", &package]),
        (BackendKind::MacPorts, Operation::Remove) => strings(["uninstall", &package]),
        (BackendKind::MacPorts, Operation::Upgrade) => strings(["upgrade", &package]),
        (BackendKind::Apt, Operation::Install) => {
            let selected =
                version.map_or_else(|| package.clone(), |value| format!("{package}={value}"));
            strings(["install", "--yes", "--", &selected])
        }
        (BackendKind::Apt, Operation::Remove) => strings(["remove", "--yes", "--", &package]),
        (BackendKind::Apt, Operation::Upgrade) => {
            let selected =
                version.map_or_else(|| package.clone(), |value| format!("{package}={value}"));
            strings(["install", "--only-upgrade", "--yes", "--", &selected])
        }
        (BackendKind::Dnf, Operation::Install) => strings(["install", "-y", "--", &package]),
        (BackendKind::Dnf, Operation::Remove) => strings(["remove", "-y", "--", &package]),
        (BackendKind::Dnf, Operation::Upgrade) => strings(["upgrade", "-y", "--", &package]),
        (BackendKind::Pacman, Operation::Install) => {
            strings(["-S", "--noconfirm", "--needed", "--", &package])
        }
        (BackendKind::Pacman, Operation::Remove) => strings(["-R", "--noconfirm", "--", &package]),
        (BackendKind::Pacman, Operation::Upgrade) => {
            strings(["-S", "--noconfirm", "--needed", "--", &package])
        }
        (BackendKind::Flatpak, Operation::Install) => strings([
            "install",
            "--noninteractive",
            "--or-update",
            "flathub",
            &package,
        ]),
        (BackendKind::Flatpak, Operation::Remove) => {
            strings(["uninstall", "--noninteractive", &package])
        }
        (BackendKind::Flatpak, Operation::Upgrade) => {
            strings(["update", "--noninteractive", &package])
        }
        (BackendKind::Snap, Operation::Install) => strings(["install", &package]),
        (BackendKind::Snap, Operation::Remove) => strings(["remove", &package]),
        (BackendKind::Snap, Operation::Upgrade) => strings(["refresh", &package]),
        (BackendKind::Zypper, Operation::Install) => {
            strings(["--non-interactive", "install", "--", &package])
        }
        (BackendKind::Zypper, Operation::Remove) => {
            strings(["--non-interactive", "remove", "--", &package])
        }
        (BackendKind::Zypper, Operation::Upgrade) => {
            strings(["--non-interactive", "update", "--", &package])
        }
        (BackendKind::Apk, Operation::Install) => {
            let selected =
                version.map_or_else(|| package.clone(), |value| format!("{package}={value}"));
            strings(["add", "--", &selected])
        }
        (BackendKind::Apk, Operation::Remove) => strings(["del", "--", &package]),
        (BackendKind::Apk, Operation::Upgrade) => strings(["upgrade", "--", &package]),
        (BackendKind::Winget, Operation::Repair) => {
            let mut args = vec!["repair", "--id", package.as_str(), "--exact", "--silent"];
            if let Some(version) = version {
                args.extend(["--version", version]);
            }
            strings(args)
        }
        (BackendKind::Scoop, Operation::Repair) => strings(["reset", &package]),
        (BackendKind::Chocolatey, Operation::Repair) => {
            let mut args = strings(["upgrade", "--force", "--yes", "--no-progress", &package]);
            if let Some(version) = version {
                args.extend(strings(["--version", version]));
            }
            args
        }
        (BackendKind::BrewFormula, Operation::Repair) => strings(["reinstall", &package]),
        (BackendKind::BrewCask, Operation::Repair) => strings(["reinstall", "--cask", &package]),
        (BackendKind::MacPorts, Operation::Repair) => strings(["-f", "install", &package]),
        (BackendKind::Apt, Operation::Repair) => {
            let selected =
                version.map_or_else(|| package.clone(), |value| format!("{package}={value}"));
            strings(["install", "--reinstall", "--yes", "--", &selected])
        }
        (BackendKind::Dnf, Operation::Repair) => strings(["reinstall", "-y", "--", &package]),
        (BackendKind::Pacman, Operation::Repair) => strings(["-S", "--noconfirm", "--", &package]),
        (BackendKind::Flatpak, Operation::Repair) => {
            return Err(adapter_error(
                "backend.repair.unsupported",
                "Flatpak exposes only a global repair operation; Siorb will not run it for one package"
                    .to_owned(),
            ));
        }
        (BackendKind::Snap, Operation::Repair) => strings(["refresh", &package]),
        (BackendKind::Zypper, Operation::Repair) => {
            strings(["--non-interactive", "install", "--force", "--", &package])
        }
        (BackendKind::Apk, Operation::Repair) => strings(["fix", "--", &package]),
        (_, Operation::Verify | Operation::Adopt) => query_arguments(kind, &package),
        (_, Operation::Reconcile) => {
            return Err(adapter_error(
                "backend.operation.planner_only",
                "reconcile must be expanded into typed install/remove steps".to_owned(),
            ));
        }
    };
    Ok(values)
}

fn validate_version_argument(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value.starts_with('-')
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || ".+~:_-".contains(character)))
    {
        return Err(adapter_error(
            "backend.version.unsafe",
            "exact version contains unsafe backend argument data".to_owned(),
        ));
    }
    Ok(())
}

fn query_arguments(kind: BackendKind, package: &str) -> Vec<String> {
    match kind {
        BackendKind::Winget => strings(["list", "--id", package, "--exact"]),
        BackendKind::Scoop | BackendKind::Flatpak => strings(["info", package]),
        BackendKind::Chocolatey => strings(["list", "--local-only", "--exact", package]),
        BackendKind::BrewFormula | BackendKind::BrewCask => {
            strings(["list", "--versions", package])
        }
        BackendKind::MacPorts => strings(["installed", package]),
        BackendKind::Apt => strings(["--just-print", "install", package]),
        BackendKind::Dnf => strings(["list", "--installed", package]),
        BackendKind::Pacman => strings(["-Q", package]),
        BackendKind::Snap => strings(["list", package]),
        BackendKind::Zypper => strings(["search", "--installed-only", "--match-exact", package]),
        BackendKind::Apk => strings(["info", "--installed", package]),
    }
}

fn strings<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn validate_package_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('-')
        || value.contains("..")
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(
                    character,
                    '\'' | '"' | '`' | '$' | ';' | '|' | '&' | '<' | '>'
                )
        })
    {
        return Err(adapter_error(
            "backend.package_id.unsafe",
            format!("native package id `{value}` is unsafe"),
        ));
    }
    Ok(())
}

const QUERY_OUTPUT_MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    Installed,
    NotInstalled,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendQueryResult {
    pub status: QueryStatus,
    pub native_id: String,
    pub observed_version: Option<String>,
    pub reason_code: String,
}

impl BackendQueryResult {
    #[must_use]
    pub fn to_installed_package(
        &self,
        logical_id: impl Into<String>,
        backend: impl Into<String>,
        scope: Scope,
    ) -> Option<InstalledPackage> {
        (self.status == QueryStatus::Installed).then(|| InstalledPackage {
            logical_id: logical_id.into(),
            native_id: self.native_id.clone(),
            backend: backend.into(),
            version: self.observed_version.clone(),
            scope,
            receipt: false,
            held: false,
            pinned: None,
        })
    }

    /// Verify installed status and, when supplied, the observed version.
    ///
    /// # Errors
    ///
    /// Returns a typed verification failure when the package is absent, query
    /// status is indeterminate, or the observed version violates the constraint.
    pub fn verify(&self, constraint: Option<&VersionConstraint>) -> Result<()> {
        match self.status {
            QueryStatus::NotInstalled => {
                return Err(verification_error(
                    "backend.verify.not_installed",
                    format!("native package `{}` is not installed", self.native_id),
                ));
            }
            QueryStatus::Indeterminate => {
                return Err(verification_error(
                    "backend.verify.indeterminate",
                    format!("installed state for `{}` is indeterminate", self.native_id),
                ));
            }
            QueryStatus::Installed => {}
        }
        if let Some(constraint) = constraint {
            let observed = self.observed_version.as_deref().ok_or_else(|| {
                verification_error(
                    "backend.verify.version_missing",
                    format!("backend did not report a version for `{}`", self.native_id),
                )
            })?;
            if !constraint.matches(observed) {
                return Err(verification_error(
                    "backend.verify.version_mismatch",
                    format!("observed version `{observed}` does not satisfy `{constraint}`"),
                ));
            }
        }
        Ok(())
    }
}

/// Parse query output without assuming UTF-8. Decisions are made from bounded
/// ASCII fields only; arbitrary diagnostics remain the executor's concern.
#[must_use]
pub fn parse_query_output(
    kind: BackendKind,
    native_id: &str,
    stdout: &[u8],
    stderr: &[u8],
    exit_code: Option<i32>,
) -> BackendQueryResult {
    if stdout.len().saturating_add(stderr.len()) > QUERY_OUTPUT_MAX_BYTES {
        return query_result(
            QueryStatus::Indeterminate,
            native_id,
            None,
            "backend.query.output_too_large",
        );
    }
    let mut combined = Vec::with_capacity(stdout.len().saturating_add(stderr.len()).min(64 * 1024));
    combined.extend_from_slice(stdout);
    combined.push(b'\n');
    combined.extend_from_slice(stderr);
    if contains_ascii_case_insensitive(&combined, b"not installed")
        || contains_ascii_case_insensitive(&combined, b"no installed package")
        || contains_ascii_case_insensitive(&combined, b"no package found")
        || contains_ascii_case_insensitive(&combined, b"new packages will be installed")
    {
        return query_result(
            QueryStatus::NotInstalled,
            native_id,
            None,
            "backend.query.not_installed",
        );
    }
    if exit_code != Some(0) {
        let status = if matches!(exit_code, Some(1)) {
            QueryStatus::NotInstalled
        } else {
            QueryStatus::Indeterminate
        };
        let reason = if status == QueryStatus::NotInstalled {
            "backend.query.not_installed"
        } else {
            "backend.query.failed"
        };
        return query_result(status, native_id, None, reason);
    }
    let observed_version = match kind {
        BackendKind::Winget => table_version_after_id(&combined, native_id),
        BackendKind::Scoop | BackendKind::Flatpak => labeled_version(&combined),
        BackendKind::Chocolatey
        | BackendKind::BrewFormula
        | BackendKind::BrewCask
        | BackendKind::Pacman => simple_package_version(&combined, native_id),
        BackendKind::MacPorts => macports_version(&combined, native_id),
        BackendKind::Apt => apt_version(&combined),
        BackendKind::Dnf => dnf_version(&combined, native_id),
        BackendKind::Snap => snap_version(&combined, native_id),
        BackendKind::Zypper => zypper_version(&combined, native_id),
        BackendKind::Apk => apk_version(&combined, native_id),
    };
    if observed_version.is_some() {
        query_result(
            QueryStatus::Installed,
            native_id,
            observed_version,
            "backend.query.installed",
        )
    } else {
        query_result(
            QueryStatus::Indeterminate,
            native_id,
            None,
            "backend.query.version_unparsed",
        )
    }
}

fn query_result(
    status: QueryStatus,
    native_id: &str,
    observed_version: Option<String>,
    reason: &str,
) -> BackendQueryResult {
    BackendQueryResult {
        status,
        native_id: native_id.to_owned(),
        observed_version,
        reason_code: reason.to_owned(),
    }
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|byte| *byte == b'\n').map(trim_ascii)
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn tokens(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty())
}

fn version_token(token: &[u8]) -> Option<String> {
    let token = trim_ascii(token).strip_prefix(b"@").unwrap_or(token);
    let token = token
        .strip_suffix(b",")
        .or_else(|| token.strip_suffix(b")"))
        .unwrap_or(token);
    if token.is_empty()
        || token.len() > 128
        || !token.first().is_some_and(u8::is_ascii_alphanumeric)
        || !token
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+~:_-".contains(byte))
    {
        return None;
    }
    String::from_utf8(token.to_vec()).ok()
}

fn eq_ascii(left: &[u8], right: &str) -> bool {
    left.eq_ignore_ascii_case(right.as_bytes())
}

fn labeled_version(bytes: &[u8]) -> Option<String> {
    for line in lines(bytes) {
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (label, value) = (&line[..separator], &line[separator + 1..]);
        if label.eq_ignore_ascii_case(b"version") {
            return tokens(value).find_map(version_token);
        }
    }
    None
}

fn simple_package_version(bytes: &[u8], package: &str) -> Option<String> {
    for line in lines(bytes) {
        let mut fields = tokens(line);
        if fields.next().is_some_and(|field| eq_ascii(field, package)) {
            return fields.find_map(version_token);
        }
    }
    None
}

fn table_version_after_id(bytes: &[u8], package: &str) -> Option<String> {
    for line in lines(bytes) {
        let fields: Vec<_> = tokens(line).collect();
        for (index, field) in fields.iter().enumerate() {
            if eq_ascii(field, package) {
                return fields.get(index + 1).and_then(|value| version_token(value));
            }
        }
    }
    None
}

fn macports_version(bytes: &[u8], package: &str) -> Option<String> {
    for line in lines(bytes) {
        let mut fields = tokens(line);
        if fields.next().is_some_and(|field| eq_ascii(field, package)) {
            return fields.find_map(version_token);
        }
    }
    None
}

fn apt_version(bytes: &[u8]) -> Option<String> {
    if let Some(version) = labeled_version(bytes) {
        return Some(version);
    }
    for line in lines(bytes) {
        if contains_ascii_case_insensitive(line, b"already the newest version") {
            if let Some(open) = line.iter().position(|byte| *byte == b'(') {
                let rest = &line[open + 1..];
                let end = rest
                    .iter()
                    .position(|byte| *byte == b')')
                    .unwrap_or(rest.len());
                return version_token(&rest[..end]);
            }
        }
        let mut fields = tokens(line);
        if fields.next() == Some(b"Inst".as_slice()) {
            if let Some(open) = line.iter().position(|byte| *byte == b'(') {
                return tokens(&line[open + 1..]).find_map(version_token);
            }
        }
    }
    None
}

fn dnf_version(bytes: &[u8], package: &str) -> Option<String> {
    for line in lines(bytes) {
        let mut fields = tokens(line);
        let Some(first) = fields.next() else { continue };
        let matches = eq_ascii(first, package)
            || first
                .splitn(2, |byte| *byte == b'.')
                .next()
                .is_some_and(|name| eq_ascii(name, package));
        if matches {
            return fields.find_map(version_token);
        }
    }
    None
}

fn snap_version(bytes: &[u8], package: &str) -> Option<String> {
    simple_package_version(bytes, package)
}

fn zypper_version(bytes: &[u8], package: &str) -> Option<String> {
    for line in lines(bytes) {
        let columns: Vec<_> = line.split(|byte| *byte == b'|').map(trim_ascii).collect();
        if let Some(index) = columns.iter().position(|column| eq_ascii(column, package)) {
            if let Some(version) = columns
                .get(index + 1)
                .and_then(|value| version_token(value))
            {
                return Some(version);
            }
        }
    }
    None
}

fn apk_version(bytes: &[u8], package: &str) -> Option<String> {
    for line in lines(bytes) {
        let Some(first) = tokens(line).next() else {
            continue;
        };
        let prefix = format!("{package}-");
        if first.starts_with(prefix.as_bytes()) {
            return version_token(&first[prefix.len()..]);
        }
    }
    None
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn adapter_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::BackendFailure,
        message,
        "Inspect the selected source with `siorb source list` or choose another backend.",
    )
    .with_reason(reason)
}

fn verification_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::VerificationFailure,
        message,
        "Refresh backend state and reconcile the Siorb receipt.",
    )
    .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_option_and_shell_injection() {
        for value in ["--help", "good;evil", "$(evil)", "two words", "../pkg"] {
            assert!(validate_package_id(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn apt_uses_argument_boundary() {
        let arguments = arguments(
            BackendKind::Apt,
            Operation::Install,
            "firefox",
            PlanOptions::default(),
        );
        assert!(arguments.is_ok());
        if let Ok(arguments) = arguments {
            assert_eq!(arguments, strings(["install", "--yes", "--", "firefox"]));
        }
    }

    #[test]
    fn repair_is_explicit_and_never_aliases_install_implicitly() {
        assert_eq!(
            arguments(
                BackendKind::Apt,
                Operation::Repair,
                "firefox",
                PlanOptions::default(),
            )
            .ok(),
            Some(strings([
                "install",
                "--reinstall",
                "--yes",
                "--",
                "firefox",
            ]))
        );
        assert_eq!(
            arguments(
                BackendKind::Dnf,
                Operation::Repair,
                "firefox",
                PlanOptions::default(),
            )
            .ok(),
            Some(strings(["reinstall", "-y", "--", "firefox"]))
        );
        assert_eq!(
            arguments(
                BackendKind::Flatpak,
                Operation::Repair,
                "org.mozilla.firefox",
                PlanOptions::default(),
            )
            .err()
            .map(|error| error.reason_code),
            Some("backend.repair.unsupported".to_owned())
        );
    }

    #[test]
    fn exact_versions_are_forwarded_and_ranges_rejected() {
        let exact = VersionConstraint::parse("=1.2.3");
        assert!(exact.is_ok());
        let Some(exact) = exact.ok() else { return };
        let arguments = arguments_with_version(
            BackendKind::Apt,
            Operation::Install,
            "firefox",
            PlanOptions::default(),
            Some(&exact),
        );
        assert_eq!(
            arguments.ok(),
            Some(strings(["install", "--yes", "--", "firefox=1.2.3"]))
        );

        let range = VersionConstraint::parse(">=1,<2");
        assert!(range.is_ok());
        let Some(range) = range.ok() else { return };
        let rejected = arguments_with_version(
            BackendKind::Apt,
            Operation::Install,
            "firefox",
            PlanOptions::default(),
            Some(&range),
        );
        assert_eq!(
            rejected.err().map(|error| error.reason_code),
            Some("backend.version.range_unsupported".to_owned())
        );
    }

    #[test]
    fn query_parsers_extract_observed_versions_from_bytes() {
        let fixtures = [
            (
                BackendKind::Winget,
                "Mozilla.Firefox",
                b"Name Id Version Source\nFirefox Mozilla.Firefox 128.0 winget\n".as_slice(),
                "128.0",
            ),
            (
                BackendKind::Pacman,
                "ripgrep",
                b"ripgrep 14.1.1-1\n".as_slice(),
                "14.1.1-1",
            ),
            (
                BackendKind::Flatpak,
                "org.mozilla.firefox",
                b"Name: Firefox\nVersion: 128.0.3\n".as_slice(),
                "128.0.3",
            ),
            (
                BackendKind::Apt,
                "firefox",
                b"firefox is already the newest version (128.0+build1).\n".as_slice(),
                "128.0+build1",
            ),
            (
                BackendKind::Apt,
                "firefox",
                b"Inst firefox (127.0+build2 Ubuntu:24.04/noble [amd64])\n".as_slice(),
                "127.0+build2",
            ),
            (
                BackendKind::Apt,
                "firefox",
                b"\x1b[2J\x1b[Hfake prompt\nInst firefox (127.0 Ubuntu [amd64])\n".as_slice(),
                "127.0",
            ),
        ];
        for (kind, package, stdout, version) in fixtures {
            let result = parse_query_output(kind, package, stdout, &[], Some(0));
            assert_eq!(result.status, QueryStatus::Installed);
            assert_eq!(result.observed_version.as_deref(), Some(version));
        }

        let constraint = VersionConstraint::parse(">=14,<15");
        assert!(constraint.is_ok());
        let Some(constraint) = constraint.ok() else {
            return;
        };
        let observed = parse_query_output(
            BackendKind::Pacman,
            "ripgrep",
            b"ripgrep 14.1.1-1\n",
            &[],
            Some(0),
        );
        assert!(observed.verify(Some(&constraint)).is_ok());
    }

    #[test]
    fn invalid_utf8_cannot_create_an_observed_version() {
        let result = parse_query_output(
            BackendKind::Pacman,
            "ripgrep",
            b"ripgrep 14.1\xff\n",
            &[],
            Some(0),
        );
        assert_eq!(result.status, QueryStatus::Indeterminate);
        assert_eq!(result.reason_code, "backend.query.version_unparsed");
    }

    proptest! {
        #[test]
        fn arbitrary_query_bytes_are_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let first = parse_query_output(
                BackendKind::Winget,
                "Vendor.Package",
                &bytes,
                &[],
                Some(0),
            );
            let second = parse_query_output(
                BackendKind::Winget,
                "Vendor.Package",
                &bytes,
                &[],
                Some(0),
            );
            prop_assert_eq!(first, second);
        }
    }
}
