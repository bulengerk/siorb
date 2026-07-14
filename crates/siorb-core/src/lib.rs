//! Shared, process-independent domain contracts for Siorb.

use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Current machine-readable API schema.
pub const SCHEMA_VERSION: &str = "1.0";

/// Why a network host cannot be used as a remotely fetched endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum PublicHostError {
    #[error("host is not a canonical DNS name or IP address")]
    Invalid,
    #[error("local host names are not remote network boundaries")]
    LocalName,
    #[error("IP address is not globally routable")]
    NonPublicAddress,
}

/// Validate and canonicalize a host used for an outbound HTTPS request.
///
/// This is deliberately pure: it performs no DNS lookup and has no ambient
/// network dependency. IP literals must be globally routable. DNS names must
/// be fully qualified ASCII names and cannot use local-only suffixes. Callers
/// must still use HTTPS, disable automatic redirects, and revalidate every
/// redirect target.
///
/// # Errors
///
/// Returns an error for malformed, single-label/local, loopback, private,
/// link-local, multicast, documentation, reserved, and otherwise non-public
/// address forms.
pub fn validate_public_network_host(host: &str) -> std::result::Result<String, PublicHostError> {
    if host.is_empty() || host.trim() != host || host.chars().any(char::is_control) {
        return Err(PublicHostError::Invalid);
    }
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = unbracketed.parse::<IpAddr>() {
        if is_public_ip(address) {
            return Ok(address.to_string());
        }
        return Err(PublicHostError::NonPublicAddress);
    }

    if !host.is_ascii() || host.len() > 253 || host.ends_with("..") {
        return Err(PublicHostError::Invalid);
    }
    let canonical = host.trim_end_matches('.').to_ascii_lowercase();
    let local_suffix = canonical.rsplit('.').next().is_some_and(|suffix| {
        matches!(suffix, "localhost" | "local" | "internal" | "home" | "lan")
    });
    if canonical.is_empty() || !canonical.contains('.') || canonical == "localhost" || local_suffix
    {
        return Err(PublicHostError::LocalName);
    }
    let mut all_numeric = true;
    for label in canonical.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PublicHostError::Invalid);
        }
        all_numeric &= label.bytes().all(|byte| byte.is_ascii_digit());
    }
    if all_numeric {
        return Err(PublicHostError::NonPublicAddress);
    }
    Ok(canonical)
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    if matches!(first, 0 | 10 | 127)
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && matches!(second, 0 | 168))
        || (first == 198 && matches!(second, 18 | 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
    {
        return false;
    }
    first < 224
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    // Currently allocated global unicast space is 2000::/3. Documentation
    // space is intentionally excluded even though it falls within that range.
    (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

/// Stable process outcome families. Values are part of the public automation API.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    InvalidInput = 2,
    UnresolvedPackage = 10,
    AmbiguousPackage = 11,
    PolicyRejected = 12,
    CatalogFailure = 20,
    BackendAbsent = 30,
    PrivilegeDenied = 31,
    BackendFailure = 32,
    VerificationFailure = 40,
    PartialCompletion = 50,
    InternalError = 70,
}

impl ExitCode {
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Machine-stable error category and support reason code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidInput,
    UnresolvedPackage,
    AmbiguousPackage,
    PolicyRejected,
    CatalogFailure,
    BackendAbsent,
    PrivilegeDenied,
    BackendFailure,
    VerificationFailure,
    PartialCompletion,
    Internal,
}

impl ErrorKind {
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::InvalidInput => ExitCode::InvalidInput,
            Self::UnresolvedPackage => ExitCode::UnresolvedPackage,
            Self::AmbiguousPackage => ExitCode::AmbiguousPackage,
            Self::PolicyRejected => ExitCode::PolicyRejected,
            Self::CatalogFailure => ExitCode::CatalogFailure,
            Self::BackendAbsent => ExitCode::BackendAbsent,
            Self::PrivilegeDenied => ExitCode::PrivilegeDenied,
            Self::BackendFailure => ExitCode::BackendFailure,
            Self::VerificationFailure => ExitCode::VerificationFailure,
            Self::PartialCompletion => ExitCode::PartialCompletion,
            Self::Internal => ExitCode::InternalError,
        }
    }

    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidInput => "input.invalid",
            Self::UnresolvedPackage => "resolution.unresolved",
            Self::AmbiguousPackage => "resolution.ambiguous",
            Self::PolicyRejected => "policy.rejected",
            Self::CatalogFailure => "catalog.invalid",
            Self::BackendAbsent => "backend.absent",
            Self::PrivilegeDenied => "privilege.denied",
            Self::BackendFailure => "backend.failed",
            Self::VerificationFailure => "verification.failed",
            Self::PartialCompletion => "execution.partial",
            Self::Internal => "internal.error",
        }
    }
}

/// Actionable error safe for terminal and JSON output.
#[derive(Clone, Debug, Error, Serialize, Deserialize)]
#[error("{message} [{reason_code}]")]
pub struct SiorbError {
    pub kind: ErrorKind,
    pub reason_code: String,
    pub message: String,
    pub state_changed: bool,
    pub next_action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SiorbError {
    #[must_use]
    pub fn new(
        kind: ErrorKind,
        message: impl Into<String>,
        next_action: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            reason_code: kind.reason_code().to_owned(),
            message: message.into(),
            state_changed: false,
            next_action: next_action.into(),
            detail: None,
        }
    }

    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason_code = reason.into();
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(sanitize_terminal(&detail.into()));
        self
    }

    #[must_use]
    pub const fn after_change(mut self) -> Self {
        self.state_changed = true;
        self
    }

    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        self.kind.exit_code()
    }
}

pub type Result<T> = std::result::Result<T, SiorbError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Macos,
    Linux,
    #[default]
    Unknown,
}

impl Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Arm64,
    X86,
    Arm,
    #[default]
    Unknown,
}

impl Architecture {
    #[must_use]
    pub fn normalize(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "x86_64" | "amd64" | "x64" => Self::X86_64,
            "aarch64" | "arm64" => Self::Arm64,
            "x86" | "i386" | "i686" => Self::X86,
            "arm" | "armv7" | "armv7l" => Self::Arm,
            _ => Self::Unknown,
        }
    }
}

impl Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
            Self::X86 => "x86",
            Self::Arm => "arm",
            Self::Unknown => "unknown",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    User,
    System,
    #[default]
    Auto,
}

impl Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::System => "system",
            Self::Auto => "auto",
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    #[default]
    Stable,
    Beta,
    Nightly,
    Custom(String),
}

impl Channel {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "stable" => Self::Stable,
            "beta" => Self::Beta,
            "nightly" => Self::Nightly,
            custom => Self::Custom(custom.to_owned()),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
            Self::Custom(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Install,
    Remove,
    Upgrade,
    Repair,
    Adopt,
    Reconcile,
    Verify,
}

impl Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Install => "install",
            Self::Remove => "remove",
            Self::Upgrade => "upgrade",
            Self::Repair => "repair",
            Self::Adopt => "adopt",
            Self::Reconcile => "reconcile",
            Self::Verify => "verify",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Community,
    VerifiedUpstream,
    Sandboxed,
    #[default]
    NativeTrusted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendInfo {
    pub id: String,
    pub executable: String,
    pub version: Option<String>,
    pub available: bool,
    pub capabilities: Vec<String>,
}

/// Release-independent compatibility classification derived from normalized
/// detector facts. A `Supported` value means the host falls inside the tested
/// detector/adapter contract; it is not a claim that a particular release was
/// exercised on that machine.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformSupport {
    Supported,
    Unsupported,
    #[default]
    Undetermined,
}

// These independent host capabilities are part of the stable JSON contract;
// collapsing them into one state machine would lose valid combinations.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlatformContext {
    pub os: OsFamily,
    pub os_version: Option<String>,
    pub distribution: Option<String>,
    pub distribution_version: Option<String>,
    #[serde(default)]
    pub distribution_like: Vec<String>,
    pub architecture: Architecture,
    pub translated: bool,
    pub libc: Option<String>,
    #[serde(default)]
    pub backends: Vec<BackendInfo>,
    pub interactive: bool,
    pub elevation_available: bool,
    #[serde(default)]
    pub supported_scopes: Vec<Scope>,
    pub offline: bool,
    #[serde(default)]
    pub restrictions: Vec<String>,
}

impl PlatformContext {
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint(self)
    }

    #[must_use]
    pub fn backend(&self, id: &str) -> Option<&BackendInfo> {
        self.backends
            .iter()
            .find(|backend| backend.id.eq_ignore_ascii_case(id) && backend.available)
    }

    /// Classify the host from the stable support reason codes emitted by the
    /// detector. Unknown/new versions stay `Undetermined` instead of being
    /// silently promoted to supported.
    #[must_use]
    pub fn support(&self) -> PlatformSupport {
        if self.os == OsFamily::Unknown
            || matches!(self.architecture, Architecture::X86 | Architecture::Arm)
            || self.restrictions.iter().any(|reason| {
                matches!(
                    reason.as_str(),
                    "unsupported_platform"
                        | "unsupported_architecture"
                        | "unsupported_distribution"
                        | "unsupported_os_version"
                )
            })
        {
            PlatformSupport::Unsupported
        } else if self.os_version.is_none()
            || self.architecture == Architecture::Unknown
            || self.restrictions.iter().any(|reason| {
                matches!(
                    reason.as_str(),
                    "architecture_unverified"
                        | "os_version_unverified"
                        | "distribution_version_unverified"
                )
            })
        {
            PlatformSupport::Undetermined
        } else {
            PlatformSupport::Supported
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogIdentity {
    pub id: String,
    pub version: u64,
    pub fingerprint: String,
    pub verified: bool,
    pub expires_unix: Option<u64>,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyIdentity {
    pub id: String,
    pub fingerprint: String,
    pub layers: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStatus {
    Success,
    Planned,
    NoChange,
    Partial,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonEnvelope<T> {
    pub schema_version: String,
    pub command: String,
    pub status: OutputStatus,
    pub correlation_id: String,
    pub platform: PlatformContext,
    pub catalog: CatalogIdentity,
    pub policy: Option<PolicyIdentity>,
    pub results: T,
    pub warnings: Vec<String>,
    pub errors: Vec<SiorbError>,
}

impl<T> JsonEnvelope<T> {
    #[must_use]
    pub fn success(
        command: impl Into<String>,
        status: OutputStatus,
        platform: PlatformContext,
        catalog: CatalogIdentity,
        policy: Option<PolicyIdentity>,
        results: T,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            command: command.into(),
            status,
            correlation_id: correlation_id(),
            platform,
            catalog,
            policy,
            results,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub logical_id: String,
    pub native_id: String,
    pub backend: String,
    pub version: Option<String>,
    pub scope: Scope,
    pub receipt: bool,
    pub held: bool,
    pub pinned: Option<String>,
}

#[must_use]
pub fn fingerprint<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

static CORRELATION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[must_use]
pub fn correlation_id() -> String {
    let sequence = CORRELATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("siorb-{:x}-{pid:x}-{sequence:x}", unix_timestamp())
}

/// Strip terminal control sequences from untrusted backend diagnostics.
#[must_use]
pub fn sanitize_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' || character == '\u{009b}' || character == '\u{009d}' {
            let sequence = if character == '\u{1b}' {
                chars.next()
            } else {
                None
            };
            let is_osc = character == '\u{009d}' || sequence == Some(']');
            let is_csi = character == '\u{009b}' || sequence == Some('[');
            if is_osc {
                let mut previous_escape = false;
                for next in chars.by_ref() {
                    if next == '\u{7}' || (previous_escape && next == '\\') {
                        break;
                    }
                    previous_escape = next == '\u{1b}';
                }
            } else if is_csi {
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            continue;
        }
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn stable_exit_codes_are_distinct() {
        let codes = [
            ExitCode::Success,
            ExitCode::InvalidInput,
            ExitCode::UnresolvedPackage,
            ExitCode::AmbiguousPackage,
            ExitCode::PolicyRejected,
            ExitCode::CatalogFailure,
            ExitCode::BackendAbsent,
            ExitCode::PrivilegeDenied,
            ExitCode::BackendFailure,
            ExitCode::VerificationFailure,
            ExitCode::PartialCompletion,
            ExitCode::InternalError,
        ];
        let mut values: Vec<_> = codes.into_iter().map(ExitCode::as_i32).collect();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), codes.len());
    }

    #[test]
    fn sanitizes_ansi_and_controls() {
        assert_eq!(
            sanitize_terminal("ok\u{1b}[31mred\u{1b}[0m\u{0}x"),
            "okredx"
        );
        assert_eq!(sanitize_terminal("safe\u{1b}]0;spoof\u{7}text"), "safetext");
    }

    #[test]
    fn public_host_validation_rejects_local_and_non_public_networks() {
        for host in [
            "localhost",
            "api.localhost",
            "service.local",
            "127.0.0.1",
            "127.1",
            "10.0.0.1",
            "172.16.1.2",
            "192.168.1.1",
            "169.254.169.254",
            "[::1]",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "metadata",
        ] {
            assert!(validate_public_network_host(host).is_err(), "{host}");
        }
    }

    #[test]
    fn public_host_validation_canonicalizes_public_hosts() {
        assert_eq!(
            validate_public_network_host("Downloads.Example.org.").as_deref(),
            Ok("downloads.example.org")
        );
        assert_eq!(
            validate_public_network_host("8.8.8.8").as_deref(),
            Ok("8.8.8.8")
        );
        assert_eq!(
            validate_public_network_host("[2606:4700:4700::1111]").as_deref(),
            Ok("2606:4700:4700::1111")
        );
    }

    proptest! {
        #[test]
        fn architecture_normalization_never_panics(value in ".{0,100}") {
            let _ = Architecture::normalize(&value);
        }

        #[test]
        fn fingerprint_is_deterministic(value in ".{0,1000}") {
            prop_assert_eq!(fingerprint(&value), fingerprint(&value));
        }
    }
}
