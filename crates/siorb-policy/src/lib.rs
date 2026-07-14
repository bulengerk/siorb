//! Local layered policy with deny-wins semantics and stable reason codes.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};
use siorb_catalog::{PackageManifest, PackageSource};
use siorb_core::{
    ErrorKind, Operation, PolicyIdentity, Result, Scope, SiorbError, fingerprint, unix_timestamp,
};
use url::Url;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyFile {
    pub schema_version: String,
    pub id: String,
    pub allow_packages: Vec<String>,
    pub deny_packages: Vec<String>,
    pub allow_categories: Vec<String>,
    pub deny_categories: Vec<String>,
    pub allow_sources: Vec<String>,
    pub deny_sources: Vec<String>,
    pub allow_backends: Vec<String>,
    pub deny_backends: Vec<String>,
    pub allow_channels: Vec<String>,
    pub deny_channels: Vec<String>,
    pub allow_scopes: Vec<String>,
    pub deny_scopes: Vec<String>,
    pub allow_licenses: Vec<String>,
    pub deny_licenses: Vec<String>,
    pub preferred_backends: Vec<String>,
    pub require_signatures: bool,
    pub require_digests: bool,
    pub trusted_publishers: Vec<String>,
    pub minimum_provenance: Option<String>,
    pub forbid_artifacts: bool,
    pub forbid_prerelease: bool,
    pub require_confirmation: bool,
    pub require_dry_run: bool,
    pub network_domains: Vec<String>,
    pub prevent_downgrade: bool,
    pub prevent_uninstall: bool,
    pub freshness_days: Option<u64>,
    /// `None` inherits the lower layer, `Some(false)` is an irreversible deny,
    /// and `Some(true)` permits only when no layer denies.
    pub allow_self_update: Option<bool>,
}

impl PolicyFile {
    #[must_use]
    pub fn secure_defaults() -> Self {
        Self {
            schema_version: "1.0".to_owned(),
            id: "builtin-secure-defaults".to_owned(),
            allow_backends: vec![
                "winget".to_owned(),
                "scoop".to_owned(),
                "chocolatey".to_owned(),
                "homebrew-formula".to_owned(),
                "homebrew-cask".to_owned(),
                "macports".to_owned(),
                "apt".to_owned(),
                "dnf".to_owned(),
                "pacman".to_owned(),
                "zypper".to_owned(),
                "apk".to_owned(),
                "flatpak".to_owned(),
                "snap".to_owned(),
                "artifact".to_owned(),
            ],
            allow_channels: vec!["stable".to_owned()],
            deny_channels: vec!["nightly".to_owned(), "custom".to_owned()],
            require_signatures: true,
            require_digests: true,
            minimum_provenance: Some("backend-repository".to_owned()),
            // Verified direct artifacts are an intentional last-resort source.
            // Higher policy layers can still forbid them with deny-wins
            // semantics; the built-in layer requires digest, signed-release
            // provenance, and a package signer for formats with a strict
            // platform verifier instead of making the adapter dead.
            forbid_artifacts: false,
            forbid_prerelease: true,
            // Explicit CLI consent is sufficient by default. Machine or
            // organization layers can require a fresh interactive prompt.
            require_confirmation: false,
            prevent_downgrade: true,
            freshness_days: Some(45),
            allow_self_update: Some(true),
            ..Self::default()
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let input = read_secure_policy(path).map_err(|error| {
            SiorbError::new(
                ErrorKind::PolicyRejected,
                format!("cannot read policy {}", path.display()),
                "Use a regular non-symlink policy with non-writable permissions and safe parent directories.",
            )
            .with_reason("policy.read.failed")
            .with_detail(error)
        })?;
        let policy: Self = toml::from_str(&input).map_err(|error| {
            SiorbError::new(
                ErrorKind::PolicyRejected,
                format!("policy {} is invalid", path.display()),
                "Validate the policy with `siorb policy validate`.",
            )
            .with_reason("policy.parse.failed")
            .with_detail(error.to_string())
        })?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "1.0" && self.schema_version != "1" {
            return Err(policy_error(
                "policy.schema.unsupported",
                format!("unsupported policy schema `{}`", self.schema_version),
            ));
        }
        if self.id.trim().is_empty() {
            return Err(policy_error(
                "policy.id.missing",
                "policy id is required".to_owned(),
            ));
        }
        for domain in &self.network_domains {
            if !valid_exact_domain(domain) {
                return Err(policy_error(
                    "policy.network_domain.invalid",
                    format!("`{domain}` is not an exact network domain"),
                ));
            }
        }
        if self.freshness_days == Some(0) {
            return Err(policy_error(
                "policy.freshness.invalid",
                "freshness_days must be greater than zero".to_owned(),
            ));
        }
        if let Some(minimum) = &self.minimum_provenance {
            if provenance_level(minimum).is_none() {
                return Err(policy_error(
                    "policy.provenance.invalid",
                    format!("`{minimum}` is not a recognized provenance level"),
                ));
            }
        }
        Ok(())
    }
}

fn read_secure_policy(path: &Path) -> std::result::Result<String, String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "policy path component {} is a link",
                current.display()
            ));
        }
        #[cfg(unix)]
        if metadata.file_type().is_dir() {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(format!(
                    "policy directory {} is group- or world-writable",
                    current.display()
                ));
            }
        }
    }
    let before = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !before.file_type().is_file() {
        return Err("policy is not a regular file".to_owned());
    }
    if before.len() > 1024 * 1024 {
        return Err("policy exceeds the 1 MiB size boundary".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.permissions().mode() & 0o022 != 0 {
            return Err("policy file is group- or world-writable".to_owned());
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            let parent = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
            if before.uid() != 0 && before.uid() != parent.uid() {
                return Err("policy file owner does not match its containing directory".to_owned());
            }
        }
    }
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("policy changed identity while it was opened".to_owned());
        }
    }
    let mut input = String::new();
    file.read_to_string(&mut input)
        .map_err(|error| error.to_string())?;
    if input.len() > 1024 * 1024 {
        return Err("policy exceeds the 1 MiB size boundary".to_owned());
    }
    Ok(input)
}

fn valid_exact_domain(domain: &str) -> bool {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[derive(Clone, Debug)]
pub struct LayeredPolicy {
    layers: Vec<PolicyFile>,
    identity: PolicyIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyReason {
    pub code: String,
    pub message: String,
    pub layer: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reasons: Vec<PolicyReason>,
    pub confirmation_required: bool,
    pub dry_run_required: bool,
}

/// Facts that cannot be derived safely from a catalog source alone. Callers
/// must provide these before authorizing execution; the timestamp is injectable
/// so policy decisions remain reproducible in tests and lock verification.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvaluationContext {
    pub dry_run: bool,
    pub now_unix: Option<u64>,
    pub installed_version: Option<String>,
    pub target_version: Option<String>,
    #[serde(default)]
    pub network_urls: Vec<String>,
}

impl PolicyEvaluationContext {
    #[must_use]
    pub fn for_runtime(dry_run: bool) -> Self {
        Self {
            dry_run,
            now_unix: Some(unix_timestamp()),
            ..Self::default()
        }
    }
}

impl Default for LayeredPolicy {
    fn default() -> Self {
        Self::new(vec![PolicyFile::secure_defaults()]).unwrap_or_else(|_| unreachable_policy())
    }
}

fn unreachable_policy() -> LayeredPolicy {
    let layers = vec![PolicyFile::secure_defaults()];
    LayeredPolicy {
        identity: PolicyIdentity {
            id: "builtin-secure-defaults".to_owned(),
            fingerprint: fingerprint(&layers),
            layers: vec!["builtin-secure-defaults".to_owned()],
        },
        layers,
    }
}

impl LayeredPolicy {
    pub fn new(mut layers: Vec<PolicyFile>) -> Result<Self> {
        if layers.is_empty() || layers[0].id != "builtin-secure-defaults" {
            layers.insert(0, PolicyFile::secure_defaults());
        }
        for layer in &layers {
            layer.validate()?;
        }
        let names: Vec<_> = layers.iter().map(|layer| layer.id.clone()).collect();
        let identity = PolicyIdentity {
            id: names
                .last()
                .cloned()
                .unwrap_or_else(|| "builtin".to_owned()),
            fingerprint: fingerprint(&layers),
            layers: names,
        };
        Ok(Self { layers, identity })
    }

    pub fn from_paths(paths: &[impl AsRef<Path>]) -> Result<Self> {
        let mut layers = vec![PolicyFile::secure_defaults()];
        for path in paths {
            layers.push(PolicyFile::load(path.as_ref())?);
        }
        Self::new(layers)
    }

    #[must_use]
    pub const fn identity(&self) -> &PolicyIdentity {
        &self.identity
    }

    #[must_use]
    pub fn backend_preference(&self, backend: &str) -> usize {
        self.layers
            .iter()
            .rev()
            .find_map(|layer| {
                layer
                    .preferred_backends
                    .iter()
                    .position(|value| value == backend)
            })
            .unwrap_or(usize::MAX)
    }

    /// Whether any active layer requires consent to be collected from an
    /// interactive review of the exact mutation. This is deny-wins: a higher
    /// layer cannot turn a lower layer's requirement into pre-supplied consent.
    #[must_use]
    pub fn requires_interactive_confirmation(&self) -> bool {
        self.layers.iter().any(|layer| layer.require_confirmation)
    }

    /// Evaluate the self-update operation independently of package sources.
    /// Deny wins across every layer; an explicit allow can never override an
    /// organizational deny from another layer.
    #[must_use]
    pub fn evaluate_self_update(&self) -> PolicyDecision {
        self.evaluate_self_update_with_context(false)
    }

    #[must_use]
    pub fn evaluate_self_update_with_context(&self, dry_run: bool) -> PolicyDecision {
        let mut reasons = Vec::new();
        for layer in &self.layers {
            if layer.allow_self_update == Some(false) {
                deny(
                    &mut reasons,
                    layer,
                    "policy.self_update.denied",
                    "self-update is disabled by policy",
                );
            }
            if layer.require_dry_run && !dry_run {
                deny(
                    &mut reasons,
                    layer,
                    "policy.dry_run.required",
                    "policy requires a dry-run for self-update",
                );
            }
        }
        PolicyDecision {
            allowed: reasons.is_empty(),
            reasons,
            confirmation_required: self.layers.iter().any(|layer| layer.require_confirmation),
            dry_run_required: self.layers.iter().any(|layer| layer.require_dry_run),
        }
    }

    /// Enforce self-update policy and return a stable policy error for CLI use.
    ///
    /// # Errors
    ///
    /// Returns `policy.self_update.denied` when any active layer disables
    /// self-update.
    pub fn enforce_self_update(&self) -> Result<()> {
        self.enforce_self_update_with_context(false)
    }

    /// Enforce self-update and dry-run controls for the current invocation.
    ///
    /// # Errors
    ///
    /// Returns a policy rejection with the first stable reason code when the
    /// active policy disallows this invocation.
    pub fn enforce_self_update_with_context(&self, dry_run: bool) -> Result<()> {
        let decision = self.evaluate_self_update_with_context(dry_run);
        if decision.allowed {
            return Ok(());
        }
        let detail = decision
            .reasons
            .iter()
            .map(|reason| format!("{}:{}", reason.layer, reason.code))
            .collect::<Vec<_>>()
            .join(", ");
        let reason_code = decision
            .reasons
            .first()
            .map_or("policy.self_update.denied", |reason| reason.code.as_str());
        let message = if reason_code == "policy.dry_run.required" {
            "self-update requires a dry-run under active policy"
        } else {
            "self-update is disabled by active policy"
        };
        Err(policy_error(reason_code, message.to_owned()).with_detail(detail))
    }

    #[must_use]
    pub fn evaluate(
        &self,
        package: &PackageManifest,
        source: &PackageSource,
        operation: Operation,
    ) -> PolicyDecision {
        self.evaluate_with_context(
            package,
            source,
            operation,
            &PolicyEvaluationContext::for_runtime(false),
        )
    }

    #[must_use]
    pub fn evaluate_with_context(
        &self,
        package: &PackageManifest,
        source: &PackageSource,
        operation: Operation,
        context: &PolicyEvaluationContext,
    ) -> PolicyDecision {
        let mut reasons = Vec::new();
        let mut confirmation_required = false;
        let mut dry_run_required = false;
        for layer in &self.layers {
            confirmation_required |= layer.require_confirmation;
            dry_run_required |= layer.require_dry_run;
            check_membership(
                layer,
                "package",
                &package.id,
                &layer.allow_packages,
                &layer.deny_packages,
                &mut reasons,
            );
            check_membership(
                layer,
                "source",
                &source.id,
                &layer.allow_sources,
                &layer.deny_sources,
                &mut reasons,
            );
            check_membership(
                layer,
                "backend",
                &source.backend,
                &layer.allow_backends,
                &layer.deny_backends,
                &mut reasons,
            );
            check_membership(
                layer,
                "channel",
                &source.channel,
                &layer.allow_channels,
                &layer.deny_channels,
                &mut reasons,
            );
            check_membership(
                layer,
                "scope",
                &source.scope,
                &layer.allow_scopes,
                &layer.deny_scopes,
                &mut reasons,
            );
            check_membership(
                layer,
                "license",
                &package.license,
                &layer.allow_licenses,
                &layer.deny_licenses,
                &mut reasons,
            );
            if !layer.allow_categories.is_empty()
                && package
                    .categories
                    .iter()
                    .all(|category| !layer.allow_categories.contains(category))
            {
                deny(
                    &mut reasons,
                    layer,
                    "policy.category.not_allowed",
                    "no package category is allowed",
                );
            }
            for category in &package.categories {
                if layer.deny_categories.contains(category) {
                    deny(
                        &mut reasons,
                        layer,
                        "policy.category.denied",
                        &format!("category `{category}` is denied"),
                    );
                }
            }
            if layer.forbid_artifacts && source.backend == "artifact" {
                deny(
                    &mut reasons,
                    layer,
                    "policy.artifact.forbidden",
                    "direct artifacts are forbidden",
                );
            }
            if layer.forbid_prerelease && source.channel != "stable" {
                deny(
                    &mut reasons,
                    layer,
                    "policy.prerelease.forbidden",
                    "pre-release channels are forbidden",
                );
            }
            let requires_native_signer = source.backend != "artifact"
                || source
                    .verification
                    .as_ref()
                    .is_some_and(|value| value.format.requires_package_signer());
            if layer.require_signatures
                && source.trust == "verified-upstream"
                && requires_native_signer
                && source
                    .verification
                    .as_ref()
                    .is_none_or(|value| value.signer.is_none())
            {
                deny(
                    &mut reasons,
                    layer,
                    "policy.signature.required",
                    "source has no required signer identity",
                );
            }
            if layer.require_digests
                && source.backend == "artifact"
                && source
                    .verification
                    .as_ref()
                    .is_none_or(|value| value.sha256.is_empty())
            {
                deny(
                    &mut reasons,
                    layer,
                    "policy.digest.required",
                    "artifact has no required digest",
                );
            }
            enforce_trusted_publishers(layer, source, &mut reasons);
            enforce_provenance(layer, source, &mut reasons);
            enforce_network_domains(layer, source, operation, context, &mut reasons);
            enforce_freshness(layer, source, context, &mut reasons);
            if layer.require_dry_run && operation != Operation::Verify && !context.dry_run {
                deny(
                    &mut reasons,
                    layer,
                    "policy.dry_run.required",
                    "policy requires a successful dry-run before this operation",
                );
            }
            if layer.prevent_downgrade
                && matches!(
                    operation,
                    Operation::Install | Operation::Upgrade | Operation::Repair
                )
            {
                enforce_no_downgrade(layer, context, &mut reasons);
            }
            if layer.prevent_uninstall && operation == Operation::Remove {
                deny(
                    &mut reasons,
                    layer,
                    "policy.uninstall.prevented",
                    "uninstallation is forbidden",
                );
            }
        }
        reasons.sort_by(|left, right| {
            left.layer
                .cmp(&right.layer)
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.message.cmp(&right.message))
        });
        reasons.dedup();
        PolicyDecision {
            allowed: reasons.is_empty(),
            reasons,
            confirmation_required,
            dry_run_required,
        }
    }
}

fn enforce_trusted_publishers(
    layer: &PolicyFile,
    source: &PackageSource,
    reasons: &mut Vec<PolicyReason>,
) {
    if layer.trusted_publishers.is_empty() {
        return;
    }
    let signer = source
        .verification
        .as_ref()
        .and_then(|verification| verification.signer.as_deref());
    match signer {
        None => deny(
            reasons,
            layer,
            "policy.publisher.missing",
            "source does not carry a verifiable publisher identity",
        ),
        Some(signer)
            if !layer
                .trusted_publishers
                .iter()
                .any(|trusted| trusted.eq_ignore_ascii_case(signer)) =>
        {
            deny(
                reasons,
                layer,
                "policy.publisher.untrusted",
                &format!("publisher `{signer}` is not trusted"),
            );
        }
        Some(_) => {}
    }
}

fn provenance_level(value: &str) -> Option<u8> {
    match value {
        "unverified" | "none" => Some(0),
        "community" => Some(1),
        "verified-upstream" => Some(2),
        "backend-repository" => Some(3),
        "signed-release" => Some(4),
        "reproducible" => Some(5),
        _ => None,
    }
}

fn enforce_provenance(layer: &PolicyFile, source: &PackageSource, reasons: &mut Vec<PolicyReason>) {
    let Some(required) = layer.minimum_provenance.as_deref() else {
        return;
    };
    let Some(required_level) = provenance_level(required) else {
        // PolicyFile::validate rejects this. Keep evaluation fail-closed for
        // programmatically constructed policy values.
        deny(
            reasons,
            layer,
            "policy.provenance.invalid",
            "policy has an unknown provenance level",
        );
        return;
    };
    let Some(actual_level) = provenance_level(source.provenance.trim()) else {
        deny(
            reasons,
            layer,
            "policy.provenance.missing",
            "source has no recognized provenance level",
        );
        return;
    };
    if actual_level < required_level {
        deny(
            reasons,
            layer,
            "policy.provenance.insufficient",
            &format!(
                "source provenance `{}` is below required `{required}`",
                source.provenance
            ),
        );
    }
}

fn enforce_network_domains(
    layer: &PolicyFile,
    source: &PackageSource,
    operation: Operation,
    context: &PolicyEvaluationContext,
    reasons: &mut Vec<PolicyReason>,
) {
    if layer.network_domains.is_empty() {
        return;
    }
    let mut urls: Vec<&str> = context.network_urls.iter().map(String::as_str).collect();
    if source.backend == "artifact" && !urls.contains(&source.package_id.as_str()) {
        urls.push(&source.package_id);
    }
    if urls.is_empty() && !matches!(operation, Operation::Verify | Operation::Adopt) {
        deny(
            reasons,
            layer,
            "policy.network_domain.unverifiable",
            "network endpoints are not known precisely enough to enforce the domain allowlist",
        );
        return;
    }
    for raw in urls {
        let parsed = Url::parse(raw);
        let Some(host) = parsed.as_ref().ok().and_then(Url::host_str) else {
            deny(
                reasons,
                layer,
                "policy.network_url.invalid",
                "network endpoint is not an absolute URL with a host",
            );
            continue;
        };
        if !layer
            .network_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            deny(
                reasons,
                layer,
                "policy.network_domain.denied",
                &format!("network domain `{host}` is not allowed"),
            );
        }
    }
}

fn enforce_freshness(
    layer: &PolicyFile,
    source: &PackageSource,
    context: &PolicyEvaluationContext,
    reasons: &mut Vec<PolicyReason>,
) {
    let Some(max_age) = layer.freshness_days else {
        return;
    };
    let Some(reviewed_day) = parse_iso_date_days(&source.reviewed_at) else {
        deny(
            reasons,
            layer,
            "policy.freshness.unknown",
            "source review date is missing or invalid",
        );
        return;
    };
    let now = context.now_unix.unwrap_or_else(unix_timestamp);
    let now_day = i64::try_from(now / 86_400).unwrap_or(i64::MAX);
    if reviewed_day > now_day {
        deny(
            reasons,
            layer,
            "policy.freshness.future",
            "source review date is in the future",
        );
        return;
    }
    let age = u64::try_from(now_day - reviewed_day).unwrap_or(u64::MAX);
    if age > max_age {
        deny(
            reasons,
            layer,
            "policy.freshness.exceeded",
            &format!("source review is {age} days old; policy permits {max_age}"),
        );
    }
}

// Days since 1970-01-01, using Howard Hinnant's civil-date transform. This
// avoids locale and timezone dependencies while validating calendar dates.
fn parse_iso_date_days(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || year < 1970 || !(1..=12).contains(&month) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn enforce_no_downgrade(
    layer: &PolicyFile,
    context: &PolicyEvaluationContext,
    reasons: &mut Vec<PolicyReason>,
) {
    let (Some(installed), Some(target)) = (
        context.installed_version.as_deref(),
        context.target_version.as_deref().and_then(exact_version),
    ) else {
        return;
    };
    if compare_versions(target, installed).is_some_and(std::cmp::Ordering::is_lt) {
        deny(
            reasons,
            layer,
            "policy.downgrade.prevented",
            &format!("target version `{target}` is older than installed `{installed}`"),
        );
    }
}

fn exact_version(value: &str) -> Option<&str> {
    let value = value.trim();
    let value = value
        .strip_prefix("==")
        .or_else(|| value.strip_prefix('='))
        .unwrap_or(value);
    if value.is_empty()
        || value.contains(',')
        || value.contains('*')
        || value.contains('x')
        || value.starts_with(['<', '>', '^', '~'])
    {
        return None;
    }
    Some(value)
}

fn compare_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    match (loose_semver(left), loose_semver(right)) {
        (Some(left), Some(right)) => Some(left.cmp(&right)),
        _ if is_safe_native_version(left) && is_safe_native_version(right) => {
            Some(compare_native_versions(left, right))
        }
        _ => None,
    }
}

fn is_safe_native_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".+~:_-".contains(character))
}

fn compare_native_versions(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let mut left = left.as_bytes();
    let mut right = right.as_bytes();
    while !left.is_empty() || !right.is_empty() {
        let left_digits = left.first().is_some_and(u8::is_ascii_digit);
        let right_digits = right.first().is_some_and(u8::is_ascii_digit);
        if left_digits && right_digits {
            let left_end = left
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(left.len());
            let right_end = right
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .unwrap_or(right.len());
            let left_number = trim_leading_zeroes(&left[..left_end]);
            let right_number = trim_leading_zeroes(&right[..right_end]);
            let ordering = left_number
                .len()
                .cmp(&right_number.len())
                .then_with(|| left_number.cmp(right_number));
            if ordering != Ordering::Equal {
                return ordering;
            }
            left = &left[left_end..];
            right = &right[right_end..];
            continue;
        }
        let left_byte = left.first().copied();
        let right_byte = right.first().copied();
        let ordering = native_byte_rank(left_byte).cmp(&native_byte_rank(right_byte));
        if ordering != Ordering::Equal {
            return ordering;
        }
        left = left.get(1..).unwrap_or_default();
        right = right.get(1..).unwrap_or_default();
    }
    Ordering::Equal
}

fn trim_leading_zeroes(mut value: &[u8]) -> &[u8] {
    while value.len() > 1 && value.first() == Some(&b'0') {
        value = &value[1..];
    }
    value
}

fn native_byte_rank(value: Option<u8>) -> u16 {
    match value {
        Some(b'~') => 0,
        None => 1,
        Some(byte) if byte.is_ascii_alphabetic() => u16::from(byte) + 2,
        Some(byte) => u16::from(byte) + 258,
    }
}

fn loose_semver(value: &str) -> Option<Version> {
    let value = value.trim().trim_start_matches(['v', 'V']);
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let (base, suffix) = value
        .find(['-', '+'])
        .map_or((value, ""), |index| value.split_at(index));
    let mut numeric: Vec<&str> = base.split('.').collect();
    if numeric.is_empty()
        || numeric.len() > 3
        || numeric
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    while numeric.len() < 3 {
        numeric.push("0");
    }
    Version::parse(&format!("{}{}", numeric.join("."), suffix)).ok()
}

fn check_membership(
    layer: &PolicyFile,
    kind: &str,
    value: &str,
    allowed: &[String],
    denied: &[String],
    reasons: &mut Vec<PolicyReason>,
) {
    if denied.iter().any(|entry| entry == value || entry == "*") {
        deny(
            reasons,
            layer,
            &format!("policy.{kind}.denied"),
            &format!("{kind} `{value}` is denied"),
        );
    } else if !allowed.is_empty() && !allowed.iter().any(|entry| entry == value || entry == "*") {
        deny(
            reasons,
            layer,
            &format!("policy.{kind}.not_allowed"),
            &format!("{kind} `{value}` is not allowed"),
        );
    }
}

fn deny(reasons: &mut Vec<PolicyReason>, layer: &PolicyFile, code: &str, message: &str) {
    reasons.push(PolicyReason {
        code: code.to_owned(),
        message: message.to_owned(),
        layer: layer.id.clone(),
    });
}

fn policy_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::PolicyRejected,
        message,
        "Correct the policy or choose an operation permitted by higher-precedence policy.",
    )
    .with_reason(reason)
}

#[must_use]
pub fn parse_scope(value: &str) -> Option<Scope> {
    match value {
        "user" => Some(Scope::User),
        "system" => Some(Scope::System),
        "auto" => Some(Scope::Auto),
        _ => None,
    }
}

#[must_use]
pub fn deduplicate(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use siorb_catalog::{ArtifactFormat, ArtifactVerification, PackageSource};

    fn package() -> PackageManifest {
        PackageManifest {
            schema_version: "1".to_owned(),
            id: "firefox".to_owned(),
            name: "Firefox".to_owned(),
            description: "Browser".to_owned(),
            aliases: vec![],
            deprecated_aliases: vec![],
            search_terms: vec![],
            homepage: "https://mozilla.org".to_owned(),
            upstream: String::new(),
            license: "MPL-2.0".to_owned(),
            risk: "standard".to_owned(),
            categories: vec!["browser".to_owned()],
            capabilities: vec![],
            channels: vec!["stable".to_owned()],
            conflicts: vec![],
            replacements: vec![],
            dependencies: vec![],
            optional_relationships: vec![],
            version_normalization: String::new(),
            verification: String::new(),
            evidence: vec![],
            reviewed_at: String::new(),
            maintainers: vec![],
            deprecated: false,
            sources: vec![],
        }
    }

    fn source() -> PackageSource {
        PackageSource {
            id: "firefox-apt".to_owned(),
            platform: "debian".to_owned(),
            distributions: vec![],
            backend: "apt".to_owned(),
            package_id: "firefox".to_owned(),
            trust: "native".to_owned(),
            scope: "system".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec!["x86_64".to_owned()],
            priority: 10,
            requires_privilege: true,
            provenance: "backend-repository".to_owned(),
            evidence: String::new(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: None,
        }
    }

    fn artifact_source(format: ArtifactFormat, signer: Option<&str>) -> PackageSource {
        let platform = match format {
            ArtifactFormat::Msi | ArtifactFormat::Msix | ArtifactFormat::Exe => "windows",
            ArtifactFormat::Pkg | ArtifactFormat::Dmg | ArtifactFormat::Zip => "macos",
            ArtifactFormat::Deb => "debian",
            ArtifactFormat::Rpm => "fedora",
            ArtifactFormat::AppImage | ArtifactFormat::Tar | ArtifactFormat::TarGz => "linux",
        };
        PackageSource {
            id: "firefox-artifact".to_owned(),
            platform: platform.to_owned(),
            distributions: Vec::new(),
            backend: "artifact".to_owned(),
            package_id: "https://downloads.example.org/firefox".to_owned(),
            trust: "verified-upstream".to_owned(),
            scope: "system".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec!["x86_64".to_owned()],
            priority: 10,
            requires_privilege: true,
            provenance: "signed-release".to_owned(),
            evidence: "https://downloads.example.org/releases".to_owned(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: Some(ArtifactVerification {
                sha256: "a".repeat(64),
                signer: signer.map(str::to_owned),
                content_type: Some("application/octet-stream".to_owned()),
                max_bytes: Some(1024),
                kind: format.kind(),
                format,
                archive_format: format.archive_name().map(str::to_owned),
                payload_path: (format == ArtifactFormat::Dmg)
                    .then(|| "Packages/Firefox.pkg".to_owned()),
                strip_components: 0,
                install_arguments: Vec::new(),
                allowed_redirect_hosts: Vec::new(),
            }),
        }
    }

    #[test]
    fn deny_wins_over_allow() {
        let layer = PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "org".to_owned(),
            allow_packages: vec!["firefox".to_owned()],
            deny_packages: vec!["firefox".to_owned()],
            ..PolicyFile::default()
        };
        let policy = LayeredPolicy::new(vec![layer]);
        assert!(policy.is_ok());
        if let Ok(policy) = policy {
            assert!(
                !policy
                    .evaluate(&package(), &source(), Operation::Install)
                    .allowed
            );
        }
    }

    #[test]
    fn confirmation_requirement_is_sticky_across_layers() {
        let enforcing = PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "machine".to_owned(),
            require_confirmation: true,
            ..PolicyFile::default()
        };
        let relaxed = PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "user".to_owned(),
            require_confirmation: false,
            ..PolicyFile::default()
        };
        let policy = LayeredPolicy::new(vec![enforcing, relaxed]);
        assert!(policy.is_ok());
        assert!(policy.is_ok_and(|policy| policy.requires_interactive_confirmation()));
    }

    #[test]
    fn built_in_signer_policy_is_format_aware_and_keeps_other_trust_gates() {
        let policy = LayeredPolicy::default();
        for format in [ArtifactFormat::Deb, ArtifactFormat::Rpm] {
            let decision = policy.evaluate(
                &package(),
                &artifact_source(format, None),
                Operation::Install,
            );
            assert!(
                decision
                    .reasons
                    .iter()
                    .all(|reason| reason.code != "policy.signature.required"),
                "{format:?}"
            );
            assert!(decision.allowed, "{format:?}: {:?}", decision.reasons);
        }

        let unsigned_msi = policy.evaluate(
            &package(),
            &artifact_source(ArtifactFormat::Msi, None),
            Operation::Install,
        );
        assert!(
            unsigned_msi
                .reasons
                .iter()
                .any(|reason| reason.code == "policy.signature.required")
        );
        let signed_msi = policy.evaluate(
            &package(),
            &artifact_source(ArtifactFormat::Msi, Some("Expected Publisher")),
            Operation::Install,
        );
        assert!(signed_msi.allowed, "{:?}", signed_msi.reasons);

        let mut missing_digest = artifact_source(ArtifactFormat::Deb, None);
        if let Some(verification) = &mut missing_digest.verification {
            verification.sha256.clear();
        }
        let decision = policy.evaluate(&package(), &missing_digest, Operation::Install);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.code == "policy.digest.required")
        );

        let mut weak_provenance = artifact_source(ArtifactFormat::Deb, None);
        weak_provenance.provenance = "community".to_owned();
        let decision = policy.evaluate(&package(), &weak_provenance, Operation::Install);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.code == "policy.provenance.insufficient")
        );
    }

    #[test]
    fn contextual_controls_have_stable_reason_codes() {
        let layer = PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "org".to_owned(),
            trusted_publishers: vec!["trusted.example".to_owned()],
            minimum_provenance: Some("signed-release".to_owned()),
            network_domains: vec!["packages.example".to_owned()],
            require_dry_run: true,
            prevent_downgrade: true,
            freshness_days: Some(1),
            ..PolicyFile::default()
        };
        let policy = LayeredPolicy::new(vec![layer]);
        assert!(policy.is_ok());
        let Some(policy) = policy.ok() else { return };
        let decision = policy.evaluate_with_context(
            &package(),
            &source(),
            Operation::Upgrade,
            &PolicyEvaluationContext {
                dry_run: false,
                now_unix: Some(2_000_000_000),
                installed_version: Some("2.0".to_owned()),
                target_version: Some("=1.0".to_owned()),
                network_urls: vec!["https://evil.example/package".to_owned()],
            },
        );
        let codes: BTreeSet<_> = decision
            .reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect();
        for expected in [
            "policy.publisher.missing",
            "policy.provenance.insufficient",
            "policy.network_domain.denied",
            "policy.dry_run.required",
            "policy.downgrade.prevented",
            "policy.freshness.exceeded",
        ] {
            assert!(codes.contains(expected), "missing reason {expected}");
        }
    }

    #[test]
    fn date_parser_is_calendar_strict() {
        assert_eq!(parse_iso_date_days("1970-01-01"), Some(0));
        assert!(parse_iso_date_days("2025-02-29").is_none());
        assert!(parse_iso_date_days("2024-02-29").is_some());
    }

    #[test]
    fn self_update_is_deny_wins() {
        let allow = PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "user".to_owned(),
            allow_self_update: Some(true),
            ..PolicyFile::default()
        };
        let deny = PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "org".to_owned(),
            allow_self_update: Some(false),
            ..PolicyFile::default()
        };
        let policy = LayeredPolicy::new(vec![deny, allow]);
        assert!(policy.is_ok());
        let Some(policy) = policy.ok() else { return };
        assert!(!policy.evaluate_self_update().allowed);
        assert_eq!(
            policy
                .enforce_self_update()
                .err()
                .map(|error| error.reason_code),
            Some("policy.self_update.denied".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn policy_loader_rejects_writable_files_and_links() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        assert!(fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).is_ok());
        let policy = directory.path().join("policy.toml");
        let contents = "schema_version = \"1.0\"\nid = \"test-policy\"\n";
        assert!(fs::write(&policy, contents).is_ok());
        assert!(fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).is_ok());
        let loaded = PolicyFile::load(&policy);
        assert!(loaded.is_ok(), "{loaded:?}");

        assert!(fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).is_ok());
        let writable = PolicyFile::load(&policy);
        assert_eq!(
            writable.err().map(|error| error.reason_code),
            Some("policy.read.failed".to_owned())
        );

        assert!(fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).is_ok());
        let linked = directory.path().join("linked.toml");
        assert!(symlink(&policy, &linked).is_ok());
        assert!(PolicyFile::load(&linked).is_err());
    }
}
