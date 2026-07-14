//! Portable software intent and deterministic platform-specific lock files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use siorb_catalog::{Catalog, Lookup, PackageManifest, PackageSource, normalize_identifier};
use siorb_core::{
    ErrorKind, InstalledPackage, Operation, PlatformContext, Result, Scope, SiorbError, fingerprint,
};
use siorb_policy::LayeredPolicy;
use siorb_resolver::{Resolution, ResolutionContext, ResolveOptions, Resolver, VersionConstraint};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub schema_version: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub policy_references: Vec<String>,
    #[serde(default)]
    pub feature_groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub packages: Vec<BundlePackage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundlePackage {
    pub id: String,
    #[serde(default = "present")]
    pub state: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default = "stable")]
    pub channel: String,
    #[serde(default = "auto_scope")]
    pub scope: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub allow_backends: Vec<String>,
    #[serde(default)]
    pub deny_backends: Vec<String>,
    #[serde(default)]
    pub on_conflict: Option<String>,
}

fn present() -> String {
    "present".to_owned()
}

fn stable() -> String {
    "stable".to_owned()
}

fn auto_scope() -> String {
    "auto".to_owned()
}

fn error_conflict() -> String {
    "error".to_owned()
}

impl Bundle {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(input: &str) -> Result<Self> {
        let bundle: Self = toml::from_str(input).map_err(|error| {
            let location = error.span().map_or_else(String::new, |span| {
                format!(" at bytes {}..{}", span.start, span.end)
            });
            SiorbError::new(
                ErrorKind::InvalidInput,
                format!("bundle TOML is invalid{location}"),
                "Fix the indicated field and run `siorb bundle validate`.",
            )
            .with_reason("bundle.parse.invalid")
            .with_detail(error.to_string())
        })?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let input = fs::read_to_string(path).map_err(|error| {
            SiorbError::new(
                ErrorKind::InvalidInput,
                format!("cannot read bundle {}", path.display()),
                "Check the path and file permissions.",
            )
            .with_reason("bundle.read.failed")
            .with_detail(error.to_string())
        })?;
        Self::from_str(&input)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "1.0" && self.schema_version != "1" {
            return Err(bundle_error(
                "bundle.schema.unsupported",
                format!("unsupported bundle schema `{}`", self.schema_version),
            ));
        }
        if self.packages.is_empty() {
            return Err(bundle_error(
                "bundle.packages.empty",
                "bundle must contain at least one package".to_owned(),
            ));
        }
        let mut identities = BTreeSet::new();
        for (index, package) in self.packages.iter().enumerate() {
            let canonical = normalize_identifier(&package.id).map_err(|error| {
                bundle_error(
                    "bundle.package.id",
                    format!("packages[{index}].id: {}", error.message),
                )
            })?;
            if !identities.insert(canonical) {
                return Err(bundle_error(
                    "bundle.package.duplicate",
                    format!("packages[{index}].id duplicates `{}`", package.id),
                ));
            }
            if !["present", "absent"].contains(&package.state.as_str()) {
                return Err(bundle_error(
                    "bundle.package.state",
                    format!("packages[{index}].state must be present or absent"),
                ));
            }
            if !["stable", "beta", "nightly"].contains(&package.channel.as_str()) {
                return Err(bundle_error(
                    "bundle.package.channel",
                    format!("packages[{index}].channel is invalid"),
                ));
            }
            if !["auto", "user", "system"].contains(&package.scope.as_str()) {
                return Err(bundle_error(
                    "bundle.package.scope",
                    format!("packages[{index}].scope is invalid"),
                ));
            }
            if package
                .allow_backends
                .iter()
                .any(|backend| package.deny_backends.contains(backend))
            {
                return Err(bundle_error(
                    "bundle.backend.conflict",
                    format!("packages[{index}] allows and denies the same backend"),
                ));
            }
            let mut features = BTreeSet::new();
            for feature in &package.features {
                if feature.is_empty()
                    || feature.len() > 64
                    || !feature.is_ascii()
                    || !feature.chars().all(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                    })
                {
                    return Err(bundle_error(
                        "bundle.feature.invalid",
                        format!("packages[{index}] has invalid feature `{feature}`"),
                    ));
                }
                if !features.insert(feature) {
                    return Err(bundle_error(
                        "bundle.feature.duplicate",
                        format!("packages[{index}] repeats feature `{feature}`"),
                    ));
                }
            }
            if let Some(version) = package.version.as_deref() {
                VersionConstraint::parse(version).map_err(|error| {
                    bundle_error(
                        "bundle.version.invalid",
                        format!("packages[{index}].version: {}", error.message),
                    )
                })?;
            }
            if package.on_conflict.as_deref().is_some_and(|value| {
                !["error", "prefer-installed", "prefer-bundle"].contains(&value)
            }) {
                return Err(bundle_error(
                    "bundle.conflict.strategy",
                    format!("packages[{index}].on_conflict is invalid"),
                ));
            }
        }
        let mut policy_references = BTreeSet::new();
        for reference in &self.policy_references {
            validate_portable_name(reference, "bundle.policy_reference.invalid")?;
            if !policy_references.insert(reference) {
                return Err(bundle_error(
                    "bundle.policy_reference.duplicate",
                    format!("bundle repeats policy reference `{reference}`"),
                ));
            }
        }
        for (group, members) in &self.feature_groups {
            validate_portable_name(group, "bundle.feature_group.invalid")?;
            if members.is_empty() {
                return Err(bundle_error(
                    "bundle.feature_group.empty",
                    format!("feature group `{group}` must contain at least one package"),
                ));
            }
            let mut seen = BTreeSet::new();
            for member in members {
                if !self.packages.iter().any(|package| &package.id == member) {
                    return Err(bundle_error(
                        "bundle.feature_group.unknown_package",
                        format!("feature group `{group}` refers to unknown package `{member}`"),
                    ));
                }
                if !seen.insert(member) {
                    return Err(bundle_error(
                        "bundle.feature_group.duplicate_package",
                        format!("feature group `{group}` repeats package `{member}`"),
                    ));
                }
            }
        }
        for (profile, members) in &self.profiles {
            validate_portable_name(profile, "bundle.profile.invalid")?;
            for member in members {
                if let Some(group) = member.strip_prefix('@') {
                    if !self.feature_groups.contains_key(group) {
                        return Err(bundle_error(
                            "bundle.profile.unknown_feature_group",
                            format!(
                                "profile `{profile}` refers to unknown feature group `{group}`"
                            ),
                        ));
                    }
                } else if !self.packages.iter().any(|package| &package.id == member) {
                    return Err(bundle_error(
                        "bundle.profile.unknown_package",
                        format!("profile `{profile}` refers to unknown package `{member}`"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn for_profile<'a>(&'a self, profile: Option<&str>) -> Result<Vec<&'a BundlePackage>> {
        let Some(profile) = profile else {
            return Ok(self.packages.iter().collect());
        };
        let members = self.profiles.get(profile).ok_or_else(|| {
            bundle_error(
                "bundle.profile.missing",
                format!("bundle has no profile `{profile}`"),
            )
        })?;
        let mut selected = BTreeSet::new();
        for member in members {
            if let Some(group) = member.strip_prefix('@') {
                let group_members = self.feature_groups.get(group).ok_or_else(|| {
                    bundle_error(
                        "bundle.profile.unknown_feature_group",
                        format!("profile `{profile}` refers to unknown feature group `{group}`"),
                    )
                })?;
                selected.extend(group_members.iter());
            } else {
                selected.insert(member);
            }
        }
        Ok(self
            .packages
            .iter()
            .filter(|package| selected.contains(&package.id))
            .collect())
    }
}

fn validate_portable_name(value: &str, reason: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(bundle_error(
            reason,
            format!("`{value}` is not a portable identifier"),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleLock {
    pub schema_version: String,
    pub intent_fingerprint: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub policy_references: Vec<String>,
    pub catalog_version: u64,
    pub catalog_fingerprint: String,
    pub policy_fingerprint: String,
    pub platform_fingerprint: String,
    pub platform_os: String,
    pub platform_architecture: String,
    pub packages: Vec<LockedPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LockedPackage {
    pub logical_id: String,
    pub desired_state: String,
    pub source_id: String,
    pub backend: String,
    pub native_id: String,
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_version: Option<String>,
    pub scope: String,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default = "error_conflict", skip_serializing_if = "is_error_conflict")]
    pub on_conflict: String,
    #[serde(default, skip_serializing_if = "LockVerificationMaterial::is_empty")]
    pub verification: LockVerificationMaterial,
    pub explanation_fingerprint: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LockVerificationMaterial {
    pub provenance: String,
    pub evidence: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
}

impl LockVerificationMaterial {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

fn is_error_conflict(value: &str) -> bool {
    value == "error"
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BundleDiff {
    pub install: Vec<String>,
    pub remove: Vec<String>,
    pub upgrade_or_verify: Vec<String>,
    pub unchanged: Vec<String>,
    pub ignored_optional: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LockPackageChange {
    pub logical_id: String,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LockRefreshReport {
    pub catalog_change: Option<String>,
    pub policy_changed: bool,
    pub platform_changed: bool,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<LockPackageChange>,
    pub unchanged: usize,
}

impl LockRefreshReport {
    #[must_use]
    pub fn human_readable(&self) -> String {
        let mut lines = Vec::new();
        lines.push(self.catalog_change.as_ref().map_or_else(
            || "catalog: unchanged".to_owned(),
            |change| format!("catalog: {change}"),
        ));
        lines.push(format!(
            "policy: {}",
            if self.policy_changed {
                "changed"
            } else {
                "unchanged"
            }
        ));
        lines.push(format!(
            "platform: {}",
            if self.platform_changed {
                "changed"
            } else {
                "unchanged"
            }
        ));
        for package in &self.added {
            lines.push(format!("+ {package}"));
        }
        for package in &self.removed {
            lines.push(format!("- {package}"));
        }
        for package in &self.changed {
            lines.push(format!(
                "~ {}: {}",
                package.logical_id,
                package.changes.join(", ")
            ));
        }
        lines.push(format!("unchanged packages: {}", self.unchanged));
        lines.join("\n")
    }
}

impl BundleLock {
    pub fn load(path: &Path) -> Result<Self> {
        const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;
        let encoded = fs::read(path).map_err(|error| {
            bundle_error(
                "bundle.lock.read",
                format!("cannot read lock {}: {error}", path.display()),
            )
        })?;
        if encoded.len() > MAX_LOCK_BYTES {
            return Err(bundle_error(
                "bundle.lock.too_large",
                format!("lock {} exceeds 16 MiB", path.display()),
            ));
        }
        serde_json::from_slice(&encoded).map_err(|error| {
            bundle_error(
                "bundle.lock.parse",
                format!("lock {} is invalid JSON: {error}", path.display()),
            )
        })
    }

    /// Verify that this lock was produced from the supplied portable intent.
    ///
    /// # Errors
    ///
    /// Returns `bundle.lock.intent_changed` when any intent field differs.
    pub fn verify_intent(&self, bundle: &Bundle) -> Result<()> {
        if self.intent_fingerprint != fingerprint(bundle) {
            return Err(bundle_error(
                "bundle.lock.intent_changed",
                "lock intent fingerprint does not match the supplied bundle".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn verify_profile(&self, profile: Option<&str>) -> Result<()> {
        if self.profile.as_deref() != profile {
            return Err(bundle_error(
                "bundle.lock.profile_changed",
                "lock profile does not match the requested bundle profile".to_owned(),
            ));
        }
        Ok(())
    }

    /// Verify that security-relevant lock material still describes the current
    /// resolution environment. A cross-platform lock is never executable.
    pub fn verify_context(
        &self,
        catalog: &Catalog,
        platform: &PlatformContext,
        policy: &LayeredPolicy,
    ) -> Result<()> {
        if self.schema_version != "1.0" && self.schema_version != "1" {
            return Err(bundle_error(
                "bundle.lock.schema",
                format!("unsupported lock schema `{}`", self.schema_version),
            ));
        }
        if self.catalog_version != catalog.identity().version
            || self.catalog_fingerprint != catalog.identity().fingerprint
        {
            return Err(bundle_error(
                "bundle.lock.catalog_changed",
                "lock catalog identity does not match the active catalog".to_owned(),
            ));
        }
        if self.policy_fingerprint != policy.identity().fingerprint {
            return Err(bundle_error(
                "bundle.lock.policy_changed",
                "lock policy fingerprint does not match the active policy".to_owned(),
            ));
        }
        if self
            .policy_references
            .iter()
            .any(|reference| !policy.identity().layers.contains(reference))
        {
            return Err(bundle_error(
                "bundle.lock.policy_reference.missing",
                "a policy layer required by the lock is not active".to_owned(),
            ));
        }
        if self.platform_fingerprint != platform.fingerprint()
            || self.platform_os != platform.os.to_string()
            || self.platform_architecture != platform.architecture.to_string()
        {
            return Err(bundle_error(
                "bundle.lock.platform_changed",
                "lock targets a different platform context".to_owned(),
            ));
        }
        let mut ids = BTreeSet::new();
        for package in &self.packages {
            if !ids.insert(&package.logical_id) {
                return Err(bundle_error(
                    "bundle.lock.package.duplicate",
                    format!("lock repeats package `{}`", package.logical_id),
                ));
            }
            if !matches!(package.desired_state.as_str(), "present" | "absent")
                || !matches!(
                    package.on_conflict.as_str(),
                    "error" | "prefer-installed" | "prefer-bundle"
                )
            {
                return Err(bundle_error(
                    "bundle.lock.package.invalid",
                    format!("locked intent for `{}` is invalid", package.logical_id),
                ));
            }
            if package.explanation_fingerprint.len() != 64
                || !package
                    .explanation_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(bundle_error(
                    "bundle.lock.explanation.invalid",
                    format!(
                        "resolution explanation fingerprint for `{}` is invalid",
                        package.logical_id
                    ),
                ));
            }
            if let Some(constraint) = package.version.as_deref() {
                VersionConstraint::parse(constraint).map_err(|error| {
                    bundle_error(
                        "bundle.lock.version.invalid",
                        format!(
                            "locked version for `{}`: {}",
                            package.logical_id, error.message
                        ),
                    )
                })?;
            }
            let manifest = exact_package(catalog, &package.logical_id)?;
            let source = manifest
                .sources
                .iter()
                .find(|source| source.id == package.source_id)
                .ok_or_else(|| {
                    bundle_error(
                        "bundle.lock.source_changed",
                        format!("locked source `{}` no longer exists", package.source_id),
                    )
                })?;
            if source.backend != package.backend || source.package_id != package.native_id {
                return Err(bundle_error(
                    "bundle.lock.identity_changed",
                    format!("native identity for `{}` changed", package.logical_id),
                ));
            }
            if verification_material(source) != package.verification {
                return Err(bundle_error(
                    "bundle.lock.verification_changed",
                    format!("verification material for `{}` changed", package.logical_id),
                ));
            }
        }
        Ok(())
    }

    /// Verify exact versions that were observed when the lock was generated.
    /// Entries without an observed version remain best-effort and are checked
    /// after installation by the backend query contract.
    pub fn verify_observed_versions(&self, installed: &[InstalledPackage]) -> Result<()> {
        for package in &self.packages {
            let Some(locked) = package.observed_version.as_deref() else {
                continue;
            };
            let observed = installed
                .iter()
                .find(|value| value.logical_id == package.logical_id)
                .and_then(|value| value.version.as_deref());
            if observed != Some(locked) {
                return Err(bundle_error(
                    "bundle.lock.version_changed",
                    format!(
                        "observed version for `{}` no longer matches locked `{locked}`",
                        package.logical_id
                    ),
                ));
            }
        }
        Ok(())
    }
}

#[must_use]
pub fn compare_locks(previous: &BundleLock, refreshed: &BundleLock) -> LockRefreshReport {
    let catalog_change = (previous.catalog_version != refreshed.catalog_version
        || previous.catalog_fingerprint != refreshed.catalog_fingerprint)
        .then(|| {
            format!(
                "version {} -> {} (fingerprint {} -> {})",
                previous.catalog_version,
                refreshed.catalog_version,
                short_fingerprint(&previous.catalog_fingerprint),
                short_fingerprint(&refreshed.catalog_fingerprint)
            )
        });
    let policy_changed = previous.policy_fingerprint != refreshed.policy_fingerprint
        || previous.policy_references != refreshed.policy_references;
    let platform_changed = previous.platform_fingerprint != refreshed.platform_fingerprint
        || previous.platform_os != refreshed.platform_os
        || previous.platform_architecture != refreshed.platform_architecture;
    let previous_packages: BTreeMap<_, _> = previous
        .packages
        .iter()
        .map(|package| (&package.logical_id, package))
        .collect();
    let refreshed_packages: BTreeMap<_, _> = refreshed
        .packages
        .iter()
        .map(|package| (&package.logical_id, package))
        .collect();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = 0;
    for (logical_id, package) in &refreshed_packages {
        let Some(old) = previous_packages.get(logical_id) else {
            added.push((*logical_id).clone());
            continue;
        };
        let field_changes = describe_package_changes(old, package);
        if field_changes.is_empty() {
            unchanged += 1;
        } else {
            changed.push(LockPackageChange {
                logical_id: (*logical_id).clone(),
                changes: field_changes,
            });
        }
    }
    for logical_id in previous_packages.keys() {
        if !refreshed_packages.contains_key(logical_id) {
            removed.push((*logical_id).clone());
        }
    }
    LockRefreshReport {
        catalog_change,
        policy_changed,
        platform_changed,
        added,
        removed,
        changed,
        unchanged,
    }
}

fn describe_package_changes(old: &LockedPackage, new: &LockedPackage) -> Vec<String> {
    let mut changes = Vec::new();
    if old.source_id != new.source_id
        || old.backend != new.backend
        || old.native_id != new.native_id
    {
        changes.push(format!(
            "source {} ({}/{}) -> {} ({}/{})",
            old.source_id, old.backend, old.native_id, new.source_id, new.backend, new.native_id
        ));
    }
    if old.version != new.version || old.observed_version != new.observed_version {
        changes.push(format!(
            "version {} -> {}",
            display_version(old.version.as_deref(), old.observed_version.as_deref()),
            display_version(new.version.as_deref(), new.observed_version.as_deref())
        ));
    }
    if old.desired_state != new.desired_state
        || old.scope != new.scope
        || old.channel != new.channel
        || old.features != new.features
        || old.on_conflict != new.on_conflict
    {
        changes.push("intent resolution changed".to_owned());
    }
    if old.verification != new.verification {
        changes.push("verification material changed".to_owned());
    }
    if old.explanation_fingerprint != new.explanation_fingerprint {
        changes.push("resolution explanation changed".to_owned());
    }
    changes
}

fn display_version(constraint: Option<&str>, observed: Option<&str>) -> String {
    match (constraint, observed) {
        (Some(constraint), Some(observed)) => format!("{constraint} (observed {observed})"),
        (Some(constraint), None) => constraint.to_owned(),
        (None, Some(observed)) => format!("observed {observed}"),
        (None, None) => "unspecified".to_owned(),
    }
}

fn short_fingerprint(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}

pub fn resolve_bundle(
    bundle: &Bundle,
    profile: Option<&str>,
    catalog: &Catalog,
    platform: &PlatformContext,
    policy: &LayeredPolicy,
    installed: &[InstalledPackage],
) -> Result<(BundleLock, Vec<(Operation, Resolution)>)> {
    resolve_bundle_with_context(
        bundle,
        profile,
        catalog,
        platform,
        policy,
        installed,
        &ResolutionContext::default(),
    )
}

/// Resolve portable intent using invocation-specific policy facts.
///
/// The original [`resolve_bundle`] entry point remains a compatibility wrapper
/// with the default context. Runtime callers should use this function so
/// dry-run, evaluation time and known network endpoints reach every install or
/// removal resolution, including conflict-driven removals.
///
/// # Errors
///
/// Returns a stable bundle, catalog, resolution or policy error when intent
/// validation fails or no permitted source can satisfy an operation.
pub fn resolve_bundle_with_context(
    bundle: &Bundle,
    profile: Option<&str>,
    catalog: &Catalog,
    platform: &PlatformContext,
    policy: &LayeredPolicy,
    installed: &[InstalledPackage],
    context: &ResolutionContext,
) -> Result<(BundleLock, Vec<(Operation, Resolution)>)> {
    bundle.validate()?;
    for reference in &bundle.policy_references {
        if !policy.identity().layers.contains(reference) {
            return Err(bundle_error(
                "bundle.policy_reference.missing",
                format!("required policy layer `{reference}` is not active"),
            ));
        }
    }
    let resolver = Resolver::new(catalog, platform, policy, installed);
    let mut operations = Vec::new();
    let mut locked = Vec::new();
    let intents = bundle.for_profile(profile)?;
    let skipped = bundle_conflict_skips(&intents, catalog)?;
    let mut scheduled_removals = BTreeSet::new();
    for intent in intents {
        if skipped.contains(&intent.id) {
            continue;
        }
        if !intent.platforms.is_empty() && !intent.platforms.contains(&platform.os.to_string()) {
            continue;
        }
        let manifest = exact_package(catalog, &intent.id)?;
        let installed_conflicts: Vec<_> = manifest
            .conflicts
            .iter()
            .filter_map(|conflict| {
                installed
                    .iter()
                    .find(|observed| observed.logical_id == *conflict)
            })
            .collect();
        if !installed_conflicts.is_empty() {
            match intent.on_conflict.as_deref().unwrap_or("error") {
                "prefer-installed" => continue,
                "prefer-bundle" => {
                    for conflict in installed_conflicts {
                        if !scheduled_removals.insert(conflict.logical_id.clone()) {
                            continue;
                        }
                        let removal = resolver.resolve_with_context(
                            &conflict.logical_id,
                            Operation::Remove,
                            &ResolveOptions {
                                via: Some(conflict.backend.clone()),
                                source: None,
                                scope: conflict.scope,
                                channel: "stable".to_owned(),
                                version: None,
                                architecture: None,
                            },
                            context,
                        )?;
                        removal.require_selected()?;
                        operations.push((Operation::Remove, removal));
                    }
                }
                _ => {
                    return Err(bundle_error(
                        "bundle.conflict.detected",
                        format!(
                            "`{}` conflicts with installed package(s): {}",
                            intent.id,
                            installed_conflicts
                                .iter()
                                .map(|package| package.logical_id.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }
        let operation = if intent.state == "absent" {
            Operation::Remove
        } else {
            Operation::Install
        };
        let options = ResolveOptions {
            via: None,
            source: None,
            scope: parse_scope(&intent.scope),
            channel: intent.channel.clone(),
            version: intent.version.clone(),
            architecture: None,
        };
        let mut resolution =
            resolver.resolve_with_context(&intent.id, operation, &options, context)?;
        resolution.selected = resolution
            .evaluations
            .iter()
            .filter(|evaluation| {
                evaluation.accepted
                    && !intent.deny_backends.contains(&evaluation.source.backend)
                    && (intent.allow_backends.is_empty()
                        || intent.allow_backends.contains(&evaluation.source.backend))
            })
            .max_by(|left, right| {
                left.rank
                    .cmp(&right.rank)
                    .then_with(|| right.source.id.cmp(&left.source.id))
            })
            .map(|evaluation| evaluation.source.clone());
        if resolution.selected.is_none()
            && resolution
                .evaluations
                .iter()
                .any(|evaluation| evaluation.accepted)
        {
            if intent.optional {
                continue;
            }
            return Err(bundle_error(
                "bundle.backend.no_allowed_candidate",
                format!(
                    "bundle backend constraints reject every compatible source for `{}`",
                    intent.id
                ),
            ));
        }
        let source = match resolution.require_selected() {
            Ok(source) => source,
            Err(_error) if intent.optional => {
                continue;
            }
            Err(error) => return Err(error),
        };
        locked.push(LockedPackage {
            logical_id: resolution.canonical_id.clone(),
            desired_state: intent.state.clone(),
            source_id: source.id.clone(),
            backend: source.backend.clone(),
            native_id: source.package_id.clone(),
            version: intent.version.clone(),
            observed_version: installed
                .iter()
                .find(|package| package.logical_id == resolution.canonical_id)
                .and_then(|package| package.version.clone()),
            scope: intent.scope.clone(),
            channel: intent.channel.clone(),
            features: sorted(intent.features.clone()),
            on_conflict: intent
                .on_conflict
                .clone()
                .unwrap_or_else(|| "error".to_owned()),
            verification: verification_material(source),
            explanation_fingerprint: fingerprint(&resolution.evaluations),
        });
        operations.push((operation, resolution));
    }
    locked.sort_by(|left, right| left.logical_id.cmp(&right.logical_id));
    let lock = BundleLock {
        schema_version: "1.0".to_owned(),
        intent_fingerprint: fingerprint(bundle),
        profile: profile.map(str::to_owned),
        policy_references: sorted(bundle.policy_references.clone()),
        catalog_version: catalog.identity().version,
        catalog_fingerprint: catalog.identity().fingerprint.clone(),
        policy_fingerprint: policy.identity().fingerprint.clone(),
        platform_fingerprint: platform.fingerprint(),
        platform_os: platform.os.to_string(),
        platform_architecture: platform.architecture.to_string(),
        packages: locked,
    };
    Ok((lock, operations))
}

fn exact_package<'a>(catalog: &'a Catalog, id: &str) -> Result<&'a PackageManifest> {
    match catalog.lookup(id)? {
        Lookup::Exact(package) | Lookup::DeprecatedAlias(package) => Ok(package),
        Lookup::Ambiguous(_) => Err(bundle_error(
            "bundle.package.ambiguous",
            format!("bundle package `{id}` is ambiguous"),
        )),
        Lookup::Missing => Err(bundle_error(
            "bundle.package.missing",
            format!("bundle package `{id}` is absent from the catalog"),
        )),
    }
}

fn bundle_conflict_skips(
    intents: &[&BundlePackage],
    catalog: &Catalog,
) -> Result<BTreeSet<String>> {
    let mut skipped = BTreeSet::new();
    for (index, left) in intents.iter().enumerate() {
        if left.state != "present" {
            continue;
        }
        let left_manifest = exact_package(catalog, &left.id)?;
        for right in &intents[index + 1..] {
            if right.state != "present" {
                continue;
            }
            let right_manifest = exact_package(catalog, &right.id)?;
            if !left_manifest.conflicts.contains(&right_manifest.id)
                && !right_manifest.conflicts.contains(&left_manifest.id)
            {
                continue;
            }
            match (
                left.on_conflict.as_deref().unwrap_or("error"),
                right.on_conflict.as_deref().unwrap_or("error"),
            ) {
                ("prefer-bundle", "prefer-installed") => {
                    skipped.insert(right.id.clone());
                }
                ("prefer-installed", "prefer-bundle") => {
                    skipped.insert(left.id.clone());
                }
                _ => {
                    return Err(bundle_error(
                        "bundle.conflict.ambiguous",
                        format!(
                            "bundle requests mutually conflicting packages `{}` and `{}`",
                            left.id, right.id
                        ),
                    ));
                }
            }
        }
    }
    Ok(skipped)
}

fn verification_material(source: &PackageSource) -> LockVerificationMaterial {
    let artifact = source.verification.as_ref();
    LockVerificationMaterial {
        provenance: source.provenance.clone(),
        evidence: source.evidence.clone(),
        sha256: artifact.map(|verification| verification.sha256.clone()),
        signer: artifact.and_then(|verification| verification.signer.clone()),
        content_type: artifact.and_then(|verification| verification.content_type.clone()),
        max_bytes: artifact.and_then(|verification| verification.max_bytes),
    }
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[must_use]
pub fn diff(bundle: &Bundle, installed: &[InstalledPackage]) -> BundleDiff {
    let mut result = BundleDiff {
        install: Vec::new(),
        remove: Vec::new(),
        upgrade_or_verify: Vec::new(),
        unchanged: Vec::new(),
        ignored_optional: Vec::new(),
    };
    for intent in &bundle.packages {
        let observed = installed
            .iter()
            .find(|package| package.logical_id == intent.id);
        match (intent.state.as_str(), observed) {
            ("present", None) if intent.optional => result.ignored_optional.push(intent.id.clone()),
            ("present", None) => result.install.push(intent.id.clone()),
            ("absent", Some(_)) => result.remove.push(intent.id.clone()),
            ("present", Some(package)) if version_mismatch(intent, package) => {
                result.upgrade_or_verify.push(intent.id.clone());
            }
            _ => result.unchanged.push(intent.id.clone()),
        }
    }
    result
}

fn version_mismatch(intent: &BundlePackage, installed: &InstalledPackage) -> bool {
    let Some(constraint) = intent.version.as_deref() else {
        return false;
    };
    let Some(observed) = installed.version.as_deref() else {
        return true;
    };
    VersionConstraint::parse(constraint)
        .map(|constraint| !constraint.matches(observed))
        .unwrap_or(true)
}

#[must_use]
pub fn export_intent(installed: &[InstalledPackage]) -> Bundle {
    let mut packages: Vec<_> = installed
        .iter()
        .map(|package| BundlePackage {
            id: package.logical_id.clone(),
            state: "present".to_owned(),
            version: package.version.clone(),
            channel: "stable".to_owned(),
            scope: package.scope.to_string(),
            optional: false,
            features: vec![],
            platforms: vec![],
            allow_backends: vec![],
            deny_backends: vec![],
            on_conflict: None,
        })
        .collect();
    packages.sort_by(|left, right| left.id.cmp(&right.id));
    Bundle {
        schema_version: "1.0".to_owned(),
        name: Some("siorb-migration".to_owned()),
        metadata: BTreeMap::from([("purpose".to_owned(), "portable migration intent".to_owned())]),
        policy_references: Vec::new(),
        feature_groups: BTreeMap::new(),
        profiles: BTreeMap::new(),
        packages,
    }
}

pub fn write_lock(path: &Path, lock: &BundleLock) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(lock)
        .map_err(|error| bundle_error("bundle.lock.encode", error.to_string()))?;
    fs::write(path, encoded).map_err(|error| bundle_error("bundle.lock.write", error.to_string()))
}

pub fn write_bundle(path: &Path, bundle: &Bundle) -> Result<()> {
    let encoded = toml::to_string_pretty(bundle)
        .map_err(|error| bundle_error("bundle.encode", error.to_string()))?;
    fs::write(path, encoded).map_err(|error| bundle_error("bundle.write", error.to_string()))
}

fn parse_scope(value: &str) -> Scope {
    match value {
        "user" => Scope::User,
        "system" => Scope::System,
        _ => Scope::Auto,
    }
}

fn bundle_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::InvalidInput,
        message,
        "Correct the portable intent and validate it before planning or applying.",
    )
    .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use siorb_core::{Architecture, BackendInfo, OsFamily};
    use siorb_policy::PolicyFile;

    fn debian_platform() -> PlatformContext {
        PlatformContext {
            os: OsFamily::Linux,
            distribution: Some("debian".to_owned()),
            architecture: Architecture::X86_64,
            backends: vec![BackendInfo {
                id: "apt".to_owned(),
                executable: "/usr/bin/apt-get".to_owned(),
                version: Some("2.9".to_owned()),
                available: true,
                capabilities: vec!["install".to_owned(), "remove".to_owned()],
            }],
            supported_scopes: vec![Scope::User, Scope::System],
            ..PlatformContext::default()
        }
    }

    fn contextual_policy() -> Result<LayeredPolicy> {
        LayeredPolicy::new(vec![PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "bundle-context".to_owned(),
            require_dry_run: true,
            network_domains: vec!["packages.example".to_owned()],
            freshness_days: Some(1),
            ..PolicyFile::default()
        }])
    }

    fn contextual_bundle() -> Result<Bundle> {
        Bundle::from_str(
            r#"
schema_version = "1.0"

[[packages]]
id = "bat"
state = "present"

[[packages]]
id = "ripgrep"
state = "absent"
"#,
        )
    }

    #[test]
    fn duplicate_package_is_rejected() {
        let input = r#"
schema_version = "1.0"
[[packages]]
id = "firefox"
[[packages]]
id = "firefox"
"#;
        assert!(Bundle::from_str(input).is_err());
    }

    #[test]
    fn diff_uses_constraint_semantics_not_string_equality() {
        let bundle = Bundle::from_str(
            r#"
schema_version = "1.0"
[[packages]]
id = "ripgrep"
version = ">=14,<15"
"#,
        );
        assert!(bundle.is_ok());
        let Some(bundle) = bundle.ok() else { return };
        let installed = [InstalledPackage {
            logical_id: "ripgrep".to_owned(),
            native_id: "ripgrep".to_owned(),
            backend: "apt".to_owned(),
            version: Some("14.1.1-1".to_owned()),
            scope: Scope::System,
            receipt: true,
            held: false,
            pinned: None,
        }];
        let changes = diff(&bundle, &installed);
        assert_eq!(changes.unchanged, vec!["ripgrep".to_owned()]);
        assert!(changes.upgrade_or_verify.is_empty());
    }

    #[test]
    fn feature_labels_are_validated() {
        let invalid = Bundle::from_str(
            r#"
schema_version = "1.0"
[[packages]]
id = "ripgrep"
features = ["core", "../script"]
"#,
        );
        assert_eq!(
            invalid.err().map(|error| error.reason_code),
            Some("bundle.feature.invalid".to_owned())
        );
    }

    #[test]
    fn profiles_expand_named_feature_groups_deterministically() {
        let bundle = Bundle::from_str(
            r#"
schema_version = "1.0"

[feature_groups]
developer = ["ripgrep", "bat"]

[profiles]
default = ["@developer", "firefox"]

[[packages]]
id = "firefox"

[[packages]]
id = "bat"

[[packages]]
id = "ripgrep"
"#,
        );
        assert!(bundle.is_ok());
        let Some(bundle) = bundle.ok() else { return };
        let selected = bundle.for_profile(Some("default"));
        assert!(selected.is_ok());
        assert_eq!(
            selected
                .unwrap_or_default()
                .iter()
                .map(|package| package.id.as_str())
                .collect::<Vec<_>>(),
            vec!["firefox", "bat", "ripgrep"]
        );
    }

    #[test]
    fn missing_policy_reference_fails_before_resolution() {
        let catalog = Catalog::bundled();
        let policy = LayeredPolicy::new(Vec::new());
        let bundle = Bundle::from_str(
            r#"
schema_version = "1.0"
policy_references = ["organization-production"]

[[packages]]
id = "ripgrep"
platforms = ["never"]
"#,
        );
        assert!(catalog.is_ok());
        assert!(policy.is_ok());
        assert!(bundle.is_ok());
        let (Some(catalog), Some(policy), Some(bundle)) = (catalog.ok(), policy.ok(), bundle.ok())
        else {
            return;
        };
        let error = resolve_bundle_with_context(
            &bundle,
            None,
            &catalog,
            &debian_platform(),
            &policy,
            &[],
            &ResolutionContext::default(),
        )
        .err();
        assert_eq!(
            error.map(|value| value.reason_code),
            Some("bundle.policy_reference.missing".to_owned())
        );
    }

    #[test]
    fn lock_refresh_report_names_source_version_and_explanation_changes() {
        let package = LockedPackage {
            logical_id: "ripgrep".to_owned(),
            desired_state: "present".to_owned(),
            source_id: "ripgrep-apt".to_owned(),
            backend: "apt".to_owned(),
            native_id: "ripgrep".to_owned(),
            version: Some("14".to_owned()),
            observed_version: Some("14.1".to_owned()),
            scope: "system".to_owned(),
            channel: "stable".to_owned(),
            features: Vec::new(),
            on_conflict: "error".to_owned(),
            verification: LockVerificationMaterial::default(),
            explanation_fingerprint: "a".repeat(64),
        };
        let previous = BundleLock {
            schema_version: "1.0".to_owned(),
            intent_fingerprint: "b".repeat(64),
            profile: Some("default".to_owned()),
            policy_references: vec!["builtin-secure-defaults".to_owned()],
            catalog_version: 1,
            catalog_fingerprint: "c".repeat(64),
            policy_fingerprint: "d".repeat(64),
            platform_fingerprint: "e".repeat(64),
            platform_os: "linux".to_owned(),
            platform_architecture: "x86_64".to_owned(),
            packages: vec![package.clone()],
        };
        let mut refreshed = previous.clone();
        refreshed.catalog_version = 2;
        refreshed.catalog_fingerprint = "f".repeat(64);
        refreshed.packages[0].source_id = "ripgrep-artifact".to_owned();
        refreshed.packages[0].backend = "artifact".to_owned();
        refreshed.packages[0].version = Some("15".to_owned());
        refreshed.packages[0].explanation_fingerprint = "0".repeat(64);
        let report = compare_locks(&previous, &refreshed);
        let human = report.human_readable();
        assert!(human.contains("catalog: version 1 -> 2"));
        assert!(human.contains("source ripgrep-apt"));
        assert!(human.contains("version 14"));
        assert!(human.contains("resolution explanation changed"));
    }

    #[test]
    fn v1_locked_package_defaults_new_security_fields() {
        let legacy = r#"{
            "logical_id":"ripgrep",
            "desired_state":"present",
            "source_id":"ripgrep-apt",
            "backend":"apt",
            "native_id":"ripgrep",
            "version":null,
            "scope":"system",
            "channel":"stable",
            "explanation_fingerprint":"abc"
        }"#;
        let parsed: std::result::Result<LockedPackage, _> = serde_json::from_str(legacy);
        assert!(parsed.is_ok());
        let Some(parsed) = parsed.ok() else { return };
        assert_eq!(parsed.on_conflict, "error");
        assert_eq!(parsed.verification, LockVerificationMaterial::default());
    }

    #[test]
    fn resolution_context_reaches_bundle_installs_and_removals() {
        let catalog = Catalog::bundled();
        let policy = contextual_policy();
        let bundle = contextual_bundle();
        assert!(catalog.is_ok());
        assert!(policy.is_ok());
        assert!(bundle.is_ok());
        let (Some(catalog), Some(policy), Some(bundle)) = (catalog.ok(), policy.ok(), bundle.ok())
        else {
            return;
        };
        let platform = debian_platform();
        let installed = [InstalledPackage {
            logical_id: "ripgrep".to_owned(),
            native_id: "ripgrep".to_owned(),
            backend: "apt".to_owned(),
            version: Some("14.1.1".to_owned()),
            scope: Scope::System,
            receipt: true,
            held: false,
            pinned: None,
        }];
        let context = ResolutionContext {
            dry_run: true,
            now_unix: Some(1_783_944_000),
            network_urls: vec!["https://packages.example/repository".to_owned()],
        };

        let resolved = resolve_bundle_with_context(
            &bundle, None, &catalog, &platform, &policy, &installed, &context,
        );
        assert!(resolved.is_ok());
        let Some((_lock, operations)) = resolved.ok() else {
            return;
        };
        assert_eq!(operations.len(), 2);
        assert!(
            operations
                .iter()
                .any(|(operation, resolution)| *operation == Operation::Install
                    && resolution.canonical_id == "bat")
        );
        assert!(
            operations
                .iter()
                .any(|(operation, resolution)| *operation == Operation::Remove
                    && resolution.canonical_id == "ripgrep")
        );
    }

    #[test]
    fn bundle_contextual_policy_fails_closed_for_each_runtime_fact() {
        let catalog = Catalog::bundled();
        let policy = contextual_policy();
        let bundle = Bundle::from_str(
            r#"
schema_version = "1.0"
[[packages]]
id = "bat"
"#,
        );
        assert!(catalog.is_ok());
        assert!(policy.is_ok());
        assert!(bundle.is_ok());
        let (Some(catalog), Some(policy), Some(bundle)) = (catalog.ok(), policy.ok(), bundle.ok())
        else {
            return;
        };
        let platform = debian_platform();
        let resolve = |context: &ResolutionContext| {
            resolve_bundle_with_context(&bundle, None, &catalog, &platform, &policy, &[], context)
        };

        let cases = [
            (
                ResolutionContext {
                    dry_run: false,
                    now_unix: Some(1_783_944_000),
                    network_urls: vec!["https://packages.example/repository".to_owned()],
                },
                "policy.dry_run.required",
            ),
            (
                ResolutionContext {
                    dry_run: true,
                    now_unix: Some(1_783_944_000),
                    network_urls: vec!["https://denied.example/repository".to_owned()],
                },
                "policy.network_domain.denied",
            ),
            (
                ResolutionContext {
                    dry_run: true,
                    now_unix: Some(2_000_000_000),
                    network_urls: vec!["https://packages.example/repository".to_owned()],
                },
                "policy.freshness.exceeded",
            ),
        ];
        for (context, reason) in cases {
            let error = resolve(&context).err();
            assert!(error.is_some());
            assert!(
                error
                    .and_then(|error| error.detail)
                    .is_some_and(|detail| detail.contains(reason))
            );
        }

        // The legacy wrapper remains callable and intentionally supplies the
        // default context, which this policy rejects as unverifiable.
        let legacy = resolve_bundle(&bundle, None, &catalog, &platform, &policy, &[]);
        assert!(legacy.is_err());
    }
}
