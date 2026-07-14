//! Deterministic, explainable catalog resolution.

use std::cmp::Reverse;
use std::fmt::{self, Display};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use siorb_catalog::{Catalog, Lookup, PackageManifest, PackageSource};
use siorb_core::{
    Architecture, ErrorKind, InstalledPackage, Operation, PlatformContext, Result, Scope,
    SiorbError,
};
use siorb_policy::{LayeredPolicy, PolicyDecision, PolicyEvaluationContext, parse_scope};

#[derive(Clone, Debug, Default)]
pub struct ResolveOptions {
    pub via: Option<String>,
    pub source: Option<String>,
    pub scope: Scope,
    pub channel: String,
    pub version: Option<String>,
    pub architecture: Option<Architecture>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResolutionContext {
    pub dry_run: bool,
    pub now_unix: Option<u64>,
    /// Supplemental endpoints used by native backends. Artifact candidates
    /// always derive their endpoint from their own catalog source so one
    /// candidate cannot be rejected because of another candidate's URL.
    pub network_urls: Vec<String>,
}

/// Parsed, bounded version constraint shared by resolution, planning and
/// backend adapters. It deliberately uses semantic constraints only; native
/// adapters must reject ranges they cannot express instead of silently
/// dropping them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionConstraint {
    raw: String,
    requirement: Option<VersionReq>,
    exact: Option<String>,
}

impl VersionConstraint {
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        if raw.is_empty()
            || raw.len() > 128
            || !raw.is_ascii()
            || raw.chars().any(|character| {
                character.is_control()
                    || !(character.is_ascii_alphanumeric() || ".,+-:<>=^~*_xX ".contains(character))
            })
        {
            return Err(version_error(input));
        }
        let compact: String = raw
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if compact.is_empty() || compact.split(',').any(str::is_empty) {
            return Err(version_error(input));
        }
        let exact = exact_constraint(&compact).map(str::to_owned);
        let requirement = if let Some(exact) = &exact {
            normalize_version(exact)
                .map(|normalized| VersionReq::parse(&format!("={normalized}")))
                .transpose()
                .map_err(|_| version_error(input))?
        } else {
            let requirement_input = compact
                .split(',')
                .map(|part| {
                    part.strip_prefix("==")
                        .map_or_else(|| part.to_owned(), |v| format!("={v}"))
                })
                .collect::<Vec<_>>()
                .join(",");
            Some(VersionReq::parse(&requirement_input).map_err(|_| version_error(input))?)
        };
        Ok(Self {
            raw: compact,
            requirement,
            exact,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub fn exact(&self) -> Option<&str> {
        self.exact.as_deref()
    }

    #[must_use]
    pub fn matches(&self, observed: &str) -> bool {
        if let Some(exact) = self.exact() {
            return match (
                self.requirement.as_ref(),
                normalize_version(observed).and_then(|version| Version::parse(&version).ok()),
            ) {
                (Some(requirement), Some(observed)) => requirement.matches(&observed),
                _ => exact == observed,
            };
        }
        let Some(requirement) = self.requirement.as_ref() else {
            return false;
        };
        semantic_versions(observed)
            .into_iter()
            .any(|observed| requirement.matches(&observed))
    }
}

fn semantic_versions(value: &str) -> Vec<Version> {
    let mut versions = Vec::new();
    if let Some(version) = normalize_version(value).and_then(|value| Version::parse(&value).ok()) {
        versions.push(version);
    }
    if let Some((base, revision)) = value.rsplit_once('-') {
        if !revision.is_empty()
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        {
            if let Some(version) =
                normalize_version(base).and_then(|value| Version::parse(&value).ok())
            {
                if !versions.contains(&version) {
                    versions.push(version);
                }
            }
        }
    }
    versions
}

impl Display for VersionConstraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.raw)
    }
}

fn exact_constraint(value: &str) -> Option<&str> {
    if value.contains(',') || value.contains(['*', 'x', 'X']) {
        return None;
    }
    if let Some(value) = value.strip_prefix("==").or_else(|| value.strip_prefix('=')) {
        return (!value.is_empty()).then_some(value);
    }
    if value.starts_with(['<', '>', '^', '~']) {
        return None;
    }
    is_safe_exact_version(value).then_some(value)
}

fn is_safe_exact_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".+~:_-".contains(character))
}

fn normalize_version(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches(['v', 'V']);
    let split = value.find(['-', '+']);
    let (base, suffix) = split.map_or((value, ""), |index| value.split_at(index));
    let mut pieces: Vec<&str> = base.split('.').collect();
    if pieces.is_empty()
        || pieces.len() > 3
        || pieces
            .iter()
            .any(|piece| piece.is_empty() || !piece.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    while pieces.len() < 3 {
        pieces.push("0");
    }
    let normalized = format!("{}{}", pieces.join("."), suffix);
    Version::parse(&normalized).ok().map(|_| normalized)
}

fn version_error(input: &str) -> SiorbError {
    SiorbError::new(
        ErrorKind::InvalidInput,
        format!("invalid version constraint `{input}`"),
        "Use a semantic constraint such as `=1.2.3` or `>=1,<2`.",
    )
    .with_reason("version.constraint.invalid")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rejection {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateEvaluation {
    pub source: PackageSource,
    pub accepted: bool,
    pub rank: Option<Rank>,
    pub rejections: Vec<Rejection>,
    pub policy: PolicyDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Rank {
    pub explicit_source: u8,
    pub explicit_backend: u8,
    pub policy_preference: Reverse<usize>,
    pub trust: u8,
    pub catalog_priority: Reverse<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolution {
    pub request: String,
    pub canonical_id: String,
    pub package_name: String,
    pub selected: Option<PackageSource>,
    pub evaluations: Vec<CandidateEvaluation>,
    pub installed: Option<InstalledPackage>,
    pub requested_version: Option<String>,
    pub warnings: Vec<String>,
}

impl Resolution {
    pub fn require_selected(&self) -> Result<&PackageSource> {
        self.selected.as_ref().ok_or_else(|| {
            let detail = self
                .evaluations
                .iter()
                .flat_map(|evaluation| {
                    evaluation.rejections.iter().map(move |rejection| {
                        format!("{}: {}", evaluation.source.id, rejection.code)
                    })
                })
                .collect::<Vec<_>>()
                .join(", ");
            SiorbError::new(
                ErrorKind::UnresolvedPackage,
                format!("no compatible source resolves `{}`", self.request),
                "Inspect `siorb why`, install a supported backend, or adjust permitted constraints.",
            )
            .with_reason("resolution.no_candidate")
            .with_detail(detail)
        })
    }
}

pub struct Resolver<'a> {
    catalog: &'a Catalog,
    platform: &'a PlatformContext,
    policy: &'a LayeredPolicy,
    installed: &'a [InstalledPackage],
}

impl std::fmt::Debug for Resolver<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Resolver")
            .field("catalog", self.catalog.identity())
            .field("platform", self.platform)
            .field("policy", self.policy.identity())
            .field("installed_count", &self.installed.len())
            .finish()
    }
}

impl<'a> Resolver<'a> {
    #[must_use]
    pub const fn new(
        catalog: &'a Catalog,
        platform: &'a PlatformContext,
        policy: &'a LayeredPolicy,
        installed: &'a [InstalledPackage],
    ) -> Self {
        Self {
            catalog,
            platform,
            policy,
            installed,
        }
    }

    pub fn resolve(
        &self,
        request: &str,
        operation: Operation,
        options: &ResolveOptions,
    ) -> Result<Resolution> {
        self.resolve_with_context(request, operation, options, &ResolutionContext::default())
    }

    pub fn resolve_with_context(
        &self,
        request: &str,
        operation: Operation,
        options: &ResolveOptions,
        context: &ResolutionContext,
    ) -> Result<Resolution> {
        if let Some(version) = options.version.as_deref() {
            VersionConstraint::parse(version)?;
        }
        let (package, mut warnings) = match self.catalog.lookup(request)? {
            Lookup::Exact(package) => (package, Vec::new()),
            Lookup::DeprecatedAlias(package) => (
                package,
                vec![format!(
                    "`{request}` is deprecated; use `{}` instead",
                    package.id
                )],
            ),
            Lookup::Ambiguous(packages) => {
                return Err(SiorbError::new(
                    ErrorKind::AmbiguousPackage,
                    format!(
                        "`{request}` is ambiguous: {}",
                        packages
                            .iter()
                            .map(|package| package.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    "Select an exact canonical package id.",
                )
                .with_reason("resolution.package.ambiguous"));
            }
            Lookup::Missing => {
                return Err(SiorbError::new(
                    ErrorKind::UnresolvedPackage,
                    format!("catalog has no exact package or alias `{request}`"),
                    "Run `siorb search` and choose an exact result.",
                )
                .with_reason("resolution.package.missing"));
            }
        };
        if package.deprecated {
            warnings.push(format!("package `{}` is deprecated", package.id));
        }
        let installed = self
            .installed
            .iter()
            .find(|value| value.logical_id == package.id)
            .cloned();
        let mut effective_options = options.clone();
        if effective_options.version.is_none()
            && matches!(
                operation,
                Operation::Install | Operation::Upgrade | Operation::Repair
            )
        {
            effective_options.version = installed.as_ref().and_then(|value| value.pinned.clone());
        }
        if let Some(version) = effective_options.version.as_deref() {
            VersionConstraint::parse(version)?;
        }
        let mut evaluations: Vec<_> = package
            .sources
            .iter()
            .cloned()
            .map(|source| {
                self.evaluate(
                    package,
                    source,
                    operation,
                    &effective_options,
                    context,
                    installed.as_ref(),
                )
            })
            .collect();
        evaluations.sort_by(|left, right| left.source.id.cmp(&right.source.id));

        let selected_index = evaluations
            .iter()
            .enumerate()
            .filter(|(_, evaluation)| evaluation.accepted)
            .max_by(|(_, left), (_, right)| {
                left.rank
                    .cmp(&right.rank)
                    .then_with(|| right.source.id.cmp(&left.source.id))
            })
            .map(|(index, _)| index);
        let selected = selected_index.map(|index| evaluations[index].source.clone());
        Ok(Resolution {
            request: request.to_owned(),
            canonical_id: package.id.clone(),
            package_name: package.name.clone(),
            selected,
            evaluations,
            installed,
            requested_version: effective_options.version,
            warnings,
        })
    }

    fn evaluate(
        &self,
        package: &PackageManifest,
        source: PackageSource,
        operation: Operation,
        options: &ResolveOptions,
        context: &ResolutionContext,
        installed: Option<&InstalledPackage>,
    ) -> CandidateEvaluation {
        let policy_context = candidate_policy_context(&source, options, context, installed);
        let policy =
            self.policy
                .evaluate_with_context(package, &source, operation, &policy_context);
        let mut rejections = Vec::new();
        if !platform_matches(self.platform, &source.platform, &source.distributions) {
            reject(
                &mut rejections,
                "candidate.platform.mismatch",
                "source does not support this host platform",
            );
        }
        let architecture = options.architecture.unwrap_or(self.platform.architecture);
        if !source.architectures.is_empty()
            && !source
                .architectures
                .iter()
                .any(|value| Architecture::normalize(value) == architecture)
        {
            reject(
                &mut rejections,
                "candidate.architecture.mismatch",
                "source does not support the selected architecture",
            );
        }
        if source.channel != options.channel {
            reject(
                &mut rejections,
                "candidate.channel.mismatch",
                "source does not provide the selected channel",
            );
        }
        if options.scope != Scope::Auto
            && parse_scope(&source.scope)
                .is_some_and(|scope| scope != Scope::Auto && scope != options.scope)
        {
            reject(
                &mut rejections,
                "candidate.scope.mismatch",
                "source does not support the selected scope",
            );
        }
        if let Some(requested) = &options.source {
            if requested != &source.id {
                reject(
                    &mut rejections,
                    "candidate.source.not_requested",
                    "another exact source was requested",
                );
            }
        }
        if let Some(requested) = &options.via {
            if requested != &source.backend && requested != source.tool_backend() {
                reject(
                    &mut rejections,
                    "candidate.backend.not_requested",
                    "another backend was explicitly requested",
                );
            }
        }
        if source.backend == "artifact" {
            if self.platform.offline {
                reject(
                    &mut rejections,
                    "candidate.artifact.offline",
                    "artifact is unavailable in offline mode unless cached",
                );
            }
        } else if self.platform.backend(source.tool_backend()).is_none() {
            reject(
                &mut rejections,
                "candidate.backend.absent",
                "required backend executable was not detected",
            );
        }
        if !policy.allowed {
            for reason in &policy.reasons {
                reject(&mut rejections, &reason.code, &reason.message);
            }
        }
        if let Some(installed) = installed {
            if installed.held && matches!(operation, Operation::Remove | Operation::Upgrade) {
                reject(
                    &mut rejections,
                    "state.package.held",
                    "package is held in Siorb state",
                );
            }
            if let (Some(pin), Some(requested)) = (&installed.pinned, &options.version) {
                if pin != requested {
                    reject(
                        &mut rejections,
                        "state.package.pinned",
                        "requested version conflicts with the pin",
                    );
                }
            }
        }
        let accepted = rejections.is_empty();
        let rank =
            accepted.then(|| Rank {
                explicit_source: u8::from(options.source.as_deref() == Some(source.id.as_str())),
                explicit_backend: u8::from(options.via.as_deref().is_some_and(|value| {
                    value == source.backend || value == source.tool_backend()
                })),
                policy_preference: Reverse(self.policy.backend_preference(&source.backend)),
                trust: match source.trust.as_str() {
                    "native" => 3,
                    "sandboxed" => 2,
                    "verified-upstream" => 1,
                    _ => 0,
                },
                catalog_priority: Reverse(source.priority),
            });
        CandidateEvaluation {
            source,
            accepted,
            rank,
            rejections,
            policy,
        }
    }
}

fn candidate_policy_context(
    source: &PackageSource,
    options: &ResolveOptions,
    context: &ResolutionContext,
    installed: Option<&InstalledPackage>,
) -> PolicyEvaluationContext {
    let network_urls = if source.backend == "artifact" {
        let mut urls = vec![source.package_id.clone()];
        if let Some(verification) = &source.verification {
            urls.extend(
                verification
                    .allowed_redirect_hosts
                    .iter()
                    .map(|host| format!("https://{host}/")),
            );
        }
        urls
    } else {
        context.network_urls.clone()
    };
    PolicyEvaluationContext {
        dry_run: context.dry_run,
        now_unix: context.now_unix,
        installed_version: installed.and_then(|value| value.version.clone()),
        target_version: options.version.clone(),
        network_urls,
    }
}

fn platform_matches(platform: &PlatformContext, selector: &str, distributions: &[String]) -> bool {
    let os_match = match selector {
        "windows" => platform.os == siorb_core::OsFamily::Windows,
        "macos" => platform.os == siorb_core::OsFamily::Macos,
        "linux" => platform.os == siorb_core::OsFamily::Linux,
        "debian" => linux_family(platform, &["debian", "ubuntu", "linuxmint", "pop"]),
        "fedora" => linux_family(
            platform,
            &["fedora", "rhel", "centos", "rocky", "almalinux"],
        ),
        "arch" => linux_family(platform, &["arch", "manjaro", "endeavouros"]),
        "opensuse" => linux_family(platform, &["opensuse", "suse", "sles"]),
        "alpine" => linux_family(platform, &["alpine"]),
        _ => false,
    };
    os_match
        && (distributions.is_empty()
            || platform
                .distribution
                .as_ref()
                .is_some_and(|id| distributions.contains(id))
            || platform
                .distribution_like
                .iter()
                .any(|id| distributions.contains(id)))
}

fn linux_family(platform: &PlatformContext, family: &[&str]) -> bool {
    platform.os == siorb_core::OsFamily::Linux
        && platform
            .distribution
            .iter()
            .chain(&platform.distribution_like)
            .any(|value| family.contains(&value.as_str()))
}

fn reject(rejections: &mut Vec<Rejection>, code: &str, message: &str) {
    rejections.push(Rejection {
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use siorb_catalog::{ArtifactKind, ArtifactVerification};
    use siorb_policy::PolicyFile;

    #[test]
    fn distribution_is_not_inferred_from_backend() {
        let platform = PlatformContext {
            os: siorb_core::OsFamily::Linux,
            distribution: Some("alpine".to_owned()),
            distribution_like: vec![],
            ..PlatformContext::default()
        };
        assert!(!platform_matches(&platform, "debian", &[]));
        assert!(platform_matches(&platform, "alpine", &[]));
    }

    #[test]
    fn parses_and_matches_typed_constraints() {
        let range = VersionConstraint::parse(">=1,<2");
        assert!(range.is_ok());
        let Some(range) = range.ok() else { return };
        assert!(range.matches("1.9.4"));
        assert!(!range.matches("2.0.0"));
        assert_eq!(range.exact(), None);

        let exact = VersionConstraint::parse("1.2.3");
        assert!(exact.is_ok());
        assert_eq!(
            exact
                .ok()
                .and_then(|value| value.exact().map(str::to_owned)),
            Some("1.2.3".to_owned())
        );

        let native = VersionConstraint::parse("=1:2.3.4-5_amd64");
        assert!(native.is_ok());
        let Some(native) = native.ok() else { return };
        assert!(native.matches("1:2.3.4-5_amd64"));
        assert!(!native.matches("1:2.3.4-4_amd64"));
    }

    #[test]
    fn rejects_malformed_constraint_deterministically() {
        for input in ["", ">=1,,<2", "1;touch", "../1", "1 || 2", "\u{1b}[31m1"] {
            let first = VersionConstraint::parse(input)
                .err()
                .map(|error| error.reason_code);
            let second = VersionConstraint::parse(input)
                .err()
                .map(|error| error.reason_code);
            assert_eq!(first, second);
            assert_eq!(first.as_deref(), Some("version.constraint.invalid"));
        }
    }

    #[test]
    fn artifact_network_policy_is_evaluated_per_candidate() {
        let catalog = Catalog::bundled();
        assert!(catalog.is_ok());
        let Some(catalog) = catalog.ok() else { return };
        let platform = PlatformContext {
            os: siorb_core::OsFamily::Linux,
            ..PlatformContext::default()
        };
        let policy = LayeredPolicy::new(vec![PolicyFile {
            schema_version: "1.0".to_owned(),
            id: "network-boundary".to_owned(),
            network_domains: vec!["allowed.example".to_owned()],
            ..PolicyFile::default()
        }]);
        assert!(policy.is_ok());
        let Some(policy) = policy.ok() else { return };
        let package = PackageManifest {
            schema_version: "1.0".to_owned(),
            id: "candidate-network-test".to_owned(),
            name: "Candidate network test".to_owned(),
            description: "Resolver policy isolation fixture".to_owned(),
            aliases: vec![],
            deprecated_aliases: vec![],
            search_terms: vec![],
            homepage: "https://allowed.example".to_owned(),
            upstream: "allowed.example".to_owned(),
            license: "MIT".to_owned(),
            risk: "standard".to_owned(),
            categories: vec!["developer-tools".to_owned()],
            capabilities: vec![],
            channels: vec!["stable".to_owned()],
            conflicts: vec![],
            replacements: vec![],
            dependencies: vec![],
            optional_relationships: vec![],
            version_normalization: "semver-loose".to_owned(),
            verification: "sha256-and-signer".to_owned(),
            evidence: vec![],
            reviewed_at: "2026-07-13".to_owned(),
            maintainers: vec![],
            deprecated: false,
            sources: vec![],
        };
        let make_source = |id: &str, url: &str| PackageSource {
            id: id.to_owned(),
            platform: "linux".to_owned(),
            distributions: vec![],
            backend: "artifact".to_owned(),
            package_id: url.to_owned(),
            trust: "verified-upstream".to_owned(),
            scope: "user".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec![],
            priority: 0,
            requires_privilege: false,
            provenance: "signed-release".to_owned(),
            evidence: url.to_owned(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: Some(ArtifactVerification {
                sha256: "0".repeat(64),
                signer: Some("trusted.example".to_owned()),
                content_type: Some("application/zip".to_owned()),
                max_bytes: Some(1024),
                kind: ArtifactKind::PortableArchive,
                format: siorb_catalog::ArtifactFormat::Zip,
                archive_format: Some("zip".to_owned()),
                payload_path: None,
                strip_components: 0,
                install_arguments: vec![],
                allowed_redirect_hosts: vec![],
            }),
        };
        let resolver = Resolver::new(&catalog, &platform, &policy, &[]);
        let context = ResolutionContext {
            dry_run: true,
            now_unix: Some(1_783_944_000),
            network_urls: vec![
                "https://allowed.example/tool.zip".to_owned(),
                "https://denied.example/tool.zip".to_owned(),
            ],
        };

        let allowed = resolver.evaluate(
            &package,
            make_source("allowed", "https://allowed.example/tool.zip"),
            Operation::Install,
            &ResolveOptions::default(),
            &context,
            None,
        );
        let denied = resolver.evaluate(
            &package,
            make_source("denied", "https://denied.example/tool.zip"),
            Operation::Install,
            &ResolveOptions::default(),
            &context,
            None,
        );
        let mut redirected = make_source("redirected", "https://allowed.example/tool.zip");
        if let Some(verification) = &mut redirected.verification {
            verification.allowed_redirect_hosts = vec!["denied.example".to_owned()];
        }
        let redirected = resolver.evaluate(
            &package,
            redirected,
            Operation::Install,
            &ResolveOptions::default(),
            &context,
            None,
        );

        assert!(
            !allowed
                .policy
                .reasons
                .iter()
                .any(|reason| reason.code == "policy.network_domain.denied")
        );
        assert!(
            denied
                .policy
                .reasons
                .iter()
                .any(|reason| reason.code == "policy.network_domain.denied")
        );
        assert!(
            redirected
                .policy
                .reasons
                .iter()
                .any(|reason| reason.code == "policy.network_domain.denied")
        );
    }

    proptest! {
        #[test]
        fn exact_constraint_round_trips_deterministically(
            major in 0_u16..1000,
            minor in 0_u16..1000,
            patch in 0_u16..1000,
        ) {
            let input = format!("={major}.{minor}.{patch}");
            let left = VersionConstraint::parse(&input);
            let right = VersionConstraint::parse(&input);
            prop_assert_eq!(left.ok(), right.ok());
        }
    }
}
