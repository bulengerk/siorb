//! Human-reviewable semantic package catalog and safe local lookup.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use siorb_core::{
    CatalogIdentity, ErrorKind, Result, SiorbError, fingerprint, validate_public_network_host,
};
use unicode_normalization::UnicodeNormalization;
use url::Url;
use walkdir::WalkDir;

const RESERVED: &[&str] = &[
    "install",
    "remove",
    "upgrade",
    "search",
    "info",
    "list",
    "plan",
    "why",
    "doctor",
    "adopt",
    "reconcile",
    "repair",
    "migrate",
    "bundle",
    "pin",
    "unpin",
    "hold",
    "unhold",
    "backend",
    "source",
    "catalog",
    "policy",
    "audit",
    "verify",
    "self",
    "completion",
    "version",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageManifest {
    #[serde(default = "manifest_schema")]
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub deprecated_aliases: Vec<String>,
    #[serde(default)]
    pub search_terms: Vec<String>,
    pub homepage: String,
    #[serde(default)]
    pub upstream: String,
    pub license: String,
    #[serde(default)]
    pub risk: String,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub replacements: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub optional_relationships: Vec<String>,
    #[serde(default)]
    pub version_normalization: String,
    #[serde(default)]
    pub verification: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub reviewed_at: String,
    #[serde(default)]
    pub maintainers: Vec<String>,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub sources: Vec<PackageSource>,
}

const fn manifest_schema() -> String {
    String::new()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageSource {
    pub id: String,
    pub platform: String,
    #[serde(default)]
    pub distributions: Vec<String>,
    pub backend: String,
    pub package_id: String,
    pub trust: String,
    pub scope: String,
    pub channel: String,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub requires_privilege: bool,
    #[serde(default)]
    pub provenance: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub reviewed_at: String,
    #[serde(default)]
    pub verification: Option<ArtifactVerification>,
}

impl PackageSource {
    /// Adapter executable identity used by platform detection.
    #[must_use]
    pub fn tool_backend(&self) -> &str {
        match self.backend.as_str() {
            "homebrew-formula" | "homebrew-cask" => "brew",
            "chocolatey" => "chocolatey",
            value => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactVerification {
    pub sha256: String,
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub kind: ArtifactKind,
    pub format: ArtifactFormat,
    #[serde(default)]
    pub archive_format: Option<String>,
    /// Safe relative path to a typed payload inside a container such as a DMG.
    #[serde(default)]
    pub payload_path: Option<String>,
    #[serde(default)]
    pub strip_components: u32,
    #[serde(default)]
    pub install_arguments: Vec<String>,
    #[serde(default)]
    pub allowed_redirect_hosts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    #[default]
    PortableArchive,
    PortableExecutable,
    NativeInstaller,
}

/// Closed set of direct-artifact formats understood by the executor.
///
/// A catalog cannot introduce an executable format or interpreter by naming a
/// new string: adding a format requires a reviewed code change here and in the
/// executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArtifactFormat {
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "tar")]
    Tar,
    #[serde(rename = "tar.gz")]
    TarGz,
    #[serde(rename = "msi")]
    Msi,
    #[serde(rename = "msix")]
    Msix,
    #[serde(rename = "exe")]
    Exe,
    #[serde(rename = "pkg")]
    Pkg,
    #[serde(rename = "dmg")]
    Dmg,
    #[serde(rename = "deb")]
    Deb,
    #[serde(rename = "rpm")]
    Rpm,
    #[serde(rename = "appimage")]
    AppImage,
}

impl ArtifactFormat {
    #[must_use]
    pub const fn kind(self) -> ArtifactKind {
        match self {
            Self::Zip | Self::Tar | Self::TarGz => ArtifactKind::PortableArchive,
            Self::AppImage => ArtifactKind::PortableExecutable,
            Self::Msi | Self::Msix | Self::Exe | Self::Pkg | Self::Dmg | Self::Deb | Self::Rpm => {
                ArtifactKind::NativeInstaller
            }
        }
    }

    #[must_use]
    pub const fn archive_name(self) -> Option<&'static str> {
        match self {
            Self::Zip => Some("zip"),
            Self::Tar => Some("tar"),
            Self::TarGz => Some("tar.gz"),
            _ => None,
        }
    }

    #[must_use]
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::Msi => "msi",
            Self::Msix => "msix",
            Self::Exe => "exe",
            Self::Pkg => "pkg",
            Self::Dmg => "dmg",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::AppImage => "AppImage",
        }
    }

    /// Whether this format has a strict package-level signer verifier on its
    /// supported host. DEB and RPM remain digest/catalog-authenticated by
    /// default; an explicitly declared RPM signer is still verified.
    #[must_use]
    pub const fn requires_package_signer(self) -> bool {
        matches!(
            self,
            Self::Msi | Self::Msix | Self::Exe | Self::Pkg | Self::Dmg
        )
    }

    #[must_use]
    pub fn supports_platform(self, platform: &str) -> bool {
        match self {
            Self::Zip => matches!(platform, "windows" | "macos"),
            Self::Tar | Self::TarGz => matches!(
                platform,
                "macos" | "linux" | "debian" | "fedora" | "arch" | "opensuse" | "alpine"
            ),
            Self::Msi | Self::Msix | Self::Exe => matches!(platform, "windows"),
            Self::Pkg | Self::Dmg => matches!(platform, "macos"),
            Self::Deb => matches!(platform, "debian"),
            Self::Rpm => matches!(platform, "fedora" | "opensuse"),
            Self::AppImage => matches!(
                platform,
                "linux" | "debian" | "fedora" | "arch" | "opensuse"
            ),
        }
    }

    #[must_use]
    pub fn accepts_content_type(self, content_type: &str) -> bool {
        content_type == "application/octet-stream"
            || match self {
                Self::Zip => content_type == "application/zip",
                Self::Tar => content_type == "application/x-tar",
                Self::TarGz => matches!(content_type, "application/gzip" | "application/x-gzip"),
                Self::Msi => matches!(
                    content_type,
                    "application/x-msi" | "application/x-msdownload-msi"
                ),
                Self::Msix => {
                    matches!(content_type, "application/msix" | "application/vnd.ms-appx")
                }
                Self::Exe => matches!(
                    content_type,
                    "application/vnd.microsoft.portable-executable" | "application/x-msdownload"
                ),
                Self::Pkg => matches!(
                    content_type,
                    "application/vnd.apple.installer+xml" | "application/x-newton-compatible-pkg"
                ),
                Self::Dmg => content_type == "application/x-apple-diskimage",
                Self::Deb => content_type == "application/vnd.debian.binary-package",
                Self::Rpm => matches!(
                    content_type,
                    "application/x-rpm" | "application/x-redhat-package-manager"
                ),
                Self::AppImage => content_type == "application/vnd.appimage",
            }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogDocument {
    #[serde(default = "catalog_schema")]
    pub schema_version: String,
    #[serde(default = "catalog_version")]
    pub catalog_version: u64,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub expires_unix: Option<u64>,
    pub packages: Vec<PackageManifest>,
}

fn catalog_schema() -> String {
    "1.0".to_owned()
}

const fn catalog_version() -> u64 {
    1
}

#[derive(Clone, Debug)]
pub struct Catalog {
    document: CatalogDocument,
    exact: BTreeMap<String, usize>,
    deprecated: BTreeMap<String, usize>,
    identity: CatalogIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub name: String,
    pub description: String,
    pub score: u32,
}

#[derive(Clone, Debug)]
pub enum Lookup<'a> {
    Exact(&'a PackageManifest),
    DeprecatedAlias(&'a PackageManifest),
    Ambiguous(Vec<&'a PackageManifest>),
    Missing,
}

impl Catalog {
    pub fn from_document(
        document: CatalogDocument,
        source: impl Into<String>,
        verified: bool,
    ) -> Result<Self> {
        validate_document(&document)?;
        let mut exact = BTreeMap::new();
        let mut deprecated = BTreeMap::new();
        for (index, package) in document.packages.iter().enumerate() {
            exact.insert(package.id.clone(), index);
            for alias in &package.aliases {
                exact.insert(normalize_identifier(alias)?, index);
            }
            for alias in &package.deprecated_aliases {
                deprecated.insert(normalize_identifier(alias)?, index);
            }
        }
        let identity = CatalogIdentity {
            id: "siorb-main".to_owned(),
            version: document.catalog_version,
            fingerprint: fingerprint(&document),
            verified,
            expires_unix: document.expires_unix,
            source: source.into(),
        };
        Ok(Self {
            document,
            exact,
            deprecated,
            identity,
        })
    }

    pub fn from_json(data: &str, source: impl Into<String>, verified: bool) -> Result<Self> {
        let document: CatalogDocument = serde_json::from_str(data).map_err(|error| {
            SiorbError::new(
                ErrorKind::CatalogFailure,
                "catalog JSON is invalid",
                "Use a catalog generated by `cargo xtask generate-catalog`.",
            )
            .with_reason("catalog.json.invalid")
            .with_detail(error.to_string())
        })?;
        Self::from_document(document, source, verified)
    }

    pub fn from_directory(path: &Path) -> Result<Self> {
        let mut packages = Vec::new();
        let mut paths: Vec<_> = WalkDir::new(path)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(walkdir::DirEntry::into_path)
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "toml")
            })
            .collect();
        paths.sort();
        for manifest_path in paths {
            let content = fs::read_to_string(&manifest_path).map_err(|error| {
                SiorbError::new(
                    ErrorKind::CatalogFailure,
                    format!("cannot read catalog manifest {}", manifest_path.display()),
                    "Check catalog file permissions.",
                )
                .with_reason("catalog.manifest.read")
                .with_detail(error.to_string())
            })?;
            let package: PackageManifest = toml::from_str(&content).map_err(|error| {
                SiorbError::new(
                    ErrorKind::CatalogFailure,
                    format!("invalid catalog manifest {}", manifest_path.display()),
                    "Fix the reported TOML value and run `cargo xtask test-catalog`.",
                )
                .with_reason("catalog.manifest.invalid")
                .with_detail(error.to_string())
            })?;
            packages.push(package);
        }
        Self::from_document(
            CatalogDocument {
                schema_version: "1.0".to_owned(),
                catalog_version: 1,
                generated_at: String::new(),
                expires_unix: None,
                packages,
            },
            path.display().to_string(),
            false,
        )
    }

    /// Catalog embedded at compile time; no network or owner service is required.
    pub fn bundled() -> Result<Self> {
        Self::from_json(
            include_str!("../../../catalog/generated/catalog.json"),
            "bundled",
            true,
        )
    }

    #[must_use]
    pub const fn identity(&self) -> &CatalogIdentity {
        &self.identity
    }

    /// Attach the expiry of the authenticated metadata envelope to a catalog.
    ///
    /// Catalog payloads intentionally do not self-assert their trust lifetime;
    /// callers that verified a signed repository use this to expose the
    /// shortest authenticated expiry in status and policy decisions.
    #[must_use]
    pub fn with_authenticated_expiry(mut self, expires_unix: u64) -> Self {
        self.identity.expires_unix = Some(
            self.identity
                .expires_unix
                .map_or(expires_unix, |catalog_expiry| {
                    catalog_expiry.min(expires_unix)
                }),
        );
        self
    }

    #[must_use]
    pub fn packages(&self) -> &[PackageManifest] {
        &self.document.packages
    }

    #[must_use]
    pub fn source_count(&self) -> usize {
        self.document
            .packages
            .iter()
            .map(|package| package.sources.len())
            .sum()
    }

    pub fn lookup(&self, request: &str) -> Result<Lookup<'_>> {
        let normalized = normalize_identifier(request)?;
        if let Some(index) = self.exact.get(&normalized) {
            return Ok(Lookup::Exact(&self.document.packages[*index]));
        }
        if let Some(index) = self.deprecated.get(&normalized) {
            return Ok(Lookup::DeprecatedAlias(&self.document.packages[*index]));
        }
        let hits = self.search(request, 5)?;
        let plausible: Vec<_> = hits
            .iter()
            .filter(|hit| hit.score >= 700)
            .filter_map(|hit| self.exact.get(&hit.id))
            .map(|index| &self.document.packages[*index])
            .collect();
        if plausible.len() > 1 {
            return Ok(Lookup::Ambiguous(plausible));
        }
        Ok(Lookup::Missing)
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let normalized = normalize_search(query)?;
        let query_tokens: Vec<_> = normalized.split_whitespace().collect();
        let mut hits = Vec::new();
        for package in &self.document.packages {
            let mut score = 0_u32;
            if package.id == normalized {
                score += 1_000;
            } else if package.id.starts_with(&normalized) {
                score += 750;
            } else if package.id.contains(&normalized) {
                score += 500;
            }
            let name = normalize_search(&package.name)?;
            if name == normalized {
                score += 900;
            } else if name.contains(&normalized) {
                score += 450;
            }
            for alias in &package.aliases {
                let alias = normalize_search(alias)?;
                if alias == normalized {
                    score += 850;
                } else if alias.contains(&normalized) {
                    score += 350;
                }
            }
            let searchable = normalize_search(&format!(
                "{} {} {}",
                package.description,
                package.categories.join(" "),
                package.search_terms.join(" ")
            ))?;
            for token in &query_tokens {
                if searchable.split_whitespace().any(|word| word == *token) {
                    score += 100;
                } else if searchable.contains(token) {
                    score += 30;
                }
            }
            if score > 0 {
                hits.push(SearchHit {
                    id: package.id.clone(),
                    name: package.name.clone(),
                    description: package.description.clone(),
                    score,
                });
            }
        }
        hits.sort_by(|left, right| right.score.cmp(&left.score).then(left.id.cmp(&right.id)));
        hits.truncate(limit);
        Ok(hits)
    }
}

pub fn validate_document(document: &CatalogDocument) -> Result<()> {
    if document.schema_version != "1" && document.schema_version != "1.0" {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            format!("unsupported catalog schema {}", document.schema_version),
            "Use catalog schema 1.0.",
        )
        .with_reason("catalog.schema.unsupported"));
    }
    let mut identities = BTreeMap::<String, String>::new();
    let mut source_ids = BTreeSet::new();
    for package in &document.packages {
        let canonical = normalize_identifier(&package.id)?;
        if canonical != package.id {
            return Err(catalog_error(
                "catalog.id.noncanonical",
                format!("package id `{}` is not canonical", package.id),
            ));
        }
        if RESERVED.contains(&canonical.as_str()) {
            return Err(catalog_error(
                "catalog.id.reserved",
                format!("package id `{canonical}` shadows a command"),
            ));
        }
        register_identity(&mut identities, &canonical, &package.id)?;
        for alias in package.aliases.iter().chain(&package.deprecated_aliases) {
            let normalized = normalize_identifier(alias)?;
            if RESERVED.contains(&normalized.as_str()) {
                return Err(catalog_error(
                    "catalog.alias.reserved",
                    format!("alias `{alias}` shadows a command"),
                ));
            }
            register_identity(&mut identities, &normalized, &package.id)?;
        }
        if package.name.trim().is_empty()
            || package.description.trim().is_empty()
            || package.homepage.trim().is_empty()
            || package.license.trim().is_empty()
        {
            return Err(catalog_error(
                "catalog.metadata.missing",
                format!("package `{}` lacks required metadata", package.id),
            ));
        }
        if package.sources.is_empty() {
            return Err(catalog_error(
                "catalog.sources.empty",
                format!("package `{}` has no sources", package.id),
            ));
        }
        for source in &package.sources {
            validate_source(package, source)?;
            if !source_ids.insert(source.id.clone()) {
                return Err(catalog_error(
                    "catalog.source.duplicate",
                    format!("duplicate source id `{}`", source.id),
                ));
            }
        }
    }
    Ok(())
}

fn register_identity(
    identities: &mut BTreeMap<String, String>,
    identity: &str,
    package: &str,
) -> Result<()> {
    if let Some(existing) = identities.insert(identity.to_owned(), package.to_owned()) {
        if existing != package {
            return Err(catalog_error(
                "catalog.alias.collision",
                format!("identity `{identity}` maps to both `{existing}` and `{package}`"),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_source(package: &PackageManifest, source: &PackageSource) -> Result<()> {
    const PLATFORMS: &[&str] = &[
        "windows", "macos", "linux", "debian", "fedora", "arch", "opensuse", "alpine",
    ];
    const BACKENDS: &[&str] = &[
        "winget",
        "scoop",
        "chocolatey",
        "homebrew-formula",
        "homebrew-cask",
        "macports",
        "apt",
        "dnf",
        "pacman",
        "zypper",
        "apk",
        "flatpak",
        "snap",
        "artifact",
    ];
    if source.id.is_empty() || source.package_id.is_empty() || source.package_id.starts_with('-') {
        return Err(catalog_error(
            "catalog.source.identifier",
            format!("package `{}` has an unsafe source identifier", package.id),
        ));
    }
    if source.package_id.chars().any(char::is_control) {
        return Err(catalog_error(
            "catalog.source.control_character",
            format!("source `{}` contains a control character", source.id),
        ));
    }
    if !PLATFORMS.contains(&source.platform.as_str())
        || !BACKENDS.contains(&source.backend.as_str())
    {
        return Err(catalog_error(
            "catalog.source.unsupported",
            format!("source `{}` has unsupported platform or backend", source.id),
        ));
    }
    if !["native", "sandboxed", "verified-upstream"].contains(&source.trust.as_str())
        || !["user", "system", "auto"].contains(&source.scope.as_str())
        || !["stable", "beta", "nightly"].contains(&source.channel.as_str())
    {
        return Err(catalog_error(
            "catalog.source.enum",
            format!("source `{}` has an invalid trust/scope/channel", source.id),
        ));
    }
    if source.backend == "artifact" {
        let artifact_url = Url::parse(&source.package_id).map_err(|error| {
            catalog_error(
                "catalog.artifact.url",
                format!(
                    "artifact source `{}` has an invalid URL: {error}",
                    source.id
                ),
            )
        })?;
        let artifact_host = artifact_url
            .host_str()
            .and_then(|host| validate_public_network_host(host).ok());
        if artifact_url.scheme() != "https"
            || artifact_host.is_none()
            || !artifact_url.username().is_empty()
            || artifact_url.password().is_some()
            || artifact_url.fragment().is_some()
        {
            return Err(catalog_error(
                "catalog.artifact.url",
                format!(
                    "artifact source `{}` must use credential-free HTTPS",
                    source.id
                ),
            ));
        }
        let verification = source.verification.as_ref().ok_or_else(|| {
            catalog_error(
                "catalog.artifact.unverified",
                format!(
                    "artifact source `{}` has no verification material",
                    source.id
                ),
            )
        })?;
        if verification.sha256.len() != 64
            || !verification
                .sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(catalog_error(
                "catalog.artifact.digest",
                format!("artifact source `{}` has an invalid SHA-256", source.id),
            ));
        }
        if verification
            .max_bytes
            .is_none_or(|size| size == 0 || size > 16 * 1024 * 1024 * 1024)
            || verification
                .content_type
                .as_ref()
                .is_none_or(|value| !value.contains('/') || value.chars().any(char::is_control))
        {
            return Err(catalog_error(
                "catalog.artifact.bounds",
                format!(
                    "artifact source `{}` lacks bounded size or content type",
                    source.id
                ),
            ));
        }
        if verification.kind != verification.format.kind() {
            return Err(catalog_error(
                "catalog.artifact.kind_format",
                format!(
                    "artifact source `{}` has a kind that does not match its typed format",
                    source.id
                ),
            ));
        }
        if !verification.format.supports_platform(&source.platform) {
            return Err(catalog_error(
                "catalog.artifact.platform_format",
                format!(
                    "artifact source `{}` uses a format unsupported on `{}`",
                    source.id, source.platform
                ),
            ));
        }
        if !verification
            .format
            .accepts_content_type(verification.content_type.as_deref().unwrap_or_default())
        {
            return Err(catalog_error(
                "catalog.artifact.content_type",
                format!(
                    "artifact source `{}` has a content type that does not match its format",
                    source.id
                ),
            ));
        }
        match verification.kind {
            ArtifactKind::PortableArchive => {
                if verification.archive_format.as_deref() != verification.format.archive_name() {
                    return Err(catalog_error(
                        "catalog.artifact.archive_format",
                        format!("artifact source `{}` has no safe archive format", source.id),
                    ));
                }
                if !verification.install_arguments.is_empty()
                    || verification.strip_components > 16
                    || verification.payload_path.is_some()
                {
                    return Err(catalog_error(
                        "catalog.artifact.archive_recipe",
                        format!(
                            "artifact source `{}` has an unsafe archive recipe",
                            source.id
                        ),
                    ));
                }
            }
            ArtifactKind::PortableExecutable => {
                if verification.format != ArtifactFormat::AppImage
                    || verification.archive_format.is_some()
                    || verification.payload_path.is_some()
                    || verification.strip_components != 0
                    || !verification.install_arguments.is_empty()
                {
                    return Err(catalog_error(
                        "catalog.artifact.portable_executable_recipe",
                        format!(
                            "artifact source `{}` has an unsafe portable executable recipe",
                            source.id
                        ),
                    ));
                }
            }
            ArtifactKind::NativeInstaller => {
                let signer_required = verification.format.requires_package_signer();
                if (signer_required && verification.signer.as_deref().is_none_or(str::is_empty))
                    || verification.archive_format.is_some()
                    || verification.strip_components != 0
                    || (verification.format == ArtifactFormat::Dmg
                        && verification.payload_path.as_deref().is_none_or(|path| {
                            !is_safe_payload_path(path)
                                || !path.to_ascii_lowercase().ends_with(".pkg")
                        }))
                    || (verification.format != ArtifactFormat::Dmg
                        && verification.payload_path.is_some())
                    || !installer_arguments_allowed(
                        verification.format,
                        &verification.install_arguments,
                    )
                {
                    return Err(catalog_error(
                        "catalog.artifact.installer_recipe",
                        format!(
                            "artifact source `{}` has an unsafe installer recipe",
                            source.id
                        ),
                    ));
                }
            }
        }
        for host in &verification.allowed_redirect_hosts {
            if validate_public_network_host(host).is_err() {
                return Err(catalog_error(
                    "catalog.artifact.redirect_host",
                    format!(
                        "artifact source `{}` has an unsafe redirect host",
                        source.id
                    ),
                ));
            }
        }
    }
    if source.evidence.trim().is_empty() || source.reviewed_at.trim().is_empty() {
        return Err(catalog_error(
            "catalog.source.evidence",
            format!("source `{}` lacks review evidence", source.id),
        ));
    }
    Ok(())
}

fn is_safe_payload_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with(['/', '\\'])
        && !value.contains('\\')
        && value.split('/').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && component.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "+-._ ".contains(character)
                })
        })
}

fn installer_arguments_allowed(format: ArtifactFormat, arguments: &[String]) -> bool {
    if arguments.len() > 4 {
        return false;
    }
    let mut seen = BTreeSet::new();
    arguments.iter().all(|argument| {
        let allowed = format == ArtifactFormat::Exe
            && matches!(
                argument.as_str(),
                "/S" | "/silent" | "/verysilent" | "/quiet" | "/norestart" | "--silent" | "--quiet"
            );
        allowed && seen.insert(argument.to_ascii_lowercase())
    })
}

fn catalog_error(reason: &str, message: String) -> SiorbError {
    SiorbError::new(
        ErrorKind::CatalogFailure,
        message,
        "Fix the catalog source and run `cargo xtask test-catalog`.",
    )
    .with_reason(reason)
}

pub fn normalize_identifier(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if !trimmed.is_ascii() {
        return Err(SiorbError::new(
            ErrorKind::InvalidInput,
            format!("`{input}` is not a safe package identifier"),
            "Use the exact ASCII canonical id shown by `siorb search`.",
        )
        .with_reason("input.identifier.confusable"));
    }
    let normalized: String = trimmed.nfkc().collect::<String>().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 80
        || normalized.starts_with('-')
        || normalized.ends_with('-')
        || !normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-._".contains(character))
    {
        return Err(SiorbError::new(
            ErrorKind::InvalidInput,
            format!("`{input}` is not a safe package identifier"),
            "Use an exact ASCII package name or run `siorb search`.",
        )
        .with_reason("input.identifier.unsafe"));
    }
    Ok(normalized)
}

fn normalize_search(input: &str) -> Result<String> {
    let value: String = input.trim().nfkc().collect::<String>().to_ascii_lowercase();
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(SiorbError::new(
            ErrorKind::InvalidInput,
            "search query is empty or unsafe",
            "Use a printable query of at most 200 characters.",
        )
        .with_reason("input.search.unsafe"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn artifact_catalog(url: &str, redirect_hosts: &[&str]) -> Result<Catalog> {
        let document = serde_json::json!({
            "schema_version": "1.0",
            "catalog_version": 1,
            "packages": [{
                "schema_version": "1.0",
                "id": "example",
                "name": "Example",
                "description": "Example artifact",
                "homepage": "https://example.org/",
                "license": "MIT",
                "sources": [{
                    "id": "example-artifact",
                    "platform": "linux",
                    "backend": "artifact",
                    "package_id": url,
                    "trust": "verified-upstream",
                    "scope": "user",
                    "channel": "stable",
                    "architectures": ["x86_64"],
                    "provenance": "signed-release",
                    "evidence": "https://example.org/releases",
                    "reviewed_at": "2026-07-13",
                    "verification": {
                        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "content_type": "application/gzip",
                        "max_bytes": 1024,
                        "kind": "portable-archive",
                        "format": "tar.gz",
                        "archive_format": "tar.gz",
                        "allowed_redirect_hosts": redirect_hosts
                    }
                }]
            }]
        });
        Catalog::from_json(&document.to_string(), "test", true)
    }

    #[test]
    fn unicode_confusable_is_not_an_install_identifier() {
        assert!(normalize_identifier("fіrefox").is_err()); // Cyrillic i.
    }

    #[test]
    fn option_like_identifier_is_rejected() {
        assert!(normalize_identifier("--help").is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn safe_ascii_identifier_normalization_is_idempotent(
            value in "[A-Za-z0-9][A-Za-z0-9+._-]{0,39}"
        ) {
            prop_assume!(!value.ends_with('-'));
            let expected = value.to_ascii_lowercase();
            let decorated = format!(" \t{value}\n");
            let first = normalize_identifier(&decorated);
            prop_assert_eq!(
                first.as_ref().ok().map(String::as_str),
                Some(expected.as_str())
            );
            let normalized = first.unwrap_or_default();
            let second = normalize_identifier(&normalized);
            prop_assert_eq!(
                second.as_ref().ok().map(String::as_str),
                Some(normalized.as_str())
            );
        }
    }

    #[test]
    fn artifact_formats_are_closed_and_platform_specific() {
        assert_eq!(ArtifactFormat::Msi.kind(), ArtifactKind::NativeInstaller);
        assert_eq!(
            ArtifactFormat::AppImage.kind(),
            ArtifactKind::PortableExecutable
        );
        assert!(ArtifactFormat::Msi.supports_platform("windows"));
        assert!(!ArtifactFormat::Msi.supports_platform("debian"));
        assert!(ArtifactFormat::AppImage.supports_platform("fedora"));
        assert!(!ArtifactFormat::AppImage.supports_platform("alpine"));
        assert!(ArtifactFormat::Deb.accepts_content_type("application/vnd.debian.binary-package"));
        assert!(!ArtifactFormat::Deb.accepts_content_type("text/html"));
    }

    #[test]
    fn native_installer_arguments_are_an_exact_allowlist() {
        assert!(installer_arguments_allowed(
            ArtifactFormat::Exe,
            &["/quiet".to_owned(), "/norestart".to_owned()]
        ));
        assert!(!installer_arguments_allowed(
            ArtifactFormat::Exe,
            &["/quiet;calc.exe".to_owned()]
        ));
        assert!(!installer_arguments_allowed(
            ArtifactFormat::Msi,
            &["/quiet".to_owned()]
        ));
    }

    #[test]
    fn dmg_payload_paths_cannot_escape_the_mount() {
        assert!(is_safe_payload_path("Packages/Example.pkg"));
        assert!(!is_safe_payload_path("../Example.pkg"));
        assert!(!is_safe_payload_path("Packages\\Example.pkg"));
        assert!(!is_safe_payload_path("/tmp/Example.pkg"));
    }

    #[test]
    fn artifact_catalog_rejects_non_public_network_hosts() {
        for url in [
            "https://localhost/tool.tar.gz",
            "https://127.0.0.1/tool.tar.gz",
            "https://10.0.0.1/tool.tar.gz",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/tool.tar.gz",
        ] {
            assert!(artifact_catalog(url, &[]).is_err(), "{url}");
        }
        assert!(
            artifact_catalog("https://downloads.example.org/tool.tar.gz", &["127.0.0.1"]).is_err()
        );
        assert!(
            artifact_catalog(
                "https://downloads.example.org/tool.tar.gz",
                &["cdn.example.org"]
            )
            .is_ok()
        );
    }
}
