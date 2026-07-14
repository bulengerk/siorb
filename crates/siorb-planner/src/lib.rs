//! Immutable, serializable execution plans and pre-execution revalidation.

use serde::{Deserialize, Serialize};
use siorb_backends::{BackendAdapter, CommandSpec, NativeAdapter, PlanOptions as BackendOptions};
use siorb_catalog::Catalog;
use siorb_core::{
    BackendInfo, ErrorKind, Operation, PlatformContext, Result, Scope, SiorbError, fingerprint,
    unix_timestamp,
};
use siorb_policy::LayeredPolicy;
use siorb_resolver::{Resolution, VersionConstraint};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reproducibility {
    FullyReproducible,
    BestEffort,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Backend,
    Download,
    Verify,
    Extract,
    Installer,
    Receipt,
    NoChange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: String,
    pub package: String,
    pub kind: StepKind,
    pub description: String,
    pub command: Option<CommandSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactPlan>,
    pub network_endpoints: Vec<String>,
    pub expected_download_bytes: Option<u64>,
    pub verification_requirements: Vec<String>,
    pub requires_privilege: bool,
    pub agreements: Vec<String>,
    pub destructive: bool,
    pub rollback_hint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactPlan {
    pub operation: Operation,
    pub url: String,
    pub sha256: String,
    pub signer: Option<String>,
    pub content_type: String,
    pub max_bytes: u64,
    pub kind: siorb_catalog::ArtifactKind,
    pub format: siorb_catalog::ArtifactFormat,
    pub archive_format: Option<String>,
    pub payload_path: Option<String>,
    pub strip_components: u32,
    pub install_arguments: Vec<String>,
    pub allowed_redirect_hosts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlannedPackage {
    pub requested: String,
    pub logical_id: String,
    pub source_id: String,
    pub backend: String,
    pub native_id: String,
    pub current_version: Option<String>,
    pub desired_version: Option<String>,
    pub scope: Scope,
    pub channel: String,
    pub architecture: siorb_core::Architecture,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevalidationGuard {
    pub platform_fingerprint: String,
    pub catalog_fingerprint: String,
    pub policy_fingerprint: String,
    pub installed_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub operation: Operation,
    pub requested: Vec<String>,
    pub catalog_fingerprint: String,
    pub platform_fingerprint: String,
    pub policy_fingerprint: Option<String>,
    pub created_at_unix: u64,
    pub reproducibility: Reproducibility,
    pub packages: Vec<PlannedPackage>,
    pub steps: Vec<PlanStep>,
    pub warnings: Vec<String>,
    pub conflicts: Vec<String>,
    pub recovery_guidance: Vec<String>,
    pub revalidation: RevalidationGuard,
}

impl ExecutionPlan {
    #[must_use]
    pub fn changes_machine(&self) -> bool {
        if self.operation == Operation::Verify {
            return false;
        }
        self.steps
            .iter()
            .any(|step| !matches!(step.kind, StepKind::NoChange | StepKind::Verify))
    }

    #[must_use]
    pub fn requires_privilege(&self) -> bool {
        self.steps.iter().any(|step| step.requires_privilege)
    }

    #[must_use]
    pub fn requires_agreements(&self) -> bool {
        self.steps.iter().any(|step| !step.agreements.is_empty())
    }

    pub fn revalidate(
        &self,
        platform: &PlatformContext,
        catalog: &Catalog,
        policy: &LayeredPolicy,
        installed: &[siorb_core::InstalledPackage],
    ) -> Result<()> {
        let current = RevalidationGuard {
            platform_fingerprint: platform.fingerprint(),
            catalog_fingerprint: catalog.identity().fingerprint.clone(),
            policy_fingerprint: policy.identity().fingerprint.clone(),
            installed_fingerprint: fingerprint(&installed),
        };
        if current.platform_fingerprint != self.revalidation.platform_fingerprint {
            return Err(plan_changed("platform facts changed after planning"));
        }
        if current.catalog_fingerprint != self.revalidation.catalog_fingerprint {
            return Err(plan_changed("catalog identity changed after planning"));
        }
        if current.policy_fingerprint != self.revalidation.policy_fingerprint {
            return Err(plan_changed("policy changed after planning"));
        }
        if current.installed_fingerprint != self.revalidation.installed_fingerprint {
            return Err(plan_changed("installed state changed after planning"));
        }
        for step in &self.steps {
            if let Some(command) = &step.command {
                command.validate()?;
                if !std::path::Path::new(&command.executable).is_file() {
                    return Err(plan_changed(&format!(
                        "backend executable {} is no longer available",
                        command.executable
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlanOptions {
    pub non_interactive: bool,
    pub accept_agreements: bool,
    pub target_architecture: siorb_core::Architecture,
}

#[derive(Debug)]
pub struct Planner<'a> {
    platform: &'a PlatformContext,
    catalog: &'a Catalog,
    policy: &'a LayeredPolicy,
    installed: &'a [siorb_core::InstalledPackage],
}

impl<'a> Planner<'a> {
    #[must_use]
    pub const fn new(
        platform: &'a PlatformContext,
        catalog: &'a Catalog,
        policy: &'a LayeredPolicy,
        installed: &'a [siorb_core::InstalledPackage],
    ) -> Self {
        Self {
            platform,
            catalog,
            policy,
            installed,
        }
    }

    pub fn build(
        &self,
        operation: Operation,
        resolutions: &[Resolution],
        options: PlanOptions,
    ) -> Result<ExecutionPlan> {
        if resolutions.is_empty() {
            return Err(SiorbError::new(
                ErrorKind::InvalidInput,
                "the operation has no package arguments",
                "Provide at least one exact logical package id.",
            )
            .with_reason("plan.packages.empty"));
        }
        let mut packages = Vec::new();
        let mut steps = Vec::new();
        let mut warnings = Vec::new();
        for (index, resolution) in resolutions.iter().enumerate() {
            let source = resolution.require_selected()?;
            let installed = resolution.installed.as_ref();
            let scope = parse_scope(&source.scope);
            packages.push(PlannedPackage {
                requested: resolution.request.clone(),
                logical_id: resolution.canonical_id.clone(),
                source_id: source.id.clone(),
                backend: source.backend.clone(),
                native_id: source.package_id.clone(),
                current_version: installed.and_then(|value| value.version.clone()),
                desired_version: resolution.requested_version.clone(),
                scope,
                channel: source.channel.clone(),
                architecture: options.target_architecture,
            });
            warnings.extend(resolution.warnings.clone());

            let no_change = match operation {
                Operation::Install => installed.is_some() && resolution.requested_version.is_none(),
                Operation::Remove => installed.is_none(),
                _ => false,
            };
            if no_change {
                steps.push(PlanStep {
                    id: format!("step-{:04}", index + 1),
                    package: resolution.canonical_id.clone(),
                    kind: StepKind::NoChange,
                    description: match operation {
                        Operation::Install => "package is already present".to_owned(),
                        Operation::Remove => "package has no Siorb receipt".to_owned(),
                        _ => "desired state is already satisfied".to_owned(),
                    },
                    command: None,
                    artifact: None,
                    network_endpoints: Vec::new(),
                    expected_download_bytes: None,
                    verification_requirements: Vec::new(),
                    requires_privilege: false,
                    agreements: Vec::new(),
                    destructive: false,
                    rollback_hint: "No rollback is necessary.".to_owned(),
                });
                continue;
            }
            if source.backend == "artifact" {
                steps.extend(artifact_steps(index, resolution, source, operation)?);
            } else {
                let adapter = NativeAdapter::for_source(source)?;
                let backend = self
                    .platform
                    .backend(source.tool_backend())
                    .ok_or_else(|| {
                        SiorbError::new(
                            ErrorKind::BackendAbsent,
                            format!(
                                "backend `{}` disappeared before planning",
                                source.tool_backend()
                            ),
                            "Install the backend or select another source.",
                        )
                    })?;
                let backend_options = BackendOptions {
                    non_interactive: options.non_interactive,
                    accept_agreements: options.accept_agreements,
                };
                steps.extend(native_steps(
                    index,
                    resolution,
                    source,
                    operation,
                    adapter,
                    backend,
                    backend_options,
                )?);
            }
        }
        let reproducibility = if resolutions.iter().all(|resolution| {
            resolution
                .requested_version
                .as_deref()
                .is_some_and(|version| {
                    VersionConstraint::parse(version)
                        .is_ok_and(|constraint| constraint.exact().is_some())
                })
        }) {
            Reproducibility::FullyReproducible
        } else {
            Reproducibility::BestEffort
        };
        let revalidation = RevalidationGuard {
            platform_fingerprint: self.platform.fingerprint(),
            catalog_fingerprint: self.catalog.identity().fingerprint.clone(),
            policy_fingerprint: self.policy.identity().fingerprint.clone(),
            installed_fingerprint: fingerprint(&self.installed),
        };
        let requested: Vec<_> = resolutions
            .iter()
            .map(|value| value.request.clone())
            .collect();
        let deterministic_material = (
            operation,
            &requested,
            &packages,
            &steps,
            &revalidation,
            reproducibility,
        );
        let plan_id = format!("plan-{}", &fingerprint(&deterministic_material)[..24]);
        Ok(ExecutionPlan {
            schema_version: "1.0".to_owned(),
            plan_id,
            operation,
            requested,
            catalog_fingerprint: self.catalog.identity().fingerprint.clone(),
            platform_fingerprint: self.platform.fingerprint(),
            policy_fingerprint: Some(self.policy.identity().fingerprint.clone()),
            created_at_unix: unix_timestamp(),
            reproducibility,
            packages,
            steps,
            warnings,
            conflicts: Vec::new(),
            recovery_guidance: vec![
                "Run `siorb reconcile` after interruption or partial completion.".to_owned(),
                "Native package managers may not support atomic rollback.".to_owned(),
            ],
            revalidation,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn native_steps(
    index: usize,
    resolution: &Resolution,
    source: &siorb_catalog::PackageSource,
    operation: Operation,
    adapter: NativeAdapter,
    backend: &BackendInfo,
    options: BackendOptions,
) -> Result<Vec<PlanStep>> {
    let version_constraint = resolution
        .requested_version
        .as_deref()
        .map(VersionConstraint::parse)
        .transpose()?;
    let command = if matches!(
        operation,
        Operation::Install | Operation::Upgrade | Operation::Repair
    ) {
        adapter.command_with_version(
            operation,
            backend,
            source,
            options,
            version_constraint.as_ref(),
        )?
    } else {
        adapter.command(operation, backend, source, options)?
    };
    let agreements = if source.backend == "winget"
        && matches!(operation, Operation::Install | Operation::Upgrade)
    {
        vec!["package and source agreements".to_owned()]
    } else {
        Vec::new()
    };
    let base_id = format!("step-{:04}", index + 1);
    let mut steps = vec![PlanStep {
        id: base_id.clone(),
        package: resolution.canonical_id.clone(),
        kind: if operation == Operation::Verify {
            StepKind::Verify
        } else {
            StepKind::Backend
        },
        description: format!("delegate {operation} to {}", source.backend),
        command: Some(command),
        artifact: None,
        network_endpoints: if matches!(operation, Operation::Verify | Operation::Adopt) {
            Vec::new()
        } else {
            vec![format!(
                "{} repository (endpoint managed by backend)",
                source.backend
            )]
        },
        expected_download_bytes: None,
        verification_requirements: vec![source.provenance.clone(), source.evidence.clone()],
        requires_privilege: source.requires_privilege
            && !matches!(operation, Operation::Verify | Operation::Adopt),
        agreements,
        destructive: operation == Operation::Remove,
        rollback_hint: rollback_hint(operation, &resolution.canonical_id),
    }];

    if matches!(
        operation,
        Operation::Install | Operation::Remove | Operation::Upgrade | Operation::Repair
    ) {
        let query = adapter.command(
            Operation::Verify,
            backend,
            source,
            BackendOptions {
                non_interactive: true,
                accept_agreements: false,
            },
        )?;
        if query.network || query.requires_privilege {
            return Err(SiorbError::new(
                ErrorKind::VerificationFailure,
                format!(
                    "backend `{}` produced an unsafe installed-state query",
                    source.backend
                ),
                "Do not execute the plan; inspect and fix the backend adapter.",
            )
            .with_reason("plan.verification.not_read_only"));
        }
        steps.push(PlanStep {
            id: format!("{base_id}-verify"),
            package: resolution.canonical_id.clone(),
            kind: StepKind::Verify,
            description: if operation == Operation::Remove {
                format!("verify package absence through {}", source.backend)
            } else {
                format!(
                    "verify observed installed state and version through {}",
                    source.backend
                )
            },
            command: Some(query),
            artifact: None,
            network_endpoints: Vec::new(),
            expected_download_bytes: None,
            verification_requirements: if operation == Operation::Remove {
                vec![
                    "read-only installed-state query".to_owned(),
                    "backend reports the package is not installed".to_owned(),
                ]
            } else {
                vec![
                    "read-only installed-state query".to_owned(),
                    "observed version satisfies the requested constraint".to_owned(),
                ]
            },
            requires_privilege: false,
            agreements: Vec::new(),
            destructive: false,
            rollback_hint: "Do not commit a receipt when observed state cannot be verified."
                .to_owned(),
        });
    }
    Ok(steps)
}

fn artifact_steps(
    index: usize,
    resolution: &Resolution,
    source: &siorb_catalog::PackageSource,
    operation: Operation,
) -> Result<Vec<PlanStep>> {
    let artifact = source
        .verification
        .as_ref()
        .map(|verification| ArtifactPlan {
            operation,
            url: source.package_id.clone(),
            sha256: verification.sha256.clone(),
            signer: verification.signer.clone(),
            content_type: verification.content_type.clone().unwrap_or_default(),
            max_bytes: verification.max_bytes.unwrap_or_default(),
            kind: verification.kind,
            format: verification.format,
            archive_format: verification.archive_format.clone(),
            payload_path: verification.payload_path.clone(),
            strip_components: verification.strip_components,
            install_arguments: verification.install_arguments.clone(),
            allowed_redirect_hosts: verification.allowed_redirect_hosts.clone(),
        });
    if operation == Operation::Adopt {
        return Err(SiorbError::new(
            ErrorKind::VerificationFailure,
            "direct artifacts cannot be adopted without an exact owned-file receipt",
            "Install the artifact through Siorb or select a native backend with query support.",
        )
        .with_reason("artifact.adopt.unsupported"));
    }
    if operation == Operation::Remove {
        if artifact
            .as_ref()
            .is_some_and(|value| value.kind == siorb_catalog::ArtifactKind::NativeInstaller)
        {
            return Err(SiorbError::new(
                ErrorKind::BackendFailure,
                "native artifact installer has no declarative uninstall identity",
                "Use a native backend mapping or add a separately reviewed uninstall capability.",
            )
            .with_reason("artifact.remove.unsupported"));
        }
        return Ok(vec![PlanStep {
            id: format!("step-{:04}-remove", index + 1),
            package: resolution.canonical_id.clone(),
            kind: StepKind::Extract,
            description: "remove only files owned by the artifact receipt".to_owned(),
            command: None,
            artifact,
            network_endpoints: vec![],
            expected_download_bytes: None,
            verification_requirements: vec!["matching Siorb artifact receipt".to_owned()],
            requires_privilege: false,
            agreements: vec![],
            destructive: true,
            rollback_hint: "Reinstall from a fresh verified artifact plan.".to_owned(),
        }]);
    }
    let requirements = source
        .verification
        .as_ref()
        .map_or_else(Vec::new, |verification| {
            let mut values = vec![format!("sha256:{}", verification.sha256)];
            if let Some(signer) = &verification.signer {
                values.push(format!("signer:{signer}"));
            }
            values
        });
    let mut steps = vec![
        PlanStep {
            id: format!("step-{:04}-download", index + 1),
            package: resolution.canonical_id.clone(),
            kind: StepKind::Download,
            description: "download artifact into an isolated temporary directory".to_owned(),
            command: None,
            artifact: artifact.clone(),
            network_endpoints: vec![source.package_id.clone()],
            expected_download_bytes: source
                .verification
                .as_ref()
                .and_then(|value| value.max_bytes),
            verification_requirements: requirements.clone(),
            requires_privilege: false,
            agreements: vec![],
            destructive: false,
            rollback_hint: "Delete the uncommitted temporary artifact.".to_owned(),
        },
        PlanStep {
            id: format!("step-{:04}-verify", index + 1),
            package: resolution.canonical_id.clone(),
            kind: StepKind::Verify,
            description: "verify digest, signer, type, and archive safety before use".to_owned(),
            command: None,
            artifact: artifact.clone(),
            network_endpoints: vec![],
            expected_download_bytes: None,
            verification_requirements: requirements,
            requires_privilege: false,
            agreements: vec![],
            destructive: false,
            rollback_hint: "Reject and delete the artifact on any mismatch.".to_owned(),
        },
    ];
    if operation != Operation::Verify {
        steps.push(PlanStep {
            id: format!("step-{:04}-install", index + 1),
            package: resolution.canonical_id.clone(),
            kind: match artifact.as_ref().map(|value| value.kind) {
                Some(
                    siorb_catalog::ArtifactKind::PortableArchive
                    | siorb_catalog::ArtifactKind::PortableExecutable,
                ) => StepKind::Extract,
                _ => StepKind::Installer,
            },
            description: "apply the verified declarative artifact recipe".to_owned(),
            command: None,
            artifact,
            network_endpoints: vec![],
            expected_download_bytes: None,
            verification_requirements: vec!["verified bytes from the preceding step".to_owned()],
            requires_privilege: source.requires_privilege,
            agreements: vec![],
            destructive: false,
            rollback_hint: "Remove only files recorded as owned by this artifact receipt."
                .to_owned(),
        });
    }
    Ok(steps)
}

fn rollback_hint(operation: Operation, package: &str) -> String {
    match operation {
        Operation::Install => format!("If safe, review a new `siorb plan remove {package}`."),
        Operation::Remove => {
            format!("Reinstall `{package}` from a newly resolved and reviewed plan.")
        }
        Operation::Upgrade => {
            format!("Downgrade `{package}` only if policy and backend support it.")
        }
        _ => "Re-run verification, then create a fresh recovery plan.".to_owned(),
    }
}

fn parse_scope(value: &str) -> Scope {
    match value {
        "user" => Scope::User,
        "system" => Scope::System,
        _ => Scope::Auto,
    }
}

fn plan_changed(message: &str) -> SiorbError {
    SiorbError::new(
        ErrorKind::VerificationFailure,
        message,
        "Discard the stale plan and resolve again before executing.",
    )
    .with_reason("plan.revalidation.changed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use siorb_catalog::{ArtifactFormat, ArtifactKind, ArtifactVerification, PackageSource};

    fn source() -> PackageSource {
        PackageSource {
            id: "ubuntu-apt".to_owned(),
            platform: "linux".to_owned(),
            distributions: vec!["ubuntu".to_owned()],
            backend: "apt".to_owned(),
            package_id: "ripgrep".to_owned(),
            trust: "native_trusted".to_owned(),
            scope: "system".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec!["x86_64".to_owned()],
            priority: 0,
            requires_privilege: true,
            provenance: "ubuntu-main".to_owned(),
            evidence: "package-index".to_owned(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: None,
        }
    }

    fn resolution(source: &PackageSource) -> Resolution {
        Resolution {
            request: "ripgrep".to_owned(),
            canonical_id: "ripgrep".to_owned(),
            package_name: "ripgrep".to_owned(),
            selected: Some(source.clone()),
            evaluations: Vec::new(),
            installed: None,
            requested_version: Some("=14.1.1".to_owned()),
            warnings: Vec::new(),
        }
    }

    fn backend() -> BackendInfo {
        BackendInfo {
            id: "apt".to_owned(),
            executable: "/usr/bin/apt-get".to_owned(),
            version: Some("test".to_owned()),
            available: true,
            capabilities: vec!["query_installed".to_owned()],
        }
    }

    #[test]
    fn native_mutations_are_followed_by_read_only_observed_state_queries() {
        let source = source();
        let resolution = resolution(&source);
        let adapter = NativeAdapter::for_source(&source);
        assert!(adapter.is_ok());
        let Some(adapter) = adapter.ok() else { return };
        for operation in [Operation::Install, Operation::Upgrade, Operation::Repair] {
            let steps = native_steps(
                0,
                &resolution,
                &source,
                operation,
                adapter,
                &backend(),
                BackendOptions {
                    non_interactive: true,
                    accept_agreements: false,
                },
            );
            assert!(steps.is_ok(), "{operation}");
            let Some(steps) = steps.ok() else { return };
            assert_eq!(steps.len(), 2, "{operation}");
            assert_eq!(steps[0].kind, StepKind::Backend, "{operation}");
            assert_eq!(steps[1].kind, StepKind::Verify, "{operation}");
            assert_eq!(steps[1].id, "step-0001-verify", "{operation}");
            let Some(query) = steps[1].command.as_ref() else {
                return;
            };
            assert!(!query.network, "{operation}");
            assert!(!query.requires_privilege, "{operation}");
        }
    }

    #[test]
    fn requested_target_architecture_is_preserved_in_planned_packages() {
        let source = source();
        let resolution = resolution(&source);
        let platform = PlatformContext {
            backends: vec![backend()],
            ..PlatformContext::default()
        };
        let catalog = Catalog::bundled();
        assert!(catalog.is_ok());
        let Some(catalog) = catalog.ok() else { return };
        let policy = LayeredPolicy::default();
        let installed = Vec::new();
        let planner = Planner::new(&platform, &catalog, &policy, &installed);
        let plan = planner.build(
            Operation::Install,
            &[resolution],
            PlanOptions {
                target_architecture: siorb_core::Architecture::Arm64,
                ..PlanOptions::default()
            },
        );
        assert!(plan.is_ok());
        assert_eq!(
            plan.ok()
                .and_then(|plan| plan.packages.into_iter().next())
                .map(|package| package.architecture),
            Some(siorb_core::Architecture::Arm64)
        );
    }

    #[test]
    fn remove_adds_read_only_absence_verification_while_adopt_stays_single_step() {
        let source = source();
        let resolution = resolution(&source);
        let adapter = NativeAdapter::for_source(&source);
        assert!(adapter.is_ok());
        let Some(adapter) = adapter.ok() else { return };
        let remove = native_steps(
            0,
            &resolution,
            &source,
            Operation::Remove,
            adapter,
            &backend(),
            BackendOptions::default(),
        );
        assert!(remove.is_ok());
        let Some(remove) = remove.ok() else { return };
        assert_eq!(remove.len(), 2);
        assert_eq!(remove[0].kind, StepKind::Backend);
        assert!(remove[0].destructive);
        assert_eq!(remove[1].kind, StepKind::Verify);
        assert!(remove[1].description.contains("absence"));
        assert!(
            remove[1]
                .verification_requirements
                .iter()
                .any(|requirement| requirement.contains("not installed"))
        );
        let Some(query) = remove[1].command.as_ref() else {
            return;
        };
        assert!(!query.network);
        assert!(!query.requires_privilege);

        let adopt = native_steps(
            0,
            &resolution,
            &source,
            Operation::Adopt,
            adapter,
            &backend(),
            BackendOptions::default(),
        );
        assert!(adopt.is_ok());
        let Some(adopt) = adopt.ok() else { return };
        assert_eq!(adopt.len(), 1);
        assert_eq!(adopt[0].kind, StepKind::Backend);
    }

    fn artifact_source(format: ArtifactFormat, kind: ArtifactKind) -> PackageSource {
        let platform = match format {
            ArtifactFormat::Msi | ArtifactFormat::Msix | ArtifactFormat::Exe => "windows",
            ArtifactFormat::Pkg | ArtifactFormat::Dmg | ArtifactFormat::Zip => "macos",
            ArtifactFormat::Deb => "debian",
            ArtifactFormat::Rpm => "fedora",
            ArtifactFormat::AppImage | ArtifactFormat::Tar | ArtifactFormat::TarGz => "linux",
        };
        PackageSource {
            id: "direct-artifact".to_owned(),
            platform: platform.to_owned(),
            distributions: Vec::new(),
            backend: "artifact".to_owned(),
            package_id: "https://downloads.example.org/ripgrep".to_owned(),
            trust: "verified-upstream".to_owned(),
            scope: "user".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec!["x86_64".to_owned()],
            priority: 1,
            requires_privilege: kind == ArtifactKind::NativeInstaller,
            provenance: "signed-upstream-metadata".to_owned(),
            evidence: "https://example.org/releases".to_owned(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: Some(ArtifactVerification {
                sha256: "a".repeat(64),
                signer: (kind == ArtifactKind::NativeInstaller).then(|| "Publisher".to_owned()),
                content_type: Some("application/octet-stream".to_owned()),
                max_bytes: Some(1024),
                kind,
                format,
                archive_format: format.archive_name().map(str::to_owned),
                payload_path: (format == ArtifactFormat::Dmg)
                    .then(|| "Packages/Example.pkg".to_owned()),
                strip_components: 0,
                install_arguments: Vec::new(),
                allowed_redirect_hosts: Vec::new(),
            }),
        }
    }

    #[test]
    fn typed_artifacts_produce_only_closed_executor_steps() {
        let appimage = artifact_source(ArtifactFormat::AppImage, ArtifactKind::PortableExecutable);
        let steps = artifact_steps(0, &resolution(&appimage), &appimage, Operation::Install);
        assert!(steps.is_ok());
        let Some(steps) = steps.ok() else { return };
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[2].kind, StepKind::Extract);
        assert_eq!(
            steps[2].artifact.as_ref().map(|recipe| recipe.format),
            Some(ArtifactFormat::AppImage)
        );

        let deb = artifact_source(ArtifactFormat::Deb, ArtifactKind::NativeInstaller);
        let steps = artifact_steps(0, &resolution(&deb), &deb, Operation::Install);
        assert!(steps.is_ok());
        let Some(steps) = steps.ok() else { return };
        assert_eq!(steps[2].kind, StepKind::Installer);
        assert!(steps[2].requires_privilege);
    }

    fn property_operation(value: u8) -> Operation {
        match value % 7 {
            0 => Operation::Install,
            1 => Operation::Remove,
            2 => Operation::Upgrade,
            3 => Operation::Repair,
            4 => Operation::Adopt,
            5 => Operation::Reconcile,
            _ => Operation::Verify,
        }
    }

    fn property_step_kind(value: u8) -> StepKind {
        match value % 7 {
            0 => StepKind::Backend,
            1 => StepKind::Download,
            2 => StepKind::Verify,
            3 => StepKind::Extract,
            4 => StepKind::Installer,
            5 => StepKind::Receipt,
            _ => StepKind::NoChange,
        }
    }

    fn property_plan(operation: Operation, raw_steps: &[(u8, bool, bool)]) -> ExecutionPlan {
        let steps = raw_steps
            .iter()
            .enumerate()
            .map(|(index, (kind, privileged, agreement))| PlanStep {
                id: format!("step-{index:04}"),
                package: "fixture".to_owned(),
                kind: property_step_kind(*kind),
                description: "property fixture".to_owned(),
                command: None,
                artifact: None,
                network_endpoints: Vec::new(),
                expected_download_bytes: None,
                verification_requirements: Vec::new(),
                requires_privilege: *privileged,
                agreements: if *agreement {
                    vec!["fixture-agreement".to_owned()]
                } else {
                    Vec::new()
                },
                destructive: false,
                rollback_hint: "fixture".to_owned(),
            })
            .collect();
        ExecutionPlan {
            schema_version: "1.0".to_owned(),
            plan_id: "plan-property".to_owned(),
            operation,
            requested: vec!["fixture".to_owned()],
            catalog_fingerprint: "catalog".to_owned(),
            platform_fingerprint: "platform".to_owned(),
            policy_fingerprint: Some("policy".to_owned()),
            created_at_unix: 0,
            reproducibility: Reproducibility::FullyReproducible,
            packages: Vec::new(),
            steps,
            warnings: Vec::new(),
            conflicts: Vec::new(),
            recovery_guidance: Vec::new(),
            revalidation: RevalidationGuard {
                platform_fingerprint: "platform".to_owned(),
                catalog_fingerprint: "catalog".to_owned(),
                policy_fingerprint: "policy".to_owned(),
                installed_fingerprint: "installed".to_owned(),
            },
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn plan_summary_flags_are_exact_step_projections(
            operation in 0_u8..7,
            raw_steps in prop::collection::vec((0_u8..7, any::<bool>(), any::<bool>()), 0..24)
        ) {
            let operation = property_operation(operation);
            let plan = property_plan(operation, &raw_steps);
            let expected_change = operation != Operation::Verify
                && plan.steps.iter().any(|step| {
                    !matches!(step.kind, StepKind::NoChange | StepKind::Verify)
                });
            let expected_privilege = plan.steps.iter().any(|step| step.requires_privilege);
            let expected_agreements = plan.steps.iter().any(|step| !step.agreements.is_empty());

            prop_assert_eq!(plan.changes_machine(), expected_change);
            prop_assert_eq!(plan.requires_privilege(), expected_privilege);
            prop_assert_eq!(plan.requires_agreements(), expected_agreements);
        }
    }
}
