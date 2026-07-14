//! Bounded, journaled execution of previously validated plans.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siorb_backends::{
    BackendAdapter, BackendKind, BackendQueryResult, CommandSpec, NativeAdapter,
    PlanOptions as BackendPlanOptions, QueryStatus, parse_query_output,
};
use siorb_catalog::PackageSource;
use siorb_core::{
    BackendInfo, ErrorKind, Operation, Result, SiorbError, sanitize_terminal, unix_timestamp,
    validate_public_network_host,
};
use siorb_planner::{ArtifactPlan, ExecutionPlan, PlanStep, PlannedPackage, StepKind};
use siorb_platform::trusted_privileged_executable;
use siorb_resolver::VersionConstraint;
use siorb_state::{
    JournalEvent, JournalState, Receipt, ReceiptOrigin, StateStore, VerificationRecord,
    VerificationStatus,
};

const JOURNAL_SCHEMA: &str = "1.0";

#[derive(Clone, Debug, Default)]
pub struct ExecutionOptions {
    pub consent: bool,
    /// True only when consent was collected from an interactive prompt for
    /// this exact plan. A pre-supplied `--yes` is deliberately not equivalent.
    pub interactive_consent: bool,
    pub policy_confirmation_required: bool,
    pub offline: bool,
    pub non_interactive: bool,
    pub accept_agreements: bool,
    pub privilege_broker: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StepReport {
    pub step_id: String,
    pub package: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    pub reason_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub transaction_id: String,
    pub plan_id: String,
    pub status: String,
    pub state_changed: bool,
    pub steps: Vec<StepReport>,
    pub recovery_actions: Vec<String>,
}

#[derive(Debug)]
pub struct Executor<'a> {
    state: &'a StateStore,
}

#[derive(Debug)]
struct DownloadedArtifact {
    directory: PathBuf,
    path: PathBuf,
    verified: bool,
}

#[derive(Debug)]
struct ExecutedStep {
    report: StepReport,
    query: Option<BackendQueryResult>,
}

impl<'a> Executor<'a> {
    #[must_use]
    pub const fn new(state: &'a StateStore) -> Self {
        Self { state }
    }

    /// Query a receipt through its catalog-selected native adapter and verify
    /// that the observed installed version still satisfies the receipt.
    ///
    /// This method runs only the adapter's non-privileged, non-networking
    /// `Verify` command and never writes Siorb state.
    ///
    /// # Errors
    ///
    /// Returns a verification error if trusted mapping data changed, the
    /// backend query cannot be executed safely, or observed state/version does
    /// not match the receipt.
    pub fn verify_receipt(
        &self,
        receipt: &Receipt,
        backend: &BackendInfo,
        source: &PackageSource,
    ) -> Result<BackendQueryResult> {
        validate_receipt_query_mapping(receipt, backend, source)?;
        let adapter = NativeAdapter::for_source(source)?;
        let command = adapter.command(
            Operation::Verify,
            backend,
            source,
            BackendPlanOptions {
                non_interactive: true,
                accept_agreements: false,
            },
        )?;
        if command.network || command.requires_privilege {
            return Err(SiorbError::new(
                ErrorKind::VerificationFailure,
                "receipt verification produced a mutating or networked backend command",
                "Do not reconcile the transaction; inspect the backend adapter and receipt.",
            )
            .with_reason("receipt.query.not_read_only"));
        }
        let output = run_bounded(&command, &ExecutionOptions::default())?;
        let constraint = receipt
            .observed_version
            .as_deref()
            .or(receipt.requested_version.as_deref());
        verified_query_result(&receipt.backend, &receipt.native_id, constraint, &output)
    }

    /// Execute a previously revalidated plan with bounded commands and an
    /// append-only transaction journal.
    ///
    /// # Errors
    ///
    /// Returns a typed error on missing consent, unsafe plan data, backend or
    /// verification failure, or partial completion that requires reconciliation.
    #[allow(clippy::too_many_lines)]
    pub fn execute(
        &self,
        plan: &ExecutionPlan,
        options: &ExecutionOptions,
    ) -> Result<ExecutionReport> {
        validate_offline(plan, options)?;
        validate_consent(plan, options)?;
        validate_native_receipt_verification(plan)?;
        let transaction_id = format!("tx-{}-{}", unix_timestamp(), &plan.plan_id[5..17]);
        self.event(
            &transaction_id,
            plan,
            None,
            JournalState::TransactionStarted,
            "execution consented",
        )?;
        let mut reports = Vec::new();
        let mut state_changed = false;
        let mut artifacts = BTreeMap::new();
        let mut observations = BTreeMap::new();
        for step in &plan.steps {
            let package = plan
                .packages
                .iter()
                .find(|package| package.logical_id == step.package)
                .ok_or_else(|| {
                    SiorbError::new(
                        ErrorKind::Internal,
                        format!(
                            "plan step `{}` references missing package `{}`",
                            step.id, step.package
                        ),
                        "Regenerate the plan and report the invalid planner output.",
                    )
                    .with_reason("executor.step.package_missing")
                })?;
            self.event(
                &transaction_id,
                plan,
                Some(&step.id),
                JournalState::StepStarted,
                &step.description,
            )?;
            let executed =
                match self.execute_step(step, plan.operation, package, options, &mut artifacts) {
                    Ok(executed) => executed,
                    Err(error) => {
                        self.event(
                            &transaction_id,
                            plan,
                            Some(&step.id),
                            JournalState::StepFailed,
                            &error.reason_code,
                        )?;
                        self.event(
                            &transaction_id,
                            plan,
                            None,
                            JournalState::TransactionFailed,
                            "execution stopped after a failed step",
                        )?;
                        let mut failure = error;
                        failure.state_changed |= state_changed;
                        if failure.state_changed {
                            failure.kind = ErrorKind::PartialCompletion;
                            "execution.partial".clone_into(&mut failure.reason_code);
                            "Run `siorb reconcile` and follow the idempotent recovery plan."
                                .clone_into(&mut failure.next_action);
                        }
                        cleanup_artifacts(&artifacts);
                        return Err(failure);
                    }
                };
            if let Some(query) = executed.query {
                observations.insert(step.package.clone(), query);
            }
            if executed.report.status == "completed"
                && step_commits_machine_state(plan.operation, step.kind)
            {
                state_changed = true;
            }
            self.event(
                &transaction_id,
                plan,
                Some(&step.id),
                step_completion_state(plan.operation, step.kind),
                "step completed",
            )?;
            reports.push(executed.report);
        }
        let receipts_changed = match self.commit_receipts(plan, &transaction_id, &observations) {
            Ok(changed) => changed,
            Err(mut error) => {
                self.event(
                    &transaction_id,
                    plan,
                    None,
                    JournalState::TransactionFailed,
                    "receipt commit failed after execution",
                )?;
                cleanup_artifacts(&artifacts);
                if state_changed || plan.operation == Operation::Adopt || error.state_changed {
                    error.kind = ErrorKind::PartialCompletion;
                    "execution.receipt_partial".clone_into(&mut error.reason_code);
                    error.state_changed = true;
                    "Run `siorb reconcile`; receipt persistence may be incomplete."
                        .clone_into(&mut error.next_action);
                }
                return Err(error);
            }
        };
        state_changed |= receipts_changed;
        cleanup_artifacts(&artifacts);
        if receipts_changed {
            self.event(
                &transaction_id,
                plan,
                None,
                JournalState::ReceiptCommitted,
                "receipt state committed",
            )?;
        }
        self.event(
            &transaction_id,
            plan,
            None,
            JournalState::TransactionCompleted,
            "all plan steps completed",
        )?;
        Ok(ExecutionReport {
            transaction_id,
            plan_id: plan.plan_id.clone(),
            status: if state_changed {
                "completed"
            } else {
                "no_change"
            }
            .to_owned(),
            state_changed,
            steps: reports,
            recovery_actions: plan.recovery_guidance.clone(),
        })
    }

    fn execute_step(
        &self,
        step: &PlanStep,
        operation: Operation,
        package: &PlannedPackage,
        options: &ExecutionOptions,
        artifacts: &mut BTreeMap<String, DownloadedArtifact>,
    ) -> Result<ExecutedStep> {
        let started = Instant::now();
        if matches!(step.kind, StepKind::NoChange) {
            return Ok(ExecutedStep {
                report: StepReport {
                    step_id: step.id.clone(),
                    package: step.package.clone(),
                    status: "no_change".to_owned(),
                    exit_code: Some(0),
                    duration_ms: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                    output_truncated: false,
                    reason_code: None,
                },
                query: None,
            });
        }
        if let Some(artifact) = &step.artifact {
            return self
                .execute_artifact_step(step, artifact, options, artifacts, started)
                .map(|report| ExecutedStep {
                    report,
                    query: None,
                });
        }
        let command = step.command.as_ref().ok_or_else(|| {
            SiorbError::new(
                ErrorKind::BackendFailure,
                format!(
                    "step `{}` has neither a command nor an artifact recipe",
                    step.id
                ),
                "Regenerate the plan from a complete, validated catalog source.",
            )
            .with_reason("executor.step.recipe_missing")
        })?;
        let is_query = step.kind == StepKind::Verify
            || matches!(operation, Operation::Verify | Operation::Adopt);
        if is_query && (command.network || command.requires_privilege) {
            return Err(SiorbError::new(
                ErrorKind::VerificationFailure,
                format!("step `{}` is not a read-only backend query", step.id),
                "Do not execute or commit a receipt from this plan; regenerate it with a safe adapter.",
            )
            .with_reason("plan.verification.not_read_only"));
        }
        let output = run_bounded(command, options)?;
        let duration_ms = started.elapsed().as_millis();
        if is_query {
            let query = if operation == Operation::Remove {
                verified_absence_query_result(&package.backend, &package.native_id, &output)?
            } else {
                verified_query_result(
                    &package.backend,
                    &package.native_id,
                    package.desired_version.as_deref(),
                    &output,
                )?
            };
            return Ok(ExecutedStep {
                report: StepReport {
                    step_id: step.id.clone(),
                    package: step.package.clone(),
                    status: "completed".to_owned(),
                    exit_code: output.exit_code,
                    duration_ms,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    output_truncated: output.truncated,
                    reason_code: Some(query.reason_code.clone()),
                },
                query: Some(query),
            });
        }
        if !output.success {
            return Err(classify_failure(command, &output));
        }
        Ok(ExecutedStep {
            report: StepReport {
                step_id: step.id.clone(),
                package: step.package.clone(),
                status: "completed".to_owned(),
                exit_code: output.exit_code,
                duration_ms,
                stdout: output.stdout,
                stderr: output.stderr,
                output_truncated: output.truncated,
                reason_code: None,
            },
            query: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn execute_artifact_step(
        &self,
        step: &PlanStep,
        recipe: &ArtifactPlan,
        options: &ExecutionOptions,
        artifacts: &mut BTreeMap<String, DownloadedArtifact>,
        started: Instant,
    ) -> Result<StepReport> {
        match step.kind {
            StepKind::Download => {
                if artifacts.contains_key(&step.package) {
                    return Err(verification_error(
                        "artifact.state.duplicate",
                        "artifact was downloaded more than once in one plan",
                    ));
                }
                let artifact = download_artifact(recipe, self.state.root())?;
                let bytes = fs::metadata(&artifact.path)
                    .map_err(|error| verification_error("artifact.metadata", &error.to_string()))?
                    .len();
                artifacts.insert(step.package.clone(), artifact);
                Ok(artifact_report(
                    step,
                    started,
                    format!("downloaded and digest-verified {bytes} bytes"),
                ))
            }
            StepKind::Verify => {
                validate_artifact_recipe(recipe)?;
                let artifact = artifacts.get_mut(&step.package).ok_or_else(|| {
                    verification_error(
                        "artifact.state.missing",
                        "artifact verification has no preceding download",
                    )
                })?;
                verify_sha256(&artifact.path, &recipe.sha256)?;
                inspect_artifact_format(&artifact.path, recipe, &ArchiveLimits::default())?;
                match recipe.kind {
                    siorb_catalog::ArtifactKind::PortableArchive
                    | siorb_catalog::ArtifactKind::PortableExecutable => {}
                    siorb_catalog::ArtifactKind::NativeInstaller => {
                        verify_native_signer(&artifact.path, recipe)?;
                    }
                }
                artifact.verified = true;
                Ok(artifact_report(
                    step,
                    started,
                    "digest, type, signer, and structure verified".to_owned(),
                ))
            }
            StepKind::Extract => {
                if recipe.operation == Operation::Remove {
                    let destination = self.state.root().join("artifacts").join(&step.package);
                    reject_link(&destination)?;
                    if destination.is_dir() {
                        fs::remove_dir_all(&destination).map_err(|error| {
                            verification_error("artifact.remove", &error.to_string())
                        })?;
                    }
                    return Ok(artifact_report(
                        step,
                        started,
                        "removed only the artifact-owned directory".to_owned(),
                    ));
                }
                let artifact = verified_artifact(artifacts, &step.package)?;
                let destination = install_owned_artifact(
                    &artifact.path,
                    recipe,
                    self.state.root(),
                    &step.package,
                )?;
                Ok(artifact_report(
                    step,
                    started,
                    format!("installed owned files under {}", destination.display()),
                ))
            }
            StepKind::Installer => {
                let artifact = verified_artifact(artifacts, &step.package)?;
                let output =
                    run_native_installer(&artifact.path, recipe, step.requires_privilege, options)?;
                if !output.success {
                    return Err(SiorbError::new(
                        ErrorKind::BackendFailure,
                        "verified native artifact installer failed",
                        "Review bounded installer output and use the platform's recovery tools.",
                    )
                    .with_reason("artifact.installer.failed")
                    .with_detail(format!(
                        "exit={:?}; stdout={}; stderr={}",
                        output.exit_code, output.stdout, output.stderr
                    )));
                }
                Ok(StepReport {
                    step_id: step.id.clone(),
                    package: step.package.clone(),
                    status: "completed".to_owned(),
                    exit_code: output.exit_code,
                    duration_ms: started.elapsed().as_millis(),
                    stdout: output.stdout,
                    stderr: output.stderr,
                    output_truncated: output.truncated,
                    reason_code: None,
                })
            }
            _ => Err(verification_error(
                "artifact.step.invalid",
                "artifact recipe appeared on an incompatible plan step",
            )),
        }
    }

    fn commit_receipts(
        &self,
        plan: &ExecutionPlan,
        transaction_id: &str,
        observations: &BTreeMap<String, BackendQueryResult>,
    ) -> Result<bool> {
        let mut changed = false;
        for package in &plan.packages {
            if !package_requires_receipt_commit(plan, &package.logical_id) {
                continue;
            }
            match plan.operation {
                Operation::Remove => {
                    if package.backend != "artifact" {
                        let observation = observations.get(&package.logical_id).ok_or_else(|| {
                            SiorbError::new(
                                ErrorKind::VerificationFailure,
                                format!(
                                    "native removal for `{}` has no backend absence observation",
                                    package.logical_id
                                ),
                                "Keep the receipt and rerun removal or reconciliation with a readable backend query.",
                            )
                            .with_reason("receipt.removal_observation.missing")
                        })?;
                        if observation.native_id != package.native_id
                            || observation.status != QueryStatus::NotInstalled
                        {
                            return Err(SiorbError::new(
                                ErrorKind::VerificationFailure,
                                format!(
                                    "backend did not confirm removal of `{}`",
                                    package.logical_id
                                ),
                                "Keep the receipt and reconcile the observed native package state.",
                            )
                            .with_reason("receipt.removal_not_verified"));
                        }
                    }
                    self.state.remove_receipt(&package.logical_id)?;
                    changed = true;
                }
                Operation::Install | Operation::Upgrade | Operation::Repair | Operation::Adopt => {
                    let observation = observations.get(&package.logical_id);
                    let native_receipt = package.backend != "artifact";
                    if native_receipt && observation.is_none() {
                        return Err(SiorbError::new(
                            ErrorKind::VerificationFailure,
                            format!(
                                "native operation for `{}` has no verified backend observation",
                                package.logical_id
                            ),
                            "Do not write a receipt; rerun with a readable native backend and post-operation verification.",
                        )
                        .with_reason("receipt.observation.missing"));
                    }
                    let verification_reason = if let Some(observation) = observation {
                        if observation.native_id != package.native_id {
                            return Err(SiorbError::new(
                                ErrorKind::VerificationFailure,
                                format!(
                                    "backend observation for `{}` returned identity `{}`",
                                    package.logical_id, observation.native_id
                                ),
                                "Do not write a receipt; inspect the backend query mapping.",
                            )
                            .with_reason("receipt.observation.identity_mismatch"));
                        }
                        let constraint = package
                            .desired_version
                            .as_deref()
                            .map(VersionConstraint::parse)
                            .transpose()?;
                        observation.verify(constraint.as_ref())?;
                        if observation.observed_version.is_none() {
                            return Err(SiorbError::new(
                                ErrorKind::VerificationFailure,
                                format!(
                                    "backend observation for `{}` has no installed version",
                                    package.logical_id
                                ),
                                "Do not write a receipt; use a backend query that reports the installed version.",
                            )
                            .with_reason("receipt.observation.version_missing"));
                        }
                        observation.reason_code.clone()
                    } else {
                        "artifact digest, signer, type, and structure verified".to_owned()
                    };
                    self.state.write_receipt(&Receipt {
                        schema_version: "1.0".to_owned(),
                        logical_id: package.logical_id.clone(),
                        native_id: package.native_id.clone(),
                        backend: package.backend.clone(),
                        source_id: package.source_id.clone(),
                        requested_version: package.desired_version.clone(),
                        observed_version: observation
                            .and_then(|value| value.observed_version.clone()),
                        scope: package.scope,
                        channel: package.channel.clone(),
                        architecture: package.architecture.to_string(),
                        catalog_fingerprint: plan.catalog_fingerprint.clone(),
                        policy_fingerprint: plan.policy_fingerprint.clone(),
                        installed_at_unix: unix_timestamp(),
                        verification: VerificationRecord {
                            status: VerificationStatus::Verified,
                            checked_at_unix: unix_timestamp(),
                            reason: verification_reason,
                        },
                        owned_files: if package.backend == "artifact"
                            && package_has_owned_artifact(plan, &package.logical_id)
                        {
                            vec![
                                self.state
                                    .root()
                                    .join("artifacts")
                                    .join(&package.logical_id)
                                    .display()
                                    .to_string(),
                            ]
                        } else {
                            Vec::new()
                        },
                        transaction_id: transaction_id.to_owned(),
                        origin: if plan.operation == Operation::Adopt {
                            ReceiptOrigin::Adopted
                        } else {
                            ReceiptOrigin::Installed
                        },
                    })?;
                    changed = true;
                }
                Operation::Reconcile | Operation::Verify => {}
            }
        }
        Ok(changed)
    }

    fn event(
        &self,
        transaction_id: &str,
        plan: &ExecutionPlan,
        step_id: Option<&str>,
        state: JournalState,
        detail: &str,
    ) -> Result<()> {
        self.state.append_event(&JournalEvent {
            schema_version: JOURNAL_SCHEMA.to_owned(),
            transaction_id: transaction_id.to_owned(),
            plan_id: plan.plan_id.clone(),
            step_id: step_id.map(str::to_owned),
            timestamp_unix: unix_timestamp(),
            state,
            detail: sanitize_terminal(detail),
        })
    }
}

fn validate_receipt_query_mapping(
    receipt: &Receipt,
    backend: &BackendInfo,
    source: &PackageSource,
) -> Result<()> {
    let mapping_matches = source.id == receipt.source_id
        && source.backend == receipt.backend
        && source.package_id == receipt.native_id
        && backend.id == source.tool_backend()
        && backend.available;
    if !mapping_matches {
        return Err(SiorbError::new(
            ErrorKind::VerificationFailure,
            format!(
                "receipt mapping for `{}` no longer matches the selected catalog source",
                receipt.logical_id
            ),
            "Do not reconcile the transaction; refresh trusted metadata and review the mapping.",
        )
        .with_reason("receipt.query.mapping_changed"));
    }
    Ok(())
}

fn verified_query_result(
    backend: &str,
    native_id: &str,
    constraint: Option<&str>,
    output: &BoundedOutput,
) -> Result<BackendQueryResult> {
    let observed = parsed_query_result(backend, native_id, output)?;
    let constraint = constraint.map(VersionConstraint::parse).transpose()?;
    observed.verify(constraint.as_ref())?;
    Ok(observed)
}

fn verified_absence_query_result(
    backend: &str,
    native_id: &str,
    output: &BoundedOutput,
) -> Result<BackendQueryResult> {
    let observed = parsed_query_result(backend, native_id, output)?;
    if observed.status != QueryStatus::NotInstalled {
        return Err(SiorbError::new(
            ErrorKind::VerificationFailure,
            format!("backend did not confirm that `{native_id}` is absent"),
            "Keep the receipt and reconcile the package through a read-only backend query.",
        )
        .with_reason("backend.verify.still_installed"));
    }
    Ok(observed)
}

fn parsed_query_result(
    backend: &str,
    native_id: &str,
    output: &BoundedOutput,
) -> Result<BackendQueryResult> {
    if output.timed_out {
        return Err(SiorbError::new(
            ErrorKind::VerificationFailure,
            format!("backend query for `{native_id}` timed out"),
            "Resolve backend locks and rerun the read-only verification.",
        )
        .with_reason("backend.query.timeout"));
    }
    if output.truncated {
        return Err(SiorbError::new(
            ErrorKind::VerificationFailure,
            format!("backend query output for `{native_id}` exceeded its bound"),
            "Do not infer installed state from truncated output; inspect the backend directly.",
        )
        .with_reason("backend.query.output_truncated"));
    }
    let kind = BackendKind::from_catalog(backend)?;
    Ok(parse_query_output(
        kind,
        native_id,
        &output.stdout_bytes,
        &output.stderr_bytes,
        output.exit_code,
    ))
}

fn step_commits_machine_state(operation: Operation, kind: StepKind) -> bool {
    match kind {
        StepKind::Backend => matches!(
            operation,
            Operation::Install
                | Operation::Remove
                | Operation::Upgrade
                | Operation::Repair
                | Operation::Reconcile
        ),
        StepKind::Extract | StepKind::Installer | StepKind::Receipt => {
            operation != Operation::Verify
        }
        StepKind::Download | StepKind::Verify | StepKind::NoChange => false,
    }
}

fn step_completion_state(operation: Operation, kind: StepKind) -> JournalState {
    if step_commits_machine_state(operation, kind)
        || matches!((operation, kind), (Operation::Adopt, StepKind::Backend))
    {
        JournalState::StepCompleted
    } else {
        JournalState::VerificationCompleted
    }
}

fn package_requires_receipt_commit(plan: &ExecutionPlan, logical_id: &str) -> bool {
    match plan.operation {
        Operation::Verify | Operation::Reconcile => false,
        Operation::Adopt => true,
        Operation::Install | Operation::Remove | Operation::Upgrade | Operation::Repair => {
            plan.steps.iter().any(|step| {
                step.package == logical_id && step_commits_machine_state(plan.operation, step.kind)
            })
        }
    }
}

fn package_has_owned_artifact(plan: &ExecutionPlan, package: &str) -> bool {
    plan.steps.iter().any(|step| {
        step.package == package
            && step.kind == StepKind::Extract
            && step.artifact.as_ref().is_some_and(|artifact| {
                matches!(
                    artifact.kind,
                    siorb_catalog::ArtifactKind::PortableArchive
                        | siorb_catalog::ArtifactKind::PortableExecutable
                )
            })
    })
}

fn artifact_report(step: &PlanStep, started: Instant, message: String) -> StepReport {
    StepReport {
        step_id: step.id.clone(),
        package: step.package.clone(),
        status: "completed".to_owned(),
        exit_code: Some(0),
        duration_ms: started.elapsed().as_millis(),
        stdout: message,
        stderr: String::new(),
        output_truncated: false,
        reason_code: None,
    }
}

fn verified_artifact<'a>(
    artifacts: &'a BTreeMap<String, DownloadedArtifact>,
    package: &str,
) -> Result<&'a DownloadedArtifact> {
    let artifact = artifacts.get(package).ok_or_else(|| {
        verification_error(
            "artifact.state.missing",
            "artifact apply has no preceding download",
        )
    })?;
    if !artifact.verified {
        return Err(verification_error(
            "artifact.state.unverified",
            "artifact apply was attempted before verification",
        ));
    }
    Ok(artifact)
}

#[allow(clippy::too_many_lines)]
fn download_artifact(recipe: &ArtifactPlan, state_root: &Path) -> Result<DownloadedArtifact> {
    if recipe.max_bytes == 0 || recipe.max_bytes > 16 * 1024 * 1024 * 1024 {
        return Err(verification_error(
            "artifact.download.bound",
            "artifact download has no acceptable size bound",
        ));
    }
    let base = reqwest::Url::parse(&recipe.url).map_err(|error| {
        verification_error(
            "artifact.url.invalid",
            &format!("invalid artifact URL: {error}"),
        )
    })?;
    let original_host = base
        .host_str()
        .ok_or_else(|| verification_error("artifact.url.host", "artifact URL has no host"))
        .and_then(|host| {
            validate_public_network_host(host).map_err(|error| {
                verification_error(
                    "artifact.url.non_public_host",
                    &format!("artifact URL host is unsafe: {error}"),
                )
            })
        })?;
    if base.scheme() != "https"
        || !base.username().is_empty()
        || base.password().is_some()
        || base.fragment().is_some()
    {
        return Err(verification_error(
            "artifact.url.unsafe",
            "artifact URL must be credential-free HTTPS without a fragment",
        ));
    }
    let mut allowed_hosts = BTreeSet::from([original_host]);
    for host in &recipe.allowed_redirect_hosts {
        let host = validate_public_network_host(host).map_err(|error| {
            verification_error(
                "artifact.redirect.non_public_host",
                &format!("artifact redirect host is unsafe: {error}"),
            )
        })?;
        allowed_hosts.insert(host);
    }
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .user_agent(concat!("siorb/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| {
            verification_error(
                "artifact.https.client",
                &format!("cannot initialize HTTPS client: {error}"),
            )
        })?;
    let parent = state_root.join("cache").join("artifact-downloads");
    ensure_real_directory(&parent)?;
    let directory = create_isolated_directory(&parent)?;
    let path = directory.join(format!("payload.{}", recipe.format.file_extension()));
    let result = (|| {
        let mut current = base;
        for redirects in 0..=5 {
            let mut response = client.get(current.clone()).send().map_err(|error| {
                verification_error(
                    "artifact.download.network",
                    &format!("artifact HTTPS request failed: {error}"),
                )
            })?;
            if response.status().is_redirection() {
                if redirects == 5 {
                    return Err(verification_error(
                        "artifact.redirect.limit",
                        "artifact exceeded five redirects",
                    ));
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        verification_error(
                            "artifact.redirect.location",
                            "redirect has no valid Location header",
                        )
                    })?;
                let next = current.join(location).map_err(|error| {
                    verification_error(
                        "artifact.redirect.invalid",
                        &format!("invalid redirect: {error}"),
                    )
                })?;
                let next_host = next
                    .host_str()
                    .and_then(|host| validate_public_network_host(host).ok());
                if next.scheme() != "https"
                    || next_host
                        .as_ref()
                        .is_none_or(|host| !allowed_hosts.contains(host))
                    || !next.username().is_empty()
                    || next.password().is_some()
                    || next.fragment().is_some()
                {
                    return Err(verification_error(
                        "artifact.redirect.boundary",
                        "redirect leaves the approved HTTPS host boundary",
                    ));
                }
                current = next;
                continue;
            }
            if !response.status().is_success() {
                return Err(verification_error(
                    "artifact.download.status",
                    &format!("artifact server returned {}", response.status()),
                ));
            }
            if response
                .content_length()
                .is_some_and(|length| length > recipe.max_bytes)
            {
                return Err(verification_error(
                    "artifact.download.size",
                    "artifact Content-Length exceeds the catalog bound",
                ));
            }
            let observed_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            if observed_type != Some(recipe.content_type.as_str()) {
                return Err(verification_error(
                    "artifact.content_type.mismatch",
                    &format!(
                        "expected content type {}, observed {}",
                        recipe.content_type,
                        observed_type.unwrap_or("missing")
                    ),
                ));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| verification_error("artifact.temp.create", &error.to_string()))?;
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            loop {
                let count = response.read(&mut buffer).map_err(|error| {
                    verification_error("artifact.download.read", &error.to_string())
                })?;
                if count == 0 {
                    break;
                }
                total = total.saturating_add(count as u64);
                if total > recipe.max_bytes {
                    return Err(verification_error(
                        "artifact.download.size",
                        "streamed artifact exceeds the catalog bound",
                    ));
                }
                hasher.update(&buffer[..count]);
                output.write_all(&buffer[..count]).map_err(|error| {
                    verification_error("artifact.temp.write", &error.to_string())
                })?;
            }
            output
                .sync_all()
                .map_err(|error| verification_error("artifact.temp.sync", &error.to_string()))?;
            let actual = hex::encode(hasher.finalize());
            if !actual.eq_ignore_ascii_case(&recipe.sha256) {
                return Err(verification_error(
                    "artifact.digest.mismatch",
                    &format!(
                        "SHA-256 mismatch: expected {}, observed {actual}",
                        recipe.sha256
                    ),
                ));
            }
            return Ok(DownloadedArtifact {
                directory: directory.clone(),
                path: path.clone(),
                verified: false,
            });
        }
        Err(verification_error(
            "artifact.redirect.limit",
            "artifact redirect loop",
        ))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

fn validate_artifact_recipe(recipe: &ArtifactPlan) -> Result<()> {
    if recipe.kind != recipe.format.kind()
        || !recipe.format.accepts_content_type(&recipe.content_type)
        || recipe.max_bytes == 0
        || recipe.max_bytes > 16 * 1024 * 1024 * 1024
    {
        return Err(verification_error(
            "artifact.recipe.type",
            "artifact kind, format, content type, or size bound is inconsistent",
        ));
    }
    if recipe
        .allowed_redirect_hosts
        .iter()
        .any(|host| validate_public_network_host(host).is_err())
    {
        return Err(verification_error(
            "artifact.recipe.redirect_host",
            "artifact recipe contains an unsafe redirect host",
        ));
    }
    match recipe.kind {
        siorb_catalog::ArtifactKind::PortableArchive => {
            if recipe.archive_format.as_deref() != recipe.format.archive_name()
                || recipe.payload_path.is_some()
                || !recipe.install_arguments.is_empty()
                || recipe.strip_components > 16
            {
                return Err(verification_error(
                    "artifact.recipe.archive",
                    "portable archive recipe is inconsistent",
                ));
            }
        }
        siorb_catalog::ArtifactKind::PortableExecutable => {
            if recipe.format != siorb_catalog::ArtifactFormat::AppImage
                || recipe.archive_format.is_some()
                || recipe.payload_path.is_some()
                || recipe.strip_components != 0
                || !recipe.install_arguments.is_empty()
            {
                return Err(verification_error(
                    "artifact.recipe.portable_executable",
                    "portable executable recipe is inconsistent",
                ));
            }
        }
        siorb_catalog::ArtifactKind::NativeInstaller => {
            let signer_required = recipe.format.requires_package_signer();
            if (signer_required && recipe.signer.as_deref().is_none_or(str::is_empty))
                || recipe.archive_format.is_some()
                || recipe.strip_components != 0
                || (recipe.format == siorb_catalog::ArtifactFormat::Dmg
                    && recipe.payload_path.as_deref().is_none_or(|path| {
                        !safe_payload_path(path) || !path.to_ascii_lowercase().ends_with(".pkg")
                    }))
                || (recipe.format != siorb_catalog::ArtifactFormat::Dmg
                    && recipe.payload_path.is_some())
                || !typed_installer_arguments(recipe)
            {
                return Err(verification_error(
                    "artifact.recipe.installer",
                    "native installer recipe is not a supported typed invocation",
                ));
            }
        }
    }
    Ok(())
}

fn safe_payload_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && value.split('/').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && component.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "+-._ ".contains(character)
                })
        })
}

fn typed_installer_arguments(recipe: &ArtifactPlan) -> bool {
    if recipe.install_arguments.len() > 4 {
        return false;
    }
    let mut seen = BTreeSet::new();
    recipe.install_arguments.iter().all(|argument| {
        recipe.format == siorb_catalog::ArtifactFormat::Exe
            && matches!(
                argument.as_str(),
                "/S" | "/silent" | "/verysilent" | "/quiet" | "/norestart" | "--silent" | "--quiet"
            )
            && seen.insert(argument.to_ascii_lowercase())
    })
}

fn inspect_artifact_format(
    path: &Path,
    recipe: &ArtifactPlan,
    limits: &ArchiveLimits,
) -> Result<()> {
    use siorb_catalog::ArtifactFormat;

    match recipe.format {
        ArtifactFormat::Zip => inspect_zip(
            File::open(path)
                .map_err(|error| verification_error("archive.read", &error.to_string()))?,
            limits,
        ),
        ArtifactFormat::Tar => inspect_tar(
            File::open(path)
                .map_err(|error| verification_error("archive.read", &error.to_string()))?,
            limits,
        ),
        ArtifactFormat::TarGz => inspect_tar(
            flate2::read::GzDecoder::new(
                File::open(path)
                    .map_err(|error| verification_error("archive.read", &error.to_string()))?,
            ),
            limits,
        ),
        ArtifactFormat::Msi => expect_prefix(
            path,
            &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
            "MSI compound-file header",
        ),
        ArtifactFormat::Msix => inspect_msix(path, limits),
        ArtifactFormat::Exe => inspect_pe(path),
        ArtifactFormat::Pkg => expect_prefix(path, b"xar!", "flat PKG XAR header"),
        ArtifactFormat::Dmg => inspect_dmg(path),
        ArtifactFormat::Deb => inspect_deb(path),
        ArtifactFormat::Rpm => expect_prefix(path, &[0xed, 0xab, 0xee, 0xdb], "RPM lead"),
        ArtifactFormat::AppImage => inspect_appimage(path),
    }
}

fn expect_prefix(path: &Path, expected: &[u8], description: &str) -> Result<()> {
    let mut file = File::open(path)
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let mut observed = vec![0_u8; expected.len()];
    file.read_exact(&mut observed).map_err(|_| {
        verification_error("artifact.type.truncated", "artifact header is truncated")
    })?;
    if observed != expected {
        return Err(verification_error(
            "artifact.type.mismatch",
            &format!("artifact does not contain the expected {description}"),
        ));
    }
    Ok(())
}

fn inspect_pe(path: &Path) -> Result<()> {
    let mut file = File::open(path)
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let length = file
        .metadata()
        .map_err(|error| verification_error("artifact.type.metadata", &error.to_string()))?
        .len();
    let mut dos = [0_u8; 64];
    file.read_exact(&mut dos)
        .map_err(|_| verification_error("artifact.type.truncated", "PE DOS header is truncated"))?;
    if &dos[..2] != b"MZ" {
        return Err(verification_error(
            "artifact.type.mismatch",
            "Windows executable has no MZ header",
        ));
    }
    let offset = u64::from(u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]));
    if offset < 64 || offset.saturating_add(4) > length {
        return Err(verification_error(
            "artifact.type.mismatch",
            "Windows executable has an invalid PE offset",
        ));
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let mut signature = [0_u8; 4];
    file.read_exact(&mut signature)
        .map_err(|_| verification_error("artifact.type.truncated", "PE signature is truncated"))?;
    if signature != *b"PE\0\0" {
        return Err(verification_error(
            "artifact.type.mismatch",
            "Windows executable has no PE signature",
        ));
    }
    Ok(())
}

fn inspect_msix(path: &Path, limits: &ArchiveLimits) -> Result<()> {
    inspect_zip(
        File::open(path).map_err(|error| verification_error("archive.read", &error.to_string()))?,
        limits,
    )?;
    let file =
        File::open(path).map_err(|error| verification_error("archive.read", &error.to_string()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| verification_error("archive.zip.invalid", &error.to_string()))?;
    let mut manifest = false;
    let mut content_types = false;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| verification_error("archive.zip.entry", &error.to_string()))?;
        manifest |= entry.name().eq_ignore_ascii_case("AppxManifest.xml");
        content_types |= entry.name().eq_ignore_ascii_case("[Content_Types].xml");
    }
    if !manifest || !content_types {
        return Err(verification_error(
            "artifact.msix.structure",
            "MSIX lacks AppxManifest.xml or [Content_Types].xml",
        ));
    }
    Ok(())
}

fn inspect_dmg(path: &Path) -> Result<()> {
    let mut file = File::open(path)
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let length = file
        .metadata()
        .map_err(|error| verification_error("artifact.type.metadata", &error.to_string()))?
        .len();
    if length < 512 {
        return Err(verification_error(
            "artifact.type.truncated",
            "DMG is shorter than its UDIF trailer",
        ));
    }
    file.seek(SeekFrom::End(-512))
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    if magic != *b"koly" {
        return Err(verification_error(
            "artifact.type.mismatch",
            "DMG has no UDIF koly trailer",
        ));
    }
    Ok(())
}

fn inspect_deb(path: &Path) -> Result<()> {
    let mut file = File::open(path)
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let length = file
        .metadata()
        .map_err(|error| verification_error("artifact.type.metadata", &error.to_string()))?
        .len();
    let mut global = [0_u8; 8];
    file.read_exact(&mut global)
        .map_err(|_| verification_error("artifact.type.truncated", "DEB ar header is truncated"))?;
    if global != *b"!<arch>\n" {
        return Err(verification_error(
            "artifact.type.mismatch",
            "DEB has no ar archive header",
        ));
    }
    let mut offset = 8_u64;
    let mut members = 0_usize;
    let mut debian_binary = false;
    let mut control = false;
    let mut data = false;
    while offset.saturating_add(60) <= length && members < 128 {
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
        let mut header = [0_u8; 60];
        file.read_exact(&mut header).map_err(|_| {
            verification_error("artifact.type.truncated", "DEB member header is truncated")
        })?;
        if &header[58..60] != b"`\n" {
            return Err(verification_error(
                "artifact.deb.structure",
                "DEB contains an invalid ar member header",
            ));
        }
        let name = String::from_utf8_lossy(&header[..16]);
        let name = name.trim().trim_end_matches('/');
        let size = std::str::from_utf8(&header[48..58])
            .ok()
            .map(str::trim)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| {
                verification_error("artifact.deb.structure", "DEB member has an invalid size")
            })?;
        debian_binary |= name == "debian-binary";
        control |= name.starts_with("control.tar");
        data |= name.starts_with("data.tar");
        offset = offset.saturating_add(60).saturating_add(size);
        if offset % 2 != 0 {
            offset = offset.saturating_add(1);
        }
        if offset > length {
            return Err(verification_error(
                "artifact.deb.structure",
                "DEB member exceeds the artifact boundary",
            ));
        }
        members += 1;
    }
    if !debian_binary || !control || !data {
        return Err(verification_error(
            "artifact.deb.structure",
            "DEB lacks debian-binary, control.tar, or data.tar members",
        ));
    }
    Ok(())
}

fn inspect_appimage(path: &Path) -> Result<()> {
    let mut file = File::open(path)
        .map_err(|error| verification_error("artifact.type.read", &error.to_string()))?;
    let mut header = [0_u8; 12];
    file.read_exact(&mut header).map_err(|_| {
        verification_error("artifact.type.truncated", "AppImage header is truncated")
    })?;
    if header[..4] != *b"\x7fELF" || header[8..11] != *b"AI\x02" {
        return Err(verification_error(
            "artifact.type.mismatch",
            "AppImage lacks the ELF and type-2 AppImage markers",
        ));
    }
    Ok(())
}

fn install_owned_artifact(
    path: &Path,
    recipe: &ArtifactPlan,
    state_root: &Path,
    package: &str,
) -> Result<PathBuf> {
    match recipe.kind {
        siorb_catalog::ArtifactKind::PortableArchive => {
            install_archive(path, recipe, state_root, package)
        }
        siorb_catalog::ArtifactKind::PortableExecutable => {
            install_appimage(path, recipe, state_root, package)
        }
        siorb_catalog::ArtifactKind::NativeInstaller => Err(verification_error(
            "artifact.step.invalid",
            "native installer cannot be committed as an owned portable artifact",
        )),
    }
}

fn install_archive(
    path: &Path,
    recipe: &ArtifactPlan,
    state_root: &Path,
    package: &str,
) -> Result<PathBuf> {
    validate_owned_component(package)?;
    let parent = state_root.join("artifacts");
    ensure_real_directory(&parent)?;
    let staging = create_isolated_directory(&parent)?;
    let limits = ArchiveLimits::default();
    let extraction = match recipe.archive_format.as_deref() {
        Some("zip") => extract_zip_archive(path, &staging, recipe.strip_components, &limits),
        Some("tar") => extract_tar_archive(
            File::open(path)
                .map_err(|error| verification_error("archive.read", &error.to_string()))?,
            &staging,
            recipe.strip_components,
            &limits,
        ),
        Some("tar.gz" | "tgz") => extract_tar_archive(
            flate2::read::GzDecoder::new(
                File::open(path)
                    .map_err(|error| verification_error("archive.read", &error.to_string()))?,
            ),
            &staging,
            recipe.strip_components,
            &limits,
        ),
        _ => Err(verification_error(
            "archive.format.unsupported",
            "portable artifact has no supported archive format",
        )),
    };
    if let Err(error) = extraction {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    let destination = parent.join(package);
    reject_link(&destination)?;
    let backup = parent.join(format!(
        ".{package}.backup-{}",
        siorb_core::correlation_id()
    ));
    let had_previous = destination.exists();
    if had_previous {
        fs::rename(&destination, &backup)
            .map_err(|error| verification_error("artifact.install.backup", &error.to_string()))?;
    }
    if let Err(error) = fs::rename(&staging, &destination) {
        if had_previous {
            let _ = fs::rename(&backup, &destination);
        }
        return Err(verification_error(
            "artifact.install.commit",
            &error.to_string(),
        ));
    }
    if had_previous {
        let _ = fs::remove_dir_all(&backup);
    }
    Ok(destination)
}

fn install_appimage(
    path: &Path,
    recipe: &ArtifactPlan,
    state_root: &Path,
    package: &str,
) -> Result<PathBuf> {
    if recipe.format != siorb_catalog::ArtifactFormat::AppImage {
        return Err(verification_error(
            "artifact.appimage.format",
            "portable executable is not a typed AppImage",
        ));
    }
    validate_owned_component(package)?;
    let parent = state_root.join("artifacts");
    ensure_real_directory(&parent)?;
    let staging = create_isolated_directory(&parent)?;
    let staged_file = staging.join(format!("{package}.AppImage"));
    let copy_result = (|| {
        let mut source = File::open(path)
            .map_err(|error| verification_error("artifact.appimage.read", &error.to_string()))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_file)
            .map_err(|error| verification_error("artifact.appimage.create", &error.to_string()))?;
        std::io::copy(&mut source, &mut output)
            .map_err(|error| verification_error("artifact.appimage.copy", &error.to_string()))?;
        output
            .sync_all()
            .map_err(|error| verification_error("artifact.appimage.sync", &error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged_file, fs::Permissions::from_mode(0o700)).map_err(
                |error| verification_error("artifact.appimage.permissions", &error.to_string()),
            )?;
        }
        verify_sha256(&staged_file, &recipe.sha256)
    })();
    if let Err(error) = copy_result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    commit_owned_staging(&parent, &staging, package)
}

fn commit_owned_staging(parent: &Path, staging: &Path, package: &str) -> Result<PathBuf> {
    let destination = parent.join(package);
    reject_link(&destination)?;
    let backup = parent.join(format!(
        ".{package}.backup-{}",
        siorb_core::correlation_id()
    ));
    let had_previous = destination.exists();
    if had_previous {
        fs::rename(&destination, &backup)
            .map_err(|error| verification_error("artifact.install.backup", &error.to_string()))?;
    }
    if let Err(error) = fs::rename(staging, &destination) {
        if had_previous {
            let _ = fs::rename(&backup, &destination);
        }
        return Err(verification_error(
            "artifact.install.commit",
            &error.to_string(),
        ));
    }
    if had_previous {
        let _ = fs::remove_dir_all(&backup);
    }
    Ok(destination)
}

fn cleanup_artifacts(artifacts: &BTreeMap<String, DownloadedArtifact>) {
    for artifact in artifacts.values() {
        let _ = fs::remove_dir_all(&artifact.directory);
    }
}

fn extract_zip_archive(
    source: &Path,
    destination: &Path,
    strip_components: u32,
    limits: &ArchiveLimits,
) -> Result<()> {
    let file = File::open(source)
        .map_err(|error| verification_error("archive.read", &error.to_string()))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| verification_error("archive.zip.invalid", &error.to_string()))?;
    if archive.len() > limits.max_entries {
        return Err(verification_error(
            "archive.entries.limit",
            "archive has too many entries",
        ));
    }
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| verification_error("archive.zip.entry", &error.to_string()))?;
        let Some(relative) = stripped_archive_path(Path::new(entry.name()), strip_components)?
        else {
            continue;
        };
        total = total.saturating_add(entry.size());
        if entry.size() > limits.max_single_file_bytes || total > limits.max_uncompressed_bytes {
            return Err(verification_error(
                "archive.size.limit",
                "archive exceeds extraction size limits",
            ));
        }
        let output = destination.join(relative);
        if entry.is_dir() {
            create_owned_directory(&output)?;
            continue;
        }
        if entry.is_symlink() {
            return Err(verification_error(
                "archive.symlink.forbidden",
                "archive symlinks are forbidden",
            ));
        }
        if let Some(parent) = output.parent() {
            create_owned_directory(parent)?;
        }
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|error| verification_error("archive.extract.create", &error.to_string()))?;
        let copied = std::io::copy(&mut entry, &mut target)
            .map_err(|error| verification_error("archive.extract.write", &error.to_string()))?;
        if copied != entry.size() {
            return Err(verification_error(
                "archive.extract.truncated",
                "archive member size changed during extraction",
            ));
        }
        #[cfg(unix)]
        set_owned_file_permissions(&target, entry.unix_mode())?;
    }
    Ok(())
}

fn extract_tar_archive<R: Read>(
    reader: R,
    destination: &Path,
    strip_components: u32,
    limits: &ArchiveLimits,
) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| verification_error("archive.tar.invalid", &error.to_string()))?;
    let mut count = 0_usize;
    let mut total = 0_u64;
    for entry in entries {
        let mut entry =
            entry.map_err(|error| verification_error("archive.tar.entry", &error.to_string()))?;
        count += 1;
        if count > limits.max_entries {
            return Err(verification_error(
                "archive.entries.limit",
                "archive has too many entries",
            ));
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(verification_error(
                "archive.special.forbidden",
                "archive links and special files are forbidden",
            ));
        }
        let path = entry
            .path()
            .map_err(|error| verification_error("archive.path.invalid", &error.to_string()))?;
        let Some(relative) = stripped_archive_path(&path, strip_components)? else {
            continue;
        };
        let size = entry.size();
        total = total.saturating_add(size);
        if size > limits.max_single_file_bytes || total > limits.max_uncompressed_bytes {
            return Err(verification_error(
                "archive.size.limit",
                "archive exceeds extraction size limits",
            ));
        }
        let output = destination.join(relative);
        if kind.is_dir() {
            create_owned_directory(&output)?;
            continue;
        }
        if let Some(parent) = output.parent() {
            create_owned_directory(parent)?;
        }
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|error| verification_error("archive.extract.create", &error.to_string()))?;
        let copied = std::io::copy(&mut entry, &mut target)
            .map_err(|error| verification_error("archive.extract.write", &error.to_string()))?;
        if copied != size {
            return Err(verification_error(
                "archive.extract.truncated",
                "archive member size changed during extraction",
            ));
        }
        #[cfg(unix)]
        {
            let mode = entry.header().mode().ok();
            set_owned_file_permissions(&target, mode)?;
        }
    }
    Ok(())
}

fn stripped_archive_path(path: &Path, strip_components: u32) -> Result<Option<PathBuf>> {
    validate_archive_path(path)?;
    let components: Vec<_> = path.components().collect();
    let strip = strip_components as usize;
    if strip >= components.len() {
        return Ok(None);
    }
    let mut result = PathBuf::new();
    for component in &components[strip..] {
        if let Component::Normal(value) = component {
            result.push(value);
        } else {
            return Err(verification_error(
                "archive.path.component",
                "archive path contains a non-normal component",
            ));
        }
    }
    validate_archive_path(&result)?;
    Ok(Some(result))
}

fn create_owned_directory(path: &Path) -> Result<()> {
    reject_link(path)?;
    fs::create_dir_all(path)
        .map_err(|error| verification_error("archive.extract.directory", &error.to_string()))?;
    reject_link(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|error| {
            verification_error("archive.extract.permissions", &error.to_string())
        })?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_owned_file_permissions(file: &File, source_mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let executable = source_mode.is_some_and(|mode| mode & 0o111 != 0);
    let mode = if executable { 0o755 } else { 0o644 };
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| verification_error("archive.extract.permissions", &error.to_string()))?;
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    reject_link(path)?;
    fs::create_dir_all(path)
        .map_err(|error| verification_error("artifact.directory.create", &error.to_string()))?;
    reject_link(path)
}

fn reject_link(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(verification_error(
                    "artifact.path.inspect",
                    &error.to_string(),
                ));
            }
        };
        let is_link = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let is_link = {
            use std::os::windows::fs::MetadataExt;
            is_link || metadata.file_attributes() & 0x400 != 0
        };
        if is_link {
            return Err(verification_error(
                "artifact.path.symlink",
                "artifact destination contains a symlink or reparse point",
            ));
        }
    }
    Ok(())
}

fn validate_owned_component(value: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+-._".contains(character))
    {
        return Err(verification_error(
            "artifact.package_id.unsafe",
            "artifact package id is unsafe for an owned destination",
        ));
    }
    Ok(())
}

fn verify_native_signer(path: &Path, recipe: &ArtifactPlan) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if !matches!(
            recipe.format,
            siorb_catalog::ArtifactFormat::Msi
                | siorb_catalog::ArtifactFormat::Msix
                | siorb_catalog::ArtifactFormat::Exe
        ) {
            return Err(verification_error(
                "artifact.format.host_mismatch",
                "artifact format is not executable on Windows",
            ));
        }
        let expected = recipe.signer.as_deref().ok_or_else(|| {
            verification_error(
                "artifact.signer.missing",
                "Windows installer has no expected Authenticode signer",
            )
        })?;
        let system_root = std::env::var_os("SYSTEMROOT").ok_or_else(|| {
            verification_error("artifact.signer.tool", "SYSTEMROOT is unavailable")
        })?;
        let powershell =
            PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let command = CommandSpec {
            executable: powershell.display().to_string(),
            arguments: vec![
                "-NoLogo".to_owned(),
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                "$s=Get-AuthenticodeSignature -LiteralPath $env:SIORB_ARTIFACT; if($s.Status -ne 'Valid'){exit 41}; $s.SignerCertificate.Subject".to_owned(),
            ],
            redacted_arguments: vec![
                "-NoLogo".to_owned(), "-NoProfile".to_owned(), "-NonInteractive".to_owned(),
                "-Command".to_owned(), "<fixed Authenticode verification>".to_owned(),
            ],
            timeout_seconds: 30,
            max_output_bytes: 64 * 1024,
            requires_privilege: false,
            network: false,
            environment: vec![("SIORB_ARTIFACT".to_owned(), path.display().to_string())],
        };
        let output = run_bounded(&command, &ExecutionOptions::default())?;
        if !output.success || output.stdout.trim() != expected {
            return Err(verification_error(
                "artifact.signer.mismatch",
                "Authenticode signer does not exactly match catalog metadata",
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let expected = recipe.signer.as_deref().ok_or_else(|| {
            verification_error(
                "artifact.signer.missing",
                "macOS installer has no expected signing identity",
            )
        })?;
        if recipe.format == siorb_catalog::ArtifactFormat::Pkg {
            return verify_pkg_signer(path, expected);
        }
        if recipe.format != siorb_catalog::ArtifactFormat::Dmg {
            return Err(verification_error(
                "artifact.format.host_mismatch",
                "artifact format is not executable on macOS",
            ));
        }
        let verification = CommandSpec {
            executable: "/usr/bin/codesign".to_owned(),
            arguments: vec![
                "--verify".to_owned(),
                "--strict".to_owned(),
                "--deep".to_owned(),
                "--verbose=4".to_owned(),
                path.display().to_string(),
            ],
            redacted_arguments: vec![
                "--verify".to_owned(),
                "--strict".to_owned(),
                "--deep".to_owned(),
                "--verbose=4".to_owned(),
                path.display().to_string(),
            ],
            timeout_seconds: 30,
            max_output_bytes: 64 * 1024,
            requires_privilege: false,
            network: false,
            environment: vec![],
        };
        let verified = run_bounded(&verification, &ExecutionOptions::default())?;
        if !verified.success {
            return Err(verification_error(
                "artifact.signer.invalid",
                "strict code-signature verification failed",
            ));
        }
        let command = CommandSpec {
            executable: "/usr/bin/codesign".to_owned(),
            arguments: vec![
                "-d".to_owned(),
                "--verbose=4".to_owned(),
                path.display().to_string(),
            ],
            redacted_arguments: vec![
                "-d".to_owned(),
                "--verbose=4".to_owned(),
                path.display().to_string(),
            ],
            timeout_seconds: 30,
            max_output_bytes: 64 * 1024,
            requires_privilege: false,
            network: false,
            environment: vec![],
        };
        let output = run_bounded(&command, &ExecutionOptions::default())?;
        let detail = format!("{}\n{}", output.stdout, output.stderr);
        if !output.success
            || (!detail
                .lines()
                .any(|line| line.strip_prefix("Authority=") == Some(expected))
                && !detail
                    .lines()
                    .any(|line| line.strip_prefix("TeamIdentifier=") == Some(expected)))
        {
            return Err(verification_error(
                "artifact.signer.mismatch",
                "code-signing identity does not exactly match catalog metadata",
            ));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        match recipe.format {
            siorb_catalog::ArtifactFormat::Deb => {
                if recipe.signer.is_some() {
                    return Err(verification_error(
                        "artifact.signer.unsupported",
                        "DEB signer identity cannot be established from the package alone",
                    ));
                }
                Ok(())
            }
            siorb_catalog::ArtifactFormat::Rpm => verify_rpm_signer(path, recipe.signer.as_deref()),
            _ => Err(verification_error(
                "artifact.format.host_mismatch",
                "artifact format is not executable on this Linux host",
            )),
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_pkg_signer(path: &Path, expected: &str) -> Result<()> {
    let command = CommandSpec {
        executable: "/usr/sbin/pkgutil".to_owned(),
        arguments: vec!["--check-signature".to_owned(), path.display().to_string()],
        redacted_arguments: vec!["--check-signature".to_owned(), path.display().to_string()],
        timeout_seconds: 30,
        max_output_bytes: 64 * 1024,
        requires_privilege: false,
        network: false,
        environment: vec![],
    };
    let output = run_bounded(&command, &ExecutionOptions::default())?;
    let detail = format!("{}\n{}", output.stdout, output.stderr);
    let identity_matches = detail.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == expected
            || trimmed
                .split_once(". ")
                .is_some_and(|(_, identity)| identity == expected)
    });
    if !output.success || !identity_matches {
        return Err(verification_error(
            "artifact.signer.mismatch",
            "PKG signer does not exactly match catalog metadata",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn verify_rpm_signer(path: &Path, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if !matches!(expected.len(), 16 | 40 | 64)
        || !expected
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(verification_error(
            "artifact.signer.identity",
            "RPM signer identity must be a 16, 40, or 64 character hexadecimal key id",
        ));
    }
    let command = CommandSpec {
        executable: "/usr/bin/rpmkeys".to_owned(),
        arguments: vec![
            "--checksig".to_owned(),
            "--verbose".to_owned(),
            "--".to_owned(),
            path.display().to_string(),
        ],
        redacted_arguments: vec![
            "--checksig".to_owned(),
            "--verbose".to_owned(),
            "--".to_owned(),
            path.display().to_string(),
        ],
        timeout_seconds: 30,
        max_output_bytes: 64 * 1024,
        requires_privilege: false,
        network: false,
        environment: vec![],
    };
    let output = run_bounded(&command, &ExecutionOptions::default())?;
    let detail = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
    let expected = expected.to_ascii_lowercase();
    if !output.success
        || !detail
            .split(|character: char| !character.is_ascii_hexdigit())
            .any(|token| token == expected)
    {
        return Err(verification_error(
            "artifact.signer.mismatch",
            "RPM signature key does not exactly match catalog metadata",
        ));
    }
    Ok(())
}

fn run_native_installer(
    path: &Path,
    recipe: &ArtifactPlan,
    requires_privilege: bool,
    options: &ExecutionOptions,
) -> Result<BoundedOutput> {
    #[cfg(target_os = "macos")]
    if recipe.format == siorb_catalog::ArtifactFormat::Dmg {
        return run_dmg_installer(path, recipe, requires_privilege, options);
    }
    let command = native_installer_command(path, recipe, requires_privilege)?;
    run_bounded(&command, options)
}

fn native_installer_command(
    path: &Path,
    recipe: &ArtifactPlan,
    requires_privilege: bool,
) -> Result<CommandSpec> {
    #[cfg(target_os = "windows")]
    {
        let system_root = std::env::var_os("SYSTEMROOT").ok_or_else(|| {
            verification_error("artifact.installer.tool", "SYSTEMROOT is unavailable")
        })?;
        let system_root = PathBuf::from(system_root);
        let (executable, arguments, environment) = match recipe.format {
            siorb_catalog::ArtifactFormat::Msi => (
                system_root
                    .join("System32/msiexec.exe")
                    .display()
                    .to_string(),
                vec![
                    "/i".to_owned(),
                    path.display().to_string(),
                    "/qn".to_owned(),
                    "/norestart".to_owned(),
                ],
                vec![],
            ),
            siorb_catalog::ArtifactFormat::Msix => (
                system_root
                    .join("System32/WindowsPowerShell/v1.0/powershell.exe")
                    .display()
                    .to_string(),
                vec![
                    "-NoLogo".to_owned(),
                    "-NoProfile".to_owned(),
                    "-NonInteractive".to_owned(),
                    "-Command".to_owned(),
                    "Add-AppxPackage -LiteralPath $env:SIORB_ARTIFACT -ForceUpdateFromAnyVersion"
                        .to_owned(),
                ],
                vec![("SIORB_ARTIFACT".to_owned(), path.display().to_string())],
            ),
            siorb_catalog::ArtifactFormat::Exe => (
                path.display().to_string(),
                recipe.install_arguments.clone(),
                vec![],
            ),
            _ => {
                return Err(verification_error(
                    "artifact.format.host_mismatch",
                    "artifact format is not executable on Windows",
                ));
            }
        };
        let command = CommandSpec {
            executable,
            redacted_arguments: arguments.clone(),
            arguments,
            timeout_seconds: 1_800,
            max_output_bytes: 1024 * 1024,
            requires_privilege,
            network: false,
            environment,
        };
        command.validate()?;
        Ok(command)
    }
    #[cfg(target_os = "macos")]
    {
        if recipe.format != siorb_catalog::ArtifactFormat::Pkg {
            return Err(verification_error(
                "artifact.format.host_mismatch",
                "artifact format is not a directly installable PKG",
            ));
        }
        let arguments = vec![
            "-pkg".to_owned(),
            path.display().to_string(),
            "-target".to_owned(),
            "/".to_owned(),
        ];
        let command = CommandSpec {
            executable: "/usr/sbin/installer".to_owned(),
            redacted_arguments: arguments.clone(),
            arguments,
            timeout_seconds: 1_800,
            max_output_bytes: 1024 * 1024,
            requires_privilege,
            network: false,
            environment: vec![],
        };
        command.validate()?;
        Ok(command)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let (executable, arguments) = match recipe.format {
            siorb_catalog::ArtifactFormat::Deb => (
                "/usr/bin/dpkg".to_owned(),
                vec![
                    "--install".to_owned(),
                    "--".to_owned(),
                    path.display().to_string(),
                ],
            ),
            siorb_catalog::ArtifactFormat::Rpm => (
                "/usr/bin/rpm".to_owned(),
                vec![
                    "--upgrade".to_owned(),
                    "--replacepkgs".to_owned(),
                    "--".to_owned(),
                    path.display().to_string(),
                ],
            ),
            _ => {
                return Err(verification_error(
                    "artifact.format.host_mismatch",
                    "artifact format is not executable on this Linux host",
                ));
            }
        };
        let command = CommandSpec {
            executable,
            redacted_arguments: arguments.clone(),
            arguments,
            timeout_seconds: 1_800,
            max_output_bytes: 1024 * 1024,
            requires_privilege,
            network: false,
            environment: vec![],
        };
        command.validate()?;
        Ok(command)
    }
}

#[cfg(target_os = "macos")]
fn run_dmg_installer(
    path: &Path,
    recipe: &ArtifactPlan,
    requires_privilege: bool,
    options: &ExecutionOptions,
) -> Result<BoundedOutput> {
    let parent = path
        .parent()
        .ok_or_else(|| verification_error("artifact.dmg.path", "DMG staging path has no parent"))?;
    let mountpoint = create_isolated_directory(parent)?;
    let attach = CommandSpec {
        executable: "/usr/bin/hdiutil".to_owned(),
        arguments: vec![
            "attach".to_owned(),
            "-readonly".to_owned(),
            "-nobrowse".to_owned(),
            "-noautoopen".to_owned(),
            "-mountpoint".to_owned(),
            mountpoint.display().to_string(),
            path.display().to_string(),
        ],
        redacted_arguments: vec![
            "attach".to_owned(),
            "-readonly".to_owned(),
            "-nobrowse".to_owned(),
            "-noautoopen".to_owned(),
            "-mountpoint".to_owned(),
            mountpoint.display().to_string(),
            path.display().to_string(),
        ],
        timeout_seconds: 120,
        max_output_bytes: 128 * 1024,
        requires_privilege: false,
        network: false,
        environment: vec![],
    };
    let attached = match run_bounded(&attach, options) {
        Ok(output) => output,
        Err(error) => {
            let _ = fs::remove_dir(&mountpoint);
            return Err(error);
        }
    };
    if !attached.success {
        let _ = fs::remove_dir(&mountpoint);
        return Err(verification_error(
            "artifact.dmg.attach",
            "hdiutil could not attach the verified DMG read-only",
        ));
    }

    let install_result = (|| {
        let payload = mountpoint.join(recipe.payload_path.as_deref().ok_or_else(|| {
            verification_error("artifact.dmg.payload", "DMG recipe has no PKG payload path")
        })?);
        reject_link(&payload)?;
        if !payload.is_file() {
            return Err(verification_error(
                "artifact.dmg.payload",
                "declared DMG payload is not a regular PKG file",
            ));
        }
        verify_pkg_signer(
            &payload,
            recipe.signer.as_deref().ok_or_else(|| {
                verification_error("artifact.signer.missing", "DMG has no expected signer")
            })?,
        )?;
        let nested = ArtifactPlan {
            format: siorb_catalog::ArtifactFormat::Pkg,
            payload_path: None,
            ..recipe.clone()
        };
        let command = native_installer_command(&payload, &nested, requires_privilege)?;
        run_bounded(&command, options)
    })();

    let detach = |force: bool| {
        let mut arguments = vec!["detach".to_owned()];
        if force {
            arguments.push("-force".to_owned());
        }
        arguments.push(mountpoint.display().to_string());
        let command = CommandSpec {
            executable: "/usr/bin/hdiutil".to_owned(),
            redacted_arguments: arguments.clone(),
            arguments,
            timeout_seconds: 120,
            max_output_bytes: 128 * 1024,
            requires_privilege: false,
            network: false,
            environment: vec![],
        };
        run_bounded(&command, options)
    };
    let detached = match detach(false) {
        Ok(output) if output.success => Some(output),
        Ok(_) | Err(_) => match detach(true) {
            Ok(output) if output.success => Some(output),
            Ok(_) | Err(_) => None,
        },
    };
    if detached.is_none() {
        return Err(verification_error(
            "artifact.dmg.detach",
            "hdiutil could not detach the installer image",
        ));
    }
    let _ = fs::remove_dir(&mountpoint);
    install_result
}

fn validate_native_receipt_verification(plan: &ExecutionPlan) -> Result<()> {
    if !matches!(
        plan.operation,
        Operation::Install | Operation::Remove | Operation::Upgrade | Operation::Repair
    ) {
        return Ok(());
    }
    for package in &plan.packages {
        if package.backend == "artifact"
            || !package_requires_receipt_commit(plan, &package.logical_id)
        {
            continue;
        }
        let last_mutation = plan
            .steps
            .iter()
            .enumerate()
            .filter(|(_, step)| {
                step.package == package.logical_id
                    && step_commits_machine_state(plan.operation, step.kind)
            })
            .map(|(index, _)| index)
            .next_back();
        let Some(last_mutation) = last_mutation else {
            continue;
        };
        let verification = plan
            .steps
            .iter()
            .skip(last_mutation + 1)
            .find(|step| step.package == package.logical_id && step.kind == StepKind::Verify)
            .ok_or_else(|| {
                SiorbError::new(
                    ErrorKind::VerificationFailure,
                    format!(
                        "native mutation for `{}` has no following installed-state query",
                        package.logical_id
                    ),
                    "Regenerate the plan; do not execute or commit a receipt without post-operation verification.",
                )
                .with_reason("plan.verification.missing")
            })?;
        let read_only = verification.artifact.is_none()
            && verification.network_endpoints.is_empty()
            && verification
                .command
                .as_ref()
                .is_some_and(|command| !command.network && !command.requires_privilege);
        if !read_only {
            return Err(SiorbError::new(
                ErrorKind::VerificationFailure,
                format!(
                    "post-operation verification for `{}` is not read-only",
                    package.logical_id
                ),
                "Regenerate the plan; do not run a networked or privileged verification step.",
            )
            .with_reason("plan.verification.not_read_only"));
        }
    }
    Ok(())
}

fn validate_consent(plan: &ExecutionPlan, options: &ExecutionOptions) -> Result<()> {
    if plan.changes_machine()
        && options.policy_confirmation_required
        && !options.interactive_consent
    {
        return Err(SiorbError::new(
            ErrorKind::PolicyRejected,
            "active policy requires interactive confirmation for this exact plan",
            "Run the command in an interactive terminal, review the plan, and confirm the prompt.",
        )
        .with_reason("policy.confirmation.interactive_required"));
    }
    if plan.changes_machine() && !options.consent {
        return Err(SiorbError::new(
            ErrorKind::InvalidInput,
            "execution requires explicit consent after showing the plan",
            "Review the plan and use `--yes`, or keep `--dry-run`.",
        )
        .with_reason("execution.consent.required"));
    }
    if options.non_interactive && !options.consent && plan.changes_machine() {
        return Err(SiorbError::new(
            ErrorKind::InvalidInput,
            "non-interactive execution cannot prompt for consent",
            "Use `--yes` only after reviewing an equivalent plan.",
        )
        .with_reason("execution.non_interactive.consent"));
    }
    if plan.requires_agreements() && !options.accept_agreements {
        return Err(SiorbError::new(
            ErrorKind::InvalidInput,
            "the plan contains package agreements that were not accepted",
            "Review the agreements and pass `--accept-agreements` when permitted.",
        )
        .with_reason("execution.agreement.required"));
    }
    if plan.requires_privilege() && options.privilege_broker.is_none() {
        return Err(SiorbError::new(
            ErrorKind::PrivilegeDenied,
            "one or more steps require privilege and no per-step broker is available",
            "Install/configure sudo or doas, use user scope, or run a non-mutating plan.",
        )
        .with_reason("privilege.broker.absent"));
    }
    Ok(())
}

fn validate_offline(plan: &ExecutionPlan, options: &ExecutionOptions) -> Result<()> {
    if !options.offline {
        return Ok(());
    }
    let network_step = plan.steps.iter().find(|step| {
        matches!(step.kind, StepKind::Download)
            || step.command.as_ref().is_some_and(|command| command.network)
    });
    let Some(step) = network_step else {
        return Ok(());
    };
    Err(SiorbError::new(
        ErrorKind::InvalidInput,
        format!(
            "offline execution rejects network step `{}` for `{}`",
            step.id, step.package
        ),
        "Use a read-only/offline-capable backend plan or disable --offline after reviewing network access.",
    )
    .with_reason("execution.offline.network_forbidden"))
}

#[derive(Debug)]
struct BoundedOutput {
    success: bool,
    exit_code: Option<i32>,
    stdout_bytes: Vec<u8>,
    stderr_bytes: Vec<u8>,
    stdout: String,
    stderr: String,
    truncated: bool,
    timed_out: bool,
}

#[allow(clippy::too_many_lines)]
fn run_bounded(spec: &CommandSpec, options: &ExecutionOptions) -> Result<BoundedOutput> {
    spec.validate()?;
    let (program, arguments) = if spec.requires_privilege {
        let broker = options.privilege_broker.as_ref().ok_or_else(|| {
            SiorbError::new(
                ErrorKind::PrivilegeDenied,
                "privileged step has no broker",
                "Configure sudo/doas or choose user scope.",
            )
        })?;
        let broker = validate_broker(broker)?;
        let privileged_executable = trusted_privileged_executable(Path::new(&spec.executable))?;
        let mut args = Vec::with_capacity(spec.arguments.len() + 3);
        if options.non_interactive
            && broker.file_name().and_then(|name| name.to_str()) == Some("sudo")
        {
            args.push("--non-interactive".to_owned());
        }
        args.push("--".to_owned());
        args.push(privileged_executable.display().to_string());
        args.extend(spec.arguments.clone());
        (broker.display().to_string(), args)
    } else {
        (spec.executable.clone(), spec.arguments.clone())
    };

    let mut command = Command::new(&program);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in [
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for (key, value) in &spec.environment {
        if safe_environment_key(key) && !value.contains('\0') {
            command.env(key, value);
        }
    }
    let mut child = command.spawn().map_err(|error| {
        SiorbError::new(
            ErrorKind::BackendFailure,
            format!("failed to start backend executable `{program}`"),
            "Check backend installation, permissions, and the reviewed plan.",
        )
        .with_reason("backend.spawn.failed")
        .with_detail(error.to_string())
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| executor_internal("stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| executor_internal("stderr pipe unavailable"))?;
    let limit = spec.max_output_bytes / 2;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, limit));
    let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|error| executor_internal(&error.to_string()))?;
                break (status, true);
            }
            Err(error) => return Err(executor_internal(&error.to_string())),
        }
    };
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| executor_internal("stdout reader failed"))?
        .map_err(|error| executor_internal(&error.to_string()))?;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| executor_internal("stderr reader failed"))?
        .map_err(|error| executor_internal(&error.to_string()))?;
    let display_stdout = sanitize_terminal(&String::from_utf8_lossy(&stdout));
    let display_stderr = sanitize_terminal(&String::from_utf8_lossy(&stderr));
    Ok(BoundedOutput {
        success: status.success() && !timed_out,
        exit_code: status.code(),
        stdout_bytes: stdout,
        stderr_bytes: stderr,
        stdout: display_stdout,
        stderr: display_stderr,
        truncated: stdout_truncated || stderr_truncated,
        timed_out,
    })
}

fn read_bounded(mut reader: impl Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut stored = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(stored.len());
        let retain = remaining.min(count);
        stored.extend_from_slice(&buffer[..retain]);
        truncated |= retain < count;
    }
    Ok((stored, truncated))
}

fn classify_failure(spec: &CommandSpec, output: &BoundedOutput) -> SiorbError {
    let diagnostic = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
    let (kind, reason, next) = if output.timed_out {
        (
            ErrorKind::BackendFailure,
            "backend.timeout",
            "Check backend locks and network health, then create a fresh plan.",
        )
    } else if diagnostic.contains("permission denied") || diagnostic.contains("access is denied") {
        (
            ErrorKind::PrivilegeDenied,
            "backend.permission_denied",
            "Choose a permitted scope or configure per-step elevation.",
        )
    } else if diagnostic.contains("not found")
        || diagnostic.contains("no package")
        || diagnostic.contains("no such package")
        || diagnostic.contains("unable to locate")
    {
        (
            ErrorKind::UnresolvedPackage,
            "backend.package_not_found",
            "Refresh the native index and verify the exact catalog mapping.",
        )
    } else if diagnostic.contains("network")
        || diagnostic.contains("timed out")
        || diagnostic.contains("could not resolve")
        || diagnostic.contains("retrieving files from repository")
    {
        (
            ErrorKind::BackendFailure,
            "backend.network",
            "Restore upstream connectivity or retry in documented offline mode.",
        )
    } else if diagnostic.contains("agreement") || diagnostic.contains("license") {
        (
            ErrorKind::BackendFailure,
            "backend.agreement",
            "Review and explicitly accept required agreements.",
        )
    } else {
        (
            ErrorKind::BackendFailure,
            "backend.exit_failure",
            "Review the bounded diagnostic and backend-specific remediation.",
        )
    };
    SiorbError::new(
        kind,
        format!("backend `{}` exited unsuccessfully", spec.executable),
        next,
    )
    .with_reason(reason)
    .with_detail(format!(
        "exit={:?}; stdout={}; stderr={}; truncated={}",
        output.exit_code, output.stdout, output.stderr, output.truncated
    ))
}

fn validate_broker(path: &Path) -> Result<PathBuf> {
    let trusted = trusted_privileged_executable(path)?;
    let name = trusted.file_name().and_then(|name| name.to_str());
    if !matches!(name, Some("sudo" | "doas" | "sudo.exe")) {
        return Err(SiorbError::new(
            ErrorKind::PrivilegeDenied,
            "privilege broker is not an absolute sudo/doas executable",
            "Use the detected system privilege broker.",
        )
        .with_reason("privilege.broker.unsafe"));
    }
    Ok(trusted)
}

fn safe_environment_key(key: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "RUBYOPT",
        "PERL5OPT",
        "NODE_OPTIONS",
        "RUSTC_WRAPPER",
    ];
    !FORBIDDEN.contains(&key)
        && !key.is_empty()
        && key.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

fn executor_internal(detail: &str) -> SiorbError {
    SiorbError::new(
        ErrorKind::Internal,
        "bounded process supervision failed",
        "Preserve the journal and report this internal error.",
    )
    .with_reason("executor.internal")
    .with_detail(detail)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    pub max_entries: usize,
    pub max_uncompressed_bytes: u64,
    pub max_single_file_bytes: u64,
    pub max_compression_ratio: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_uncompressed_bytes: 2 * 1024 * 1024 * 1024,
            max_single_file_bytes: 512 * 1024 * 1024,
            max_compression_ratio: 200,
        }
    }
}

/// Verify a file against an exact lowercase or uppercase SHA-256 digest.
///
/// # Errors
///
/// Returns a verification error when the digest is malformed, the file cannot
/// be read, or its digest does not match.
pub fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    if expected.len() != 64 || !expected.chars().all(|value| value.is_ascii_hexdigit()) {
        return Err(verification_error(
            "artifact.digest.invalid",
            "expected SHA-256 is invalid",
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| verification_error("artifact.read", &error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| verification_error("artifact.read", &error.to_string()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(verification_error(
            "artifact.digest.mismatch",
            &format!("SHA-256 mismatch: expected {expected}, observed {actual}"),
        ));
    }
    Ok(())
}

/// Inspect a ZIP archive without extracting it, enforcing path and size limits.
///
/// # Errors
///
/// Returns a verification error for malformed archives, unsafe paths or entry
/// types, or any configured resource limit violation.
pub fn inspect_zip<R: Read + Seek>(reader: R, limits: &ArchiveLimits) -> Result<()> {
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|error| verification_error("archive.zip.invalid", &error.to_string()))?;
    if archive.len() > limits.max_entries {
        return Err(verification_error(
            "archive.entries.limit",
            "archive has too many entries",
        ));
    }
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| verification_error("archive.zip.entry", &error.to_string()))?;
        validate_archive_path(Path::new(entry.name()))?;
        if entry.size() > limits.max_single_file_bytes {
            return Err(verification_error(
                "archive.file.limit",
                "archive member exceeds size limit",
            ));
        }
        total = total.saturating_add(entry.size());
        if total > limits.max_uncompressed_bytes {
            return Err(verification_error(
                "archive.total.limit",
                "archive expands beyond total size limit",
            ));
        }
        if entry.compressed_size() > 0
            && entry.size() / entry.compressed_size() > limits.max_compression_ratio
        {
            return Err(verification_error(
                "archive.ratio.limit",
                "archive compression ratio is unsafe",
            ));
        }
        if entry.is_symlink() {
            return Err(verification_error(
                "archive.symlink.forbidden",
                "archive symlinks are forbidden",
            ));
        }
    }
    Ok(())
}

/// Inspect a TAR archive without extracting it, enforcing path and size limits.
///
/// # Errors
///
/// Returns a verification error for malformed archives, unsafe paths or entry
/// types, or any configured resource limit violation.
pub fn inspect_tar<R: Read>(reader: R, limits: &ArchiveLimits) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut count = 0_usize;
    let mut total = 0_u64;
    let entries = archive
        .entries()
        .map_err(|error| verification_error("archive.tar.invalid", &error.to_string()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| verification_error("archive.tar.entry", &error.to_string()))?;
        count += 1;
        if count > limits.max_entries {
            return Err(verification_error(
                "archive.entries.limit",
                "archive has too many entries",
            ));
        }
        let path = entry
            .path()
            .map_err(|error| verification_error("archive.path.invalid", &error.to_string()))?;
        validate_archive_path(&path)?;
        let size = entry.size();
        if size > limits.max_single_file_bytes {
            return Err(verification_error(
                "archive.file.limit",
                "archive member exceeds size limit",
            ));
        }
        total = total.saturating_add(size);
        if total > limits.max_uncompressed_bytes {
            return Err(verification_error(
                "archive.total.limit",
                "archive expands beyond total size limit",
            ));
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink()
            || kind.is_hard_link()
            || kind.is_block_special()
            || kind.is_character_special()
            || kind.is_fifo()
        {
            return Err(verification_error(
                "archive.special.forbidden",
                "archive special files and links are forbidden",
            ));
        }
    }
    Ok(())
}

/// Validate that an archive path is relative and cannot escape its destination.
///
/// # Errors
///
/// Returns a verification error for absolute, rooted, parent-traversing, or
/// platform-prefixed paths.
pub fn validate_archive_path(path: &Path) -> Result<()> {
    let Some(raw) = path.to_str() else {
        return Err(verification_error(
            "archive.path.encoding",
            "archive path is not valid Unicode",
        ));
    };
    let windows_reserved = |component: &str| {
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    };
    let unsafe_component = raw.split('/').any(|component| {
        component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with(' ')
            || component.ends_with('.')
            || windows_reserved(component)
    });
    if raw.starts_with("//")
        || raw.contains('\\')
        || raw.contains(':')
        || raw.chars().any(char::is_control)
        || unsafe_component
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || path.as_os_str().is_empty()
    {
        return Err(verification_error(
            "archive.path.traversal",
            "archive path escapes the extraction root",
        ));
    }
    Ok(())
}

/// Create a private, uniquely named directory beneath an existing parent.
///
/// # Errors
///
/// Returns a verification error when the parent is unsafe or the directory
/// cannot be created with private permissions.
pub fn create_isolated_directory(parent: &Path) -> Result<PathBuf> {
    let path = parent.join(format!("siorb-artifact-{}", siorb_core::correlation_id()));
    fs::create_dir(&path)
        .map_err(|error| verification_error("artifact.temp.create", &error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| verification_error("artifact.temp.permissions", &error.to_string()))?;
    }
    Ok(path)
}

fn verification_error(reason: &str, detail: &str) -> SiorbError {
    SiorbError::new(
        ErrorKind::VerificationFailure,
        detail,
        "Delete the untrusted artifact and use a verified source.",
    )
    .with_reason(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use siorb_core::Scope;
    use siorb_planner::{Reproducibility, RevalidationGuard};

    fn test_tempdir() -> std::io::Result<tempfile::TempDir> {
        if cfg!(target_os = "macos") {
            tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize()?)
        } else {
            tempfile::tempdir()
        }
    }

    fn bounded_output(stdout: &[u8]) -> BoundedOutput {
        BoundedOutput {
            success: true,
            exit_code: Some(0),
            stdout_bytes: stdout.to_vec(),
            stderr_bytes: Vec::new(),
            stdout: String::from_utf8_lossy(stdout).into_owned(),
            stderr: String::new(),
            truncated: false,
            timed_out: false,
        }
    }

    fn planned_package() -> PlannedPackage {
        PlannedPackage {
            requested: "ripgrep".to_owned(),
            logical_id: "ripgrep".to_owned(),
            source_id: "arch-pacman".to_owned(),
            backend: "pacman".to_owned(),
            native_id: "ripgrep".to_owned(),
            current_version: None,
            desired_version: Some(">=14,<15".to_owned()),
            scope: Scope::System,
            channel: "stable".to_owned(),
            architecture: siorb_core::Architecture::X86_64,
        }
    }

    fn plan(operation: Operation, steps: Vec<PlanStep>) -> ExecutionPlan {
        ExecutionPlan {
            schema_version: "1.0".to_owned(),
            plan_id: "plan-0123456789abcdef01234567".to_owned(),
            operation,
            requested: vec!["ripgrep".to_owned()],
            catalog_fingerprint: "catalog".to_owned(),
            platform_fingerprint: "platform".to_owned(),
            policy_fingerprint: Some("policy".to_owned()),
            created_at_unix: 1,
            reproducibility: Reproducibility::BestEffort,
            packages: vec![planned_package()],
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

    fn backend_step() -> PlanStep {
        PlanStep {
            id: "step-0001".to_owned(),
            package: "ripgrep".to_owned(),
            kind: StepKind::Backend,
            description: "test backend".to_owned(),
            command: None,
            artifact: None,
            network_endpoints: Vec::new(),
            expected_download_bytes: None,
            verification_requirements: Vec::new(),
            requires_privilege: false,
            agreements: Vec::new(),
            destructive: false,
            rollback_hint: String::new(),
        }
    }

    fn receipt() -> Receipt {
        Receipt {
            schema_version: "1.0".to_owned(),
            logical_id: "ripgrep".to_owned(),
            native_id: "ripgrep".to_owned(),
            backend: "pacman".to_owned(),
            source_id: "arch-pacman".to_owned(),
            requested_version: Some(">=14,<15".to_owned()),
            observed_version: None,
            scope: Scope::System,
            channel: "stable".to_owned(),
            architecture: "x86_64".to_owned(),
            catalog_fingerprint: "catalog".to_owned(),
            policy_fingerprint: Some("policy".to_owned()),
            installed_at_unix: 1,
            verification: VerificationRecord {
                status: VerificationStatus::Unavailable,
                checked_at_unix: 1,
                reason: "test".to_owned(),
            },
            owned_files: Vec::new(),
            transaction_id: "tx-old".to_owned(),
            origin: ReceiptOrigin::Installed,
        }
    }

    fn source() -> PackageSource {
        PackageSource {
            id: "arch-pacman".to_owned(),
            platform: "linux".to_owned(),
            distributions: vec!["arch".to_owned()],
            backend: "pacman".to_owned(),
            package_id: "ripgrep".to_owned(),
            trust: "native_trusted".to_owned(),
            scope: "system".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec!["x86_64".to_owned()],
            priority: 0,
            requires_privilege: false,
            provenance: "test".to_owned(),
            evidence: "test".to_owned(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: None,
        }
    }

    #[test]
    fn traversal_and_absolute_archive_paths_are_rejected() {
        assert!(validate_archive_path(Path::new("../escape")).is_err());
        assert!(validate_archive_path(Path::new("/absolute")).is_err());
        assert!(validate_archive_path(Path::new("safe/subdir/file")).is_ok());
    }

    #[test]
    fn unsafe_environment_names_are_rejected() {
        assert!(!safe_environment_key("LD_PRELOAD"));
        assert!(!safe_environment_key("bad-key"));
        assert!(safe_environment_key("LANG"));
    }

    #[test]
    fn backend_query_is_verified_from_bounded_raw_bytes() {
        let output = bounded_output(b"ripgrep 14.1.1-1\n");
        let result = verified_query_result("pacman", "ripgrep", Some(">=14,<15"), &output);
        assert_eq!(
            result
                .ok()
                .and_then(|result| result.observed_version)
                .as_deref(),
            Some("14.1.1-1")
        );

        let mismatch = verified_query_result("pacman", "ripgrep", Some("=13.0.0"), &output);
        assert_eq!(
            mismatch.err().map(|error| error.reason_code),
            Some("backend.verify.version_mismatch".to_owned())
        );
    }

    #[test]
    fn backend_failure_classifier_covers_conservative_package_and_network_phrases() {
        let spec = CommandSpec {
            executable: "/fixture/backend".to_owned(),
            arguments: Vec::new(),
            redacted_arguments: Vec::new(),
            timeout_seconds: 10,
            max_output_bytes: 1024,
            requires_privilege: false,
            network: false,
            environment: Vec::new(),
        };
        for (diagnostic, expected) in [
            ("firefox (no such package)", "backend.package_not_found"),
            (
                "Problem retrieving files from repository.",
                "backend.network",
            ),
        ] {
            let mut output = bounded_output(b"");
            output.success = false;
            output.exit_code = Some(1);
            output.stderr = diagnostic.to_owned();
            output.stderr_bytes = diagnostic.as_bytes().to_vec();
            assert_eq!(classify_failure(&spec, &output).reason_code, expected);
        }
    }

    #[test]
    fn truncated_query_output_is_never_accepted() {
        let mut output = bounded_output(b"ripgrep 14.1.1-1\n");
        output.truncated = true;
        let result = verified_query_result("pacman", "ripgrep", None, &output);
        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("backend.query.output_truncated".to_owned())
        );
    }

    #[test]
    fn download_and_verification_steps_are_not_committed_machine_state() {
        assert!(!step_commits_machine_state(
            Operation::Install,
            StepKind::Download
        ));
        assert!(!step_commits_machine_state(
            Operation::Verify,
            StepKind::Verify
        ));
        assert!(!step_commits_machine_state(
            Operation::Adopt,
            StepKind::Backend
        ));
        assert!(step_commits_machine_state(
            Operation::Install,
            StepKind::Backend
        ));
        assert_eq!(
            step_completion_state(Operation::Install, StepKind::Download),
            JournalState::VerificationCompleted
        );
    }

    #[test]
    fn offline_rejects_native_network_before_journaling() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let mut step = backend_step();
        step.command = Some(CommandSpec {
            executable: directory.path().join("must-not-run").display().to_string(),
            arguments: Vec::new(),
            redacted_arguments: Vec::new(),
            timeout_seconds: 10,
            max_output_bytes: 1024,
            requires_privilege: false,
            network: true,
            environment: Vec::new(),
        });
        let result = Executor::new(&state).execute(
            &plan(Operation::Install, vec![step]),
            &ExecutionOptions {
                consent: true,
                offline: true,
                ..ExecutionOptions::default()
            },
        );

        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("execution.offline.network_forbidden".to_owned())
        );
        assert_eq!(state.journal().ok().map(|events| events.len()), Some(0));
        assert_eq!(
            state.receipts().ok().map(|receipts| receipts.len()),
            Some(0)
        );
    }

    #[test]
    fn offline_rejects_artifact_download_before_journaling() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let mut step = backend_step();
        step.kind = StepKind::Download;
        let result = Executor::new(&state).execute(
            &plan(Operation::Install, vec![step]),
            &ExecutionOptions {
                consent: true,
                offline: true,
                ..ExecutionOptions::default()
            },
        );

        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("execution.offline.network_forbidden".to_owned())
        );
        assert_eq!(state.journal().ok().map(|events| events.len()), Some(0));
        assert_eq!(
            state.receipts().ok().map(|receipts| receipts.len()),
            Some(0)
        );
    }

    #[test]
    fn policy_confirmation_cannot_be_satisfied_by_presupplied_consent() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let result = Executor::new(&state).execute(
            &plan(Operation::Install, vec![backend_step()]),
            &ExecutionOptions {
                consent: true,
                interactive_consent: false,
                policy_confirmation_required: true,
                ..ExecutionOptions::default()
            },
        );

        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("policy.confirmation.interactive_required".to_owned())
        );
        assert_eq!(state.journal().ok().map(|events| events.len()), Some(0));
        assert_eq!(
            state.receipts().ok().map(|receipts| receipts.len()),
            Some(0)
        );
    }

    #[test]
    fn native_mutation_without_following_query_is_rejected_before_journaling() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let result = Executor::new(&state).execute(
            &plan(Operation::Install, vec![backend_step()]),
            &ExecutionOptions {
                consent: true,
                ..ExecutionOptions::default()
            },
        );
        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("plan.verification.missing".to_owned())
        );
        assert_eq!(state.journal().ok().map(|events| events.len()), Some(0));
        assert_eq!(state.receipts().ok().map(|values| values.len()), Some(0));
    }

    #[cfg(unix)]
    fn shell_step(id: &str, kind: StepKind, script: &str) -> PlanStep {
        PlanStep {
            id: id.to_owned(),
            package: "ripgrep".to_owned(),
            kind,
            description: id.to_owned(),
            command: Some(CommandSpec {
                executable: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), script.to_owned()],
                redacted_arguments: vec!["-c".to_owned(), "<test-script>".to_owned()],
                timeout_seconds: 10,
                max_output_bytes: 64 * 1024,
                requires_privilege: false,
                network: false,
                environment: Vec::new(),
            }),
            artifact: None,
            network_endpoints: Vec::new(),
            expected_download_bytes: None,
            verification_requirements: Vec::new(),
            requires_privilege: false,
            agreements: Vec::new(),
            destructive: false,
            rollback_hint: String::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn successful_native_mutation_commits_only_after_observed_version_verification() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let steps = vec![
            shell_step("step-0001", StepKind::Backend, "exit 0"),
            shell_step(
                "step-0001-verify",
                StepKind::Verify,
                "printf 'ripgrep 14.1.1-1\\n'",
            ),
        ];
        let report = Executor::new(&state).execute(
            &plan(Operation::Install, steps),
            &ExecutionOptions {
                consent: true,
                ..ExecutionOptions::default()
            },
        );
        assert!(report.is_ok());
        let receipts = state.receipts();
        assert!(receipts.is_ok());
        let Some(receipt) = receipts.ok().and_then(|mut values| values.pop()) else {
            return;
        };
        assert_eq!(receipt.observed_version.as_deref(), Some("14.1.1-1"));
        assert_eq!(receipt.verification.status, VerificationStatus::Verified);
        let journal = state.journal();
        assert!(journal.is_ok());
        let Some(journal) = journal.ok() else { return };
        let verification = journal
            .iter()
            .position(|event| event.state == JournalState::VerificationCompleted);
        let receipt_commit = journal
            .iter()
            .position(|event| event.state == JournalState::ReceiptCommitted);
        assert!(matches!(
            (verification, receipt_commit),
            (Some(verified), Some(committed)) if verified < committed
        ));
    }

    #[cfg(unix)]
    #[test]
    fn failed_post_mutation_query_is_partial_and_never_commits_a_receipt() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let steps = vec![
            shell_step("step-0001", StepKind::Backend, "exit 0"),
            shell_step(
                "step-0001-verify",
                StepKind::Verify,
                "printf 'not installed\\n'; exit 1",
            ),
        ];
        let result = Executor::new(&state).execute(
            &plan(Operation::Install, steps),
            &ExecutionOptions {
                consent: true,
                ..ExecutionOptions::default()
            },
        );
        assert!(result.is_err());
        let Some(error) = result.err() else { return };
        assert_eq!(error.kind, ErrorKind::PartialCompletion);
        assert!(error.state_changed);
        assert_eq!(error.reason_code, "execution.partial");
        assert_eq!(state.receipts().ok().map(|values| values.len()), Some(0));
        assert!(
            state
                .reconciliation_statuses()
                .is_ok_and(|statuses| statuses.iter().any(|status| status.required))
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_remove_retains_receipt_until_absence_is_verified() {
        let failed_directory = test_tempdir();
        assert!(failed_directory.is_ok());
        let Some(failed_directory) = failed_directory.ok() else {
            return;
        };
        let failed_state = StateStore::new(failed_directory.path().join("state"));
        assert!(failed_state.is_ok());
        let Some(failed_state) = failed_state.ok() else {
            return;
        };
        assert!(failed_state.write_receipt(&receipt()).is_ok());
        let still_installed = vec![
            shell_step("step-0001", StepKind::Backend, "exit 0"),
            shell_step(
                "step-0001-verify",
                StepKind::Verify,
                "printf 'ripgrep 14.1.1-1\\n'",
            ),
        ];
        let result = Executor::new(&failed_state).execute(
            &plan(Operation::Remove, still_installed),
            &ExecutionOptions {
                consent: true,
                ..ExecutionOptions::default()
            },
        );
        assert!(result.is_err());
        let Some(error) = result.err() else { return };
        assert_eq!(error.kind, ErrorKind::PartialCompletion);
        assert!(error.state_changed);
        assert_eq!(
            failed_state.receipts().ok().map(|values| values.len()),
            Some(1)
        );

        let success_directory = test_tempdir();
        assert!(success_directory.is_ok());
        let Some(success_directory) = success_directory.ok() else {
            return;
        };
        let success_state = StateStore::new(success_directory.path().join("state"));
        assert!(success_state.is_ok());
        let Some(success_state) = success_state.ok() else {
            return;
        };
        assert!(success_state.write_receipt(&receipt()).is_ok());
        let absent = vec![
            shell_step("step-0001", StepKind::Backend, "exit 0"),
            shell_step(
                "step-0001-verify",
                StepKind::Verify,
                "printf 'not installed\\n'; exit 1",
            ),
        ];
        let report = Executor::new(&success_state).execute(
            &plan(Operation::Remove, absent),
            &ExecutionOptions {
                consent: true,
                ..ExecutionOptions::default()
            },
        );
        assert!(report.is_ok());
        assert!(
            success_state
                .receipts()
                .is_ok_and(|values| values.is_empty())
        );
        let journal = success_state.journal();
        assert!(journal.is_ok());
        let Some(journal) = journal.ok() else { return };
        let verification = journal
            .iter()
            .position(|event| event.state == JournalState::VerificationCompleted);
        let receipt_commit = journal
            .iter()
            .position(|event| event.state == JournalState::ReceiptCommitted);
        assert!(matches!(
            (verification, receipt_commit),
            (Some(verified), Some(committed)) if verified < committed
        ));
    }

    #[test]
    fn native_receipt_requires_verified_observation_and_never_copies_requested_version() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let executor = Executor::new(&state);
        let mut install = plan(Operation::Install, vec![backend_step()]);
        install.packages[0].architecture = siorb_core::Architecture::Arm64;
        let changed = executor.commit_receipts(&install, "tx-test", &BTreeMap::new());
        assert_eq!(
            changed.err().map(|error| error.reason_code),
            Some("receipt.observation.missing".to_owned())
        );
        assert_eq!(state.receipts().ok().map(|values| values.len()), Some(0));

        let observation = BackendQueryResult {
            status: siorb_backends::QueryStatus::Installed,
            native_id: "ripgrep".to_owned(),
            observed_version: Some("14.1.1-1".to_owned()),
            reason_code: "backend.query.installed".to_owned(),
        };
        let observations = BTreeMap::from([("ripgrep".to_owned(), observation)]);
        let changed = executor.commit_receipts(&install, "tx-test", &observations);
        assert_eq!(changed.ok(), Some(true));
        let receipts = state.receipts();
        assert!(receipts.is_ok());
        let Some(receipt) = receipts.ok().and_then(|mut values| values.pop()) else {
            return;
        };
        assert_eq!(receipt.requested_version.as_deref(), Some(">=14,<15"));
        assert_eq!(receipt.observed_version.as_deref(), Some("14.1.1-1"));
        assert_eq!(receipt.architecture, "arm64");
        assert_eq!(receipt.verification.status, VerificationStatus::Verified);

        let adopted_directory = test_tempdir();
        assert!(adopted_directory.is_ok());
        let Some(adopted_directory) = adopted_directory.ok() else {
            return;
        };
        let adopted_state = StateStore::new(adopted_directory.path().join("state"));
        assert!(adopted_state.is_ok());
        let Some(adopted_state) = adopted_state.ok() else {
            return;
        };
        let adopted_executor = Executor::new(&adopted_state);
        let adoption_observation = BackendQueryResult {
            status: siorb_backends::QueryStatus::Installed,
            native_id: "ripgrep".to_owned(),
            observed_version: Some("14.1.1-1".to_owned()),
            reason_code: "backend.query.installed".to_owned(),
        };
        let observations = BTreeMap::from([("ripgrep".to_owned(), adoption_observation)]);
        let adopted = plan(Operation::Adopt, vec![backend_step()]);
        let changed = adopted_executor.commit_receipts(&adopted, "tx-adopt", &observations);
        assert_eq!(changed.ok(), Some(true));
        let receipts = adopted_state.receipts();
        assert!(receipts.is_ok());
        let Some(receipt) = receipts.ok().and_then(|mut values| values.pop()) else {
            return;
        };
        assert_eq!(receipt.observed_version.as_deref(), Some("14.1.1-1"));
        assert_eq!(receipt.verification.status, VerificationStatus::Verified);
    }

    #[test]
    fn receipt_verification_rejects_changed_mapping_before_execution() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let executor = Executor::new(&state);
        let mut changed = source();
        changed.package_id = "different-native-id".to_owned();
        let backend = BackendInfo {
            id: "pacman".to_owned(),
            executable: directory.path().join("missing").display().to_string(),
            version: None,
            available: true,
            capabilities: Vec::new(),
        };
        let result = executor.verify_receipt(&receipt(), &backend, &changed);
        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("receipt.query.mapping_changed".to_owned())
        );
        assert_eq!(state.receipts().ok().map(|values| values.len()), Some(0));
        assert_eq!(state.journal().ok().map(|values| values.len()), Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn receipt_verification_is_read_only_and_returns_observed_version() {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let state = StateStore::new(directory.path().join("state"));
        assert!(state.is_ok());
        let Some(state) = state.ok() else { return };
        let executable = directory.path().join("pacman-fixture");
        assert!(fs::write(&executable, b"#!/bin/sh\nprintf 'ripgrep 14.1.1-1\\n'\n").is_ok());
        let permissions = fs::Permissions::from_mode(0o700);
        assert!(fs::set_permissions(&executable, permissions).is_ok());
        let backend = BackendInfo {
            id: "pacman".to_owned(),
            executable: executable.display().to_string(),
            version: Some("test".to_owned()),
            available: true,
            capabilities: vec!["query_installed".to_owned()],
        };
        let executor = Executor::new(&state);
        let verified = executor.verify_receipt(&receipt(), &backend, &source());
        assert_eq!(
            verified
                .ok()
                .and_then(|value| value.observed_version)
                .as_deref(),
            Some("14.1.1-1")
        );
        assert_eq!(state.receipts().ok().map(|values| values.len()), Some(0));
        assert_eq!(state.journal().ok().map(|values| values.len()), Some(0));

        let mut step = backend_step();
        step.command = Some(CommandSpec {
            executable: executable.display().to_string(),
            arguments: Vec::new(),
            redacted_arguments: Vec::new(),
            timeout_seconds: 10,
            max_output_bytes: 64 * 1024,
            requires_privilege: false,
            network: false,
            environment: Vec::new(),
        });
        let report = executor.execute(
            &plan(Operation::Adopt, vec![step]),
            &ExecutionOptions {
                consent: true,
                ..ExecutionOptions::default()
            },
        );
        assert!(report.is_ok());
        let Some(report) = report.ok() else { return };
        assert!(report.state_changed);
        assert_eq!(
            report
                .steps
                .first()
                .and_then(|step| step.reason_code.as_deref()),
            Some("backend.query.installed")
        );
        let receipts = state.receipts();
        assert!(receipts.is_ok());
        assert_eq!(
            receipts
                .ok()
                .and_then(|mut values| values.pop())
                .and_then(|receipt| receipt.observed_version)
                .as_deref(),
            Some("14.1.1-1")
        );
    }

    fn artifact_recipe(
        format: siorb_catalog::ArtifactFormat,
        kind: siorb_catalog::ArtifactKind,
    ) -> ArtifactPlan {
        let signer = format
            .requires_package_signer()
            .then(|| "Expected Publisher".to_owned());
        ArtifactPlan {
            operation: Operation::Install,
            url: "https://downloads.example.org/payload".to_owned(),
            sha256: "0".repeat(64),
            signer,
            content_type: "application/octet-stream".to_owned(),
            max_bytes: 1024 * 1024,
            kind,
            format,
            archive_format: format.archive_name().map(str::to_owned),
            payload_path: (format == siorb_catalog::ArtifactFormat::Dmg)
                .then(|| "Packages/Example.pkg".to_owned()),
            strip_components: 0,
            install_arguments: Vec::new(),
            allowed_redirect_hosts: Vec::new(),
        }
    }

    #[test]
    fn typed_recipe_rejects_kind_confusion_and_option_injection() {
        let confused = artifact_recipe(
            siorb_catalog::ArtifactFormat::Msi,
            siorb_catalog::ArtifactKind::PortableArchive,
        );
        assert_eq!(
            validate_artifact_recipe(&confused)
                .err()
                .map(|error| error.reason_code),
            Some("artifact.recipe.type".to_owned())
        );

        let mut injected = artifact_recipe(
            siorb_catalog::ArtifactFormat::Exe,
            siorb_catalog::ArtifactKind::NativeInstaller,
        );
        injected.install_arguments = vec!["/quiet;calc.exe".to_owned()];
        assert_eq!(
            validate_artifact_recipe(&injected)
                .err()
                .map(|error| error.reason_code),
            Some("artifact.recipe.installer".to_owned())
        );
        injected.install_arguments = vec!["/quiet".to_owned(), "/norestart".to_owned()];
        assert!(validate_artifact_recipe(&injected).is_ok());
    }

    #[test]
    fn artifact_transport_rejects_non_public_hosts_before_network_or_state_access() {
        let mut recipe = artifact_recipe(
            siorb_catalog::ArtifactFormat::AppImage,
            siorb_catalog::ArtifactKind::PortableExecutable,
        );
        for url in [
            "https://localhost/tool.AppImage",
            "https://127.0.0.1/tool.AppImage",
            "https://10.0.0.1/tool.AppImage",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/tool.AppImage",
        ] {
            recipe.url = url.to_owned();
            let error = download_artifact(&recipe, Path::new("/state/must-not-be-created")).err();
            assert_eq!(
                error.map(|error| error.reason_code),
                Some("artifact.url.non_public_host".to_owned()),
                "{url}"
            );
        }

        recipe.url = "https://downloads.example.org/tool.AppImage".to_owned();
        recipe.allowed_redirect_hosts = vec!["192.168.1.10".to_owned()];
        assert_eq!(
            validate_artifact_recipe(&recipe)
                .err()
                .map(|error| error.reason_code),
            Some("artifact.recipe.redirect_host".to_owned())
        );
        recipe.allowed_redirect_hosts = vec!["cdn.example.org".to_owned()];
        assert!(validate_artifact_recipe(&recipe).is_ok());
    }

    #[test]
    fn executable_format_magic_is_checked_before_use() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let payload = directory.path().join("payload");
        assert!(fs::write(&payload, b"<html>not an installer</html>").is_ok());
        let limits = ArchiveLimits::default();
        for (format, kind) in [
            (
                siorb_catalog::ArtifactFormat::Msi,
                siorb_catalog::ArtifactKind::NativeInstaller,
            ),
            (
                siorb_catalog::ArtifactFormat::Exe,
                siorb_catalog::ArtifactKind::NativeInstaller,
            ),
            (
                siorb_catalog::ArtifactFormat::Pkg,
                siorb_catalog::ArtifactKind::NativeInstaller,
            ),
            (
                siorb_catalog::ArtifactFormat::Rpm,
                siorb_catalog::ArtifactKind::NativeInstaller,
            ),
            (
                siorb_catalog::ArtifactFormat::AppImage,
                siorb_catalog::ArtifactKind::PortableExecutable,
            ),
        ] {
            assert!(
                inspect_artifact_format(&payload, &artifact_recipe(format, kind), &limits).is_err(),
                "{format:?}"
            );
        }
    }

    #[test]
    fn typed_native_format_headers_are_recognized() {
        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let limits = ArchiveLimits::default();

        let msi = directory.path().join("fixture.msi");
        assert!(fs::write(&msi, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).is_ok());
        assert!(
            inspect_artifact_format(
                &msi,
                &artifact_recipe(
                    siorb_catalog::ArtifactFormat::Msi,
                    siorb_catalog::ArtifactKind::NativeInstaller,
                ),
                &limits,
            )
            .is_ok()
        );

        let exe = directory.path().join("fixture.exe");
        let mut pe = vec![0_u8; 128];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&64_u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        assert!(fs::write(&exe, pe).is_ok());
        assert!(
            inspect_artifact_format(
                &exe,
                &artifact_recipe(
                    siorb_catalog::ArtifactFormat::Exe,
                    siorb_catalog::ArtifactKind::NativeInstaller,
                ),
                &limits,
            )
            .is_ok()
        );

        for (name, prefix, format) in [
            (
                "fixture.pkg",
                b"xar!".as_slice(),
                siorb_catalog::ArtifactFormat::Pkg,
            ),
            (
                "fixture.rpm",
                [0xed, 0xab, 0xee, 0xdb].as_slice(),
                siorb_catalog::ArtifactFormat::Rpm,
            ),
        ] {
            let path = directory.path().join(name);
            assert!(fs::write(&path, prefix).is_ok());
            assert!(
                inspect_artifact_format(
                    &path,
                    &artifact_recipe(format, siorb_catalog::ArtifactKind::NativeInstaller),
                    &limits,
                )
                .is_ok()
            );
        }

        let dmg = directory.path().join("fixture.dmg");
        let mut image = vec![0_u8; 512];
        image[..4].copy_from_slice(b"koly");
        assert!(fs::write(&dmg, image).is_ok());
        assert!(
            inspect_artifact_format(
                &dmg,
                &artifact_recipe(
                    siorb_catalog::ArtifactFormat::Dmg,
                    siorb_catalog::ArtifactKind::NativeInstaller,
                ),
                &limits,
            )
            .is_ok()
        );

        let deb = directory.path().join("fixture.deb");
        let mut bytes = b"!<arch>\n".to_vec();
        for (name, data) in [
            ("debian-binary/", b"2.0\n".as_slice()),
            ("control.tar.gz/", b"".as_slice()),
            ("data.tar.gz/", b"".as_slice()),
        ] {
            let header = format!(
                "{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                "0",
                "0",
                "0",
                "100644",
                data.len()
            );
            assert_eq!(header.len(), 60);
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(data);
            if data.len() % 2 != 0 {
                bytes.push(b'\n');
            }
        }
        assert!(fs::write(&deb, bytes).is_ok());
        assert!(
            inspect_artifact_format(
                &deb,
                &artifact_recipe(
                    siorb_catalog::ArtifactFormat::Deb,
                    siorb_catalog::ArtifactKind::NativeInstaller,
                ),
                &limits,
            )
            .is_ok()
        );
    }

    #[test]
    fn msix_requires_the_declared_package_structure() {
        use zip::write::SimpleFileOptions;

        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let path = directory.path().join("fixture.msix");
        let file = File::create(&path);
        assert!(file.is_ok());
        let Some(file) = file.ok() else { return };
        let mut writer = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        assert!(writer.start_file("AppxManifest.xml", options).is_ok());
        assert!(writer.write_all(b"<Package />").is_ok());
        assert!(writer.start_file("[Content_Types].xml", options).is_ok());
        assert!(writer.write_all(b"<Types />").is_ok());
        assert!(writer.finish().is_ok());
        let recipe = artifact_recipe(
            siorb_catalog::ArtifactFormat::Msix,
            siorb_catalog::ArtifactKind::NativeInstaller,
        );
        assert!(inspect_artifact_format(&path, &recipe, &ArchiveLimits::default()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn appimage_is_committed_as_private_owned_executable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = test_tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let payload = directory.path().join("tool.AppImage");
        let mut bytes = vec![0_u8; 128];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[8..11].copy_from_slice(b"AI\x02");
        assert!(fs::write(&payload, &bytes).is_ok());
        let mut recipe = artifact_recipe(
            siorb_catalog::ArtifactFormat::AppImage,
            siorb_catalog::ArtifactKind::PortableExecutable,
        );
        recipe.sha256 = hex::encode(Sha256::digest(&bytes));
        assert!(inspect_artifact_format(&payload, &recipe, &ArchiveLimits::default()).is_ok());
        let state_root = directory.path().join("state");
        let installed = install_appimage(&payload, &recipe, &state_root, "example");
        assert!(installed.is_ok());
        let Some(installed) = installed.ok() else {
            return;
        };
        let executable = installed.join("example.AppImage");
        let metadata = fs::metadata(executable);
        assert!(metadata.is_ok());
        let Some(metadata) = metadata.ok() else {
            return;
        };
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[test]
    fn linux_native_formats_use_fixed_tools_and_arguments() {
        let deb = artifact_recipe(
            siorb_catalog::ArtifactFormat::Deb,
            siorb_catalog::ArtifactKind::NativeInstaller,
        );
        let command = native_installer_command(Path::new("/tmp/example.deb"), &deb, true);
        assert!(command.is_ok());
        let Some(command) = command.ok() else { return };
        assert_eq!(command.executable, "/usr/bin/dpkg");
        assert_eq!(
            command.arguments,
            ["--install", "--", "/tmp/example.deb"]
                .map(str::to_owned)
                .to_vec()
        );
        assert!(command.requires_privilege);

        let rpm = artifact_recipe(
            siorb_catalog::ArtifactFormat::Rpm,
            siorb_catalog::ArtifactKind::NativeInstaller,
        );
        let command = native_installer_command(Path::new("/tmp/example.rpm"), &rpm, true);
        assert!(command.is_ok());
        let Some(command) = command.ok() else { return };
        assert_eq!(command.executable, "/usr/bin/rpm");
        assert_eq!(
            command.arguments,
            ["--upgrade", "--replacepkgs", "--", "/tmp/example.rpm"]
                .map(str::to_owned)
                .to_vec()
        );
    }
}
