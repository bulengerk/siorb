//! Siorb command-line interface and orchestration boundary.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use serde::Serialize;
use serde_json::{Value, json};
use siorb_bundle::{
    Bundle, BundleLock, compare_locks, diff as bundle_diff, export_intent,
    resolve_bundle_with_context, write_bundle, write_lock,
};
use siorb_catalog::{Catalog, Lookup};
use siorb_core::{
    Architecture, CatalogIdentity, ErrorKind, ExitCode, JsonEnvelope, Operation, OutputStatus,
    PlatformContext, Scope, SiorbError,
};
use siorb_executor::{ExecutionOptions, Executor};
use siorb_planner::{ExecutionPlan, PlanOptions, Planner};
use siorb_platform::SystemDetector;
#[cfg(unix)]
use siorb_platform::trusted_privileged_executable;
use siorb_policy::{LayeredPolicy, PolicyFile};
use siorb_resolver::{Resolution, ResolutionContext, ResolveOptions, Resolver, VersionConstraint};
use siorb_state::StateStore;
use siorb_update::{
    DirectoryTransport, HttpsTransport, ReleaseTarget, RootMetadata, SelfUpdateDisposition, Signed,
    StaticTransport, extract_release_binary, install_current_executable, load_rollback_state,
    select_release_target, store_rollback_state, verify_from_transport,
};

#[derive(Parser, Debug)]
#[command(
    name = "siorb",
    about = "Explainable cross-platform package orchestration",
    disable_version_flag = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[arg(long, global = true)]
    dry_run: bool,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    non_interactive: bool,
    #[arg(long, global = true)]
    yes: bool,
    #[arg(long, global = true)]
    accept_agreements: bool,
    #[arg(long, global = true)]
    via: Option<String>,
    #[arg(long, global = true)]
    source: Option<String>,
    #[arg(long, global = true, value_enum, default_value_t = ScopeArg::Auto)]
    scope: ScopeArg,
    #[arg(long, global = true, default_value = "stable")]
    channel: String,
    #[arg(long = "version", global = true)]
    version_constraint: Option<String>,
    #[arg(long, global = true, value_enum)]
    arch: Option<ArchArg>,
    #[arg(long, global = true)]
    offline: bool,
    #[arg(long, global = true)]
    explain: bool,
    #[arg(long, global = true)]
    catalog: Option<String>,
    #[arg(long, global = true)]
    policy: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = ColorArg::Auto)]
    color: ColorArg,
    #[arg(long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ScopeArg {
    User,
    System,
    #[default]
    Auto,
}

impl From<ScopeArg> for Scope {
    fn from(value: ScopeArg) -> Self {
        match value {
            ScopeArg::User => Self::User,
            ScopeArg::System => Self::System,
            ScopeArg::Auto => Self::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ArchArg {
    #[value(alias = "amd64", alias = "x64")]
    X86_64,
    #[value(alias = "aarch64")]
    Arm64,
    X86,
    Arm,
}

impl From<ArchArg> for Architecture {
    fn from(value: ArchArg) -> Self {
        match value {
            ArchArg::X86_64 => Self::X86_64,
            ArchArg::Arm64 => Self::Arm64,
            ArchArg::X86 => Self::X86,
            ArchArg::Arm => Self::Arm,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ColorArg {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OperationArg {
    Install,
    Remove,
    Upgrade,
    Repair,
    Adopt,
    Verify,
}

impl From<OperationArg> for Operation {
    fn from(value: OperationArg) -> Self {
        match value {
            OperationArg::Install => Self::Install,
            OperationArg::Remove => Self::Remove,
            OperationArg::Upgrade => Self::Upgrade,
            OperationArg::Repair => Self::Repair,
            OperationArg::Adopt => Self::Adopt,
            OperationArg::Verify => Self::Verify,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    Install {
        packages: Vec<String>,
    },
    Remove {
        packages: Vec<String>,
    },
    Upgrade {
        packages: Vec<String>,
    },
    Search {
        query: String,
    },
    Info {
        package: String,
    },
    List,
    Plan {
        operation: OperationArg,
        arguments: Vec<String>,
    },
    Why {
        package: String,
    },
    Doctor,
    Adopt {
        packages: Vec<String>,
    },
    Reconcile,
    Repair {
        packages: Vec<String>,
    },
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
    Bundle {
        #[command(subcommand)]
        command: BundleCommand,
    },
    Pin {
        package: String,
        version: Option<String>,
    },
    Unpin {
        package: String,
    },
    Hold {
        package: String,
    },
    Unhold {
        package: String,
    },
    Backend {
        #[command(subcommand)]
        command: BackendCommand,
    },
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Audit,
    Verify {
        packages: Vec<String>,
    },
    #[command(name = "self")]
    SelfCommand {
        #[command(subcommand)]
        command: SelfSubcommand,
    },
    Completion {
        shell: Shell,
    },
    Version,
}

#[derive(Subcommand, Debug)]
enum MigrateCommand {
    Export {
        #[arg(long)]
        output: PathBuf,
    },
    Apply {
        file: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum BundleCommand {
    Validate {
        file: PathBuf,
    },
    Plan {
        file: PathBuf,
        #[arg(long)]
        profile: Option<String>,
    },
    Apply {
        file: PathBuf,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        lock: Option<PathBuf>,
    },
    Diff {
        file: PathBuf,
    },
    Lock {
        file: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        profile: Option<String>,
    },
    Refresh {
        file: PathBuf,
        #[arg(long)]
        lock: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum BackendCommand {
    List,
    Inspect { backend: String },
}

#[derive(Subcommand, Debug)]
enum SourceCommand {
    List { package: String },
}

#[derive(Subcommand, Debug)]
enum CatalogCommand {
    Status,
    Update,
    Verify { path: Option<PathBuf> },
    Use { path_or_url: String },
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    Validate { path: PathBuf },
    Explain { package: String },
}

#[derive(Subcommand, Debug)]
enum SelfSubcommand {
    Update,
}

#[derive(Debug)]
struct AppContext {
    platform: PlatformContext,
    catalog: Catalog,
    policy: LayeredPolicy,
    state: StateStore,
    installed: Vec<siorb_core::InstalledPackage>,
}

impl AppContext {
    fn load(cli: &Cli) -> siorb_core::Result<Self> {
        let platform = SystemDetector::default().offline(cli.offline).detect();
        let state = StateStore::discover()?;
        let catalog = load_catalog(cli.catalog.as_deref(), &state)?;
        let policy = load_policy(cli.policy.as_deref())?;
        let installed = state.installed_snapshot()?;
        Ok(Self {
            platform,
            catalog,
            policy,
            state,
            installed,
        })
    }
}

#[must_use]
pub fn main_entry() -> i32 {
    let arguments = shorthand_arguments(env::args_os().collect());
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let offline_requested = arguments.iter().any(|argument| argument == "--offline");
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::Success.as_i32();
            }
            if json_requested {
                emit_parse_error(&error, offline_requested);
            } else {
                let _ = error.print();
            }
            return ExitCode::InvalidInput.as_i32();
        }
    };
    if let Err(error) = validate_global_flags(&cli) {
        emit_early_error(&cli, &error);
        return error.exit_code().as_i32();
    }
    if matches!(cli.command, Commands::Version) && !cli.json {
        if !cli.quiet {
            println!("siorb {}", env!("CARGO_PKG_VERSION"));
        }
        return ExitCode::Success.as_i32();
    }
    let context = match AppContext::load(&cli) {
        Ok(context) => context,
        Err(error) => {
            emit_early_error(&cli, &error);
            return error.exit_code().as_i32();
        }
    };
    match dispatch(&cli, &context) {
        Ok(()) => ExitCode::Success.as_i32(),
        Err(error) => {
            emit_error(&cli, &context, &error);
            error.exit_code().as_i32()
        }
    }
}

fn emit_parse_error(error: &clap::Error, offline: bool) {
    let parse_error = SiorbError::new(
        ErrorKind::InvalidInput,
        "command-line arguments are invalid",
        "Correct the command syntax and retry; run `siorb --help` for usage.",
    )
    .with_reason("input.cli.parse")
    .with_detail(error.to_string());
    let envelope = JsonEnvelope {
        schema_version: siorb_core::SCHEMA_VERSION.to_owned(),
        command: "parse".to_owned(),
        status: OutputStatus::Error,
        correlation_id: siorb_core::correlation_id(),
        platform: SystemDetector::default().offline(offline).detect(),
        catalog: CatalogIdentity {
            id: "unavailable".to_owned(),
            version: 0,
            fingerprint: String::new(),
            verified: false,
            expires_unix: None,
            source: "unavailable".to_owned(),
        },
        policy: None,
        results: Value::Null,
        warnings: Vec::new(),
        errors: vec![parse_error],
    };
    if let Ok(encoded) = serde_json::to_string_pretty(&envelope) {
        println!("{encoded}");
    }
}

fn shorthand_arguments(mut arguments: Vec<OsString>) -> Vec<OsString> {
    const COMMANDS: &[&str] = &[
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
        "help",
    ];
    if let Some(value) = arguments.get(1).and_then(|value| value.to_str()) {
        if !value.starts_with('-') && !COMMANDS.contains(&value) {
            arguments.insert(1, OsString::from("install"));
        }
    }
    arguments
}

fn validate_global_flags(cli: &Cli) -> siorb_core::Result<()> {
    if cli.quiet && cli.verbose > 0 {
        return Err(input_error(
            "input.output.conflict",
            "--quiet cannot be combined with --verbose",
        ));
    }
    if cli.offline
        && cli
            .catalog
            .as_deref()
            .is_some_and(|value| value.starts_with("https://"))
    {
        return Err(input_error(
            "input.offline.catalog",
            "--offline cannot use an HTTPS catalog",
        ));
    }
    if cli.channel.trim().is_empty() || cli.channel.chars().any(char::is_control) {
        return Err(input_error(
            "input.channel.invalid",
            "channel must be printable and non-empty",
        ));
    }
    if cli.non_interactive && !cli.dry_run && !cli.yes && is_mutating(&cli.command) {
        return Err(input_error(
            "input.non_interactive.consent",
            "non-interactive mutation requires --yes after a reviewed equivalent plan",
        ));
    }
    Ok(())
}

fn is_mutating(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Install { .. }
            | Commands::Remove { .. }
            | Commands::Upgrade { .. }
            | Commands::Repair { .. }
            | Commands::Adopt { .. }
            | Commands::Reconcile
            | Commands::Pin { .. }
            | Commands::Unpin { .. }
            | Commands::Hold { .. }
            | Commands::Unhold { .. }
            | Commands::SelfCommand {
                command: SelfSubcommand::Update,
            }
            | Commands::Bundle {
                command: BundleCommand::Apply { .. }
                    | BundleCommand::Lock { .. }
                    | BundleCommand::Refresh { .. }
            }
            | Commands::Migrate {
                command: MigrateCommand::Apply { .. } | MigrateCommand::Export { .. }
            }
            | Commands::Catalog {
                command: CatalogCommand::Use { .. } | CatalogCommand::Update
            }
    )
}

fn dispatch(cli: &Cli, context: &AppContext) -> siorb_core::Result<()> {
    match &cli.command {
        Commands::Install { packages } => {
            handle_operation(cli, context, Operation::Install, packages, false)
        }
        Commands::Remove { packages } => {
            handle_operation(cli, context, Operation::Remove, packages, false)
        }
        Commands::Upgrade { packages } => {
            let packages = default_to_installed(packages, context);
            handle_operation(cli, context, Operation::Upgrade, &packages, false)
        }
        Commands::Search { query } => {
            let hits = context.catalog.search(query, 50)?;
            let human = if hits.is_empty() {
                format!("No local catalog results for `{query}`.")
            } else {
                hits.iter()
                    .map(|hit| format!("{:<28} {}", hit.id, hit.description))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            emit(cli, context, "search", OutputStatus::Success, &hits, &human)
        }
        Commands::Info { package } => {
            let manifest = exact_package(&context.catalog, package)?;
            emit(
                cli,
                context,
                "info",
                OutputStatus::Success,
                manifest,
                &format!(
                    "{} ({})\n{}\nlicense: {}\nhomepage: {}\nsources: {}",
                    manifest.name,
                    manifest.id,
                    manifest.description,
                    manifest.license,
                    manifest.homepage,
                    manifest.sources.len()
                ),
            )
        }
        Commands::List => {
            let human = if context.installed.is_empty() {
                "No Siorb receipts. Use `siorb adopt <package>` for exact external installations."
                    .to_owned()
            } else {
                context
                    .installed
                    .iter()
                    .map(|package| {
                        format!(
                            "{:<28} {:<12} {}",
                            package.logical_id,
                            package.backend,
                            package.version.as_deref().unwrap_or("unknown")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            emit(
                cli,
                context,
                "list",
                OutputStatus::Success,
                &context.installed,
                &human,
            )
        }
        Commands::Plan {
            operation,
            arguments,
        } => {
            let operation = Operation::from(*operation);
            let packages = if operation == Operation::Upgrade {
                default_to_installed(arguments, context)
            } else {
                arguments.clone()
            };
            handle_operation(cli, context, operation, &packages, true)
        }
        Commands::Why { package } => {
            let resolution = resolve_one(cli, context, package, Operation::Install)?;
            let selected = resolution
                .selected
                .as_ref()
                .map_or("none", |source| source.id.as_str());
            let rejected = resolution
                .evaluations
                .iter()
                .filter(|value| !value.accepted)
                .count();
            emit(
                cli,
                context,
                "why",
                if resolution.selected.is_some() {
                    OutputStatus::Success
                } else {
                    OutputStatus::NoChange
                },
                &resolution,
                &format!(
                    "{} -> {selected}; {rejected} candidate(s) rejected",
                    resolution.canonical_id
                ),
            )
        }
        Commands::Doctor => handle_doctor(cli, context),
        Commands::Adopt { packages } => {
            if packages.is_empty() {
                let result = json!({
                    "status": "selection_required",
                    "message": "Automatic broad adoption is intentionally disabled; exact identity confirmation is required.",
                    "next_action": "Run `siorb adopt <exact-package>` for each package to query."
                });
                emit(
                    cli,
                    context,
                    "adopt",
                    OutputStatus::NoChange,
                    &result,
                    result["message"].as_str().unwrap_or_default(),
                )
            } else {
                handle_operation(cli, context, Operation::Adopt, packages, false)
            }
        }
        Commands::Reconcile => handle_reconcile(cli, context),
        Commands::Repair { packages } => handle_operation(
            cli,
            context,
            Operation::Repair,
            &default_to_installed(packages, context),
            false,
        ),
        Commands::Migrate { command } => handle_migrate(cli, context, command),
        Commands::Bundle { command } => handle_bundle(cli, context, command),
        Commands::Pin { package, version } => {
            let canonical = exact_package(&context.catalog, package)?.id.clone();
            let effective_version = match version {
                Some(version) => {
                    VersionConstraint::parse(version)?;
                    version.clone()
                }
                None => context
                    .installed
                    .iter()
                    .find(|installed| installed.logical_id == canonical)
                    .and_then(|installed| installed.version.clone())
                    .ok_or_else(|| {
                        SiorbError::new(
                            ErrorKind::InvalidInput,
                            format!("cannot infer a pin version for `{canonical}`"),
                            "Install or adopt the package with an observed version, or pass an explicit version constraint.",
                        )
                        .with_reason("state.pin.version_unavailable")
                    })?,
            };
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "pin",
                    OutputStatus::Planned,
                    &json!({"package":canonical,"version":effective_version,"dry_run":true}),
                    &format!(
                        "Would pin `{canonical}` to `{effective_version}`; no preference state was changed (--dry-run)."
                    ),
                );
            }
            context
                .state
                .pin(&canonical, Some(effective_version.clone()))?;
            emit(
                cli,
                context,
                "pin",
                OutputStatus::Success,
                &json!({"package":canonical,"version":effective_version}),
                &format!("Pinned `{canonical}` to `{effective_version}`."),
            )
        }
        Commands::Unpin { package } => {
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "unpin",
                    OutputStatus::Planned,
                    &json!({"package":package,"dry_run":true}),
                    &format!(
                        "Would remove the pin for `{package}`; no preference state was changed (--dry-run)."
                    ),
                );
            }
            let changed = context.state.unpin(package)?;
            emit(
                cli,
                context,
                "unpin",
                if changed {
                    OutputStatus::Success
                } else {
                    OutputStatus::NoChange
                },
                &json!({"package":package,"changed":changed}),
                if changed {
                    "Pin removed."
                } else {
                    "Package was not pinned."
                },
            )
        }
        Commands::Hold { package } => {
            ensure_known_package(context, package)?;
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "hold",
                    OutputStatus::Planned,
                    &json!({"package":package,"dry_run":true}),
                    &format!(
                        "Would hold `{package}`; no preference state was changed (--dry-run)."
                    ),
                );
            }
            context.state.hold(package)?;
            emit(
                cli,
                context,
                "hold",
                OutputStatus::Success,
                &json!({"package":package}),
                &format!("Held `{package}`."),
            )
        }
        Commands::Unhold { package } => {
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "unhold",
                    OutputStatus::Planned,
                    &json!({"package":package,"dry_run":true}),
                    &format!(
                        "Would remove the hold for `{package}`; no preference state was changed (--dry-run)."
                    ),
                );
            }
            let changed = context.state.unhold(package)?;
            emit(
                cli,
                context,
                "unhold",
                if changed {
                    OutputStatus::Success
                } else {
                    OutputStatus::NoChange
                },
                &json!({"package":package,"changed":changed}),
                if changed {
                    "Hold removed."
                } else {
                    "Package was not held."
                },
            )
        }
        Commands::Backend { command } => handle_backend(cli, context, command),
        Commands::Source { command } => handle_source(cli, context, command),
        Commands::Catalog { command } => handle_catalog(cli, context, command),
        Commands::Policy { command } => handle_policy(cli, context, command),
        Commands::Audit => handle_audit(cli, context),
        Commands::Verify { packages } => handle_operation(
            cli,
            context,
            Operation::Verify,
            &default_to_installed(packages, context),
            false,
        ),
        Commands::SelfCommand {
            command: SelfSubcommand::Update,
        } => handle_self_update(cli, context),
        Commands::Completion { shell } => {
            let mut command = Cli::command();
            generate(*shell, &mut command, "siorb", &mut io::stdout());
            Ok(())
        }
        Commands::Version => {
            let result = json!({
                "version": env!("CARGO_PKG_VERSION"),
                "schema_version": siorb_core::SCHEMA_VERSION,
                "target": option_env!("TARGET").unwrap_or("unknown")
            });
            emit(
                cli,
                context,
                "version",
                OutputStatus::Success,
                &result,
                &format!("siorb {}", env!("CARGO_PKG_VERSION")),
            )
        }
    }
}

fn handle_operation(
    cli: &Cli,
    context: &AppContext,
    operation: Operation,
    packages: &[String],
    plan_only: bool,
) -> siorb_core::Result<()> {
    if packages.is_empty() {
        return Err(input_error(
            "input.packages.empty",
            "operation requires at least one package",
        ));
    }
    let resolver = Resolver::new(
        &context.catalog,
        &context.platform,
        &context.policy,
        &context.installed,
    );
    let options = resolve_options(cli);
    let resolution_context = resolution_context(cli.dry_run || plan_only);
    let resolutions: Vec<_> = packages
        .iter()
        .map(|package| {
            resolver.resolve_with_context(package, operation, &options, &resolution_context)
        })
        .collect::<siorb_core::Result<_>>()?;
    let planner = Planner::new(
        &context.platform,
        &context.catalog,
        &context.policy,
        &context.installed,
    );
    let plan = planner.build(
        operation,
        &resolutions,
        PlanOptions {
            non_interactive: cli.non_interactive,
            accept_agreements: cli.accept_agreements,
            target_architecture: cli
                .arch
                .map_or(context.platform.architecture, Architecture::from),
        },
    )?;
    if plan_only || cli.dry_run {
        let status = if plan.changes_machine() {
            OutputStatus::Planned
        } else {
            OutputStatus::NoChange
        };
        let human = format_plan_with_explanations(&plan, &resolutions, cli.explain, true);
        if cli.explain {
            return emit(
                cli,
                context,
                &format!("plan {operation}"),
                status,
                &json!({"plan":&plan,"resolutions":&resolutions}),
                &human,
            );
        }
        return emit(
            cli,
            context,
            &format!("plan {operation}"),
            status,
            &plan,
            &human,
        );
    }
    if !cli.json && !cli.quiet {
        println!(
            "{}",
            format_plan_with_explanations(&plan, &resolutions, cli.explain, false)
        );
    }
    let (consent, interactive_consent) = collect_mutation_consent(
        cli,
        context.policy.requires_interactive_confirmation() && plan.changes_machine(),
        || prompt_for_consent(cli, &plan),
    )?;
    let execution_context = AppContext::load(cli)?;
    plan.revalidate(
        &execution_context.platform,
        &execution_context.catalog,
        &execution_context.policy,
        &execution_context.installed,
    )?;
    let privilege_broker = detected_privilege_broker();
    let report = Executor::new(&execution_context.state).execute(
        &plan,
        &ExecutionOptions {
            consent,
            interactive_consent,
            policy_confirmation_required: execution_context
                .policy
                .requires_interactive_confirmation(),
            offline: cli.offline,
            non_interactive: cli.non_interactive,
            accept_agreements: cli.accept_agreements,
            privilege_broker,
        },
    )?;
    emit(
        cli,
        context,
        &operation.to_string(),
        if report.state_changed {
            OutputStatus::Success
        } else {
            OutputStatus::NoChange
        },
        &json!({"plan": plan, "execution": report, "resolutions": if cli.explain { Some(&resolutions) } else { None }}),
        if report.state_changed {
            "Plan completed and receipt state committed."
        } else {
            "Desired state already satisfied."
        },
    )
}

fn resolve_one(
    cli: &Cli,
    context: &AppContext,
    package: &str,
    operation: Operation,
) -> siorb_core::Result<Resolution> {
    Resolver::new(
        &context.catalog,
        &context.platform,
        &context.policy,
        &context.installed,
    )
    .resolve_with_context(
        package,
        operation,
        &resolve_options(cli),
        &resolution_context(true),
    )
}

fn resolve_options(cli: &Cli) -> ResolveOptions {
    ResolveOptions {
        via: cli.via.clone(),
        source: cli.source.clone(),
        scope: Scope::from(cli.scope),
        channel: cli.channel.clone(),
        version: cli.version_constraint.clone(),
        architecture: cli.arch.map(Architecture::from),
    }
}

fn resolution_context(dry_run: bool) -> ResolutionContext {
    ResolutionContext {
        dry_run,
        now_unix: Some(siorb_core::unix_timestamp()),
        network_urls: Vec::new(),
    }
}

fn default_to_installed(packages: &[String], context: &AppContext) -> Vec<String> {
    if packages.is_empty() {
        context
            .installed
            .iter()
            .map(|package| package.logical_id.clone())
            .collect()
    } else {
        packages.to_vec()
    }
}

fn handle_doctor(cli: &Cli, context: &AppContext) -> siorb_core::Result<()> {
    let available: Vec<_> = context
        .platform
        .backends
        .iter()
        .filter(|backend| backend.available)
        .collect();
    let mut remediation = Vec::new();
    if context.platform.os == siorb_core::OsFamily::Unknown {
        remediation.push("This operating-system family is not supported.".to_owned());
    }
    if available.is_empty() {
        remediation.push(
            "Install a supported native package backend or use a verified artifact mapping."
                .to_owned(),
        );
    }
    if !context.catalog.identity().verified {
        remediation.push(
            "The selected local catalog is valid but not authenticated by bundled trust metadata."
                .to_owned(),
        );
    }
    if !context.state.unfinished_transactions()?.is_empty() {
        remediation.push("Run `siorb reconcile` before starting a new mutation.".to_owned());
    }
    let result = json!({
        "platform": context.platform,
        "catalog": context.catalog.identity(),
        "state_directory": context.state.root(),
        "available_backends": available,
        "remediation": remediation,
        "mutated": false
    });
    let human = format!(
        "host: {} {}\narchitecture: {}\ndistribution: {}\navailable backends: {}\ncatalog: v{} ({})\n{}",
        context.platform.os,
        context.platform.os_version.as_deref().unwrap_or("unknown"),
        context.platform.architecture,
        context.platform.distribution.as_deref().unwrap_or("n/a"),
        available
            .iter()
            .map(|value| value.id.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        context.catalog.identity().version,
        if context.catalog.identity().verified {
            "verified"
        } else {
            "local/unverified"
        },
        remediation.join("\n")
    );
    emit(
        cli,
        context,
        "doctor",
        OutputStatus::Success,
        &result,
        &human,
    )
}

fn handle_reconcile(cli: &Cli, context: &AppContext) -> siorb_core::Result<()> {
    let statuses = context.state.transactions_requiring_reconciliation()?;
    let receipts = context.state.receipts()?;
    let executor = Executor::new(&context.state);
    let mut receipt_results = BTreeMap::new();
    let mut receipt_verification = Vec::new();
    let mut drift_plan = Vec::new();
    for receipt in &receipts {
        let result = verify_declared_receipt(context, &executor, receipt);
        match result {
            Ok(observed) => {
                receipt_results.insert(receipt.logical_id.clone(), true);
                receipt_verification.push(json!({
                    "package":receipt.logical_id,
                    "declared":true,
                    "verified":true,
                    "observed":observed
                }));
            }
            Err(error) => {
                let reason_code = error.reason_code.clone();
                receipt_results.insert(receipt.logical_id.clone(), false);
                receipt_verification.push(json!({
                    "package":receipt.logical_id,
                    "declared":true,
                    "verified":false,
                    "error":error
                }));
                drift_plan.push(json!({
                    "package":receipt.logical_id,
                    "operation":"repair-or-review",
                    "command":format!("siorb plan repair {}", receipt.logical_id),
                    "reason_code":reason_code
                }));
            }
        }
    }
    let mut verification = Vec::new();
    let mut verified_transactions = Vec::new();
    for status in &statuses {
        let transaction_receipts: Vec<_> = receipts
            .iter()
            .filter(|receipt| receipt.transaction_id == status.transaction_id)
            .collect();
        if transaction_receipts.is_empty() {
            verification.push(json!({
                "transaction_id":status.transaction_id,
                "verified":false,
                "reason":"no committed receipt identifies the interrupted mutation"
            }));
            continue;
        }
        let packages = transaction_receipts
            .iter()
            .map(|receipt| {
                let verified = receipt_results
                    .get(&receipt.logical_id)
                    .copied()
                    .unwrap_or(false);
                json!({"package":receipt.logical_id,"verified":verified})
            })
            .collect::<Vec<_>>();
        let transaction_verified = transaction_receipts.iter().all(|receipt| {
            receipt_results
                .get(&receipt.logical_id)
                .copied()
                .unwrap_or(false)
        });
        if transaction_verified {
            verified_transactions.push(status.transaction_id.clone());
        }
        verification.push(json!({
            "transaction_id":status.transaction_id,
            "verified":transaction_verified,
            "packages":packages
        }));
    }
    let mut reconciled = Vec::new();
    if !cli.dry_run && !verified_transactions.is_empty() {
        let (consent, _) = collect_mutation_consent(
            cli,
            context.policy.requires_interactive_confirmation(),
            || prompt_for_reconciliation(cli, verified_transactions.len()),
        )?;
        if !consent {
            return Err(input_error(
                "input.consent.required",
                "recording verified reconciliation requires confirmation or --yes",
            ));
        }
        for transaction_id in &verified_transactions {
            context.state.mark_reconciled(
                transaction_id,
                "all committed receipts were verified against current backend state",
            )?;
            reconciled.push(transaction_id.clone());
        }
    }
    let remaining = context.state.transactions_requiring_reconciliation()?;
    let result = json!({
        "transactions_before": statuses,
        "declared_receipts": receipt_verification,
        "verification": verification,
        "reconciled_transactions":reconciled,
        "remaining_transactions": remaining,
        "unknown_software_removed": false,
        "drift_plan":&drift_plan,
        "recommended_actions": [
            "Verify interrupted backend steps before retrying.",
            "Create a fresh install/remove plan for declared drift.",
            "Never remove unknown software automatically."
        ]
    });
    let output_status = if !reconciled.is_empty() {
        OutputStatus::Success
    } else if statuses.is_empty() && drift_plan.is_empty() {
        OutputStatus::NoChange
    } else {
        OutputStatus::Planned
    };
    emit(
        cli,
        context,
        "reconcile",
        output_status,
        &result,
        if output_status == OutputStatus::NoChange {
            "Declared receipts match current backend state; no unfinished transaction was found."
        } else if !reconciled.is_empty() {
            "Verified transaction receipts and recorded reconciliation; no unknown software was removed."
        } else {
            "Reconciliation is still required. Review the verification results; no unknown software was removed."
        },
    )
}

fn verify_declared_receipt(
    context: &AppContext,
    executor: &Executor<'_>,
    receipt: &siorb_state::Receipt,
) -> siorb_core::Result<Value> {
    let manifest = exact_package(&context.catalog, &receipt.logical_id)?;
    let source = manifest
        .sources
        .iter()
        .find(|source| source.id == receipt.source_id)
        .ok_or_else(|| {
            SiorbError::new(
                ErrorKind::VerificationFailure,
                "receipt source is absent from the active catalog",
                "Review the mapping change and create a fresh explicit plan.",
            )
            .with_reason("reconcile.receipt.source_missing")
        })?;
    if receipt.backend == "artifact" && source.backend == "artifact" {
        let owned_root = context.state.root().join("artifacts");
        if receipt.owned_files.is_empty()
            || receipt
                .owned_files
                .iter()
                .any(|owned| !artifact_owned_path_is_safe(Path::new(owned), &owned_root))
        {
            return Err(SiorbError::new(
                ErrorKind::VerificationFailure,
                "artifact receipt has missing or unsafe owned paths",
                "Do not remove unknown files; create a fresh repair plan.",
            )
            .with_reason("reconcile.artifact.owned_path"));
        }
        return Ok(json!({"kind":"artifact-owned-paths","paths":receipt.owned_files}));
    }
    let backend = context
        .platform
        .backend(source.tool_backend())
        .filter(|backend| backend.available)
        .ok_or_else(|| {
            SiorbError::new(
                ErrorKind::BackendAbsent,
                "receipt backend is unavailable",
                "Restore the exact backend or select a reviewed replacement source.",
            )
            .with_reason("reconcile.receipt.backend_missing")
        })?;
    executor
        .verify_receipt(receipt, backend, source)
        .map(|observed| json!({"kind":"native-backend-query","result":observed}))
}

fn artifact_owned_path_is_safe(path: &Path, owned_root: &Path) -> bool {
    if !path.starts_with(owned_root) {
        return false;
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        #[cfg(not(windows))]
        let linked = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let linked = {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            metadata.file_type().is_symlink()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        };
        if linked {
            return false;
        }
    }
    true
}

fn handle_migrate(
    cli: &Cli,
    context: &AppContext,
    command: &MigrateCommand,
) -> siorb_core::Result<()> {
    match command {
        MigrateCommand::Export { output } => {
            let bundle = export_intent(&context.installed);
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "migrate export",
                    OutputStatus::Planned,
                    &json!({"output":output,"packages":bundle.packages.len(),"bundle":bundle,"dry_run":true}),
                    &format!(
                        "Would export portable intent to {}; no file was written (--dry-run).",
                        output.display()
                    ),
                );
            }
            write_bundle(output, &bundle)?;
            emit(
                cli,
                context,
                "migrate export",
                OutputStatus::Success,
                &json!({"output":output,"packages":bundle.packages.len()}),
                &format!("Exported portable intent to {}.", output.display()),
            )
        }
        MigrateCommand::Apply { file } => apply_bundle(cli, context, file, None, None),
    }
}

fn handle_bundle(
    cli: &Cli,
    context: &AppContext,
    command: &BundleCommand,
) -> siorb_core::Result<()> {
    match command {
        BundleCommand::Validate { file } => {
            let bundle = Bundle::load(file)?;
            emit(
                cli,
                context,
                "bundle validate",
                OutputStatus::Success,
                &json!({"file":file,"valid":true,"packages":bundle.packages.len(),"profiles":bundle.profiles.keys().collect::<Vec<_>>()}),
                &format!(
                    "{} is valid ({} package intents).",
                    file.display(),
                    bundle.packages.len()
                ),
            )
        }
        BundleCommand::Plan { file, profile } => {
            plan_bundle(cli, context, file, profile.as_deref())
        }
        BundleCommand::Apply {
            file,
            profile,
            lock,
        } => apply_bundle(cli, context, file, profile.as_deref(), lock.as_deref()),
        BundleCommand::Diff { file } => {
            let bundle = Bundle::load(file)?;
            let difference = bundle_diff(&bundle, &context.installed);
            emit(
                cli,
                context,
                "bundle diff",
                OutputStatus::Success,
                &difference,
                &format!(
                    "install: {}\nremove: {}\nupgrade/verify: {}\nunchanged: {}",
                    difference.install.join(", "),
                    difference.remove.join(", "),
                    difference.upgrade_or_verify.join(", "),
                    difference.unchanged.join(", ")
                ),
            )
        }
        BundleCommand::Lock {
            file,
            output,
            profile,
        } => {
            let bundle = Bundle::load(file)?;
            let (lock, _) = resolve_bundle_with_context(
                &bundle,
                profile.as_deref(),
                &context.catalog,
                &context.platform,
                &context.policy,
                &context.installed,
                &resolution_context(true),
            )?;
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "bundle lock",
                    OutputStatus::Planned,
                    &json!({"output":output,"lock":lock,"dry_run":true}),
                    &format!(
                        "Would write deterministic lock to {}; no file was written (--dry-run).",
                        output.display()
                    ),
                );
            }
            write_lock(output, &lock)?;
            emit(
                cli,
                context,
                "bundle lock",
                OutputStatus::Success,
                &lock,
                &format!("Wrote deterministic lock to {}.", output.display()),
            )
        }
        BundleCommand::Refresh {
            file,
            lock,
            output,
            profile,
        } => {
            let bundle = Bundle::load(file)?;
            let previous = BundleLock::load(lock)?;
            previous.verify_intent(&bundle)?;
            previous.verify_profile(profile.as_deref())?;
            let (refreshed, _) = resolve_bundle_with_context(
                &bundle,
                profile.as_deref(),
                &context.catalog,
                &context.platform,
                &context.policy,
                &context.installed,
                &resolution_context(true),
            )?;
            let report = compare_locks(&previous, &refreshed);
            let destination = output.as_deref().unwrap_or(lock);
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "bundle refresh",
                    OutputStatus::Planned,
                    &json!({"output":destination,"lock":&refreshed,"changes":&report,"dry_run":true}),
                    &format!(
                        "Would refresh {}; no file was written (--dry-run).\n{}",
                        destination.display(),
                        report.human_readable()
                    ),
                );
            }
            write_lock(destination, &refreshed)?;
            emit(
                cli,
                context,
                "bundle refresh",
                OutputStatus::Success,
                &json!({"output":destination,"lock":&refreshed,"changes":&report}),
                &format!(
                    "Refreshed {}.\n{}",
                    destination.display(),
                    report.human_readable()
                ),
            )
        }
    }
}

fn plan_bundle(
    cli: &Cli,
    context: &AppContext,
    file: &Path,
    profile: Option<&str>,
) -> siorb_core::Result<()> {
    plan_bundle_with_lock(cli, context, file, profile, None)
}

fn plan_bundle_with_lock(
    cli: &Cli,
    context: &AppContext,
    file: &Path,
    profile: Option<&str>,
    lock_path: Option<&Path>,
) -> siorb_core::Result<()> {
    let bundle = Bundle::load(file)?;
    let (lock, operations) = resolve_bundle_with_context(
        &bundle,
        profile,
        &context.catalog,
        &context.platform,
        &context.policy,
        &context.installed,
        &resolution_context(true),
    )?;
    verify_supplied_lock(lock_path, &bundle, profile, context, &lock)?;
    let plans = build_bundle_plans(cli, context, &operations)?;
    emit(
        cli,
        context,
        "bundle plan",
        OutputStatus::Planned,
        &json!({"lock":lock,"plans":plans}),
        &plans
            .iter()
            .map(|plan| format_plan(plan, true))
            .collect::<Vec<_>>()
            .join("\n\n"),
    )
}

fn apply_bundle(
    cli: &Cli,
    context: &AppContext,
    file: &Path,
    profile: Option<&str>,
    lock_path: Option<&Path>,
) -> siorb_core::Result<()> {
    if cli.dry_run {
        return plan_bundle_with_lock(cli, context, file, profile, lock_path);
    }
    let bundle = Bundle::load(file)?;
    let (lock, operations) = resolve_bundle_with_context(
        &bundle,
        profile,
        &context.catalog,
        &context.platform,
        &context.policy,
        &context.installed,
        &resolution_context(false),
    )?;
    verify_supplied_lock(lock_path, &bundle, profile, context, &lock)?;
    let plans = build_bundle_plans(cli, context, &operations)?;
    if !cli.json && !cli.quiet {
        println!(
            "{}",
            plans
                .iter()
                .map(|plan| format_plan(plan, false))
                .collect::<Vec<_>>()
                .join("\n\n")
        );
    }
    let plans_change_machine = plans.iter().any(ExecutionPlan::changes_machine);
    let (consent, interactive_consent) = collect_mutation_consent(
        cli,
        context.policy.requires_interactive_confirmation() && plans_change_machine,
        || prompt_for_multiple(cli, &plans),
    )?;
    let execution_context = AppContext::load(cli)?;
    if lock_path.is_some() {
        lock.verify_context(
            &execution_context.catalog,
            &execution_context.platform,
            &execution_context.policy,
        )?;
        lock.verify_observed_versions(&execution_context.installed)?;
    }
    for plan in &plans {
        plan.revalidate(
            &execution_context.platform,
            &execution_context.catalog,
            &execution_context.policy,
            &execution_context.installed,
        )?;
    }
    let privilege_broker = detected_privilege_broker();
    let mut reports = Vec::new();
    for plan in &plans {
        reports.push(Executor::new(&execution_context.state).execute(
            plan,
            &ExecutionOptions {
                consent,
                interactive_consent,
                policy_confirmation_required:
                    execution_context.policy.requires_interactive_confirmation(),
                offline: cli.offline,
                non_interactive: cli.non_interactive,
                accept_agreements: cli.accept_agreements,
                privilege_broker: privilege_broker.clone(),
            },
        )?);
    }
    emit(
        cli,
        context,
        "bundle apply",
        OutputStatus::Success,
        &json!({"lock":lock,"plans":plans,"executions":reports}),
        "Bundle plans completed.",
    )
}

fn verify_supplied_lock(
    lock_path: Option<&Path>,
    bundle: &Bundle,
    profile: Option<&str>,
    context: &AppContext,
    refreshed: &BundleLock,
) -> siorb_core::Result<()> {
    let Some(lock_path) = lock_path else {
        return Ok(());
    };
    let supplied = BundleLock::load(lock_path)?;
    supplied.verify_intent(bundle)?;
    supplied.verify_profile(profile)?;
    supplied.verify_context(&context.catalog, &context.platform, &context.policy)?;
    supplied.verify_observed_versions(&context.installed)?;
    if &supplied != refreshed {
        return Err(SiorbError::new(
            ErrorKind::VerificationFailure,
            "bundle resolution no longer matches the supplied lock",
            "Run `siorb bundle refresh` and review its change report before applying.",
        )
        .with_reason("bundle.lock.resolution_changed"));
    }
    Ok(())
}

fn build_bundle_plans(
    cli: &Cli,
    context: &AppContext,
    operations: &[(Operation, Resolution)],
) -> siorb_core::Result<Vec<ExecutionPlan>> {
    let planner = Planner::new(
        &context.platform,
        &context.catalog,
        &context.policy,
        &context.installed,
    );
    let mut plans = Vec::new();
    let mut offset = 0;
    while offset < operations.len() {
        let operation = operations[offset].0;
        let end = operations[offset..]
            .iter()
            .position(|(candidate, _)| *candidate != operation)
            .map_or(operations.len(), |relative| offset + relative);
        let resolutions = operations[offset..end]
            .iter()
            .map(|(_, resolution)| resolution.clone())
            .collect::<Vec<_>>();
        plans.push(
            planner.build(
                operation,
                &resolutions,
                PlanOptions {
                    non_interactive: cli.non_interactive,
                    accept_agreements: cli.accept_agreements,
                    target_architecture: cli
                        .arch
                        .map_or(context.platform.architecture, Architecture::from),
                },
            )?,
        );
        offset = end;
    }
    Ok(plans)
}

fn detected_privilege_broker() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let candidates = [
            PathBuf::from("/usr/bin/sudo"),
            PathBuf::from("/bin/sudo"),
            PathBuf::from("/usr/bin/doas"),
            PathBuf::from("/bin/doas"),
            PathBuf::from("/usr/local/bin/doas"),
        ];
        trusted_privilege_broker_from(&candidates)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(unix)]
fn trusted_privilege_broker_from(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find_map(|candidate| trusted_privileged_executable(candidate).ok())
}

fn handle_backend(
    cli: &Cli,
    context: &AppContext,
    command: &BackendCommand,
) -> siorb_core::Result<()> {
    match command {
        BackendCommand::List => {
            let human = context
                .platform
                .backends
                .iter()
                .map(|backend| {
                    format!(
                        "{:<14} {:<11} {}",
                        backend.id,
                        if backend.available {
                            "available"
                        } else {
                            "missing"
                        },
                        backend.executable
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            emit(
                cli,
                context,
                "backend list",
                OutputStatus::Success,
                &context.platform.backends,
                &human,
            )
        }
        BackendCommand::Inspect { backend } => {
            let info = context
                .platform
                .backends
                .iter()
                .find(|value| value.id == *backend)
                .ok_or_else(|| {
                    input_error("backend.unknown", &format!("unknown backend `{backend}`"))
                })?;
            emit(
                cli,
                context,
                "backend inspect",
                OutputStatus::Success,
                info,
                &format!(
                    "{}: {}\nexecutable: {}\ncapabilities: {}",
                    info.id,
                    if info.available {
                        "available"
                    } else {
                        "missing"
                    },
                    info.executable,
                    info.capabilities.join(", ")
                ),
            )
        }
    }
}

fn handle_source(
    cli: &Cli,
    context: &AppContext,
    command: &SourceCommand,
) -> siorb_core::Result<()> {
    match command {
        SourceCommand::List { package } => {
            let manifest = exact_package(&context.catalog, package)?;
            let human = manifest
                .sources
                .iter()
                .map(|source| {
                    format!(
                        "{:<32} {:<18} {:<10} {}",
                        source.id, source.backend, source.platform, source.package_id
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            emit(
                cli,
                context,
                "source list",
                OutputStatus::Success,
                &manifest.sources,
                &human,
            )
        }
    }
}

fn handle_catalog(
    cli: &Cli,
    context: &AppContext,
    command: &CatalogCommand,
) -> siorb_core::Result<()> {
    match command {
        CatalogCommand::Status => {
            let identity = context.catalog.identity();
            let expired = identity
                .expires_unix
                .is_some_and(|expiry| expiry <= siorb_core::unix_timestamp());
            let result = json!({
                "identity": identity,
                "packages": context.catalog.packages().len(),
                "mappings": context.catalog.source_count(),
                "offline_usable": identity.verified && !expired,
                "expired": expired
            });
            emit(
                cli,
                context,
                "catalog status",
                OutputStatus::Success,
                &result,
                &format!(
                    "catalog v{}: {} packages, {} mappings, {}",
                    identity.version,
                    context.catalog.packages().len(),
                    context.catalog.source_count(),
                    if identity.verified {
                        "verified"
                    } else {
                        "not signature-authenticated"
                    }
                ),
            )
        }
        CatalogCommand::Verify { path } => verify_catalog_path(cli, context, path.as_deref()),
        CatalogCommand::Use { path_or_url } => {
            validate_catalog_source(path_or_url)?;
            if cli.dry_run {
                return emit(
                    cli,
                    context,
                    "catalog use",
                    OutputStatus::Planned,
                    &json!({"source":path_or_url,"activation":"not changed","dry_run":true}),
                    "Catalog source is valid; no source preference was changed (--dry-run).",
                );
            }
            let path = context.state.root().join("catalog-source");
            atomic_text_write(&path, path_or_url)?;
            emit(
                cli,
                context,
                "catalog use",
                OutputStatus::Success,
                &json!({"source":path_or_url,"activation":"next invocation"}),
                "Catalog source saved. The next update will authenticate it before activation.",
            )
        }
        CatalogCommand::Update => update_catalog(cli, context),
    }
}

fn verify_catalog_path(
    cli: &Cli,
    context: &AppContext,
    path: Option<&Path>,
) -> siorb_core::Result<()> {
    let path = path.unwrap_or_else(|| Path::new("catalog/fixtures/runtime-tuf/valid"));
    let result = if path.is_dir() && path.join("timestamp.json").exists() {
        let transport = DirectoryTransport::new(path.to_path_buf());
        let repository = verify_repository_transport(&transport, context.state.root())?;
        let bytes = fs::read(path.join("catalog.json"))
            .map_err(|error| catalog_io_error(&error.to_string()))?;
        repository.verify_target("catalog.json", &bytes)?;
        let catalog = Catalog::from_json(
            &String::from_utf8_lossy(&bytes),
            path.display().to_string(),
            true,
        )?;
        json!({"kind":"signed_repository","valid":true,"version":repository.state.targets,"packages":catalog.packages().len(),"mappings":catalog.source_count()})
    } else {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            format!("{} is not a complete signed catalog repository", path.display()),
            "Provide a directory containing timestamp, snapshot, targets, catalog, and the required root-rotation metadata.",
        )
        .with_reason("catalog.verify.signed_repository_required"));
    };
    emit(
        cli,
        context,
        "catalog verify",
        OutputStatus::Success,
        &result,
        &format!("{} validated successfully.", path.display()),
    )
}

fn update_catalog(cli: &Cli, context: &AppContext) -> siorb_core::Result<()> {
    let source = env::var("SIORB_CATALOG_MIRROR")
        .ok()
        .or_else(|| {
            fs::read_to_string(context.state.root().join("catalog-source"))
                .ok()
                .map(|value| value.trim().to_owned())
        })
        .ok_or_else(|| {
            SiorbError::new(
            ErrorKind::CatalogFailure,
            "no static catalog mirror is configured",
            "Run `siorb catalog use <local-directory-or-https-url>` or set SIORB_CATALOG_MIRROR.",
        ).with_reason("catalog.update.source_missing")
        })?;
    if cli.offline && source.starts_with("https://") {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "an HTTPS catalog update is unavailable in offline mode",
            "Use a complete local signed repository from removable media, or disable --offline.",
        )
        .with_reason("catalog.update.offline_remote"));
    }
    let transport: Box<dyn StaticTransport> = if source.starts_with("https://") {
        Box::new(HttpsTransport::new(&source, &[])?)
    } else {
        let directory = source.strip_prefix("file://").unwrap_or(&source);
        Box::new(DirectoryTransport::new(PathBuf::from(directory)))
    };
    let _update_lock = (!cli.dry_run)
        .then(|| CatalogUpdateLock::acquire(context.state.root()))
        .transpose()?;
    let repository = verify_repository_transport(transport.as_ref(), context.state.root())?;
    let catalog_bytes = transport.fetch("catalog.json", 64 * 1024 * 1024)?;
    repository.verify_target("catalog.json", &catalog_bytes)?;
    let catalog = Catalog::from_json(
        &String::from_utf8_lossy(&catalog_bytes),
        source.clone(),
        true,
    )?
    .with_authenticated_expiry(authenticated_repository_expiry(&repository));
    if cli.dry_run {
        return emit(
            cli,
            context,
            "catalog update",
            OutputStatus::Planned,
            &json!({"source":source,"cached":false,"packages":catalog.packages().len(),"mappings":catalog.source_count(),"versions":repository.state,"dry_run":true}),
            "Catalog metadata and target verified; no cache or rollback state was changed (--dry-run).",
        );
    }
    let (cache, cached_repository) = cache_verified_catalog_repository(
        transport.as_ref(),
        &repository,
        &catalog_bytes,
        context.state.root(),
    )?;
    emit(
        cli,
        context,
        "catalog update",
        OutputStatus::Success,
        &json!({"source":source,"cache":cache,"packages":catalog.packages().len(),"mappings":catalog.source_count(),"versions":cached_repository.state}),
        "Verified catalog update cached. It will become active on the next invocation.",
    )
}

fn authenticated_repository_expiry(repository: &siorb_update::VerifiedRepository) -> u64 {
    repository
        .root
        .signed
        .expires_unix
        .min(repository.timestamp.signed.expires_unix)
        .min(repository.snapshot.signed.expires_unix)
        .min(repository.targets.signed.expires_unix)
}

fn cache_verified_catalog_repository(
    transport: &dyn StaticTransport,
    repository: &siorb_update::VerifiedRepository,
    catalog_bytes: &[u8],
    state_root: &Path,
) -> siorb_core::Result<(PathBuf, siorb_update::VerifiedRepository)> {
    let cache_root = state_root.join("cache");
    let repository_name = format!(
        "repository-r{}-t{}-s{}-g{}-{}",
        repository.state.root,
        repository.state.timestamp,
        repository.state.snapshot,
        repository.state.targets,
        siorb_core::correlation_id()
    );
    validate_cache_component(&repository_name)?;
    let staging = cache_root.join(&repository_name);
    fs::create_dir(&staging).map_err(|error| catalog_io_error(&error.to_string()))?;
    #[cfg(unix)]
    set_private_directory_permissions(&staging)?;

    let result = (|| {
        let trusted_root = runtime_trusted_root()?;
        for version in (trusted_root.signed.version + 1)..=repository.root.signed.version {
            let name = format!("{version}.root.json");
            write_cache_file(&staging.join(&name), &transport.fetch(&name, 1024 * 1024)?)?;
        }

        write_cache_file(
            &staging.join("timestamp.json"),
            &transport.fetch("timestamp.json", 1024 * 1024)?,
        )?;
        let snapshot_name = if repository.root.signed.consistent_snapshot {
            format!("{}.snapshot.json", repository.snapshot.signed.version)
        } else {
            "snapshot.json".to_owned()
        };
        write_cache_file(
            &staging.join(&snapshot_name),
            &transport.fetch(&snapshot_name, 4 * 1024 * 1024)?,
        )?;
        let targets_name = if repository.root.signed.consistent_snapshot {
            format!("{}.targets.json", repository.targets.signed.version)
        } else {
            "targets.json".to_owned()
        };
        write_cache_file(
            &staging.join(&targets_name),
            &transport.fetch(&targets_name, 32 * 1024 * 1024)?,
        )?;
        write_cache_file(&staging.join("catalog.json"), catalog_bytes)?;

        let cached_transport = DirectoryTransport::new(staging.clone());
        let cached_repository = verify_repository_transport(&cached_transport, state_root)?;
        if cached_repository.state != repository.state {
            return Err(SiorbError::new(
                ErrorKind::CatalogFailure,
                "catalog mirror changed while an update was being cached",
                "Retry against a stable static mirror; the previous catalog remains active.",
            )
            .with_reason("catalog.cache.repository_changed"));
        }
        let cached_catalog = cached_transport.fetch("catalog.json", 64 * 1024 * 1024)?;
        cached_repository.verify_target("catalog.json", &cached_catalog)?;
        #[cfg(unix)]
        sync_directory(&staging)?;

        // Only a complete repository that re-verifies from the compiled trust
        // anchor is made active. The pointer is the atomic commit boundary.
        let active_pointer = cache_root.join("active-repository");
        if let Some(previous) = read_cache_pointer(&active_pointer)? {
            atomic_text_write(&cache_root.join("previous-repository"), &previous)?;
        }
        atomic_text_write(&active_pointer, &repository_name)?;
        store_rollback_state(&cache_root.join("rollback.json"), &cached_repository.state)?;
        Ok((staging.clone(), cached_repository))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn runtime_trusted_root() -> siorb_core::Result<Signed<RootMetadata>> {
    serde_json::from_slice(include_bytes!(
        "../../../catalog/trusted-root/runtime-root.json"
    ))
    .map_err(|error| catalog_io_error(&format!("runtime root is invalid: {error}")))
}

fn verify_repository_transport(
    transport: &dyn StaticTransport,
    state_root: &Path,
) -> siorb_core::Result<siorb_update::VerifiedRepository> {
    verify_repository_transport_with_state(transport, &state_root.join("cache/rollback.json"))
}

fn verify_repository_transport_with_state(
    transport: &dyn StaticTransport,
    rollback_path: &Path,
) -> siorb_core::Result<siorb_update::VerifiedRepository> {
    // The trust anchor is compiled in. A mirror can never replace it.
    let root = runtime_trusted_root()?;
    let state = load_rollback_state(rollback_path)?;
    verify_from_transport(transport, root, state, siorb_core::unix_timestamp())
}

fn handle_policy(
    cli: &Cli,
    context: &AppContext,
    command: &PolicyCommand,
) -> siorb_core::Result<()> {
    match command {
        PolicyCommand::Validate { path } => {
            let policy = PolicyFile::load(path)?;
            emit(
                cli,
                context,
                "policy validate",
                OutputStatus::Success,
                &json!({"path":path,"id":policy.id,"valid":true}),
                &format!("Policy {} is valid.", path.display()),
            )
        }
        PolicyCommand::Explain { package } => {
            let resolution = resolve_one(cli, context, package, Operation::Install)?;
            let decisions: Vec<_> = resolution.evaluations.iter().map(|evaluation| {
                json!({"source":evaluation.source.id,"allowed":evaluation.policy.allowed,"reasons":evaluation.policy.reasons})
            }).collect();
            emit(
                cli,
                context,
                "policy explain",
                OutputStatus::Success,
                &json!({"package":resolution.canonical_id,"policy":context.policy.identity(),"decisions":decisions}),
                &format!(
                    "Policy `{}` evaluated {} source(s); use --json for all reason codes.",
                    context.policy.identity().id,
                    decisions.len()
                ),
            )
        }
    }
}

fn handle_audit(cli: &Cli, context: &AppContext) -> siorb_core::Result<()> {
    let unfinished = context.state.unfinished_transactions()?;
    let mut findings = Vec::new();
    if !context.catalog.identity().verified {
        findings.push(json!({"severity":"warning","code":"audit.catalog.unverified","message":"selected catalog is not signature-authenticated"}));
    }
    if context
        .catalog
        .identity()
        .expires_unix
        .is_some_and(|expiry| expiry <= siorb_core::unix_timestamp())
    {
        findings.push(json!({"severity":"error","code":"audit.catalog.expired","message":"catalog metadata is expired"}));
    }
    for transaction in &unfinished {
        findings.push(json!({"severity":"warning","code":"audit.transaction.unfinished","transaction_id":transaction}));
    }
    for receipt in &context.installed {
        if matches!(
            context.catalog.lookup(&receipt.logical_id),
            Ok(Lookup::Missing)
        ) {
            findings.push(json!({"severity":"warning","code":"audit.receipt.catalog_missing","package":receipt.logical_id}));
        }
    }
    let status = if findings.is_empty() {
        OutputStatus::Success
    } else {
        OutputStatus::Partial
    };
    emit(
        cli,
        context,
        "audit",
        status,
        &json!({"findings":findings,"receipts_checked":context.installed.len(),"unknown_software_removed":false}),
        if findings.is_empty() {
            "Audit completed with no findings."
        } else {
            "Audit found issues; use --json for stable reason codes."
        },
    )
}

fn handle_self_update(cli: &Cli, context: &AppContext) -> siorb_core::Result<()> {
    context
        .policy
        .enforce_self_update_with_context(cli.dry_run)?;
    if cli.offline {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "self-update cannot fetch release targets in offline mode",
            "Install a locally verified release artifact or disable --offline.",
        )
        .with_reason("self_update.offline"));
    }
    let source = env::var("SIORB_RELEASE_MIRROR")
        .ok()
        .or_else(|| env::var("SIORB_CATALOG_MIRROR").ok())
        .or_else(|| {
            fs::read_to_string(context.state.root().join("catalog-source"))
                .ok()
                .map(|value| value.trim().to_owned())
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            SiorbError::new(
                ErrorKind::CatalogFailure,
                "no signed release mirror is configured",
                "Set SIORB_RELEASE_MIRROR to a signed static HTTPS repository or local test fixture.",
            )
            .with_reason("self_update.source_missing")
        })?;
    let transport: Box<dyn StaticTransport> = if source.starts_with("https://") {
        Box::new(HttpsTransport::new(&source, &[])?)
    } else {
        let directory = source.strip_prefix("file://").unwrap_or(&source);
        Box::new(DirectoryTransport::new(PathBuf::from(directory)))
    };
    let rollback_path = context.state.root().join("cache/release-rollback.json");
    let repository = verify_repository_transport_with_state(transport.as_ref(), &rollback_path)?;
    let Some(target) = select_release_target(
        &repository,
        env!("CARGO_PKG_VERSION"),
        context.platform.os,
        context.platform.architecture,
    )?
    else {
        return emit(
            cli,
            context,
            "self update",
            OutputStatus::NoChange,
            &json!({"current_version":env!("CARGO_PKG_VERSION"),"source":source,"update_available":false}),
            "Siorb is already up to date for this platform.",
        );
    };
    if cli.dry_run {
        return emit(
            cli,
            context,
            "self update",
            OutputStatus::Planned,
            &json!({"current_version":env!("CARGO_PKG_VERSION"),"source":source,"target":target,"verified_metadata":true,"downloaded":false}),
            &format!(
                "Signed Siorb {} is available as `{}`; no executable was downloaded or changed (--dry-run).",
                target.version, target.name
            ),
        );
    }
    let (consent, _interactive_consent) = collect_mutation_consent(
        cli,
        context.policy.requires_interactive_confirmation(),
        || prompt_for_self_update(cli, &target),
    )?;
    if !consent {
        return Err(input_error(
            "input.consent.required",
            "self-update requires explicit confirmation or --yes",
        ));
    }
    let maximum_bytes = usize::try_from(target.length).map_err(|_| {
        SiorbError::new(
            ErrorKind::CatalogFailure,
            "signed release target is too large for this platform",
            "Use a supported release target within the documented size boundary.",
        )
        .with_reason("self_update.size")
    })?;
    let archive = transport.fetch(&target.name, maximum_bytes)?;
    repository.verify_target(&target.name, &archive)?;
    let binary = extract_release_binary(&archive, &target)?;
    let disposition = install_current_executable(&binary)?;
    store_rollback_state(&rollback_path, &repository.state)?;
    let human = match disposition {
        SelfUpdateDisposition::Replaced => format!(
            "Siorb was atomically updated from {} to {}.",
            env!("CARGO_PKG_VERSION"),
            target.version
        ),
        SelfUpdateDisposition::ScheduledAfterExit => format!(
            "Siorb {} was verified and will replace the executable after this process exits.",
            target.version
        ),
    };
    emit(
        cli,
        context,
        "self update",
        OutputStatus::Success,
        &json!({"previous_version":env!("CARGO_PKG_VERSION"),"target":target,"source":source,"disposition":disposition}),
        &human,
    )
}

fn load_catalog(selection: Option<&str>, state: &StateStore) -> siorb_core::Result<Catalog> {
    let Some(selection) = selection else {
        let cache_root = state.root().join("cache");
        let active = load_cached_catalog_pointer(
            &cache_root.join("active-repository"),
            &cache_root,
            state.root(),
        );
        match active {
            Ok(Some(catalog)) => return Ok(catalog),
            Ok(None) => {}
            Err(active_error) => {
                if let Ok(Some(catalog)) = load_cached_catalog_pointer(
                    &cache_root.join("previous-repository"),
                    &cache_root,
                    state.root(),
                ) {
                    return Ok(catalog);
                }
                return Err(active_error);
            }
        }
        if let Some(catalog) = load_cached_catalog_pointer(
            &cache_root.join("previous-repository"),
            &cache_root,
            state.root(),
        )? {
            return Ok(catalog);
        }
        return Catalog::bundled();
    };
    if selection.starts_with("https://") {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "direct HTTPS catalog selection must be authenticated and cached before use",
            "Run `siorb catalog use URL` and `siorb catalog update`, then use the verified cache.",
        )
        .with_reason("catalog.remote.not_cached"));
    }
    let path = Path::new(selection.strip_prefix("file://").unwrap_or(selection));
    if !path.is_dir() || !path.join("timestamp.json").is_file() {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "explicit catalogs must be complete signed repository directories",
            "Use a signed repository directory, or omit --catalog to use the authenticated bundled/cache catalog.",
        )
        .with_reason("catalog.selection.unsigned"));
    }
    let transport = DirectoryTransport::new(path.to_path_buf());
    let repository = verify_repository_transport(&transport, state.root())?;
    let bytes = transport.fetch("catalog.json", 64 * 1024 * 1024)?;
    repository.verify_target("catalog.json", &bytes)?;
    Catalog::from_json(&String::from_utf8_lossy(&bytes), selection, true)
}

fn load_cached_catalog_pointer(
    pointer: &Path,
    cache_root: &Path,
    state_root: &Path,
) -> siorb_core::Result<Option<Catalog>> {
    let Some(repository_name) = read_cache_pointer(pointer)? else {
        return Ok(None);
    };
    let verified_cache = cache_root.join(repository_name);
    let metadata = fs::symlink_metadata(&verified_cache)
        .map_err(|error| catalog_io_error(&error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "the selected catalog cache is not a regular directory",
            "Remove the untrusted cache and run `siorb catalog update`.",
        )
        .with_reason("catalog.cache.file_type"));
    }
    let transport = DirectoryTransport::new(verified_cache.clone());
    let repository = verify_repository_transport(&transport, state_root)?;
    let catalog_bytes = transport.fetch("catalog.json", 64 * 1024 * 1024)?;
    repository.verify_target("catalog.json", &catalog_bytes)?;
    let catalog = Catalog::from_json(
        &String::from_utf8_lossy(&catalog_bytes),
        verified_cache.display().to_string(),
        true,
    )?
    .with_authenticated_expiry(authenticated_repository_expiry(&repository));
    // Recover safely if activation committed immediately before a process or
    // machine interruption.
    store_rollback_state(&cache_root.join("rollback.json"), &repository.state)?;
    Ok(Some(catalog))
}

fn read_cache_pointer(path: &Path) -> siorb_core::Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(catalog_io_error(&error.to_string())),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "a catalog cache pointer is not a regular file",
            "Remove the untrusted cache pointer and run `siorb catalog update`.",
        )
        .with_reason("catalog.cache.pointer_file_type"));
    }
    if metadata.len() > 256 {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "a catalog cache pointer exceeds its size boundary",
            "Remove the corrupt cache pointer and run `siorb catalog update`.",
        )
        .with_reason("catalog.cache.pointer_size"));
    }
    let value = fs::read_to_string(path).map_err(|error| catalog_io_error(&error.to_string()))?;
    let value = value.trim().to_owned();
    validate_cache_component(&value)?;
    Ok(Some(value))
}

fn load_policy(explicit: Option<&Path>) -> siorb_core::Result<LayeredPolicy> {
    let mut layers = vec![PolicyFile::secure_defaults()];
    let machine = if cfg!(windows) {
        env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Siorb/policy.toml"))
    } else {
        Some(PathBuf::from("/etc/siorb/policy.toml"))
    };
    if let Some(path) = machine.filter(|path| path.is_file()) {
        layers.push(PolicyFile::load(&path)?);
    }
    if let Some(path) = env::var_os("SIORB_ORG_POLICY").map(PathBuf::from) {
        layers.push(PolicyFile::load(&path)?);
    }
    if let Some(path) = user_policy_path().filter(|path| path.is_file()) {
        layers.push(PolicyFile::load(&path)?);
    }
    if let Some(path) = explicit {
        layers.push(PolicyFile::load(path)?);
    }
    LayeredPolicy::new(layers)
}

fn user_policy_path() -> Option<PathBuf> {
    if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Siorb/policy.toml"))
    } else if cfg!(target_os = "macos") {
        env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| path.join("Library/Application Support/Siorb/policy.toml"))
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|path| path.join(".config"))
            })
            .map(|path| path.join("siorb/policy.toml"))
    }
}

fn exact_package<'a>(
    catalog: &'a Catalog,
    request: &str,
) -> siorb_core::Result<&'a siorb_catalog::PackageManifest> {
    match catalog.lookup(request)? {
        Lookup::Exact(package) | Lookup::DeprecatedAlias(package) => Ok(package),
        Lookup::Ambiguous(packages) => Err(SiorbError::new(
            ErrorKind::AmbiguousPackage,
            format!(
                "`{request}` is ambiguous: {}",
                packages
                    .iter()
                    .map(|package| package.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "Use an exact canonical id.",
        )),
        Lookup::Missing => Err(SiorbError::new(
            ErrorKind::UnresolvedPackage,
            format!("catalog has no exact package `{request}`"),
            "Run `siorb search` and select an exact id.",
        )),
    }
}

fn ensure_known_package(context: &AppContext, package: &str) -> siorb_core::Result<()> {
    let _ = exact_package(&context.catalog, package)?;
    Ok(())
}

fn format_plan(plan: &ExecutionPlan, dry_run: bool) -> String {
    let mut lines = vec![format!(
        "PLAN {} {} [{}]",
        plan.operation,
        plan.requested.join(", "),
        plan.plan_id
    )];
    for package in &plan.packages {
        lines.push(format!(
            "  {} -> {} / {} ({}, {})",
            package.logical_id, package.backend, package.native_id, package.scope, package.channel
        ));
    }
    for step in &plan.steps {
        lines.push(format!("  {}: {}", step.id, step.description));
        if let Some(command) = &step.command {
            lines.push(format!(
                "    exec: {} {}",
                command.executable,
                command.redacted_arguments.join(" ")
            ));
        }
        if step.requires_privilege {
            lines.push("    privilege: per-step elevation required".to_owned());
        }
        if !step.agreements.is_empty() {
            lines.push(format!("    agreements: {}", step.agreements.join(", ")));
        }
    }
    if dry_run {
        lines.push("No changes made (plan/dry-run).".to_owned());
    }
    lines.join("\n")
}

fn format_plan_with_explanations(
    plan: &ExecutionPlan,
    resolutions: &[Resolution],
    explain: bool,
    dry_run: bool,
) -> String {
    let mut rendered = format_plan(plan, dry_run);
    if !explain {
        return rendered;
    }
    for resolution in resolutions {
        rendered.push_str(&format!(
            "\n\nRESOLUTION {} -> {}",
            resolution.request,
            resolution
                .selected
                .as_ref()
                .map_or("none", |source| source.id.as_str())
        ));
        for evaluation in &resolution.evaluations {
            if evaluation.accepted {
                rendered.push_str(&format!("\n  accepted: {}", evaluation.source.id));
            } else {
                let reasons = evaluation
                    .rejections
                    .iter()
                    .map(|rejection| rejection.code.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                rendered.push_str(&format!(
                    "\n  rejected: {} ({reasons})",
                    evaluation.source.id
                ));
            }
        }
    }
    rendered
}

fn prompt_for_self_update(cli: &Cli, target: &ReleaseTarget) -> siorb_core::Result<bool> {
    if cli.non_interactive || cli.json || !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!(
        "Replace the current Siorb executable with signed version {}? [y/N] ",
        target.version
    );
    io::stderr()
        .flush()
        .map_err(|error| input_error("input.prompt.write", &error.to_string()))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| input_error("input.prompt.read", &error.to_string()))?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn prompt_for_reconciliation(cli: &Cli, count: usize) -> siorb_core::Result<bool> {
    if cli.non_interactive || cli.json || !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Record {count} verified transaction reconciliation(s)? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| input_error("input.prompt.write", &error.to_string()))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| input_error("input.prompt.read", &error.to_string()))?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn prompt_for_consent(cli: &Cli, plan: &ExecutionPlan) -> siorb_core::Result<bool> {
    if !plan.changes_machine() {
        return Ok(true);
    }
    if cli.non_interactive || cli.json || !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Apply this exact plan? [y/N] ");
    io::stderr()
        .flush()
        .map_err(|error| input_error("input.prompt.write", &error.to_string()))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| input_error("input.prompt.read", &error.to_string()))?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn collect_mutation_consent<F>(
    cli: &Cli,
    policy_requires_interactive: bool,
    prompt: F,
) -> siorb_core::Result<(bool, bool)>
where
    F: FnOnce() -> siorb_core::Result<bool>,
{
    if policy_requires_interactive {
        let confirmed = prompt()?;
        if !confirmed {
            return Err(SiorbError::new(
                ErrorKind::PolicyRejected,
                "active policy requires interactive confirmation for this mutation",
                "Run the command in an interactive terminal, review the exact plan, and confirm the prompt.",
            )
            .with_reason("policy.confirmation.interactive_required"));
        }
        return Ok((true, true));
    }
    Ok((cli.yes || prompt()?, false))
}

fn prompt_for_multiple(cli: &Cli, plans: &[ExecutionPlan]) -> siorb_core::Result<bool> {
    if plans.iter().all(|plan| !plan.changes_machine()) {
        return Ok(true);
    }
    if cli.non_interactive || cli.json || !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Apply all {} exact plans in order? [y/N] ", plans.len());
    io::stderr()
        .flush()
        .map_err(|error| input_error("input.prompt.write", &error.to_string()))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| input_error("input.prompt.read", &error.to_string()))?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn emit<T: Serialize>(
    cli: &Cli,
    context: &AppContext,
    command: &str,
    status: OutputStatus,
    result: &T,
    human: &str,
) -> siorb_core::Result<()> {
    if cli.quiet && !cli.json && status != OutputStatus::Error {
        return Ok(());
    }
    if cli.json {
        let value = serde_json::to_value(result).map_err(|error| {
            SiorbError::new(
                ErrorKind::Internal,
                "failed to encode command result",
                "Report the command and preserve local diagnostics.",
            )
            .with_reason("output.json.encode")
            .with_detail(error.to_string())
        })?;
        let envelope = JsonEnvelope::success(
            command,
            status,
            context.platform.clone(),
            context.catalog.identity().clone(),
            Some(context.policy.identity().clone()),
            value,
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).map_err(|error| {
                SiorbError::new(
                    ErrorKind::Internal,
                    "failed to encode JSON envelope",
                    "Report the command and preserve local diagnostics.",
                )
                .with_reason("output.envelope.encode")
                .with_detail(error.to_string())
            })?
        );
    } else if !human.is_empty() {
        let color = matches!(cli.color, ColorArg::Always)
            || (matches!(cli.color, ColorArg::Auto) && io::stdout().is_terminal());
        if color {
            let code = match status {
                OutputStatus::Success => "32",
                OutputStatus::Planned | OutputStatus::NoChange => "36",
                OutputStatus::Partial => "33",
                OutputStatus::Error => "31",
            };
            println!("\u{1b}[{code}m{human}\u{1b}[0m");
        } else {
            println!("{human}");
        }
        if cli.verbose > 0 {
            println!(
                "context: platform={} catalog=v{}:{} policy={}",
                context.platform.fingerprint(),
                context.catalog.identity().version,
                short_digest(&context.catalog.identity().fingerprint),
                short_digest(&context.policy.identity().fingerprint)
            );
        }
    }
    Ok(())
}

fn short_digest(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}

fn emit_error(cli: &Cli, context: &AppContext, error: &SiorbError) {
    if cli.json {
        let envelope = JsonEnvelope {
            schema_version: siorb_core::SCHEMA_VERSION.to_owned(),
            command: command_name(&cli.command),
            status: OutputStatus::Error,
            correlation_id: siorb_core::correlation_id(),
            platform: context.platform.clone(),
            catalog: context.catalog.identity().clone(),
            policy: Some(context.policy.identity().clone()),
            results: Value::Null,
            warnings: Vec::new(),
            errors: vec![error.clone()],
        };
        if let Ok(encoded) = serde_json::to_string_pretty(&envelope) {
            println!("{encoded}");
        }
    } else {
        eprintln!("error: {}", error.message);
        if let Some(detail) = &error.detail {
            eprintln!("reason: {detail}");
        }
        eprintln!("state changed: {}", error.state_changed);
        eprintln!("next: {}", error.next_action);
        eprintln!("code: {}", error.reason_code);
    }
}

fn emit_early_error(cli: &Cli, error: &SiorbError) {
    if cli.json {
        let platform = SystemDetector::default().offline(cli.offline).detect();
        let envelope = JsonEnvelope {
            schema_version: siorb_core::SCHEMA_VERSION.to_owned(),
            command: command_name(&cli.command),
            status: OutputStatus::Error,
            correlation_id: siorb_core::correlation_id(),
            platform,
            catalog: CatalogIdentity {
                id: "unavailable".to_owned(),
                version: 0,
                fingerprint: String::new(),
                verified: false,
                expires_unix: None,
                source: "unavailable".to_owned(),
            },
            policy: None,
            results: Value::Null,
            warnings: Vec::new(),
            errors: vec![error.clone()],
        };
        if let Ok(encoded) = serde_json::to_string_pretty(&envelope) {
            println!("{encoded}");
        }
    } else {
        eprintln!("error: {} [{}]", error.message, error.reason_code);
        eprintln!("next: {}", error.next_action);
    }
}

fn command_name(command: &Commands) -> String {
    match command {
        Commands::Install { .. } => "install",
        Commands::Remove { .. } => "remove",
        Commands::Upgrade { .. } => "upgrade",
        Commands::Search { .. } => "search",
        Commands::Info { .. } => "info",
        Commands::List => "list",
        Commands::Plan { .. } => "plan",
        Commands::Why { .. } => "why",
        Commands::Doctor => "doctor",
        Commands::Adopt { .. } => "adopt",
        Commands::Reconcile => "reconcile",
        Commands::Repair { .. } => "repair",
        Commands::Migrate { .. } => "migrate",
        Commands::Bundle { .. } => "bundle",
        Commands::Pin { .. } => "pin",
        Commands::Unpin { .. } => "unpin",
        Commands::Hold { .. } => "hold",
        Commands::Unhold { .. } => "unhold",
        Commands::Backend { .. } => "backend",
        Commands::Source { .. } => "source",
        Commands::Catalog { .. } => "catalog",
        Commands::Policy { .. } => "policy",
        Commands::Audit => "audit",
        Commands::Verify { .. } => "verify",
        Commands::SelfCommand { .. } => "self update",
        Commands::Completion { .. } => "completion",
        Commands::Version => "version",
    }
    .to_owned()
}

fn validate_catalog_source(source: &str) -> siorb_core::Result<()> {
    if source.starts_with("https://") {
        if source.contains('@') || source.contains('#') || source.chars().any(char::is_control) {
            return Err(input_error(
                "catalog.source.unsafe",
                "HTTPS catalog URL contains credentials, fragment, or control data",
            ));
        }
        return Ok(());
    }
    let path = source.strip_prefix("file://").unwrap_or(source);
    if Path::new(path).is_dir() {
        Ok(())
    } else {
        Err(input_error(
            "catalog.source.missing",
            "catalog source must be an existing local directory or credential-free HTTPS URL",
        ))
    }
}

fn atomic_text_write(path: &Path, value: &str) -> siorb_core::Result<()> {
    atomic_bytes_write(path, value.as_bytes())
}

fn atomic_bytes_write(path: &Path, value: &[u8]) -> siorb_core::Result<()> {
    #[cfg(windows)]
    {
        use atomicwrites::{AllowOverwrite, AtomicFile};

        AtomicFile::new(path, AllowOverwrite)
            .write(|file| {
                file.write_all(value)?;
                file.sync_all()
            })
            .map_err(|error| {
                let error: io::Error = error.into();
                catalog_io_error(&error.to_string())
            })
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let temporary = path.with_extension(format!("tmp-{}", siorb_core::correlation_id()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| catalog_io_error(&error.to_string()))?;
        if let Err(error) = file.write_all(value).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(catalog_io_error(&error.to_string()));
        }
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(catalog_io_error(&error.to_string()));
        }
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| catalog_io_error(&error.to_string()))?;
        }
        Ok(())
    }
}

fn validate_cache_component(value: &str) -> siorb_core::Result<()> {
    if value.is_empty()
        || value.len() > 160
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._".contains(character))
    {
        return Err(SiorbError::new(
            ErrorKind::CatalogFailure,
            "the active catalog cache pointer is unsafe",
            "Remove the cache pointer and run `siorb catalog update`.",
        )
        .with_reason("catalog.cache.pointer_unsafe"));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> siorb_core::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| catalog_io_error(&error.to_string()))?;
    Ok(())
}

#[derive(Debug)]
struct CatalogUpdateLock {
    path: PathBuf,
    file: Option<fs::File>,
}

impl CatalogUpdateLock {
    fn acquire(state_root: &Path) -> siorb_core::Result<Self> {
        let path = state_root.join("cache/catalog-update.lock");
        match open_catalog_lock(&path) {
            Ok(file) => Ok(Self {
                path,
                file: Some(file),
            }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|error| catalog_io_error(&error.to_string()))?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(SiorbError::new(
                        ErrorKind::CatalogFailure,
                        "the catalog update lock is not a regular file",
                        "Remove the untrusted state entry before retrying the update.",
                    )
                    .with_reason("catalog.update.lock_file_type"));
                }
                Err(SiorbError::new(
                    ErrorKind::CatalogFailure,
                    "another catalog update is already in progress or left a stale lock",
                    "Wait for the update to finish; after a confirmed crash, remove cache/catalog-update.lock and retry.",
                )
                .with_reason("catalog.update.locked"))
            }
            Err(error) => Err(catalog_io_error(&error.to_string())),
        }
    }
}

impl Drop for CatalogUpdateLock {
    fn drop(&mut self) {
        let _ = self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}

fn open_catalog_lock(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    writeln!(
        file,
        "pid={} created={}",
        std::process::id(),
        siorb_core::unix_timestamp()
    )?;
    file.sync_all()?;
    Ok(file)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> siorb_core::Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| catalog_io_error(&error.to_string()))?;
    Ok(())
}

fn write_cache_file(path: &Path, value: &[u8]) -> siorb_core::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| catalog_io_error(&error.to_string()))?;
    file.write_all(value)
        .and_then(|()| file.sync_all())
        .map_err(|error| catalog_io_error(&error.to_string()))
}

fn input_error(reason: &str, message: &str) -> SiorbError {
    SiorbError::new(
        ErrorKind::InvalidInput,
        message,
        "Review `siorb help` and provide compatible, explicit input.",
    )
    .with_reason(reason)
}

fn catalog_io_error(message: &str) -> SiorbError {
    SiorbError::new(
        ErrorKind::CatalogFailure,
        message,
        "Check catalog path, permissions, static metadata, and signatures.",
    )
    .with_reason("catalog.io")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_tempdir() -> std::io::Result<tempfile::TempDir> {
        if cfg!(target_os = "macos") {
            tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize()?)
        } else {
            tempfile::tempdir()
        }
    }

    #[test]
    fn shorthand_inserts_install_for_exact_first_token() {
        let values =
            shorthand_arguments(vec!["siorb".into(), "firefox".into(), "--dry-run".into()]);
        assert_eq!(
            values.get(1).and_then(|value| value.to_str()),
            Some("install")
        );
    }

    #[test]
    fn catalog_cache_pointer_accepts_only_one_safe_component() {
        assert!(validate_cache_component("repository-r1-t2-s3-g4-abc123").is_ok());
        for unsafe_value in ["", ".", "..", "../old", "nested/repository", "repo\nother"] {
            assert!(validate_cache_component(unsafe_value).is_err());
        }
    }

    #[test]
    fn authenticated_catalog_cache_rejects_payload_tampering() {
        let temporary = state_tempdir();
        assert!(temporary.is_ok());
        let Some(temporary) = temporary.ok() else {
            return;
        };
        let state = StateStore::new(temporary.path().join("state"));
        assert!(state.is_ok(), "state initialization failed: {state:?}");
        let Some(state) = state.ok() else {
            return;
        };
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/fixtures/runtime-tuf/valid");
        let transport = DirectoryTransport::new(fixture);
        let repository = verify_repository_transport(&transport, state.root());
        assert!(
            repository.is_ok(),
            "catalog repository verification failed: {repository:?}"
        );
        let Some(repository) = repository.ok() else {
            return;
        };
        let catalog_bytes = transport.fetch("catalog.json", 64 * 1024 * 1024);
        assert!(catalog_bytes.is_ok());
        let Some(catalog_bytes) = catalog_bytes.ok() else {
            return;
        };
        let cached = cache_verified_catalog_repository(
            &transport,
            &repository,
            &catalog_bytes,
            state.root(),
        );
        assert!(cached.is_ok());
        let Some((cache, _)) = cached.ok() else {
            return;
        };
        assert!(load_catalog(None, &state).is_ok());
        assert!(fs::write(cache.join("catalog.json"), b"{}").is_ok());
        let tampered = load_catalog(None, &state);
        assert!(tampered.is_err());
        assert!(fs::write(cache.join("catalog.json"), &catalog_bytes).is_ok());
        let replacement = cache_verified_catalog_repository(
            &transport,
            &repository,
            &catalog_bytes,
            state.root(),
        );
        assert!(replacement.is_ok());
        let Some((replacement, _)) = replacement.ok() else {
            return;
        };
        assert!(fs::write(replacement.join("catalog.json"), b"{}").is_ok());
        assert!(load_catalog(None, &state).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn privilege_broker_selection_rejects_user_controlled_candidates() {
        let temporary = tempfile::tempdir();
        assert!(temporary.is_ok());
        let Some(temporary) = temporary.ok() else {
            return;
        };
        let fake = temporary.path().join("sudo");
        assert!(fs::write(&fake, b"fixture").is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(fs::set_permissions(&fake, fs::Permissions::from_mode(0o777)).is_ok());
        }
        assert!(trusted_privilege_broker_from(&[fake]).is_none());
    }

    #[test]
    fn catalog_updates_are_serialized_by_a_private_lock() {
        let temporary = state_tempdir();
        assert!(temporary.is_ok());
        let Some(temporary) = temporary.ok() else {
            return;
        };
        let state = StateStore::new(temporary.path().join("state"));
        assert!(state.is_ok(), "state initialization failed: {state:?}");
        let Some(state) = state.ok() else {
            return;
        };
        let first = CatalogUpdateLock::acquire(state.root());
        assert!(first.is_ok());
        assert!(CatalogUpdateLock::acquire(state.root()).is_err());
        drop(first);
        assert!(CatalogUpdateLock::acquire(state.root()).is_ok());
    }

    #[test]
    fn command_names_are_not_rewritten() {
        let values = shorthand_arguments(vec!["siorb".into(), "search".into(), "browser".into()]);
        assert_eq!(
            values.get(1).and_then(|value| value.to_str()),
            Some("search")
        );
    }

    #[test]
    fn all_documented_global_flags_parse() {
        let parsed = Cli::try_parse_from([
            "siorb",
            "install",
            "firefox",
            "--dry-run",
            "--json",
            "--non-interactive",
            "--yes",
            "--accept-agreements",
            "--via",
            "apt",
            "--source",
            "firefox-apt",
            "--scope",
            "system",
            "--channel",
            "stable",
            "--version",
            ">=1",
            "--arch",
            "x86-64",
            "--offline",
            "--explain",
            "--color",
            "never",
        ]);
        assert!(parsed.is_ok());
    }

    #[test]
    fn yes_does_not_bypass_policy_required_interaction() {
        let cli = Cli::try_parse_from(["siorb", "--yes", "--non-interactive", "self", "update"]);
        assert!(cli.is_ok());
        let Some(cli) = cli.ok() else { return };
        let result = collect_mutation_consent(&cli, true, || Ok(false));
        assert_eq!(
            result.err().map(|error| error.reason_code),
            Some("policy.confirmation.interactive_required".to_owned())
        );
    }
}
