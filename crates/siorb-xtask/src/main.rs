mod benchmark;
mod release;
mod repository;
mod support;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

type DynError = Box<dyn Error + Send + Sync + 'static>;
type Result<T> = std::result::Result<T, DynError>;

#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    about = "Siorb repository validation, generation, benchmarks, and release automation",
    arg_required_else_help = true
)]
pub(crate) struct Xtask {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate repository contracts, generated output, scripts, schemas, tests, and fuzz targets.
    Verify,
    /// Validate versioned JSON schemas and their positive/negative fixture corpus.
    TestSchemas,
    /// Validate semantic catalog sources, signed fixtures, and Rust catalog/update tests.
    TestCatalog,
    /// Validate generated CLI help, Markdown links, and documented command syntax.
    TestDocs,
    /// Generate and validate the backend-free static catalog website.
    BuildSite,
    /// Generate deterministic catalog indexes and signed-update development fixtures.
    GenerateCatalog,
    /// Generate the CLI reference directly from the compiled command model.
    GenerateDocs {
        /// Compare output without writing it (used by repository gates).
        #[arg(long, hide = true)]
        check: bool,
    },
    /// Build a native archive plus SBOM, provenance, manifest, and checksums, or verify a candidate.
    Package {
        /// Rust target triple. Defaults to rustc's host target.
        #[arg(long)]
        target: Option<String>,
        /// New, empty output directory.
        #[arg(long, default_value = "dist")]
        out: PathBuf,
        /// Verify an existing package/release directory instead of building.
        #[arg(long, value_name = "DIRECTORY", conflicts_with = "target")]
        verify: Option<PathBuf>,
    },
    /// Run every release gate and create a signed development-only local candidate.
    ReleaseLocal {
        /// New, empty output directory.
        #[arg(long, default_value = "dist")]
        out: PathBuf,
    },
    /// Measure optimized search, resolution, planning, startup, and peak RSS.
    Benchmark {
        /// Enforce committed thresholds locally (CI always enforces them).
        #[arg(long)]
        check: bool,
    },
    /// Prepare unsigned runtime catalog metadata and optionally bind release artifacts.
    PrepareCatalog {
        /// Directory of immutable release artifacts to copy and describe as signed targets.
        #[arg(long)]
        artifacts: Option<PathBuf>,
        /// New, empty output directory.
        #[arg(long, default_value = "dist/catalog")]
        out: PathBuf,
    },
    /// Add one authorized Ed25519 signature and refresh downstream metadata bindings.
    SignMetadata {
        /// Online metadata role. Root signing is deliberately not supported here.
        #[arg(long, value_enum)]
        role: SigningRole,
        /// File containing 32 raw secret bytes or 64 hexadecimal digits.
        #[arg(long)]
        key: PathBuf,
        /// Prepared metadata directory.
        #[arg(long, default_value = "dist/catalog")]
        out: PathBuf,
    },
    /// Optimized-process benchmark worker; not part of the public repository interface.
    #[command(name = "__benchmark-worker", hide = true)]
    BenchmarkWorker {
        #[arg(long)]
        catalog_multiplier: u64,
        #[arg(long)]
        warmup_iterations: u64,
        #[arg(long)]
        search_iterations: u64,
        #[arg(long)]
        resolver_iterations: u64,
        #[arg(long)]
        plan_iterations: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SigningRole {
    Targets,
    Snapshot,
    Timestamp,
}

impl SigningRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Targets => "targets",
            Self::Snapshot => "snapshot",
            Self::Timestamp => "timestamp",
        }
    }
}

fn main() -> ExitCode {
    match execute(Xtask::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask failed: {error}");
            let mut source = error.source();
            while let Some(cause) = source {
                eprintln!("  caused by: {cause}");
                source = cause.source();
            }
            ExitCode::FAILURE
        }
    }
}

fn execute(arguments: Xtask) -> Result<()> {
    let root = support::repository_root()?;
    match arguments.command {
        Commands::Verify => repository::verify(&root),
        Commands::TestSchemas => repository::test_schemas(&root),
        Commands::TestCatalog => repository::test_catalog(&root),
        Commands::TestDocs => repository::test_docs(&root),
        Commands::BuildSite => repository::build_site(&root),
        Commands::GenerateCatalog => repository::generate_catalog(&root),
        Commands::GenerateDocs { check } => repository::generate_docs(&root, check),
        Commands::Package {
            target,
            out,
            verify,
        } => release::package(
            &root,
            &resolve_path(&root, &out),
            target.as_deref(),
            verify
                .as_ref()
                .map(|path| resolve_path(&root, path))
                .as_deref(),
        ),
        Commands::ReleaseLocal { out } => release::release_local(&root, &resolve_path(&root, &out)),
        Commands::Benchmark { check } => benchmark::run(&root, check),
        Commands::PrepareCatalog { artifacts, out } => release::prepare_catalog(
            &root,
            artifacts
                .as_ref()
                .map(|path| resolve_path(&root, path))
                .as_deref(),
            &resolve_path(&root, &out),
        ),
        Commands::SignMetadata { role, key, out } => {
            release::sign_metadata(&resolve_path(&root, &out), role, &resolve_path(&root, &key))
        }
        Commands::BenchmarkWorker {
            catalog_multiplier,
            warmup_iterations,
            search_iterations,
            resolver_iterations,
            plan_iterations,
        } => {
            let metrics = benchmark::worker(benchmark::worker_workload(
                catalog_multiplier,
                warmup_iterations,
                search_iterations,
                resolver_iterations,
                plan_iterations,
            ))?;
            println!(
                "{}",
                serde_json::to_string(&metrics).map_err(|error| {
                    support::message(format!("cannot encode benchmark metrics: {error}"))
                })?
            );
            Ok(())
        }
    }
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    }
}
