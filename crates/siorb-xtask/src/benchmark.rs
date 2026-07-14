use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use siorb_catalog::{Catalog, CatalogDocument};
use siorb_core::{Architecture, BackendInfo, Operation, OsFamily, PlatformContext, Scope};
use siorb_planner::{PlanOptions, Planner};
use siorb_policy::LayeredPolicy;
use siorb_resolver::{ResolveOptions, Resolver};

use crate::Result;
use crate::support::{capture, executable_name, message, run as run_command, target_directory};

const BASELINE_PATH: &str = "benches/baseline.json";

#[derive(Clone, Debug, Deserialize)]
struct Baseline {
    schema_version: String,
    reference_runner: String,
    workload: Workload,
    thresholds: Thresholds,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct Workload {
    catalog_multiplier: u64,
    warmup_iterations: u64,
    search_iterations: u64,
    resolver_iterations: u64,
    plan_iterations: u64,
    startup_warmups: u64,
    startup_samples: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct Thresholds {
    search_p95_ns: u64,
    resolver_p95_ns: u64,
    plan_p95_ns: u64,
    startup_p95_ms: u64,
    peak_rss_bytes_10x_catalog: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerMetrics {
    catalog_packages: usize,
    search_p95_ns: u64,
    resolver_p95_ns: u64,
    plan_p95_ns: u64,
    peak_rss_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct Results {
    schema_version: String,
    reference_runner: String,
    catalog_packages: usize,
    catalog_multiplier: u64,
    search_p95_ns: u64,
    resolver_p95_ns: u64,
    plan_p95_ns: u64,
    startup_median_ms: u64,
    startup_p95_ms: u64,
    peak_rss_bytes: Option<u64>,
    thresholds_enforced: bool,
    passed: bool,
}

pub fn run(root: &Path, check: bool) -> Result<()> {
    let baseline = load_baseline(root)?;
    validate_workload(&baseline.workload)?;
    run_command(
        root,
        "cargo",
        [
            "build",
            "--locked",
            "--release",
            "-p",
            "siorb-xtask",
            "-p",
            "siorb-cli",
        ],
    )?;
    let target = target_directory(root)?;
    let worker = target.join("release").join(executable_name("xtask"));
    let arguments = [
        "__benchmark-worker".to_owned(),
        "--catalog-multiplier".to_owned(),
        baseline.workload.catalog_multiplier.to_string(),
        "--warmup-iterations".to_owned(),
        baseline.workload.warmup_iterations.to_string(),
        "--search-iterations".to_owned(),
        baseline.workload.search_iterations.to_string(),
        "--resolver-iterations".to_owned(),
        baseline.workload.resolver_iterations.to_string(),
        "--plan-iterations".to_owned(),
        baseline.workload.plan_iterations.to_string(),
    ];
    let output = capture(root, &worker, arguments)?;
    let metrics: WorkerMetrics = serde_json::from_slice(&output.stdout).map_err(|error| {
        message(format!(
            "benchmark worker emitted invalid JSON: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        ))
    })?;
    ensure_nonzero_metrics(&metrics)?;
    let siorb = target.join("release").join(executable_name("siorb"));
    let startup = measure_startup(
        root,
        &siorb,
        baseline.workload.startup_warmups,
        baseline.workload.startup_samples,
    )?;
    let startup_median_ms = duration_ms(startup[startup.len() / 2]);
    let p95_index = (startup.len() * 95).div_ceil(100).saturating_sub(1);
    let startup_p95_ms = duration_ms(startup[p95_index]);
    let enforce = check || std::env::var_os("CI").is_some();
    let failures = threshold_failures(&metrics, startup_p95_ms, &baseline.thresholds);
    let passed = failures.is_empty();
    let results = Results {
        schema_version: "1.1".to_owned(),
        reference_runner: baseline.reference_runner,
        catalog_packages: metrics.catalog_packages,
        catalog_multiplier: baseline.workload.catalog_multiplier,
        search_p95_ns: metrics.search_p95_ns,
        resolver_p95_ns: metrics.resolver_p95_ns,
        plan_p95_ns: metrics.plan_p95_ns,
        startup_median_ms,
        startup_p95_ms,
        peak_rss_bytes: metrics.peak_rss_bytes,
        thresholds_enforced: enforce,
        passed,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&results)
            .map_err(|error| message(format!("cannot encode benchmark results: {error}")))?
    );
    if !failures.is_empty() {
        let detail = failures.join("\n");
        if enforce {
            return Err(message(format!("performance baseline failed:\n{detail}")));
        }
        eprintln!(
            "warning: measurements exceeded the committed reference thresholds; rerun with --check to fail:\n{detail}"
        );
    }
    if enforce {
        println!("performance thresholds passed");
    } else {
        println!("performance measurements complete (threshold reporting mode)");
    }
    Ok(())
}

pub(crate) fn worker(workload: Workload) -> Result<WorkerMetrics> {
    validate_workload(&workload)?;
    let catalog = multiplied_catalog(workload.catalog_multiplier)?;
    let executable = std::env::current_exe()
        .map_err(|error| message(format!("cannot locate benchmark executable: {error}")))?;
    let platform = PlatformContext {
        os: OsFamily::Linux,
        os_version: Some("benchmark".to_owned()),
        distribution: Some("debian".to_owned()),
        distribution_version: Some("benchmark".to_owned()),
        distribution_like: Vec::new(),
        architecture: Architecture::X86_64,
        translated: false,
        libc: Some("glibc".to_owned()),
        backends: vec![BackendInfo {
            id: "apt".to_owned(),
            executable: executable.display().to_string(),
            version: Some("benchmark".to_owned()),
            available: true,
            capabilities: vec![
                "install".to_owned(),
                "remove".to_owned(),
                "upgrade".to_owned(),
                "verify".to_owned(),
            ],
        }],
        interactive: false,
        elevation_available: false,
        supported_scopes: vec![Scope::User, Scope::System],
        offline: true,
        restrictions: Vec::new(),
    };
    let policy = LayeredPolicy::default();
    let installed = Vec::new();
    let resolver = Resolver::new(&catalog, &platform, &policy, &installed);
    let options = ResolveOptions {
        via: Some("apt".to_owned()),
        source: Some("firefox-apt".to_owned()),
        scope: Scope::System,
        channel: "stable".to_owned(),
        version: None,
        architecture: Some(Architecture::X86_64),
    };
    let resolution = resolver.resolve("firefox", Operation::Install, &options)?;
    resolution.require_selected()?;
    let planner = Planner::new(&platform, &catalog, &policy, &installed);
    planner.build(
        Operation::Install,
        std::slice::from_ref(&resolution),
        PlanOptions {
            non_interactive: true,
            accept_agreements: false,
            target_architecture: Architecture::X86_64,
        },
    )?;

    for index in 0..workload.warmup_iterations {
        let query = benchmark_query(index);
        black_box(catalog.search(query, 20)?);
        let value = resolver.resolve("firefox", Operation::Install, &options)?;
        black_box(planner.build(
            Operation::Install,
            std::slice::from_ref(&value),
            PlanOptions {
                non_interactive: true,
                accept_agreements: false,
                target_architecture: Architecture::X86_64,
            },
        )?);
    }

    let search_p95_ns = sample_p95_ns(workload.search_iterations, |index| {
        black_box(catalog.search(benchmark_query(index), 20)?);
        Ok(())
    })?;
    let resolver_p95_ns = sample_p95_ns(workload.resolver_iterations, |_| {
        black_box(resolver.resolve("firefox", Operation::Install, &options)?);
        Ok(())
    })?;
    let plan_p95_ns = sample_p95_ns(workload.plan_iterations, |_| {
        black_box(planner.build(
            Operation::Install,
            std::slice::from_ref(&resolution),
            PlanOptions {
                non_interactive: true,
                accept_agreements: false,
                target_architecture: Architecture::X86_64,
            },
        )?);
        Ok(())
    })?;

    Ok(WorkerMetrics {
        catalog_packages: catalog.packages().len(),
        search_p95_ns,
        resolver_p95_ns,
        plan_p95_ns,
        peak_rss_bytes: peak_rss_bytes(),
    })
}

fn multiplied_catalog(multiplier: u64) -> Result<Catalog> {
    let bundled = Catalog::bundled()?;
    let mut packages = Vec::with_capacity(
        bundled
            .packages()
            .len()
            .saturating_mul(usize::try_from(multiplier).unwrap_or(usize::MAX)),
    );
    for copy in 0..multiplier {
        for original in bundled.packages() {
            let mut package = original.clone();
            if copy > 0 {
                let suffix = format!("-benchmark-{copy}");
                package.id.push_str(&suffix);
                package.name = format!("{} benchmark {copy}", package.name);
                for alias in package
                    .aliases
                    .iter_mut()
                    .chain(package.deprecated_aliases.iter_mut())
                {
                    alias.push_str(&suffix);
                }
                for source in &mut package.sources {
                    source.id.push_str(&suffix);
                }
            }
            packages.push(package);
        }
    }
    Catalog::from_document(
        CatalogDocument {
            schema_version: "1.0".to_owned(),
            catalog_version: bundled.identity().version,
            generated_at: "benchmark".to_owned(),
            expires_unix: bundled.identity().expires_unix,
            packages,
        },
        format!("benchmark-{multiplier}x"),
        true,
    )
    .map_err(Into::into)
}

fn load_baseline(root: &Path) -> Result<Baseline> {
    let path = root.join(BASELINE_PATH);
    let bytes = fs::read(&path)
        .map_err(|error| message(format!("cannot read {}: {error}", path.display())))?;
    let baseline: Baseline = serde_json::from_slice(&bytes)
        .map_err(|error| message(format!("invalid benchmark baseline: {error}")))?;
    if baseline.schema_version != "1.1" {
        return Err(message(format!(
            "unsupported benchmark baseline schema `{}`",
            baseline.schema_version
        )));
    }
    Ok(baseline)
}

fn validate_workload(workload: &Workload) -> Result<()> {
    if workload.catalog_multiplier < 10
        || workload.catalog_multiplier > 100
        || workload.search_iterations == 0
        || workload.resolver_iterations == 0
        || workload.plan_iterations == 0
        || workload.startup_samples == 0
        || workload.startup_samples > 1_000
        || workload.search_iterations > 10_000_000
        || workload.resolver_iterations > 10_000_000
        || workload.plan_iterations > 10_000_000
    {
        return Err(message(
            "benchmark workload counts are zero or unreasonably large",
        ));
    }
    Ok(())
}

fn ensure_nonzero_metrics(metrics: &WorkerMetrics) -> Result<()> {
    if metrics.catalog_packages == 0
        || metrics.search_p95_ns == 0
        || metrics.resolver_p95_ns == 0
        || metrics.plan_p95_ns == 0
    {
        return Err(message(
            "benchmark worker returned a zero duration; workload may have been optimized away",
        ));
    }
    Ok(())
}

fn benchmark_query(index: u64) -> &'static str {
    const QUERIES: [&str; 8] = [
        "browser",
        "developer tools",
        "terminal",
        "security",
        "firefox",
        "kubernetes",
        "database",
        "media",
    ];
    let query_index = usize::try_from(index % QUERIES.len() as u64).unwrap_or_default();
    QUERIES[query_index]
}

fn sample_p95_ns<F>(iterations: u64, mut operation: F) -> Result<u64>
where
    F: FnMut(u64) -> Result<()>,
{
    let capacity = usize::try_from(iterations)
        .map_err(|_| message("benchmark sample count does not fit memory"))?;
    let mut samples = Vec::with_capacity(capacity);
    for index in 0..iterations {
        let started = Instant::now();
        operation(index)?;
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    Ok(u64::try_from(samples[index].as_nanos()).unwrap_or(u64::MAX))
}

fn measure_startup(
    root: &Path,
    executable: &Path,
    warmups: u64,
    samples: u64,
) -> Result<Vec<Duration>> {
    if !executable.is_file() {
        return Err(message(format!(
            "startup benchmark binary is missing: {}",
            executable.display()
        )));
    }
    let state =
        target_directory(root)?.join(format!("siorb-benchmark-state-{}", std::process::id()));
    if state.exists() {
        fs::remove_dir_all(&state).map_err(|error| {
            message(format!(
                "cannot reset benchmark state {}: {error}",
                state.display()
            ))
        })?;
    }
    fs::create_dir_all(&state)?;
    let execute = || -> Result<Duration> {
        let started = Instant::now();
        let status = Command::new(executable)
            .args(["--offline", "version"])
            .current_dir(root)
            .env("SIORB_STATE_DIR", &state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| message(format!("cannot run startup benchmark: {error}")))?;
        if !status.success() {
            return Err(message(format!(
                "startup benchmark exited with {}",
                status
                    .code()
                    .map_or_else(|| "a signal".to_owned(), |code| format!("exit code {code}"))
            )));
        }
        Ok(started.elapsed())
    };
    for _ in 0..warmups {
        black_box(execute()?);
    }
    let sample_capacity = usize::try_from(samples)
        .map_err(|_| message("startup sample count does not fit memory"))?;
    let mut values = Vec::with_capacity(sample_capacity);
    for _ in 0..samples {
        values.push(execute()?);
    }
    values.sort_unstable();
    fs::remove_dir_all(&state).map_err(|error| {
        message(format!(
            "cannot clean benchmark state {}: {error}",
            state.display()
        ))
    })?;
    Ok(values)
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn threshold_failures(
    metrics: &WorkerMetrics,
    startup_p95_ms: u64,
    thresholds: &Thresholds,
) -> Vec<String> {
    let mut failures = Vec::new();
    compare(
        &mut failures,
        "search_p95_ns",
        metrics.search_p95_ns,
        thresholds.search_p95_ns,
    );
    compare(
        &mut failures,
        "resolver_p95_ns",
        metrics.resolver_p95_ns,
        thresholds.resolver_p95_ns,
    );
    compare(
        &mut failures,
        "plan_p95_ns",
        metrics.plan_p95_ns,
        thresholds.plan_p95_ns,
    );
    compare(
        &mut failures,
        "startup_p95_ms",
        startup_p95_ms,
        thresholds.startup_p95_ms,
    );
    match metrics.peak_rss_bytes {
        Some(value) => compare(
            &mut failures,
            "peak_rss_bytes_10x_catalog",
            value,
            thresholds.peak_rss_bytes_10x_catalog,
        ),
        None => failures.push(
            "peak_rss_bytes is unavailable; the enforced reference gate requires Linux /proc"
                .to_owned(),
        ),
    }
    failures
}

fn compare(failures: &mut Vec<String>, name: &str, observed: u64, maximum: u64) {
    if observed > maximum {
        failures.push(format!("{name}: observed {observed}, maximum {maximum}"));
    }
}

#[cfg(target_os = "linux")]
fn peak_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kibibytes = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    kibibytes.checked_mul(1024)
}

#[cfg(not(target_os = "linux"))]
const fn peak_rss_bytes() -> Option<u64> {
    None
}

pub(crate) fn worker_workload(
    catalog_multiplier: u64,
    warmup_iterations: u64,
    search_iterations: u64,
    resolver_iterations: u64,
    plan_iterations: u64,
) -> Workload {
    Workload {
        catalog_multiplier,
        warmup_iterations,
        search_iterations,
        resolver_iterations,
        plan_iterations,
        startup_warmups: 1,
        startup_samples: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_workload_is_not_constant() {
        assert_ne!(benchmark_query(0), benchmark_query(1));
        assert_eq!(benchmark_query(0), benchmark_query(8));
    }

    #[test]
    fn memory_workload_uses_exactly_ten_bundled_catalogs() {
        let bundled = Catalog::bundled();
        let multiplied = multiplied_catalog(10);
        assert!(bundled.is_ok());
        assert!(multiplied.is_ok());
        if let (Ok(bundled), Ok(multiplied)) = (bundled, multiplied) {
            assert_eq!(multiplied.packages().len(), bundled.packages().len() * 10);
        }
    }

    #[test]
    fn threshold_comparison_reports_regressions() {
        let metrics = WorkerMetrics {
            catalog_packages: 1_200,
            search_p95_ns: 2,
            resolver_p95_ns: 2,
            plan_p95_ns: 2,
            peak_rss_bytes: Some(2),
        };
        let thresholds = Thresholds {
            search_p95_ns: 1,
            resolver_p95_ns: 1,
            plan_p95_ns: 1,
            startup_p95_ms: 1,
            peak_rss_bytes_10x_catalog: 1,
        };
        assert_eq!(threshold_failures(&metrics, 2, &thresholds).len(), 5);
    }
}
