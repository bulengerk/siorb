use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use siorb_backends::CommandSpec;
use siorb_catalog::Catalog;
use siorb_core::{Operation, PlatformContext, Scope};
use siorb_executor::{ExecutionOptions, Executor};
use siorb_planner::{
    ExecutionPlan, PlanOptions, PlanStep, PlannedPackage, Planner, Reproducibility,
    RevalidationGuard, StepKind,
};
use siorb_policy::LayeredPolicy;
use siorb_resolver::{ResolutionContext, ResolveOptions, Resolver};
use siorb_state::StateStore;

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    platform_golden: String,
    argv: Vec<String>,
    fake_backend: Option<FakeBackend>,
    network: Option<NetworkExpectation>,
    catalog_fixture: Option<String>,
    state_fixture: Option<String>,
    requires_mutation: bool,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct FakeBackend {
    id: String,
    expected_invocations: u32,
    exit_code: Option<i32>,
    stderr: Option<String>,
    output_bytes: Option<usize>,
    query_stdout: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NetworkExpectation {
    allowed_requests: u32,
}

#[derive(Debug, Deserialize)]
struct Expected {
    exit_code: i32,
    status: String,
    state_changed: bool,
    plan_backend: Option<String>,
    reason_code: Option<String>,
}

fn scenarios() -> Vec<Scenario> {
    serde_json::from_str(include_str!("scenarios.json")).expect("E2E scenario matrix")
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests directory has repository parent")
        .to_path_buf()
}

#[test]
fn every_host_safe_scenario_executes_a_real_contract_path() {
    let scenarios = scenarios();
    assert_eq!(scenarios.len(), 10);
    let mut handled = 0;
    for scenario in &scenarios {
        assert!(!scenario.requires_mutation, "{}", scenario.name);
        match scenario.name.as_str() {
            "linux dry-run produces an apt plan without executing"
            | "windows dry-run produces an exact winget plan"
            | "macos dry-run selects the native cask" => {
                assert_plan_scenario(scenario);
            }
            "offline search uses only the bundled catalog" => {
                let query = argument_after(&scenario.argv, "search");
                let catalog = Catalog::bundled().expect("embedded catalog");
                assert!(
                    !catalog
                        .search(query, 50)
                        .expect("offline search")
                        .is_empty()
                );
                assert_eq!(
                    scenario
                        .network
                        .as_ref()
                        .map(|value| value.allowed_requests),
                    Some(0)
                );
                assert_eq!(scenario.expected.exit_code, 0);
                assert_eq!(scenario.expected.status, "success");
            }
            "non-interactive winget refuses unaccepted agreements" => {
                let error = build_plan(scenario).expect_err("agreements must be rejected");
                assert_eq!(Some(error.reason_code), scenario.expected.reason_code);
                assert_eq!(scenario.expected.exit_code, 2);
            }
            "option-like shorthand is invalid input" => {
                let mut arguments = vec!["siorb".to_owned()];
                arguments.extend(scenario.argv.clone());
                assert!(siorb_cli::Cli::try_parse_from(arguments).is_err());
                assert_eq!(scenario.expected.exit_code, 2);
                assert_eq!(
                    scenario.expected.reason_code.as_deref(),
                    Some("input.invalid")
                );
            }
            "ambiguous logical name never mutates" => assert_ambiguous_scenario(scenario),
            "backend failure is typed and bounded" => assert_backend_failure_scenario(scenario),
            "fake native install verifies state and commits a receipt" => {
                assert_backend_success_scenario(scenario);
            }
            "interrupted transaction is reported for reconciliation" => {
                assert_interrupted_scenario(scenario);
            }
            other => panic!("unhandled E2E scenario {other}"),
        }
        handled += 1;
    }
    assert_eq!(handled, scenarios.len());
}

#[test]
fn cli_parse_failure_is_one_json_document_with_a_stable_reason() {
    let directory = tempfile::tempdir().expect("isolated CLI state");
    let output = Command::new(env!("CARGO_BIN_EXE_siorb-test-driver"))
        .args(["--json", "--definitely-not-a-flag"])
        .env("SIORB_STATE_DIR", directory.path().join("state"))
        .env_remove("SIORB_ORG_POLICY")
        .output()
        .expect("run CLI test driver");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stderr.is_empty(),
        "JSON mode must not split diagnostics"
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("single JSON envelope");
    assert_eq!(value["status"], "error");
    assert_eq!(value["errors"][0]["reason_code"], "input.cli.parse");
}

fn assert_plan_scenario(scenario: &Scenario) {
    let plan = build_plan(scenario).expect("dry-run plan");
    assert!(plan.changes_machine());
    assert_eq!(scenario.expected.exit_code, 0);
    assert_eq!(scenario.expected.status, "planned");
    assert_eq!(
        plan.packages
            .first()
            .map(|package| package.backend.as_str()),
        scenario.expected.plan_backend.as_deref()
    );
    assert_eq!(
        scenario
            .fake_backend
            .as_ref()
            .map(|backend| backend.expected_invocations),
        Some(0)
    );
}

fn build_plan(scenario: &Scenario) -> siorb_core::Result<ExecutionPlan> {
    let mut platform = load_platform(&scenario.platform_golden);
    for backend in &mut platform.backends {
        backend.executable = format!("/fixture/{}", backend.id);
        backend.available = true;
    }
    let catalog = load_catalog(scenario.catalog_fixture.as_deref());
    let policy = LayeredPolicy::default();
    let installed = Vec::new();
    let request = scenario
        .argv
        .iter()
        .find(|argument| argument.as_str() == "firefox")
        .map_or("firefox", String::as_str);
    let resolver = Resolver::new(&catalog, &platform, &policy, &installed);
    let resolution = resolver.resolve_with_context(
        request,
        Operation::Install,
        &ResolveOptions {
            via: None,
            source: None,
            scope: Scope::Auto,
            channel: "stable".to_owned(),
            version: None,
            architecture: None,
        },
        &ResolutionContext {
            dry_run: true,
            now_unix: Some(1_783_987_200),
            network_urls: Vec::new(),
        },
    )?;
    Planner::new(&platform, &catalog, &policy, &installed).build(
        Operation::Install,
        &[resolution],
        PlanOptions {
            non_interactive: scenario
                .argv
                .iter()
                .any(|value| value == "--non-interactive"),
            accept_agreements: scenario
                .argv
                .iter()
                .any(|value| value == "--accept-agreements"),
            target_architecture: platform.architecture,
        },
    )
}

fn assert_ambiguous_scenario(scenario: &Scenario) {
    let platform = load_platform(&scenario.platform_golden);
    let catalog = load_catalog(scenario.catalog_fixture.as_deref());
    let policy = LayeredPolicy::default();
    let error = Resolver::new(&catalog, &platform, &policy, &[])
        .resolve(
            "code",
            Operation::Install,
            &ResolveOptions {
                channel: "stable".to_owned(),
                ..ResolveOptions::default()
            },
        )
        .expect_err("ambiguous request must fail");
    assert_eq!(error.exit_code().as_i32(), scenario.expected.exit_code);
    assert_eq!(Some(error.reason_code), scenario.expected.reason_code);
    assert_eq!(
        scenario
            .fake_backend
            .as_ref()
            .map(|backend| backend.expected_invocations),
        Some(0)
    );
}

fn assert_interrupted_scenario(scenario: &Scenario) {
    let directory = tempfile::tempdir().expect("isolated state fixture");
    let store = StateStore::new(directory.path().join("state")).expect("state store");
    let fixture = repository_root().join(
        scenario
            .state_fixture
            .as_deref()
            .expect("interrupted-state fixture path"),
    );
    let journal = store.root().join("journal.ndjson");
    fs::copy(fixture, &journal).expect("copy interrupted journal");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600))
            .expect("secure journal permissions");
    }
    let statuses = store
        .transactions_requiring_reconciliation()
        .expect("reconciliation status");
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].reason_code, "state.transaction.interrupted");
    assert_eq!(scenario.expected.status, "planned");
    assert_eq!(scenario.expected.exit_code, 0);
}

#[cfg(unix)]
fn assert_backend_failure_scenario(scenario: &Scenario) {
    use std::os::unix::fs::PermissionsExt;

    let backend = scenario
        .fake_backend
        .as_ref()
        .expect("fake backend fixture");
    assert_eq!(backend.expected_invocations, 1);
    assert_eq!(backend.output_bytes, Some(20));
    let directory = tempfile::tempdir().expect("isolated executor fixture");
    let diagnostic = directory.path().join("stderr.txt");
    fs::write(
        &diagnostic,
        backend.stderr.as_deref().expect("captured stderr"),
    )
    .expect("write backend stderr");
    let executable = directory.path().join("backend");
    fs::write(&executable, b"#!/bin/sh\ncat \"$1\" >&2\nexit \"$2\"\n")
        .expect("write backend fixture");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
        .expect("secure backend fixture");
    let state = StateStore::new(directory.path().join("state")).expect("state store");
    let plan = failure_plan(
        &backend.id,
        executable.display().to_string(),
        diagnostic.display().to_string(),
        backend.exit_code.unwrap_or(1),
    );
    let error = Executor::new(&state)
        .execute(
            &plan,
            &ExecutionOptions {
                consent: true,
                non_interactive: true,
                accept_agreements: true,
                ..ExecutionOptions::default()
            },
        )
        .expect_err("backend fixture must fail");
    assert_eq!(error.exit_code().as_i32(), scenario.expected.exit_code);
    assert_eq!(Some(error.reason_code), scenario.expected.reason_code);
    assert!(!error.state_changed);
}

fn assert_backend_success_scenario(scenario: &Scenario) {
    let backend = scenario
        .fake_backend
        .as_ref()
        .expect("fake backend fixture");
    assert_eq!(backend.expected_invocations, 2);
    let query_stdout = backend
        .query_stdout
        .as_deref()
        .expect("parseable query fixture");
    let directory = tempfile::tempdir().expect("isolated executor fixture");
    let executable = directory.path().join(format!(
        "fake-native-backend{}",
        std::env::consts::EXE_SUFFIX
    ));
    fs::copy(env!("CARGO_BIN_EXE_siorb-test-driver"), &executable)
        .expect("copy disposable fake backend");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("secure fake backend fixture");
    }

    let state = StateStore::new(directory.path().join("state")).expect("state store");
    let fixture_root = directory.path().to_string_lossy().into_owned();
    let plan = success_plan(
        &backend.id,
        executable.display().to_string(),
        fixture_root.clone(),
        query_stdout,
    );
    for command in plan.steps.iter().filter_map(|step| step.command.as_ref()) {
        assert_eq!(Path::new(&command.executable), executable);
        assert!(!command.network);
        assert!(!command.requires_privilege);
        assert!(command.environment.is_empty());
        assert_eq!(
            command.arguments.get(1).map(String::as_str),
            Some(fixture_root.as_str())
        );
    }

    let report = Executor::new(&state)
        .execute(
            &plan,
            &ExecutionOptions {
                consent: true,
                non_interactive: true,
                accept_agreements: true,
                ..ExecutionOptions::default()
            },
        )
        .expect("fake backend install and verification must succeed");
    assert_eq!(report.status, scenario.expected.status);
    assert_eq!(report.state_changed, scenario.expected.state_changed);
    assert_eq!(report.steps.len(), 2);
    assert_eq!(scenario.expected.exit_code, 0);
    assert_eq!(scenario.expected.plan_backend.as_deref(), Some("apt"));

    let invocations = fs::read_to_string(directory.path().join("fake-backend-invocations.log"))
        .expect("fake backend invocation log");
    assert_eq!(
        invocations.lines().collect::<Vec<_>>(),
        ["install", "query"]
    );
    assert_eq!(
        fs::read(directory.path().join("fake-native-package.installed"))
            .expect("fake installed-state marker"),
        b"installed\n"
    );
    let receipts = state.receipts().expect("committed receipt");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].logical_id, "firefox");
    assert_eq!(receipts[0].backend, backend.id);
    assert_eq!(receipts[0].observed_version.as_deref(), Some("128.0.3"));
    assert_eq!(receipts[0].architecture, "x86_64");
    assert_eq!(receipts[0].verification.reason, "backend.query.installed");

    let mut top_level = fs::read_dir(directory.path())
        .expect("temporary fixture contents")
        .map(|entry| {
            entry
                .expect("temporary fixture entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    top_level.sort();
    let mut expected = vec![
        "fake-backend-invocations.log".to_owned(),
        format!("fake-native-backend{}", std::env::consts::EXE_SUFFIX),
        "fake-native-package.installed".to_owned(),
        "state".to_owned(),
    ];
    expected.sort();
    assert_eq!(top_level, expected);
}

#[cfg(not(unix))]
fn assert_backend_failure_scenario(scenario: &Scenario) {
    let backend = scenario
        .fake_backend
        .as_ref()
        .expect("fake backend fixture");
    assert_eq!(backend.expected_invocations, 1);
    assert_eq!(
        scenario.expected.reason_code.as_deref(),
        Some("backend.network")
    );
}

#[cfg(unix)]
fn failure_plan(
    backend: &str,
    executable: String,
    diagnostic: String,
    exit_code: i32,
) -> ExecutionPlan {
    let command = CommandSpec {
        executable,
        arguments: vec![diagnostic, exit_code.to_string()],
        redacted_arguments: vec!["<diagnostic>".to_owned(), exit_code.to_string()],
        timeout_seconds: 5,
        max_output_bytes: 16 * 1024,
        requires_privilege: false,
        network: false,
        environment: Vec::new(),
    };
    let query = CommandSpec {
        executable: "/bin/true".to_owned(),
        arguments: Vec::new(),
        redacted_arguments: Vec::new(),
        timeout_seconds: 5,
        max_output_bytes: 16 * 1024,
        requires_privilege: false,
        network: false,
        environment: Vec::new(),
    };
    native_execution_plan(backend, command, query)
}

fn success_plan(
    backend: &str,
    executable: String,
    fixture_root: String,
    query_stdout: &str,
) -> ExecutionPlan {
    let command = CommandSpec {
        executable: executable.clone(),
        arguments: vec![
            "--fake-native-backend".to_owned(),
            fixture_root.clone(),
            "install".to_owned(),
        ],
        redacted_arguments: vec![
            "--fake-native-backend".to_owned(),
            "<fixture-root>".to_owned(),
            "install".to_owned(),
        ],
        timeout_seconds: 5,
        max_output_bytes: 16 * 1024,
        requires_privilege: false,
        network: false,
        environment: Vec::new(),
    };
    let query = CommandSpec {
        executable,
        arguments: vec![
            "--fake-native-backend".to_owned(),
            fixture_root,
            "query".to_owned(),
            query_stdout.to_owned(),
        ],
        redacted_arguments: vec![
            "--fake-native-backend".to_owned(),
            "<fixture-root>".to_owned(),
            "query".to_owned(),
            "<query-output>".to_owned(),
        ],
        timeout_seconds: 5,
        max_output_bytes: 16 * 1024,
        requires_privilege: false,
        network: false,
        environment: Vec::new(),
    };
    native_execution_plan(backend, command, query)
}

fn native_execution_plan(backend: &str, command: CommandSpec, query: CommandSpec) -> ExecutionPlan {
    ExecutionPlan {
        schema_version: "1.0".to_owned(),
        plan_id: "plan-0123456789abcdef01234567".to_owned(),
        operation: Operation::Install,
        requested: vec!["firefox".to_owned()],
        catalog_fingerprint: "catalog".to_owned(),
        platform_fingerprint: "platform".to_owned(),
        policy_fingerprint: Some("policy".to_owned()),
        created_at_unix: 1,
        reproducibility: Reproducibility::BestEffort,
        packages: vec![PlannedPackage {
            requested: "firefox".to_owned(),
            logical_id: "firefox".to_owned(),
            source_id: format!("firefox-{backend}"),
            backend: backend.to_owned(),
            native_id: "firefox".to_owned(),
            current_version: None,
            desired_version: None,
            scope: Scope::User,
            channel: "stable".to_owned(),
            architecture: siorb_core::Architecture::X86_64,
        }],
        steps: vec![
            plan_step("mutate", StepKind::Backend, command),
            plan_step("query", StepKind::Verify, query),
        ],
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

fn plan_step(id: &str, kind: StepKind, command: CommandSpec) -> PlanStep {
    PlanStep {
        id: format!("step-{id}"),
        package: "firefox".to_owned(),
        kind,
        description: id.to_owned(),
        command: Some(command),
        artifact: None,
        network_endpoints: Vec::new(),
        expected_download_bytes: None,
        verification_requirements: Vec::new(),
        requires_privilege: false,
        agreements: Vec::new(),
        destructive: false,
        rollback_hint: "none".to_owned(),
    }
}

fn load_platform(relative: &str) -> PlatformContext {
    let path = repository_root().join(relative);
    serde_json::from_slice(&fs::read(path).expect("platform golden"))
        .expect("platform golden shape")
}

fn load_catalog(relative: Option<&str>) -> Catalog {
    match relative {
        Some(relative) => {
            let path = repository_root().join(relative);
            Catalog::from_json(
                &fs::read_to_string(path).expect("catalog fixture"),
                "E2E fixture",
                true,
            )
            .expect("catalog fixture shape")
        }
        None => Catalog::bundled().expect("embedded catalog"),
    }
}

fn argument_after<'a>(arguments: &'a [String], command: &str) -> &'a str {
    arguments
        .iter()
        .position(|argument| argument == command)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
        .expect("scenario command argument")
}
