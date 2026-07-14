use serde::Deserialize;
use siorb_backends::{BackendKind, CommandSpec, QueryStatus, parse_query_output};
use siorb_core::{Operation, Scope};
use siorb_executor::{ExecutionOptions, Executor};
use siorb_planner::{
    ExecutionPlan, PlanStep, PlannedPackage, Reproducibility, RevalidationGuard, StepKind,
};
use siorb_state::StateStore;

#[derive(Debug, Deserialize)]
struct CapturedCase {
    backend: String,
    operation: String,
    exit_code: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    state: Option<String>,
    native_id: Option<String>,
    version: Option<String>,
    error: Option<String>,
    reason_code: Option<String>,
    diagnostic_contains_escape: Option<bool>,
}

fn cases() -> Vec<CapturedCase> {
    serde_json::from_str(include_str!("../fixtures/backends/captured-output.json"))
        .expect("captured backend output fixture")
}

#[test]
fn every_captured_query_is_parsed_from_bounded_raw_bytes() {
    let mut exercised = 0;
    for case in cases().into_iter().filter(|case| case.operation == "query") {
        exercised += 1;
        let native_id = case
            .expected
            .native_id
            .as_deref()
            .expect("query fixture native id");
        let result = parse_query_output(
            backend_kind(&case.backend),
            native_id,
            case.stdout.as_bytes(),
            case.stderr.as_bytes(),
            Some(case.exit_code),
        );
        assert_eq!(case.expected.state.as_deref(), Some("installed"));
        assert_eq!(result.status, QueryStatus::Installed, "{}", case.backend);
        assert_eq!(result.native_id, native_id);
        assert_eq!(
            result.observed_version, case.expected.version,
            "{}",
            case.backend
        );
        if case.expected.diagnostic_contains_escape == Some(false) {
            let diagnostic = siorb_core::sanitize_terminal(&case.stdout);
            assert!(!diagnostic.contains('\u{1b}'));
        }
    }
    assert_eq!(exercised, 7);
}

#[cfg(unix)]
#[test]
fn captured_install_failures_flow_through_the_real_executor_classifier() {
    use std::os::unix::fs::PermissionsExt;

    let mut exercised = 0;
    for case in cases()
        .into_iter()
        .filter(|case| case.operation == "install")
    {
        exercised += 1;
        assert!(case.expected.error.is_some());
        let directory = tempfile::tempdir().expect("temporary executor fixture");
        let diagnostic = directory.path().join("diagnostic.txt");
        std::fs::write(&diagnostic, format!("{}{}", case.stdout, case.stderr))
            .expect("write captured diagnostic");
        let executable = directory.path().join("backend-fixture");
        std::fs::write(&executable, b"#!/bin/sh\ncat \"$1\" >&2\nexit \"$2\"\n")
            .expect("write fake backend");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("make fake backend executable");
        let state = StateStore::new(directory.path().join("state")).expect("state store");
        let exit_code = if (1..=255).contains(&case.exit_code) {
            case.exit_code
        } else {
            1
        };
        let plan = failure_plan(
            &case.backend,
            executable.display().to_string(),
            diagnostic.display().to_string(),
            exit_code,
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
            .expect_err("captured backend failure must fail");
        assert_eq!(
            Some(error.reason_code.as_str()),
            case.expected.reason_code.as_deref(),
            "{}",
            case.backend
        );
        assert!(!error.state_changed);
        assert!(state.receipts().is_ok_and(|receipts| receipts.is_empty()));
    }
    assert_eq!(exercised, 4);
}

fn backend_kind(value: &str) -> BackendKind {
    match value {
        "winget" => BackendKind::Winget,
        "apt" => BackendKind::Apt,
        "dnf" => BackendKind::Dnf,
        "pacman" => BackendKind::Pacman,
        "brew" => BackendKind::BrewCask,
        "flatpak" => BackendKind::Flatpak,
        "zypper" => BackendKind::Zypper,
        "apk" => BackendKind::Apk,
        other => panic!("unknown captured backend {other}"),
    }
}

#[cfg(unix)]
fn failure_plan(
    backend: &str,
    executable: String,
    diagnostic: String,
    exit_code: i32,
) -> ExecutionPlan {
    let package = PlannedPackage {
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
    };
    let mutation = PlanStep {
        id: "step-mutation".to_owned(),
        package: "firefox".to_owned(),
        kind: StepKind::Backend,
        description: "captured backend failure".to_owned(),
        command: Some(CommandSpec {
            executable,
            arguments: vec![diagnostic, exit_code.to_string()],
            redacted_arguments: vec!["<captured-diagnostic>".to_owned(), exit_code.to_string()],
            timeout_seconds: 5,
            max_output_bytes: 16 * 1024,
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
        rollback_hint: "none; mutation failed".to_owned(),
    };
    let query = PlanStep {
        id: "step-query".to_owned(),
        package: "firefox".to_owned(),
        kind: StepKind::Verify,
        description: "unreached read-only query".to_owned(),
        command: Some(CommandSpec {
            executable: "/bin/true".to_owned(),
            arguments: Vec::new(),
            redacted_arguments: Vec::new(),
            timeout_seconds: 5,
            max_output_bytes: 16 * 1024,
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
        rollback_hint: "none".to_owned(),
    };
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
        packages: vec![package],
        steps: vec![mutation, query],
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
