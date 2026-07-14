use serde::Deserialize;
use siorb_backends::{BackendAdapter, NativeAdapter, PlanOptions};
use siorb_catalog::PackageSource;
use siorb_core::{BackendInfo, Operation};

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    catalog_backend: String,
    backend_id: String,
    operation: String,
    package_id: String,
    #[serde(default)]
    non_interactive: bool,
    #[serde(default)]
    accept_agreements: bool,
    available: Option<bool>,
    expected_arguments: Option<Vec<String>>,
    expected_reason: Option<String>,
}

fn operation(value: &str) -> Operation {
    match value {
        "install" => Operation::Install,
        "remove" => Operation::Remove,
        "upgrade" => Operation::Upgrade,
        "verify" => Operation::Verify,
        other => panic!("unsupported operation in fixture: {other}"),
    }
}

fn fake_executable(id: &str) -> String {
    if cfg!(windows) {
        format!(r"C:\fake\{id}.exe")
    } else {
        format!("/fake/{id}")
    }
}

#[test]
fn every_native_adapter_obeys_the_typed_command_contract() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../fixtures/backends/contract-cases.json"))
            .expect("backend contract fixture must be valid JSON");

    for case in cases {
        let source = PackageSource {
            id: format!("{}-fixture", case.backend_id),
            platform: "linux".to_owned(),
            distributions: Vec::new(),
            backend: case.catalog_backend,
            package_id: case.package_id,
            trust: "native".to_owned(),
            scope: "system".to_owned(),
            channel: "stable".to_owned(),
            architectures: vec!["x86_64".to_owned()],
            priority: 0,
            requires_privilege: false,
            provenance: "fixture".to_owned(),
            evidence: "https://example.invalid/evidence".to_owned(),
            reviewed_at: "2026-07-13".to_owned(),
            verification: None,
        };
        let adapter = NativeAdapter::for_source(&source).expect("known fixture backend");
        let backend = BackendInfo {
            id: case.backend_id.clone(),
            executable: fake_executable(&case.backend_id),
            version: Some("fixture".to_owned()),
            available: case.available.unwrap_or(true),
            capabilities: vec!["install".to_owned()],
        };
        let result = adapter.command(
            operation(&case.operation),
            &backend,
            &source,
            PlanOptions {
                non_interactive: case.non_interactive,
                accept_agreements: case.accept_agreements,
            },
        );

        match (case.expected_arguments, case.expected_reason, result) {
            (Some(expected), None, Ok(command)) => {
                assert_eq!(command.arguments, expected, "{}", case.name);
                assert_eq!(
                    command.redacted_arguments, command.arguments,
                    "{}",
                    case.name
                );
                assert!(command.validate().is_ok(), "{}", case.name);
            }
            (None, Some(reason), Err(error)) => {
                assert_eq!(error.reason_code, reason, "{}", case.name);
                assert!(!error.state_changed, "{}", case.name);
            }
            (_, _, unexpected) => panic!("{}: unexpected result {unexpected:?}", case.name),
        }
    }
}
