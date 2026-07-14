use serde::Deserialize;
use siorb_backends::{BackendAdapter, NativeAdapter, PlanOptions};
use siorb_catalog::PackageSource;
use siorb_core::{BackendInfo, Operation};

#[derive(Debug, Deserialize)]
struct TerminalCase {
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct UnicodeCase {
    value: String,
    valid: bool,
    reason_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArchivePathCase {
    path: String,
    kind: String,
    valid: bool,
    reason_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArgumentCase {
    value: String,
    context: String,
    valid: bool,
    reason_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UrlCase {
    url: String,
    valid: bool,
    reason_code: Option<String>,
    redirect: Option<String>,
    redirect_count: Option<u32>,
}

#[test]
fn untrusted_backend_output_cannot_control_the_terminal() {
    let cases: Vec<TerminalCase> = serde_json::from_str(include_str!("terminal-output.json"))
        .expect("terminal security fixture");
    for case in cases {
        assert_eq!(
            siorb_core::sanitize_terminal(&case.input),
            case.expected,
            "input {:?}",
            case.input
        );
    }
}

#[test]
fn exact_install_identifiers_reject_unicode_ambiguity() {
    let cases: Vec<UnicodeCase> = serde_json::from_str(include_str!("unicode-ambiguity.json"))
        .expect("Unicode security fixture");
    for case in cases {
        if case.reason_code.as_deref() == Some("catalog.alias.reserved") {
            continue;
        }
        let actual = siorb_catalog::normalize_identifier(&case.value);
        assert_eq!(actual.is_ok(), case.valid, "input {:?}", case.value);
    }
}

#[test]
fn every_argument_injection_case_reaches_the_typed_adapter_boundary() {
    let cases: Vec<ArgumentCase> = serde_json::from_str(include_str!("argument-injection.json"))
        .expect("argument-injection fixture");
    for case in cases {
        if !case.value.is_ascii() {
            let result = siorb_catalog::normalize_identifier(&case.value);
            assert_eq!(result.is_ok(), case.valid, "input {:?}", case.value);
            assert_eq!(
                result.err().map(|error| error.reason_code),
                case.reason_code,
                "input {:?}",
                case.value
            );
            continue;
        }

        let (catalog_backend, backend_id) = match case.context.as_str() {
            "winget_package_id" => ("winget", "winget"),
            "flatpak_package_id" => ("flatpak", "flatpak"),
            _ => ("apt", "apt"),
        };
        let source = native_source(catalog_backend, &case.value);
        let adapter = NativeAdapter::for_source(&source).expect("known fixture backend");
        let backend = BackendInfo {
            id: backend_id.to_owned(),
            executable: fake_executable(backend_id),
            version: Some("fixture".to_owned()),
            available: true,
            capabilities: vec!["install".to_owned()],
        };
        let result = adapter.command(
            Operation::Install,
            &backend,
            &source,
            PlanOptions {
                non_interactive: false,
                accept_agreements: true,
            },
        );
        assert_eq!(result.is_ok(), case.valid, "input {:?}", case.value);
        if case.valid {
            let command = result.expect("valid package id must produce a command");
            assert!(
                command
                    .arguments
                    .iter()
                    .any(|argument| argument == &case.value)
            );
            assert!(command.validate().is_ok());
        } else {
            assert_eq!(
                result.err().map(|error| error.reason_code),
                case.reason_code,
                "input {:?}",
                case.value
            );
        }
    }
}

#[test]
fn reachable_artifact_url_policy_cases_are_enforced_by_catalog_validation() {
    let cases: Vec<UrlCase> =
        serde_json::from_str(include_str!("url-policy.json")).expect("URL policy fixture");
    let mut live_redirect_cases = 0;
    for case in cases {
        let needs_live_redirect = case.redirect_count.is_some()
            || case
                .redirect
                .as_deref()
                .is_some_and(|redirect| redirect.starts_with("https://"));
        if needs_live_redirect {
            live_redirect_cases += 1;
            continue;
        }
        let candidate = case.redirect.as_deref().unwrap_or(&case.url);
        let result = artifact_catalog(candidate);
        assert_eq!(result.is_ok(), case.valid, "URL {candidate}");
        if !case.valid {
            assert_eq!(
                result.err().map(|error| error.reason_code).as_deref(),
                Some("catalog.artifact.url"),
                "fixture expectation {:?}",
                case.reason_code
            );
        }
    }
    assert_eq!(
        live_redirect_cases, 2,
        "new redirect fixtures must be wired to an exposed redirect validator"
    );
}

#[test]
fn fuzzy_code_request_is_ambiguous_and_never_auto_selected() {
    let catalog = siorb_catalog::Catalog::from_json(
        include_str!("../fixtures/catalog/ambiguous-code.json"),
        "security-fixture",
        true,
    )
    .expect("ambiguous catalog fixture");
    let lookup = catalog.lookup("code").expect("safe query");
    match lookup {
        siorb_catalog::Lookup::Ambiguous(packages) => assert_eq!(packages.len(), 2),
        other => panic!("expected ambiguity, got {other:?}"),
    }
}

#[test]
fn archive_paths_are_safe_for_every_destination_platform() {
    let cases: Vec<ArchivePathCase> = serde_json::from_str(include_str!("archive-paths.json"))
        .expect("archive path security fixture");
    for case in cases {
        if case.kind != "file" || case.reason_code.as_deref() == Some("archive.ratio.limit") {
            continue;
        }
        let result = siorb_executor::validate_archive_path(std::path::Path::new(&case.path));
        assert_eq!(result.is_ok(), case.valid, "archive path {:?}", case.path);
        if !case.valid {
            assert_eq!(
                result.err().map(|error| error.reason_code),
                case.reason_code,
                "archive path {:?}",
                case.path
            );
        }
    }
}

fn native_source(backend: &str, package_id: &str) -> PackageSource {
    PackageSource {
        id: format!("{backend}-security-fixture"),
        platform: "linux".to_owned(),
        distributions: Vec::new(),
        backend: backend.to_owned(),
        package_id: package_id.to_owned(),
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
    }
}

fn fake_executable(backend: &str) -> String {
    if cfg!(windows) {
        format!(r"C:\fixture\{backend}.exe")
    } else {
        format!("/fixture/{backend}")
    }
}

fn artifact_catalog(url: &str) -> siorb_core::Result<siorb_catalog::Catalog> {
    let document = serde_json::json!({
        "schema_version": "1.0",
        "catalog_version": 1,
        "generated_at": "2026-07-13T00:00:00Z",
        "packages": [{
            "schema_version": "1.0",
            "id": "security-artifact",
            "name": "Security artifact",
            "description": "URL policy fixture",
            "homepage": "https://example.org/",
            "license": "Apache-2.0",
            "sources": [{
                "id": "security-artifact-source",
                "platform": "linux",
                "backend": "artifact",
                "package_id": url,
                "trust": "verified-upstream",
                "scope": "user",
                "channel": "stable",
                "architectures": ["x86_64"],
                "provenance": "upstream-release",
                "evidence": "https://example.org/releases",
                "reviewed_at": "2026-07-13",
                "verification": {
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "content_type": "application/gzip",
                    "max_bytes": 1048576,
                    "kind": "portable-archive",
                    "format": "tar.gz",
                    "archive_format": "tar.gz"
                }
            }]
        }]
    });
    siorb_catalog::Catalog::from_json(&document.to_string(), "security-url-fixture", true)
}
