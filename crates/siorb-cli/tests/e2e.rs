// Test harness setup failures must abort the current case with diagnostics;
// production crates continue to deny panic paths.
#![allow(clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use siorb_core::Scope;
use siorb_state::{Receipt, ReceiptOrigin, StateStore, VerificationRecord, VerificationStatus};

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn isolated_workspace_base() -> PathBuf {
    if cfg!(target_os = "macos") {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap_or_else(|error| panic!("cannot canonicalize CLI test workspace: {error}"))
    } else {
        std::env::temp_dir()
    }
}

#[derive(Debug)]
struct IsolatedWorkspace {
    root: PathBuf,
    state: PathBuf,
    tools: PathBuf,
}

impl IsolatedWorkspace {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let root = isolated_workspace_base().join(format!(
            "siorb-cli-e2e-{}-{nonce}-{}",
            std::process::id(),
            TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let state = root.join("state");
        let tools = root.join("tools");
        fs::create_dir_all(&tools)
            .unwrap_or_else(|error| panic!("cannot create isolated CLI test directory: {error}"));
        Self { root, state, tools }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_siorb"));
        command
            .env("SIORB_STATE_DIR", &self.state)
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("PROGRAMDATA", self.root.join("program-data"))
            .env_remove("SIORB_ORG_POLICY")
            .env_remove("SIORB_CATALOG_MIRROR")
            .env_remove("SIORB_RELEASE_MIRROR")
            .env_remove("SIORB_OS_VERSION");
        command
    }

    fn assert_no_transaction(&self) {
        assert!(
            !self.state.join("journal.ndjson").exists(),
            "read-only CLI test unexpectedly created a transaction journal"
        );
        let receipts = self.state.join("receipts");
        if receipts.is_dir() {
            let count = fs::read_dir(receipts)
                .map(|entries| entries.filter_map(Result::ok).count())
                .unwrap_or(usize::MAX);
            assert_eq!(count, 0, "read-only CLI test unexpectedly wrote a receipt");
        }
    }
}

impl Drop for IsolatedWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run_json(workspace: &IsolatedWorkspace, arguments: &[&str]) -> (Output, Value) {
    let output = workspace
        .command()
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("cannot start siorb test binary: {error}"));
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "siorb did not emit JSON: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, value)
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "siorb failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn offline_search_and_info_use_the_embedded_catalog() {
    let workspace = IsolatedWorkspace::new();
    let (search_output, search) = run_json(
        &workspace,
        &[
            "--offline",
            "--json",
            "--non-interactive",
            "search",
            "firefox",
        ],
    );
    assert_success(&search_output);
    assert_eq!(search["command"], "search");
    assert_eq!(search["status"], "success");
    assert!(
        search["results"]
            .as_array()
            .is_some_and(|results| results.iter().any(|result| result["id"] == "firefox"))
    );

    let (info_output, info) = run_json(
        &workspace,
        &[
            "--offline",
            "--json",
            "--non-interactive",
            "info",
            "firefox",
        ],
    );
    assert_success(&info_output);
    assert_eq!(info["command"], "info");
    assert_eq!(info["results"]["id"], "firefox");
    assert_eq!(info["errors"], Value::Array(Vec::new()));
    workspace.assert_no_transaction();
}

#[test]
fn doctor_is_structured_and_does_not_mutate_package_state() {
    let workspace = IsolatedWorkspace::new();
    let (output, doctor) = run_json(
        &workspace,
        &["--offline", "--json", "--non-interactive", "doctor"],
    );
    assert_success(&output);
    assert_eq!(doctor["command"], "doctor");
    assert_eq!(doctor["status"], "success");
    assert_eq!(doctor["results"]["mutated"], false);
    assert!(doctor["results"]["platform"].is_object());
    workspace.assert_no_transaction();
}

#[test]
fn json_quiet_still_emits_a_complete_envelope() {
    let workspace = IsolatedWorkspace::new();
    let (output, result) = run_json(
        &workspace,
        &[
            "--offline",
            "--json",
            "--quiet",
            "--non-interactive",
            "search",
            "firefox",
        ],
    );
    assert_success(&output);
    assert_eq!(result["command"], "search");
    assert_eq!(result["status"], "success");
    assert!(result["results"].is_array());
    workspace.assert_no_transaction();
}

#[test]
fn dry_run_builds_a_typed_plan_without_invoking_the_backend() {
    let workspace = IsolatedWorkspace::new();
    let Some((executable_name, source_id, expected_backend)) = platform_test_backend() else {
        return;
    };
    let executable = workspace.tools.join(executable_name);
    let marker = workspace.root.join("backend-invoked");
    write_probe_only_backend(&executable, &marker);
    let path = std::env::join_paths([&workspace.tools])
        .unwrap_or_else(|error| panic!("cannot encode isolated PATH: {error}"));

    let output = workspace
        .command()
        .env("PATH", path)
        .env("SIORB_TEST_BACKEND_MARKER", &marker)
        .args([
            "--offline",
            "--dry-run",
            "--json",
            "--non-interactive",
            "--accept-agreements",
            "--source",
            source_id,
            "plan",
            "install",
            "firefox",
        ])
        .output()
        .unwrap_or_else(|error| panic!("cannot start siorb test binary: {error}"));
    assert_success(&output);
    let plan: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("cannot decode plan JSON: {error}"));
    assert_eq!(plan["command"], "plan install");
    assert_eq!(plan["status"], "planned");
    assert_eq!(plan["results"]["operation"], "install");
    assert_eq!(plan["results"]["packages"][0]["backend"], expected_backend);
    assert!(
        plan["results"]["steps"]
            .as_array()
            .is_some_and(|steps| steps.iter().any(|step| {
                step["kind"] == "backend"
                    && step["command"]["arguments"].is_array()
                    && step["command"]["executable"]
                        .as_str()
                        .is_some_and(|path| Path::new(path).is_absolute())
            }))
    );
    assert!(!marker.exists(), "dry-run invoked the fake package backend");
    workspace.assert_no_transaction();
}

#[test]
fn explain_includes_candidate_decisions_in_json_plan_output() {
    let workspace = IsolatedWorkspace::new();
    let Some((executable_name, source_id, expected_backend)) = platform_test_backend() else {
        return;
    };
    let executable = workspace.tools.join(executable_name);
    let marker = workspace.root.join("backend-invoked");
    write_probe_only_backend(&executable, &marker);
    let path = std::env::join_paths([&workspace.tools])
        .unwrap_or_else(|error| panic!("cannot encode isolated PATH: {error}"));

    let output = workspace
        .command()
        .env("PATH", path)
        .env("SIORB_TEST_BACKEND_MARKER", &marker)
        .args([
            "--offline",
            "--dry-run",
            "--json",
            "--explain",
            "--non-interactive",
            "--accept-agreements",
            "--source",
            source_id,
            "plan",
            "install",
            "firefox",
        ])
        .output()
        .unwrap_or_else(|error| panic!("cannot start siorb explanation test: {error}"));
    assert_success(&output);
    let result: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("cannot decode explained plan JSON: {error}"));
    assert_eq!(result["command"], "plan install");
    assert_eq!(
        result["results"]["plan"]["packages"][0]["backend"],
        expected_backend
    );
    assert!(
        result["results"]["resolutions"][0]["evaluations"]
            .as_array()
            .is_some_and(|evaluations| evaluations.iter().any(|candidate| {
                candidate["source"]["id"] == source_id && candidate["accepted"] == true
            }))
    );
    assert!(!marker.exists(), "explanation dry-run invoked the backend");
    workspace.assert_no_transaction();
}

#[test]
fn catalog_verify_requires_and_accepts_a_complete_signed_repository() {
    let workspace = IsolatedWorkspace::new();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/fixtures/runtime-tuf/valid");
    let fixture_text = fixture.to_string_lossy().into_owned();
    let (valid_output, valid) = run_json(
        &workspace,
        &[
            "--json",
            "--non-interactive",
            "catalog",
            "verify",
            &fixture_text,
        ],
    );
    assert_success(&valid_output);
    assert_eq!(valid["results"]["kind"], "signed_repository");
    assert_eq!(valid["results"]["valid"], true);

    let unsigned = fixture.join("catalog.json");
    let unsigned_text = unsigned.to_string_lossy().into_owned();
    let (invalid_output, invalid) = run_json(
        &workspace,
        &[
            "--json",
            "--non-interactive",
            "catalog",
            "verify",
            &unsigned_text,
        ],
    );
    assert!(!invalid_output.status.success());
    assert_eq!(
        invalid["errors"][0]["reason_code"],
        "catalog.verify.signed_repository_required"
    );
    workspace.assert_no_transaction();
}

#[test]
fn versionless_pin_infers_and_persists_the_observed_receipt_version() {
    let workspace = IsolatedWorkspace::new();
    write_observed_receipt(&workspace, "127.0+build2");
    let (output, result) = run_json(
        &workspace,
        &["--json", "--non-interactive", "--yes", "pin", "firefox"],
    );
    assert_success(&output);
    assert_eq!(result["command"], "pin");
    assert_eq!(result["results"]["version"], "127.0+build2");

    let preferences = fs::read(workspace.state.join("preferences.json"))
        .unwrap_or_else(|error| panic!("cannot read pin preferences: {error}"));
    let preferences: Value = serde_json::from_slice(&preferences)
        .unwrap_or_else(|error| panic!("cannot decode pin preferences: {error}"));
    assert_eq!(preferences["pins"]["firefox"], "127.0+build2");
}

#[test]
fn offline_self_update_fails_closed_without_touching_the_executable() {
    let workspace = IsolatedWorkspace::new();
    let (output, failure) = run_json(
        &workspace,
        &[
            "--offline",
            "--json",
            "--non-interactive",
            "--yes",
            "self",
            "update",
        ],
    );
    assert_eq!(output.status.code(), Some(20));
    assert_eq!(failure["command"], "self update");
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["errors"][0]["reason_code"], "self_update.offline");
    assert_eq!(failure["errors"][0]["state_changed"], false);
    workspace.assert_no_transaction();
}

#[test]
fn dry_run_local_mutators_leave_preferences_catalog_and_outputs_unchanged() {
    let workspace = IsolatedWorkspace::new();
    for arguments in [
        vec![
            "--dry-run",
            "--json",
            "--non-interactive",
            "pin",
            "firefox",
            "127.0",
        ],
        vec![
            "--dry-run",
            "--json",
            "--non-interactive",
            "unpin",
            "firefox",
        ],
        vec![
            "--dry-run",
            "--json",
            "--non-interactive",
            "hold",
            "firefox",
        ],
        vec![
            "--dry-run",
            "--json",
            "--non-interactive",
            "unhold",
            "firefox",
        ],
    ] {
        let (output, result) = run_json(&workspace, &arguments);
        assert_success(&output);
        assert_eq!(result["status"], "planned");
    }

    let catalog_source = workspace.root.to_string_lossy().into_owned();
    let (use_output, use_result) = run_json(
        &workspace,
        &[
            "--dry-run",
            "--json",
            "--non-interactive",
            "catalog",
            "use",
            &catalog_source,
        ],
    );
    assert_success(&use_output);
    assert_eq!(use_result["status"], "planned");

    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/fixtures/runtime-tuf/valid");
    let update_output = workspace
        .command()
        .env("SIORB_CATALOG_MIRROR", &fixture)
        .args([
            "--dry-run",
            "--json",
            "--non-interactive",
            "catalog",
            "update",
        ])
        .output()
        .unwrap_or_else(|error| panic!("cannot start catalog update dry-run: {error}"));
    assert_success(&update_output);
    let update: Value = serde_json::from_slice(&update_output.stdout)
        .unwrap_or_else(|error| panic!("cannot decode catalog update JSON: {error}"));
    assert_eq!(update["status"], "planned");
    assert_eq!(update["results"]["cached"], false);

    let migration_output = workspace.root.join("exported-siorb.toml");
    let migration = workspace
        .command()
        .args([
            "--dry-run",
            "--json",
            "--non-interactive",
            "migrate",
            "export",
            "--output",
        ])
        .arg(&migration_output)
        .output()
        .unwrap_or_else(|error| panic!("cannot start migration dry-run: {error}"));
    assert_success(&migration);
    let migration_result: Value = serde_json::from_slice(&migration.stdout)
        .unwrap_or_else(|error| panic!("cannot decode migration dry-run JSON: {error}"));
    assert_eq!(migration_result["status"], "planned");

    let bundle_path = workspace.root.join("siorb.toml");
    fs::write(
        &bundle_path,
        "schema_version = \"1.0\"\n\n[[packages]]\nid = \"firefox\"\nplatforms = [\"never\"]\n",
    )
    .unwrap_or_else(|error| panic!("cannot create bundle fixture: {error}"));
    let lock_output = workspace.root.join("siorb.lock.json");
    let lock = workspace
        .command()
        .args(["--dry-run", "--json", "--non-interactive", "bundle", "lock"])
        .arg(&bundle_path)
        .arg("--output")
        .arg(&lock_output)
        .output()
        .unwrap_or_else(|error| panic!("cannot start bundle lock dry-run: {error}"));
    assert_success(&lock);
    let lock_result: Value = serde_json::from_slice(&lock.stdout)
        .unwrap_or_else(|error| panic!("cannot decode bundle lock dry-run JSON: {error}"));
    assert_eq!(lock_result["status"], "planned");

    assert!(!workspace.state.join("preferences.json").exists());
    assert!(!workspace.state.join("catalog-source").exists());
    assert!(!workspace.state.join("cache/active-repository").exists());
    let cache_entries = fs::read_dir(workspace.state.join("cache"))
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(usize::MAX);
    assert_eq!(cache_entries, 0, "catalog update dry-run wrote cache state");
    assert!(!migration_output.exists());
    assert!(!lock_output.exists());
    workspace.assert_no_transaction();
}

#[test]
fn noninteractive_yes_reaches_the_backend_under_default_policy() {
    let workspace = IsolatedWorkspace::new();
    let Some((executable_name, source_id, _expected_backend)) = platform_test_backend() else {
        return;
    };
    let executable = workspace.tools.join(executable_name);
    let marker = workspace.root.join("backend-invoked");
    write_probe_only_backend(&executable, &marker);
    let path = std::env::join_paths([&workspace.tools])
        .unwrap_or_else(|error| panic!("cannot encode isolated PATH: {error}"));
    let output = workspace
        .command()
        .env("PATH", path)
        .env("SIORB_TEST_BACKEND_MARKER", &marker)
        .args([
            "--json",
            "--non-interactive",
            "--yes",
            "--accept-agreements",
            "--source",
            source_id,
            "install",
            "firefox",
        ])
        .output()
        .unwrap_or_else(|error| panic!("cannot start policy confirmation test: {error}"));
    assert!(!output.status.success());
    let failure: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("cannot decode backend failure JSON: {error}"));
    assert_ne!(
        failure["errors"][0]["reason_code"], "policy.confirmation.interactive_required",
        "the built-in policy must accept reviewed --non-interactive --yes automation"
    );
    assert!(
        marker.exists(),
        "default-policy command did not reach the fake backend"
    );
}

fn platform_test_backend() -> Option<(&'static str, &'static str, &'static str)> {
    if cfg!(target_os = "windows") {
        // A Windows backend probe requires a valid PE executable. The
        // deterministic text fixture used below is intentionally only an
        // executable on Unix, so do not pretend it can stand in for winget.
        None
    } else if cfg!(target_os = "macos") {
        Some(("brew", "firefox-homebrew-cask", "homebrew-cask"))
    } else if cfg!(target_os = "linux") {
        Some(("flatpak", "firefox-flatpak", "flatpak"))
    } else {
        None
    }
}

fn write_probe_only_backend(path: &Path, marker: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ] || [ \"$1\" = \"version\" ]; then\n  printf 'fixture {}\\n'\n  exit 0\nfi\nprintf invoked > \"{}\"\nexit 97\n",
            supported_fixture_backend_version(),
            marker.display(),
        );
        fs::write(path, script)
            .unwrap_or_else(|error| panic!("cannot write fake backend: {error}"));
        let mut permissions = fs::metadata(path)
            .unwrap_or_else(|error| panic!("cannot inspect fake backend: {error}"))
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
            .unwrap_or_else(|error| panic!("cannot make fake backend executable: {error}"));
    }
    #[cfg(not(unix))]
    {
        let _ = marker;
        fs::write(path, b"fixture backend")
            .unwrap_or_else(|error| panic!("cannot write fake backend: {error}"));
    }
}

#[cfg(unix)]
fn supported_fixture_backend_version() -> &'static str {
    if cfg!(target_os = "windows") {
        "1.8.0"
    } else if cfg!(target_os = "macos") {
        "4.2.0"
    } else {
        "1.14.0"
    }
}

fn write_observed_receipt(workspace: &IsolatedWorkspace, version: &str) {
    let state = StateStore::new(workspace.state.clone())
        .unwrap_or_else(|error| panic!("cannot create receipt state: {error}"));
    state
        .write_receipt(&Receipt {
            schema_version: "1.0".to_owned(),
            logical_id: "firefox".to_owned(),
            native_id: "org.mozilla.firefox".to_owned(),
            backend: "flatpak".to_owned(),
            source_id: "firefox-flatpak".to_owned(),
            requested_version: None,
            observed_version: Some(version.to_owned()),
            scope: Scope::User,
            channel: "stable".to_owned(),
            architecture: "x86_64".to_owned(),
            catalog_fingerprint: "fixture-catalog".to_owned(),
            policy_fingerprint: None,
            installed_at_unix: 1,
            verification: VerificationRecord {
                status: VerificationStatus::Verified,
                checked_at_unix: 1,
                reason: "fixture observation".to_owned(),
            },
            owned_files: Vec::new(),
            transaction_id: "fixture-transaction".to_owned(),
            origin: ReceiptOrigin::Observed,
        })
        .unwrap_or_else(|error| panic!("cannot write receipt fixture: {error}"));
}
