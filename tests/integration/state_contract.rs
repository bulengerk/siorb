use serde::Deserialize;
use siorb_core::Scope;
use siorb_state::{Receipt, ReceiptOrigin, StateStore, VerificationRecord, VerificationStatus};

#[derive(Debug, Deserialize)]
struct PermissionCase {
    platform: String,
    mode: Option<String>,
    owner: Option<String>,
    acl: Option<Vec<String>>,
    symlink: Option<bool>,
    valid: bool,
    reason_code: Option<String>,
}

fn permission_cases() -> Vec<PermissionCase> {
    serde_json::from_str(include_str!("../security/state-permissions.json"))
        .expect("state permission fixture")
}

fn receipt(version: &str) -> Receipt {
    Receipt {
        schema_version: "1.0".to_owned(),
        logical_id: "firefox".to_owned(),
        native_id: "firefox".to_owned(),
        backend: "apt".to_owned(),
        source_id: "firefox-apt".to_owned(),
        requested_version: None,
        observed_version: Some(version.to_owned()),
        scope: Scope::System,
        channel: "stable".to_owned(),
        architecture: "x86_64".to_owned(),
        catalog_fingerprint: "a".repeat(64),
        policy_fingerprint: None,
        installed_at_unix: 1,
        verification: VerificationRecord {
            status: VerificationStatus::Verified,
            checked_at_unix: 1,
            reason: "fixture".to_owned(),
        },
        owned_files: Vec::new(),
        transaction_id: "tx-fixture".to_owned(),
        origin: ReceiptOrigin::Installed,
    }
}

#[test]
fn atomic_receipt_update_replaces_the_previous_version() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let store = StateStore::new(directory.path().join("state")).expect("state store");
    store.write_receipt(&receipt("1")).expect("first receipt");
    store
        .write_receipt(&receipt("2"))
        .expect("replacement receipt");
    let receipts = store.receipts().expect("read receipts");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].observed_version.as_deref(), Some("2"));
}

#[cfg(unix)]
#[test]
fn state_root_must_not_follow_a_symbolic_link() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary state directory");
    let actual = directory.path().join("attacker-controlled");
    std::fs::create_dir(&actual).expect("attacker directory");
    let link = directory.path().join("state");
    symlink(&actual, &link).expect("state symlink");
    let case = permission_cases()
        .into_iter()
        .find(|case| case.symlink == Some(true))
        .expect("symlink permission case");
    let error = StateStore::new(link).expect_err("state root symlink must be rejected");
    assert_eq!(Some(error.reason_code), case.reason_code);
    assert!(!case.valid);
}

#[cfg(unix)]
#[test]
fn state_file_modes_from_the_security_corpus_are_enforced() {
    use std::os::unix::fs::PermissionsExt;

    let cases: Vec<_> = permission_cases()
        .into_iter()
        .filter(|case| {
            case.platform == "linux"
                && case.owner.as_deref() == Some("current_user")
                && case.mode.is_some()
        })
        .collect();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let store = StateStore::new(directory.path().join("state")).expect("state store");
        store.write_receipt(&receipt("1")).expect("fixture receipt");
        let path = store.root().join("receipts/firefox.json");
        let mode = u32::from_str_radix(case.mode.as_deref().expect("fixture mode"), 8)
            .expect("octal fixture mode");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set fixture permissions");
        let result = store.receipts();
        assert_eq!(result.is_ok(), case.valid, "mode {:04o}", mode);
        if !case.valid {
            assert_eq!(
                result.err().map(|error| error.reason_code),
                case.reason_code
            );
        }
    }
}

#[test]
fn privileged_owner_and_acl_rows_remain_explicit_in_the_corpus() {
    let privileged: Vec<_> = permission_cases()
        .into_iter()
        .filter(|case| case.owner.as_deref() == Some("other_user") || case.acl.as_ref().is_some())
        .collect();
    assert_eq!(privileged.len(), 3);
    assert!(privileged.iter().any(|case| case.valid));
    assert!(privileged.iter().any(|case| !case.valid));
}
