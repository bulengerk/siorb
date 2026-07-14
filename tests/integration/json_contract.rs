use std::collections::BTreeSet;

use serde_json::{Value, json};
use siorb_bundle::{Bundle, BundleLock};
use siorb_core::{
    Architecture, CatalogIdentity, JsonEnvelope, OsFamily, OutputStatus, PlatformContext, Scope,
};
use siorb_executor::ExecutionReport;
use siorb_planner::ExecutionPlan;
use siorb_resolver::Resolution;
use siorb_state::{
    JournalEvent, JournalState, Receipt, ReceiptOrigin, VerificationRecord, VerificationStatus,
};

fn platform() -> PlatformContext {
    PlatformContext {
        os: OsFamily::Linux,
        os_version: Some("24.04".to_owned()),
        distribution: Some("ubuntu".to_owned()),
        distribution_version: Some("24.04".to_owned()),
        distribution_like: vec!["debian".to_owned()],
        architecture: Architecture::X86_64,
        translated: false,
        libc: Some("glibc".to_owned()),
        backends: Vec::new(),
        interactive: false,
        elevation_available: true,
        supported_scopes: vec![Scope::User, Scope::System],
        offline: true,
        restrictions: Vec::new(),
    }
}

#[test]
fn envelope_has_exactly_the_versioned_public_fields() {
    let envelope = JsonEnvelope::success(
        "doctor",
        OutputStatus::Success,
        platform(),
        CatalogIdentity {
            id: "bundled".to_owned(),
            version: 1,
            fingerprint: "a".repeat(64),
            verified: true,
            expires_unix: None,
            source: "embedded".to_owned(),
        },
        None,
        json!({"healthy": true}),
    );
    let value = serde_json::to_value(envelope).expect("envelope serialization");
    let keys: BTreeSet<_> = value
        .as_object()
        .expect("envelope is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "catalog",
            "command",
            "correlation_id",
            "errors",
            "platform",
            "policy",
            "results",
            "schema_version",
            "status",
            "warnings",
        ])
    );
    assert_eq!(value["schema_version"], "1.0");
    assert_eq!(value["status"], "success");
    assert!(value["errors"].as_array().is_some_and(Vec::is_empty));
}

#[test]
fn hand_authored_envelope_fixture_round_trips_through_runtime_types() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/command-output/doctor-success.json"
    ))
    .expect("envelope fixture");
    let runtime: JsonEnvelope<Value> =
        serde_json::from_value(fixture.clone()).expect("runtime envelope shape");
    assert_eq!(
        serde_json::to_value(runtime).expect("envelope serialization"),
        fixture
    );
}

#[test]
fn plan_and_bundle_fixtures_round_trip_through_runtime_types() {
    let plan_fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/execution-plan/install-firefox.json"
    ))
    .expect("plan fixture");
    let plan: ExecutionPlan =
        serde_json::from_value(plan_fixture.clone()).expect("runtime execution plan shape");
    assert_eq!(
        serde_json::to_value(plan).expect("plan serialization"),
        plan_fixture
    );

    let bundle_fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/bundle/developer-workstation.json"
    ))
    .expect("bundle fixture");
    let bundle: Bundle =
        serde_json::from_value(bundle_fixture.clone()).expect("runtime bundle shape");
    assert_eq!(
        serde_json::to_value(bundle).expect("bundle serialization"),
        bundle_fixture
    );

    let lock_fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/bundle-lock/ubuntu.json"
    ))
    .expect("bundle lock fixture");
    let lock: BundleLock =
        serde_json::from_value(lock_fixture.clone()).expect("runtime bundle lock shape");
    assert_eq!(
        serde_json::to_value(lock).expect("bundle lock serialization"),
        lock_fixture
    );
}

#[test]
fn resolution_and_execution_report_fixtures_match_runtime_types() {
    let resolution_fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/resolution/firefox-apt.json"
    ))
    .expect("resolution fixture");
    let resolution: Resolution =
        serde_json::from_value(resolution_fixture.clone()).expect("runtime resolution shape");
    assert_eq!(
        serde_json::to_value(resolution).expect("resolution serialization"),
        resolution_fixture
    );

    let report_fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/execution-report/no-change.json"
    ))
    .expect("execution report fixture");
    let report: ExecutionReport =
        serde_json::from_value(report_fixture.clone()).expect("runtime execution report shape");
    assert_eq!(
        serde_json::to_value(report).expect("execution report serialization"),
        report_fixture
    );
}

#[test]
fn receipt_fixture_is_the_production_serialization_shape() {
    let receipt = Receipt {
        schema_version: "1.0".to_owned(),
        logical_id: "firefox".to_owned(),
        native_id: "firefox".to_owned(),
        backend: "apt".to_owned(),
        source_id: "firefox-apt".to_owned(),
        requested_version: None,
        observed_version: Some("127.0+build2".to_owned()),
        scope: Scope::System,
        channel: "stable".to_owned(),
        architecture: "x86_64".to_owned(),
        catalog_fingerprint: "a".repeat(64),
        policy_fingerprint: None,
        installed_at_unix: 1_783_969_200,
        verification: VerificationRecord {
            status: VerificationStatus::Verified,
            checked_at_unix: 1_783_969_203,
            reason: "backend-installed-state".to_owned(),
        },
        owned_files: Vec::new(),
        transaction_id: "3d00d246-e15f-4ddb-91d7-63db369278a0".to_owned(),
        origin: ReceiptOrigin::Installed,
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/receipt/firefox.json"
    ))
    .expect("receipt fixture");
    assert_eq!(
        serde_json::to_value(receipt).expect("receipt serialization"),
        fixture
    );
}

#[test]
fn every_runtime_verification_status_matches_the_published_receipt_schema() {
    let schema: Value = serde_json::from_str(include_str!("../../schemas/v1/receipt.schema.json"))
        .expect("receipt schema");
    let schema_values: BTreeSet<_> =
        schema["properties"]["verification"]["properties"]["status"]["enum"]
            .as_array()
            .expect("verification status enum")
            .iter()
            .filter_map(Value::as_str)
            .collect();
    let runtime_values: BTreeSet<_> = [
        VerificationStatus::Verified,
        VerificationStatus::Failed,
        VerificationStatus::Unavailable,
        VerificationStatus::BackendCompleted,
    ]
    .into_iter()
    .map(|status| serde_json::to_value(status).expect("verification status serialization"))
    .filter_map(|value| value.as_str().map(str::to_owned))
    .collect();
    let runtime_refs: BTreeSet<_> = runtime_values.iter().map(String::as_str).collect();
    assert_eq!(runtime_refs, schema_values);
    for value in runtime_values {
        let decoded: VerificationStatus =
            serde_json::from_value(Value::String(value)).expect("verification status parse");
        assert!(matches!(
            decoded,
            VerificationStatus::Verified
                | VerificationStatus::Failed
                | VerificationStatus::Unavailable
                | VerificationStatus::BackendCompleted
        ));
    }
}

#[test]
fn journal_fixture_is_the_production_serialization_shape() {
    let event = JournalEvent {
        schema_version: "1.0".to_owned(),
        transaction_id: "3d00d246-e15f-4ddb-91d7-63db369278a0".to_owned(),
        plan_id: "plan-1".to_owned(),
        step_id: Some("install-firefox".to_owned()),
        timestamp_unix: 1_783_969_202,
        state: JournalState::StepCompleted,
        detail: "exit_code=0".to_owned(),
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/schemas/v1/valid/transaction-event/step-completed.json"
    ))
    .expect("journal fixture");
    assert_eq!(
        serde_json::to_value(event).expect("journal serialization"),
        fixture
    );
}
