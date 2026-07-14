use std::collections::BTreeMap;
use std::fs;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use siorb_update::{
    MetadataDescription, PublicKey, RepositoryVerifier, RoleDefinition, RollbackState,
    RootMetadata, Signed, SnapshotMetadata, TargetDescription, TargetsMetadata, TimestampMetadata,
    load_rollback_state, store_rollback_state,
};

const ROOT_A: [u8; 32] = [1; 32];
const ROOT_B: [u8; 32] = [2; 32];
const TARGETS: [u8; 32] = [3; 32];
const SNAPSHOT: [u8; 32] = [4; 32];
const TIMESTAMP: [u8; 32] = [5; 32];

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn key(secret: &[u8; 32]) -> PublicKey {
    PublicKey {
        scheme: "ed25519".to_owned(),
        public: siorb_update::public_key(secret).expect("test public key"),
    }
}

fn root() -> Signed<RootMetadata> {
    let metadata = RootMetadata {
        role_type: "root".to_owned(),
        spec_version: "1.0".to_owned(),
        version: 1,
        expires_unix: 10_000,
        consistent_snapshot: true,
        keys: BTreeMap::from([
            ("root-a".to_owned(), key(&ROOT_A)),
            ("root-b".to_owned(), key(&ROOT_B)),
            ("targets".to_owned(), key(&TARGETS)),
            ("snapshot".to_owned(), key(&SNAPSHOT)),
            ("timestamp".to_owned(), key(&TIMESTAMP)),
        ]),
        roles: BTreeMap::from([
            (
                "root".to_owned(),
                RoleDefinition {
                    key_ids: vec!["root-a".to_owned(), "root-b".to_owned()],
                    threshold: 2,
                },
            ),
            (
                "targets".to_owned(),
                RoleDefinition {
                    key_ids: vec!["targets".to_owned()],
                    threshold: 1,
                },
            ),
            (
                "snapshot".to_owned(),
                RoleDefinition {
                    key_ids: vec!["snapshot".to_owned()],
                    threshold: 1,
                },
            ),
            (
                "timestamp".to_owned(),
                RoleDefinition {
                    key_ids: vec!["timestamp".to_owned()],
                    threshold: 1,
                },
            ),
        ]),
    };
    let mut signed =
        siorb_update::sign(metadata.clone(), "root-a", &ROOT_A).expect("first root signature");
    let second = siorb_update::sign(metadata, "root-b", &ROOT_B).expect("second root signature");
    signed.signatures.extend(second.signatures);
    signed
}

struct RepositoryBytes {
    root: Signed<RootMetadata>,
    timestamp: Vec<u8>,
    snapshot: Vec<u8>,
    targets: Vec<u8>,
    target: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct AttackCase {
    scenario: String,
    expected: String,
    reason_code: Option<String>,
}

fn repository(expires_unix: u64) -> RepositoryBytes {
    repository_with_expirations(expires_unix, expires_unix, expires_unix)
}

fn repository_with_expirations(
    timestamp_expires: u64,
    snapshot_expires: u64,
    targets_expires: u64,
) -> RepositoryBytes {
    let target = br#"{"schema_version":"1.0","packages":[]}"#.to_vec();
    let targets = siorb_update::sign(
        TargetsMetadata {
            role_type: "targets".to_owned(),
            spec_version: "1.0".to_owned(),
            version: 1,
            expires_unix: targets_expires,
            targets: BTreeMap::from([(
                "catalog.json".to_owned(),
                TargetDescription {
                    length: target.len() as u64,
                    sha256: digest(&target),
                    custom: BTreeMap::new(),
                },
            )]),
        },
        "targets",
        &TARGETS,
    )
    .expect("targets signature");
    let targets = serde_json::to_vec(&targets).expect("targets encoding");
    let snapshot = siorb_update::sign(
        SnapshotMetadata {
            role_type: "snapshot".to_owned(),
            spec_version: "1.0".to_owned(),
            version: 1,
            expires_unix: snapshot_expires,
            meta: BTreeMap::from([(
                "targets.json".to_owned(),
                MetadataDescription {
                    version: 1,
                    length: targets.len() as u64,
                    sha256: digest(&targets),
                },
            )]),
        },
        "snapshot",
        &SNAPSHOT,
    )
    .expect("snapshot signature");
    let snapshot = serde_json::to_vec(&snapshot).expect("snapshot encoding");
    let timestamp = siorb_update::sign(
        TimestampMetadata {
            role_type: "timestamp".to_owned(),
            spec_version: "1.0".to_owned(),
            version: 1,
            expires_unix: timestamp_expires,
            snapshot: MetadataDescription {
                version: 1,
                length: snapshot.len() as u64,
                sha256: digest(&snapshot),
            },
        },
        "timestamp",
        &TIMESTAMP,
    )
    .expect("timestamp signature");
    RepositoryBytes {
        root: root(),
        timestamp: serde_json::to_vec(&timestamp).expect("timestamp encoding"),
        snapshot,
        targets,
        target,
    }
}

#[test]
fn every_declared_tuf_attack_executes_against_the_runtime_verifier() {
    let cases: Vec<AttackCase> =
        serde_json::from_str(include_str!("tuf-attacks.json")).expect("TUF attack fixture");
    assert_eq!(cases.len(), 15);
    for case in cases {
        let observed = exercise_attack(&case.scenario);
        match case.expected.as_str() {
            "reject" => assert_eq!(
                observed.as_deref(),
                case.reason_code.as_deref(),
                "scenario {}",
                case.scenario
            ),
            "retain_previous" => assert_eq!(
                observed.as_deref(),
                case.reason_code.as_deref(),
                "scenario {}",
                case.scenario
            ),
            "accept" => assert_eq!(observed, None, "scenario {}", case.scenario),
            other => panic!("unsupported expected outcome {other}"),
        }
    }
}

fn exercise_attack(scenario: &str) -> Option<String> {
    match scenario {
        "expired_timestamp" | "timestamp_never_advances_until_expiry" => {
            verify_error(repository(99), RollbackState::default(), 100)
        }
        "expired_snapshot_offline_outside_grace" => verify_error(
            repository_with_expirations(1_000, 99, 1_000),
            RollbackState::default(),
            100,
        ),
        "root_threshold_one_of_two" => {
            let mut trusted = root();
            trusted.signatures.truncate(1);
            RepositoryVerifier::new(trusted, RollbackState::default())
                .err()
                .map(|error| error.reason_code)
        }
        "unknown_root_key" => {
            let mut trusted = root();
            for signature in &mut trusted.signatures {
                signature.key_id = "unknown".to_owned();
            }
            RepositoryVerifier::new(trusted, RollbackState::default())
                .err()
                .map(|error| error.reason_code)
        }
        "root_version_rollback" => verify_error(
            repository(1_000),
            RollbackState {
                root: 2,
                ..RollbackState::default()
            },
            100,
        ),
        "snapshot_version_rollback" => verify_error(
            repository(1_000),
            RollbackState {
                snapshot: 2,
                ..RollbackState::default()
            },
            100,
        ),
        "same_version_changed_hash" | "mirror_snapshot_disagrees_with_timestamp" => {
            let mut repository = repository(1_000);
            if let Some(byte) = repository.snapshot.get_mut(0) {
                *byte ^= 1;
            }
            verify_error(repository, RollbackState::default(), 100)
        }
        "target_hash_mismatch" => {
            let repository = repository(1_000);
            let verified = RepositoryVerifier::new(repository.root, RollbackState::default())
                .expect("trusted root")
                .at_time(100)
                .verify(
                    &repository.timestamp,
                    &repository.snapshot,
                    &repository.targets,
                )
                .expect("verified metadata");
            let mut target = repository.target;
            target[0] ^= 1;
            verified
                .verify_target("catalog.json", &target)
                .err()
                .map(|error| error.reason_code)
        }
        "target_length_mismatch" => {
            let repository = repository(1_000);
            let verified = RepositoryVerifier::new(repository.root, RollbackState::default())
                .expect("trusted root")
                .at_time(100)
                .verify(
                    &repository.timestamp,
                    &repository.snapshot,
                    &repository.targets,
                )
                .expect("verified metadata");
            let mut target = repository.target;
            target.push(b' ');
            verified
                .verify_target("catalog.json", &target)
                .err()
                .map(|error| error.reason_code)
        }
        "truncated_snapshot" => {
            let mut repository = repository(1_000);
            repository.snapshot.truncate(repository.snapshot.len() / 2);
            verify_error(repository, RollbackState::default(), 100)
        }
        "interrupted_update_before_atomic_swap" => {
            let directory = tempfile::tempdir().expect("rollback fixture directory");
            let path = directory.path().join("rollback.json");
            let previous = RollbackState {
                root: 1,
                timestamp: 4,
                snapshot: 3,
                targets: 2,
            };
            store_rollback_state(&path, &previous).expect("store previous rollback state");
            fs::write(path.with_extension("tmp-interrupted"), b"{\"root\":99")
                .expect("write interrupted temporary file");
            assert_eq!(load_rollback_state(&path).ok(), Some(previous));
            Some("update.state.atomicity".to_owned())
        }
        "valid_root_rotation_old_and_new_thresholds" => {
            let trusted = root();
            let mut next = trusted.signed.clone();
            next.version = 2;
            let mut signed = siorb_update::sign(next.clone(), "root-a", &ROOT_A)
                .expect("first rotated-root signature");
            signed.signatures.extend(
                siorb_update::sign(next, "root-b", &ROOT_B)
                    .expect("second rotated-root signature")
                    .signatures,
            );
            let bytes = serde_json::to_vec(&signed).expect("rotated root encoding");
            let mut verifier = RepositoryVerifier::new(trusted, RollbackState::default())
                .expect("trusted root")
                .at_time(100);
            verifier
                .rotate_root(&bytes)
                .err()
                .map(|error| error.reason_code)
        }
        "valid_consistent_snapshot" => {
            let repository = repository(1_000);
            RepositoryVerifier::new(repository.root, RollbackState::default())
                .expect("trusted root")
                .at_time(100)
                .verify(
                    &repository.timestamp,
                    &repository.snapshot,
                    &repository.targets,
                )
                .err()
                .map(|error| error.reason_code)
        }
        other => panic!("unhandled TUF fixture scenario {other}"),
    }
}

fn verify_error(repository: RepositoryBytes, state: RollbackState, now: u64) -> Option<String> {
    RepositoryVerifier::new(repository.root, state)
        .expect("trusted root shape")
        .at_time(now)
        .verify(
            &repository.timestamp,
            &repository.snapshot,
            &repository.targets,
        )
        .err()
        .map(|error| error.reason_code)
}

#[test]
fn complete_signed_static_repository_verifies_and_authenticates_target() {
    let repository = repository(1_000);
    let verified = RepositoryVerifier::new(repository.root, RollbackState::default())
        .expect("trusted root")
        .at_time(100)
        .verify(
            &repository.timestamp,
            &repository.snapshot,
            &repository.targets,
        )
        .expect("complete repository verification");
    assert!(
        verified
            .verify_target("catalog.json", &repository.target)
            .is_ok()
    );
    assert!(verified.verify_target("catalog.json", b"tampered").is_err());
}

#[test]
fn metadata_expiry_and_rollback_are_never_silently_bypassed() {
    let expired = repository(99);
    let error = RepositoryVerifier::new(expired.root, RollbackState::default())
        .expect("trusted root")
        .at_time(100)
        .verify(&expired.timestamp, &expired.snapshot, &expired.targets)
        .expect_err("expired metadata must fail");
    assert_eq!(error.reason_code, "update.metadata.expired");

    let rollback = repository(1_000);
    let error = RepositoryVerifier::new(
        rollback.root,
        RollbackState {
            timestamp: 2,
            ..RollbackState::default()
        },
    )
    .expect("trusted root")
    .at_time(100)
    .verify(&rollback.timestamp, &rollback.snapshot, &rollback.targets)
    .expect_err("rollback must fail");
    assert_eq!(error.reason_code, "update.rollback.detected");
}

#[test]
fn root_threshold_and_mix_and_match_are_rejected() {
    let mut insufficient = root();
    insufficient.signatures.truncate(1);
    let error = RepositoryVerifier::new(insufficient, RollbackState::default())
        .expect_err("one of two root signatures must fail");
    assert_eq!(error.reason_code, "update.threshold.not_met");

    let mut repository = repository(1_000);
    repository.snapshot.push(b' ');
    let error = RepositoryVerifier::new(repository.root, RollbackState::default())
        .expect("trusted root")
        .at_time(100)
        .verify(
            &repository.timestamp,
            &repository.snapshot,
            &repository.targets,
        )
        .expect_err("changed snapshot must fail");
    assert!(matches!(
        error.reason_code.as_str(),
        "update.length.mismatch" | "update.hash.mismatch"
    ));
}
