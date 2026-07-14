use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use siorb_core::{Architecture, OsFamily, PlatformSupport};
use siorb_platform::{ProbeOutput, ProbeRunner, SystemDetector, parse_os_release};

#[test]
fn every_linux_family_os_release_fixture_is_parsed_as_inert_data() {
    let fixtures = [
        ("debian-12.os-release", "debian", Some("12")),
        ("ubuntu-24.04.os-release", "ubuntu", Some("24.04")),
        ("fedora-42.os-release", "fedora", Some("42")),
        ("rhel-10.os-release", "rhel", Some("10.0")),
        ("arch.os-release", "arch", None),
        ("opensuse-15.6.os-release", "opensuse-leap", Some("15.6")),
        ("alpine-3.21.os-release", "alpine", Some("3.21.3")),
    ];
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/platform-detection");
    for (name, expected_id, expected_version) in fixtures {
        let input = std::fs::read_to_string(root.join(name)).expect("platform fixture");
        let parsed = parse_os_release(&input);
        assert_eq!(
            parsed.get("ID").map(String::as_str),
            Some(expected_id),
            "{name}"
        );
        assert_eq!(
            parsed.get("VERSION_ID").map(String::as_str),
            expected_version,
            "{name}"
        );
    }
}

#[test]
fn adversarial_os_release_is_never_interpreted_as_a_program() {
    let input = include_str!("../fixtures/platform-detection/adversarial.os-release");
    let parsed = parse_os_release(input);
    assert_eq!(parsed.get("ID").map(String::as_str), Some("second"));
    assert_eq!(
        parsed.get("VERSION_ID").map(String::as_str),
        Some("$(touch /tmp/siorb-must-not-exist)")
    );
    assert!(!parsed.contains_key("lowercase_key"));
    assert!(!parsed.contains_key("BAD-KEY"));
}

#[cfg(unix)]
#[test]
fn executable_lookup_rejects_a_non_executable_regular_file() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let candidate = directory.path().join("fake-backend");
    std::fs::write(&candidate, b"not executable").expect("fake backend");
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
        .expect("permissions");
    assert!(
        siorb_platform::find_executable(
            "fake-backend",
            Some(directory.path().to_str().expect("utf-8 temp path"))
        )
        .is_none()
    );
}

#[derive(Clone, Debug, Deserialize)]
struct BackendInput {
    executable: String,
    output: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DetectionScenario {
    golden: String,
    support: PlatformSupport,
    os: OsFamily,
    os_version: Option<String>,
    process_architecture: Architecture,
    native_architecture: Architecture,
    os_release: Option<String>,
    os_release_inline: Option<String>,
    libc: Option<String>,
    interactive: bool,
    elevation_available: bool,
    offline: bool,
    container: bool,
    compatibility_layer: bool,
    backends: Vec<BackendInput>,
}

#[derive(Clone, Debug)]
struct ScenarioProbe {
    outputs: BTreeMap<String, ProbeOutput>,
}

impl ProbeRunner for ScenarioProbe {
    fn run(
        &self,
        executable: &Path,
        _arguments: &[&str],
        _timeout: Duration,
        _max_output_bytes: usize,
    ) -> io::Result<ProbeOutput> {
        let name = executable
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fixture executable"))?;
        self.outputs
            .get(name)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fixture probe output"))
    }
}

#[test]
fn every_platform_golden_is_produced_from_detector_inputs() {
    let test_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_root = test_root.join("fixtures/platform-detection");
    let golden_root = test_root.join("golden/platform");
    let scenarios: Vec<DetectionScenario> = serde_json::from_slice(
        &std::fs::read(fixture_root.join("scenarios.json")).expect("detector scenarios"),
    )
    .expect("detector scenario JSON");
    let scenario_names: BTreeSet<_> = scenarios
        .iter()
        .map(|scenario| scenario.golden.clone())
        .collect();
    let golden_names: BTreeSet<_> = std::fs::read_dir(&golden_root)
        .expect("platform golden directory")
        .map(|entry| entry.expect("platform golden entry").file_name())
        .filter_map(|name| name.to_str().map(str::to_owned))
        .filter(|name| name.ends_with(".json"))
        .collect();
    assert!(
        scenario_names.len() >= 20,
        "platform matrix unexpectedly shrank"
    );
    assert_eq!(
        scenario_names, golden_names,
        "every golden needs detector inputs"
    );

    for scenario in scenarios {
        let sandbox = tempfile::tempdir().expect("detector sandbox");
        let bin = sandbox.path().join("bin");
        std::fs::create_dir(&bin).expect("fixture bin directory");
        let release = sandbox.path().join("os-release");
        let release_bytes = scenario.os_release_inline.clone().map_or_else(
            || {
                scenario.os_release.as_ref().map_or_else(Vec::new, |name| {
                    std::fs::read(fixture_root.join(name)).expect("os-release fixture")
                })
            },
            String::into_bytes,
        );
        std::fs::write(&release, release_bytes).expect("sandbox os-release");

        let mut outputs = BTreeMap::new();
        for backend in &scenario.backends {
            let executable = bin.join(&backend.executable);
            std::fs::write(&executable, b"fixture executable").expect("fixture executable");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
                    .expect("fixture executable mode");
            }
            outputs.insert(
                backend.executable.clone(),
                ProbeOutput {
                    exit_code: Some(0),
                    stdout: backend.output.as_bytes().to_vec(),
                    ..ProbeOutput::default()
                },
            );
        }

        let mut detector = SystemDetector::default()
            .with_host(scenario.os, scenario.process_architecture)
            .with_native_architecture(scenario.native_architecture)
            .with_os_release(release)
            .with_path(bin.display().to_string())
            .with_probe(ScenarioProbe { outputs })
            .with_interactive(scenario.interactive)
            .with_elevation_available(scenario.elevation_available)
            .with_container(scenario.container)
            .with_compatibility_layer(scenario.compatibility_layer)
            .offline(scenario.offline);
        if let Some(version) = scenario.os_version {
            detector = detector.with_os_version(version);
        }
        if let Some(libc) = scenario.libc {
            detector = detector.with_libc(libc);
        }
        let mut detected = detector.detect();
        for backend in &mut detected.backends {
            let filename = Path::new(&backend.executable)
                .file_name()
                .and_then(|name| name.to_str())
                .expect("detected executable filename");
            backend.executable = format!("fixture-bin/{filename}");
        }
        assert_eq!(detected.support(), scenario.support, "{}", scenario.golden);

        let expected: serde_json::Value = serde_json::from_slice(
            &std::fs::read(golden_root.join(&scenario.golden)).expect("platform golden"),
        )
        .expect("platform golden JSON");
        let actual = serde_json::to_value(&detected).expect("platform serialization");
        assert_eq!(actual, expected, "{}", scenario.golden);
    }
}
