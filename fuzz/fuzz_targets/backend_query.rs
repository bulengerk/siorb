#![no_main]

use libfuzzer_sys::fuzz_target;
use siorb_backends::{BackendKind, parse_query_output};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, output)) = data.split_first() else {
        return;
    };
    let kind = match selector % 14 {
        0 => BackendKind::Winget,
        1 => BackendKind::Scoop,
        2 => BackendKind::Chocolatey,
        3 => BackendKind::BrewFormula,
        4 => BackendKind::BrewCask,
        5 => BackendKind::MacPorts,
        6 => BackendKind::Apt,
        7 => BackendKind::Dnf,
        8 => BackendKind::Pacman,
        9 => BackendKind::Zypper,
        10 => BackendKind::Apk,
        11 => BackendKind::Snap,
        12 => BackendKind::Flatpak,
        _ => BackendKind::Apt,
    };
    let split = output.len() / 2;
    let exit_code = match selector % 4 {
        0 => Some(0),
        1 => Some(1),
        2 => Some(127),
        _ => None,
    };
    let _ = parse_query_output(
        kind,
        "fuzz-package",
        &output[..split],
        &output[split..],
        exit_code,
    );
});
