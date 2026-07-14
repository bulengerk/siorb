#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let output = siorb_core::sanitize_terminal(&input);
    assert!(
        !output
            .chars()
            .any(|character| { character.is_control() && character != '\n' && character != '\t' })
    );
});
