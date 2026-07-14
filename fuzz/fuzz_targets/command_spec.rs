#![no_main]

use libfuzzer_sys::fuzz_target;
use siorb_backends::CommandSpec;

fuzz_target!(|data: &[u8]| {
    if let Ok(command) = serde_json::from_slice::<CommandSpec>(data) {
        let _ = command.validate();
    }
});
