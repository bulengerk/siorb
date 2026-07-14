#![no_main]

use libfuzzer_sys::fuzz_target;
use siorb_core::validate_public_network_host;
use siorb_policy::PolicyFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(host) = std::str::from_utf8(data) {
        let _ = validate_public_network_host(host);
    }
    if let Ok(policy) = serde_json::from_slice::<PolicyFile>(data) {
        let _ = policy.validate();
    }
});
