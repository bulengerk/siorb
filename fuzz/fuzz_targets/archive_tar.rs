#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use siorb_executor::ArchiveLimits;

fuzz_target!(|data: &[u8]| {
    let _ = siorb_executor::inspect_tar(Cursor::new(data), &ArchiveLimits::default());
});
