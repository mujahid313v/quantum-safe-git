#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let text = String::from_utf8_lossy(input);
    let _ = qsg_trust::parse_allowed_signers(&text);
});
