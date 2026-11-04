#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = qsg_sshsig::decode_blob(input);
    if let Ok(text) = core::str::from_utf8(input) {
        let _ = qsg_sshsig::decode_armor(text);
    }
});
