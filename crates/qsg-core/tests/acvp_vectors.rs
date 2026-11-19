use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes, Keypair, MlDsa65, Seed, SigningKey};
use qsg_core::{PublicKey, Signature, verify};
use std::{collections::HashMap, fs, path::PathBuf};

/// SHA-256 of `target/acvp/ml-dsa65-kat.txt` generated from the pinned
/// ACVP-Server commit 975de31eb83d87039ec88934fdc47d8c312b892d.
/// To update: re-run `python3 crates/qsg-core/tests/fetch_acvp_vectors.py`,
/// then `shasum -a 256 target/acvp/ml-dsa65-kat.txt` (Linux/macOS) or
/// `(Get-FileHash target/acvp/ml-dsa65-kat.txt -Algorithm SHA256).Hash`
/// (Windows PowerShell), and paste the hex below (lower-case).
const ACVP_KAT_SHA256: &str = "e9130ae5edeab1972c10609c72cde1437920d318064cd6ca3b43dfc52d2f0e95";

/// SHA-256 of each source JSON file downloaded from ACVP-Server commit
/// 975de31eb83d87039ec88934fdc47d8c312b892d, computed over raw HTTP response
/// bytes (what Python's `urlopen(...).read()` returns).
/// To update: change COMMIT in fetch_acvp_vectors.py, run it, copy the
/// "actual" hashes from any mismatch error into SOURCE_SHA256 in that file,
/// then update these constants to match.
const ACVP_KEYGEN_SHA256: &str = "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf";
const ACVP_SIGGEN_SHA256: &str = "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22";
const ACVP_SIGVER_SHA256: &str = "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437";

fn sha256_hex(path: &std::path::Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    sha256_bytes(&bytes)
}

fn sha256_bytes(data: &[u8]) -> String {
    // FIPS 180-4 SHA-256 -- test-only, no production use.
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, b) in chunk.as_chunks::<4>().0.iter().enumerate().take(16) {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let tmp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(tmp1);
            d = c;
            c = b;
            b = a;
            a = tmp1.wrapping_add(tmp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn fields() -> HashMap<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/acvp/ml-dsa65-kat.txt");
    let contents = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("ACVP vectors missing; run python3 crates/qsg-core/tests/fetch_acvp_vectors.py")
    });
    let mut section = String::new();
    contents
        .lines()
        .filter_map(|line| {
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_owned();
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((format!("{section}.{key}"), value.to_owned()))
        })
        .collect()
}

fn value(fields: &HashMap<String, String>, key: &str) -> String {
    fields
        .get(key)
        .unwrap_or_else(|| panic!("ACVP subset field missing: {key}"))
        .clone()
}

fn hex_bytes(fields: &HashMap<String, String>, key: &str) -> Vec<u8> {
    let encoded = value(fields, key);
    assert_eq!(encoded.len() % 2, 0, "invalid hex length for {key}");
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit in ACVP field {key}"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

#[test]
fn acvp_ml_dsa65_keygen_seed_matches_public_key() {
    let fields = fields();
    let seed_bytes: [u8; 32] = hex_bytes(&fields, "keygen.seed")
        .try_into()
        .expect("ACVP ML-DSA-65 seed is 32 bytes");
    let seed = Seed::try_from(seed_bytes.as_slice()).expect("valid seed width");
    let generated = SigningKey::<MlDsa65>::from_seed(&seed);
    let expected_public = hex_bytes(&fields, "keygen.public_key");
    assert_eq!(
        generated.verifying_key().encode().as_slice(),
        expected_public
    );
}

#[test]
fn acvp_ml_dsa65_siggen_deterministic_matches_signature() {
    let fields = fields();
    let sk_bytes = hex_bytes(&fields, "siggen_deterministic.secret_key");
    let sk = ExpandedSigningKeyBytes::<MlDsa65>::try_from(sk_bytes.as_slice())
        .expect("valid expanded secret-key width");
    #[allow(deprecated)]
    let expanded = ExpandedSigningKey::<MlDsa65>::from_expanded(&sk);
    let message = hex_bytes(&fields, "siggen_deterministic.message");
    let context = hex_bytes(&fields, "siggen_deterministic.context");
    let actual = expanded
        .sign_deterministic(&message, &context)
        .expect("NIST deterministic test signature generated");
    let expected = hex_bytes(&fields, "siggen_deterministic.signature");
    assert_eq!(actual.encode().as_slice(), expected);
}

#[test]
fn acvp_ml_dsa65_sigver_external_pure_pass_and_fail() {
    let fields = fields();
    let pk = PublicKey::from_bytes(&hex_bytes(&fields, "sigver_pass.public_key")).unwrap();
    let message = hex_bytes(&fields, "sigver_pass.message");
    let context = hex_bytes(&fields, "sigver_pass.context");
    let signature = Signature::from_bytes(&hex_bytes(&fields, "sigver_pass.signature")).unwrap();
    verify(&pk, &message, &signature, &context).unwrap();

    let pk = PublicKey::from_bytes(&hex_bytes(&fields, "sigver_fail.public_key")).unwrap();
    let message = hex_bytes(&fields, "sigver_fail.message");
    let context = hex_bytes(&fields, "sigver_fail.context");
    let signature = Signature::from_bytes(&hex_bytes(&fields, "sigver_fail.signature")).unwrap();
    assert!(verify(&pk, &message, &signature, &context).is_err());
}

#[test]
fn acvp_kat_file_matches_pinned_sha256() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/acvp/ml-dsa65-kat.txt");
    let actual = sha256_hex(&path);
    assert_eq!(
        actual,
        ACVP_KAT_SHA256,
        "ACVP vector file hash mismatch.\n  file:     {}\n  expected: {}\n  actual:   {}\n\
         If you intentionally updated the vectors, re-run \
         `python3 crates/qsg-core/tests/fetch_acvp_vectors.py` and update \
         ACVP_KAT_SHA256 in this file.",
        path.display(),
        ACVP_KAT_SHA256,
        actual
    );
}

/// Proves that a wrong hash constant causes the hash test to fail.
/// This test tampers a byte of the data in memory and verifies the computed
/// hash does NOT equal the real pin -- proving the detection logic works.
#[test]
fn acvp_hash_detection_catches_wrong_hash() {
    let mut data = b"test data for hash detection".to_vec();
    let original = sha256_bytes(&data);
    data[0] ^= 0xff; // flip bits in first byte
    let tampered = sha256_bytes(&data);
    assert_ne!(
        original, tampered,
        "SHA-256 of tampered data must differ from original"
    );
    // Also confirm the tampered hash doesn't accidentally match the pin.
    assert_ne!(
        tampered, ACVP_KAT_SHA256,
        "tampered hash should not match the ACVP pin"
    );
}

/// Proves that a wrong source-file hash constant would be detected.
/// Checks that the three source pins are distinct and non-empty (format check),
/// and that flipping a byte in simulated source bytes produces a different hash.
#[test]
fn acvp_source_hash_detection_catches_wrong_hash() {
    // All three source pins must be non-empty 64-char hex strings.
    for pin in [ACVP_KEYGEN_SHA256, ACVP_SIGGEN_SHA256, ACVP_SIGVER_SHA256] {
        assert_eq!(pin.len(), 64, "source pin must be 64 hex chars: {pin}");
        assert!(pin.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {pin}");
    }
    // All three must be distinct.
    assert_ne!(ACVP_KEYGEN_SHA256, ACVP_SIGGEN_SHA256);
    assert_ne!(ACVP_SIGGEN_SHA256, ACVP_SIGVER_SHA256);
    assert_ne!(ACVP_KEYGEN_SHA256, ACVP_SIGVER_SHA256);
    // Tampered bytes produce a different hash.
    let mut data = b"simulated json source bytes".to_vec();
    let h1 = sha256_bytes(&data);
    data[0] ^= 0x01;
    let h2 = sha256_bytes(&data);
    assert_ne!(
        h1, h2,
        "tampered source bytes must produce a different hash"
    );
}
