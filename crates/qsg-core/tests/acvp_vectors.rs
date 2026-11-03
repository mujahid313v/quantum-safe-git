use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes, Keypair, MlDsa65, Seed, SigningKey};
use qsg_core::{PublicKey, Signature, verify};
use std::{collections::HashMap, fs, path::PathBuf};

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
        .chunks_exact(2)
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
