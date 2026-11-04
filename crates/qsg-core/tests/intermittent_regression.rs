use qsg_core::{Error, SIGNATURE_SIZE, Signature, keygen, sign, verify};
use rand::{Rng, RngCore};

const CASE: &str = include_str!("regressions/macos-proptest-2026-11-03.txt");

fn field<'a>(case: &'a str, name: &str) -> &'a str {
    case.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .expect("regression fixture field exists")
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

#[test]
fn ci_regression_input_round_trips_and_corruptions_fail() {
    let message = decode_hex(field(CASE, "message_hex"));
    let context = decode_hex(field(CASE, "context_hex"));
    let message_bit: usize = field(CASE, "message_bit").parse().unwrap();
    let signature_bit: usize = field(CASE, "signature_bit").parse().unwrap();
    assert_eq!(message.len(), 18);
    assert_eq!(context.len(), 65);

    let (public_key, secret_key) = keygen().unwrap();
    let signature = sign(&secret_key, &message, &context).unwrap();
    verify(&public_key, &message, &signature, &context).unwrap();

    let mut changed_message = message.clone();
    let bit = message_bit % (changed_message.len() * 8);
    changed_message[bit / 8] ^= 1 << (bit % 8);
    assert!(verify(&public_key, &changed_message, &signature, &context).is_err());

    let mut changed_signature = signature.as_bytes().to_vec();
    changed_signature[signature_bit / 8] ^= 1 << (signature_bit % 8);
    match Signature::from_bytes(&changed_signature) {
        Ok(changed_signature) => {
            assert!(verify(&public_key, &message, &changed_signature, &context).is_err());
        }
        Err(Error::InvalidSignature) => {}
        Err(error) => panic!("unexpected signature parse error: {error}"),
    }
}

#[test]
#[ignore = "manual 1,000,000-operation ML-DSA stress test"]
fn million_hedged_signatures_verify() {
    const ITERATIONS: usize = 1_000_000;
    const KEY_ROTATION_INTERVAL: usize = 1_000;

    let mut rng = rand::rng();
    let mut current_key = None;
    let mut failures = 0usize;
    let mut failing_parameters = Vec::new();

    for iteration in 0..ITERATIONS {
        if iteration % KEY_ROTATION_INTERVAL == 0 {
            current_key = Some(keygen().expect("key generation succeeds"));
        }
        let (public_key, secret_key) = current_key.as_ref().unwrap();
        let message_len = rng.random_range(0..=4096);
        let context_len = rng.random_range(0..=255);
        let mut message = vec![0; message_len];
        let mut context = vec![0; context_len];
        rng.fill_bytes(&mut message);
        rng.fill_bytes(&mut context);

        match sign(secret_key, &message, &context) {
            Ok(signature) if verify(public_key, &message, &signature, &context).is_ok() => {}
            Ok(_) => {
                failures += 1;
                failing_parameters.push((iteration, message_len, context_len));
            }
            Err(_) => {
                failures += 1;
                failing_parameters.push((iteration, message_len, context_len));
            }
        }
    }

    println!(
        "iterations={ITERATIONS}, key_rotation_interval={KEY_ROTATION_INTERVAL}, arch={}, failures={failures}",
        std::env::consts::ARCH
    );
    for (iteration, message_len, context_len) in &failing_parameters {
        println!(
            "failure iteration={iteration}, message_len={message_len}, context_len={context_len}"
        );
    }
    assert_eq!(failures, 0, "valid signing/verification operations failed");
    assert_eq!(SIGNATURE_SIZE, 3309);
}
