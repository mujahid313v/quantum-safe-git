use qsg_sshsig::{
    ML_DSA_65_KEY_TYPE, SshSignature, build_signed_data, decode_blob, encode_blob, sign_ml_dsa65,
    verify_ml_dsa65,
};
use std::{fs, path::PathBuf};

const MESSAGE: &[u8] = b"QSGit M2 fixed ML-DSA-65 vector message\n";

fn key_blob(key_type: &str, key: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    value.extend_from_slice(key_type.as_bytes());
    value.extend_from_slice(&(key.len() as u32).to_be_bytes());
    value.extend_from_slice(key);
    value
}

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join(name)
}

#[test]
fn ml_dsa65_round_trip_and_negative_cases() {
    let (public, secret) = qsg_core::keygen().unwrap();
    let record = sign_ml_dsa65(&public, &secret, MESSAGE).unwrap();
    verify_ml_dsa65(&record, MESSAGE).unwrap();
    assert!(verify_ml_dsa65(&record, b"altered message").is_err());

    let mut wrong_namespace = record.clone();
    wrong_namespace.namespace = "other".to_owned();
    assert!(verify_ml_dsa65(&wrong_namespace, MESSAGE).is_err());

    let public_bytes = key_blob(ML_DSA_65_KEY_TYPE, public.as_bytes());
    let signature_bytes = qsg_core::Signature::from_bytes(
        parse_key_blob(&record.signature)
            .expect("signature inner blob")
            .1,
    )
    .unwrap();
    let signed_data = build_signed_data("git", b"", "sha512", MESSAGE).unwrap();
    assert!(qsg_core::verify(&public, &signed_data, &signature_bytes, b"wrong-context").is_err());

    let (other_public, _) = qsg_core::keygen().unwrap();
    let mut wrong_key = record;
    wrong_key.public_key = key_blob(ML_DSA_65_KEY_TYPE, other_public.as_bytes());
    assert!(verify_ml_dsa65(&wrong_key, MESSAGE).is_err());

    let truncated_key = key_blob(
        ML_DSA_65_KEY_TYPE,
        &public_bytes[4 + ML_DSA_65_KEY_TYPE.len() + 4..][..1951],
    );
    let mut invalid = SshSignature {
        public_key: truncated_key,
        namespace: "git".to_owned(),
        reserved: Vec::new(),
        hash_algorithm: "sha512".to_owned(),
        signature: key_blob(ML_DSA_65_KEY_TYPE, signature_bytes.as_bytes()),
    };
    assert!(encode_blob(&invalid).is_err());

    invalid.public_key = key_blob(ML_DSA_65_KEY_TYPE, &[0; 1953]);
    assert!(encode_blob(&invalid).is_err());
    invalid.public_key = public_bytes;
    invalid.signature = key_blob(ML_DSA_65_KEY_TYPE, &[0; 3308]);
    assert!(encode_blob(&invalid).is_err());
    invalid.signature = key_blob(ML_DSA_65_KEY_TYPE, &[0; 3310]);
    assert!(encode_blob(&invalid).is_err());
}

#[test]
fn sshsig_binary_rejects_truncated_extended_and_corrupted_version() {
    let (public, secret) = qsg_core::keygen().unwrap();
    let record = sign_ml_dsa65(&public, &secret, MESSAGE).unwrap();
    let blob = encode_blob(&record).unwrap();
    assert!(decode_blob(&blob[..blob.len() - 1]).is_err());
    let mut extended = blob.clone();
    extended.push(0);
    assert!(decode_blob(&extended).is_err());
    let mut wrong_version = blob;
    wrong_version[9] = 2;
    assert!(decode_blob(&wrong_version).is_err());
}

#[test]
fn fixed_valid_and_mutated_ml_dsa65_vectors_verify_as_documented() {
    for name in ["ml-dsa65-valid-1.sshsig", "ml-dsa65-valid-2.sshsig"] {
        let bytes = fs::read(vector_path(name)).expect("fixed valid signature vector");
        let record = decode_blob(&bytes).unwrap();
        verify_ml_dsa65(&record, MESSAGE).unwrap();
    }
    for name in ["ml-dsa65-mutated-1.sshsig", "ml-dsa65-mutated-2.sshsig"] {
        let bytes = fs::read(vector_path(name)).expect("fixed mutated signature vector");
        let record = decode_blob(&bytes).unwrap();
        assert!(verify_ml_dsa65(&record, MESSAGE).is_err());
    }
}

#[test]
#[ignore = "manual fixture generation; writes new hedged signatures under tests/vectors"]
fn regenerate_hedged_ml_dsa65_vectors() {
    fs::create_dir_all(vector_path("dummy").parent().unwrap()).unwrap();
    let (public, secret) = qsg_core::keygen().unwrap();
    for index in 1..=2 {
        let record = sign_ml_dsa65(&public, &secret, MESSAGE).unwrap();
        let blob = encode_blob(&record).unwrap();
        fs::write(
            vector_path(&format!("ml-dsa65-valid-{index}.sshsig")),
            &blob,
        )
        .unwrap();

        let signature = parse_key_blob(&record.signature).unwrap().1;
        let mut changed_signature = signature.to_vec();
        let last = changed_signature.len() - 1;
        changed_signature[last] ^= 1;
        let mut mutated = record;
        mutated.signature = key_blob(ML_DSA_65_KEY_TYPE, &changed_signature);
        let blob = encode_blob(&mutated).unwrap();
        fs::write(
            vector_path(&format!("ml-dsa65-mutated-{index}.sshsig")),
            blob,
        )
        .unwrap();
    }
}

fn parse_key_blob(input: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    let type_len =
        u32::from_be_bytes(input.get(..4).ok_or(())?.try_into().map_err(|_| ())?) as usize;
    let key_type = input.get(4..4 + type_len).ok_or(())?;
    let value_len_offset = 4 + type_len;
    let value_len = u32::from_be_bytes(
        input
            .get(value_len_offset..value_len_offset + 4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?,
    ) as usize;
    let value_start = value_len_offset + 4;
    let value = input.get(value_start..value_start + value_len).ok_or(())?;
    if value_start + value_len != input.len() {
        return Err(());
    }
    Ok((key_type, value))
}
