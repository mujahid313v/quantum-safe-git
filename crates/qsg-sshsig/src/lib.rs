#![forbid(unsafe_code)]

//! Strict SSHSIG wire encoding, armor, and signed-data construction.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use qsg_core::{PublicKey, SecretKey, Signature as MlDsaSignature};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

const MAGIC: &[u8; 6] = b"SSHSIG";
const VERSION: u32 = 1;
pub const ED25519_KEY_TYPE: &str = "ssh-ed25519";
pub const ML_DSA_65_KEY_TYPE: &str = "ssh-mldsa65@qsgit";
pub const MAX_BLOB_SIZE: usize = 64 * 1024;
pub const MAX_ARMOR_SIZE: usize = 128 * 1024;
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";

#[derive(Debug, Error)]
pub enum Error {
    #[error("SSHSIG blob exceeds the 64 KiB limit")]
    BlobTooLarge,
    #[error("armored SSHSIG exceeds the 128 KiB limit")]
    ArmorTooLarge,
    #[error("invalid SSHSIG magic")]
    InvalidMagic,
    #[error("unsupported SSHSIG version")]
    UnsupportedVersion,
    #[error("truncated or malformed SSH wire data")]
    MalformedWire,
    #[error("trailing bytes after SSHSIG blob")]
    TrailingBytes,
    #[error("unsupported SSHSIG namespace")]
    UnsupportedNamespace,
    #[error("reserved SSHSIG field must be empty")]
    NonEmptyReserved,
    #[error("unsupported SSHSIG hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error("unknown or mismatched SSH key type")]
    UnknownKeyType,
    #[error("invalid Ed25519 public key length")]
    InvalidPublicKeyLength,
    #[error("invalid Ed25519 signature length")]
    InvalidSignatureLength,
    #[error("invalid ML-DSA-65 public key length")]
    InvalidMlDsaPublicKeyLength,
    #[error("invalid ML-DSA-65 signature length")]
    InvalidMlDsaSignatureLength,
    #[error("ML-DSA-65 operation failed: {0}")]
    MlDsa(#[from] qsg_core::Error),
    #[error("invalid SSH signature armor")]
    InvalidArmor,
    #[error("invalid base64 in SSH signature armor")]
    InvalidBase64,
}

pub type Result<T> = core::result::Result<T, Error>;

/// SSHSIG envelope fields. `public_key` and `signature` are inner SSH blobs:
/// `string(key_type) || string(key_bytes)` and `string(key_type) || string(sig_bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignature {
    pub public_key: Vec<u8>,
    pub namespace: String,
    pub reserved: Vec<u8>,
    pub hash_algorithm: String,
    pub signature: Vec<u8>,
}

/// Construct the OpenSSH PROTOCOL.sshsig signed-data preimage.
///
/// OpenSSH PROTOCOL.sshsig section 3 specifies `byte[6] "SSHSIG"`, then
/// `string namespace`, `string reserved`, `string hash_algorithm`, and
/// `string H(message)`. Section 2 says the message is hashed first. We use
/// SHA-512 and encode the digest as an SSH string, matching that layout.
/// OpenSSH's wording is: "Data to be signed is first hashed with the specified
/// hash_algorithm." It then says: "The data is concatenated and passed to the
/// SSH signing function." Source: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
pub fn build_signed_data(
    namespace: &str,
    reserved: &[u8],
    hash_algorithm: &str,
    message: &[u8],
) -> Result<Vec<u8>> {
    validate_header(namespace.as_bytes(), reserved, hash_algorithm.as_bytes())?;
    let digest = Sha512::digest(message);
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    write_string(&mut output, namespace.as_bytes())?;
    write_string(&mut output, reserved)?;
    write_string(&mut output, hash_algorithm.as_bytes())?;
    write_string(&mut output, &digest)?;
    check_blob_size(output.len())?;
    Ok(output)
}

/// Encode an SSHSIG binary blob using version 1.
pub fn encode_blob(signature: &SshSignature) -> Result<Vec<u8>> {
    validate_header(
        signature.namespace.as_bytes(),
        &signature.reserved,
        signature.hash_algorithm.as_bytes(),
    )?;
    validate_key_and_signature(&signature.public_key, &signature.signature)?;
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    write_string(&mut output, &signature.public_key)?;
    write_string(&mut output, signature.namespace.as_bytes())?;
    write_string(&mut output, &signature.reserved)?;
    write_string(&mut output, signature.hash_algorithm.as_bytes())?;
    write_string(&mut output, &signature.signature)?;
    check_blob_size(output.len())?;
    Ok(output)
}

/// Make an ML-DSA-65 SSHSIG record. Signing uses qsg-core's hedged signing
/// with the fixed QSGit-v1 context.
pub fn sign_ml_dsa65(
    public_key: &PublicKey,
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<SshSignature> {
    let signed_data = build_signed_data("git", b"", "sha512", message)?;
    let signature = qsg_core::sign(secret_key, &signed_data, b"QSGit-v1")?;
    Ok(SshSignature {
        public_key: encode_key_blob(ML_DSA_65_KEY_TYPE, public_key.as_bytes())?,
        namespace: "git".to_owned(),
        reserved: Vec::new(),
        hash_algorithm: "sha512".to_owned(),
        signature: encode_key_blob(ML_DSA_65_KEY_TYPE, signature.as_bytes())?,
    })
}

/// Verify an ML-DSA-65 SSHSIG record with the fixed QSGit-v1 context.
pub fn verify_ml_dsa65(record: &SshSignature, message: &[u8]) -> Result<()> {
    validate_header(
        record.namespace.as_bytes(),
        &record.reserved,
        record.hash_algorithm.as_bytes(),
    )?;
    let (key_type, key_bytes) = parse_inner_blob(&record.public_key)?;
    let (signature_type, signature_bytes) = parse_inner_blob(&record.signature)?;
    if key_type != ML_DSA_65_KEY_TYPE.as_bytes() || signature_type != key_type {
        return Err(Error::UnknownKeyType);
    }
    if key_bytes.len() != qsg_core::PUBLIC_KEY_SIZE {
        return Err(Error::InvalidMlDsaPublicKeyLength);
    }
    if signature_bytes.len() != qsg_core::SIGNATURE_SIZE {
        return Err(Error::InvalidMlDsaSignatureLength);
    }
    let public = PublicKey::from_bytes(key_bytes)?;
    let signature = MlDsaSignature::from_bytes(signature_bytes)?;
    let signed_data = build_signed_data("git", b"", "sha512", message)?;
    qsg_core::verify(&public, &signed_data, &signature, b"QSGit-v1")?;
    Ok(())
}

/// OpenSSH-style SHA256 fingerprint of an SSH public-key blob.
pub fn fingerprint(public_key_blob: &[u8]) -> Result<String> {
    let (key_type, key_bytes) = parse_inner_blob(public_key_blob)?;
    match key_type {
        key_type if key_type == ED25519_KEY_TYPE.as_bytes() && key_bytes.len() == 32 => {}
        key_type
            if key_type == ML_DSA_65_KEY_TYPE.as_bytes()
                && key_bytes.len() == qsg_core::PUBLIC_KEY_SIZE => {}
        key_type if key_type == ED25519_KEY_TYPE.as_bytes() => {
            return Err(Error::InvalidPublicKeyLength);
        }
        key_type if key_type == ML_DSA_65_KEY_TYPE.as_bytes() => {
            return Err(Error::InvalidMlDsaPublicKeyLength);
        }
        _ => return Err(Error::UnknownKeyType),
    }
    let digest = Sha256::digest(public_key_blob);
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

/// Strictly decode a version 1 SSHSIG binary blob.
pub fn decode_blob(input: &[u8]) -> Result<SshSignature> {
    check_blob_size(input.len())?;
    let mut reader = Reader::new(input);
    if reader.take(6)? != MAGIC {
        return Err(Error::InvalidMagic);
    }
    if reader.uint32()? != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let public_key = reader.string()?.to_vec();
    let namespace = reader.string()?.to_vec();
    let reserved = reader.string()?.to_vec();
    let hash_algorithm = reader.string()?.to_vec();
    let signature = reader.string()?.to_vec();
    if !reader.is_empty() {
        return Err(Error::TrailingBytes);
    }
    validate_header(&namespace, &reserved, &hash_algorithm)?;
    validate_key_and_signature(&public_key, &signature)?;
    Ok(SshSignature {
        public_key,
        namespace: String::from_utf8(namespace).map_err(|_| Error::UnsupportedNamespace)?,
        reserved,
        hash_algorithm: String::from_utf8(hash_algorithm)
            .map_err(|_| Error::UnsupportedHashAlgorithm)?,
        signature,
    })
}

/// Encode an SSHSIG blob with LF line endings, 70-character base64 lines, and a
/// final LF after the footer.
pub fn encode_armor(blob: &[u8]) -> Result<String> {
    check_blob_size(blob.len())?;
    let encoded = STANDARD.encode(blob);
    let line_count = encoded.len().div_ceil(70);
    let mut output =
        String::with_capacity(BEGIN.len() + END.len() + encoded.len() + line_count + 3);
    output.push_str(BEGIN);
    output.push('\n');
    for line in encoded.as_bytes().chunks(70) {
        // Base64 output is ASCII by construction.
        output.push_str(core::str::from_utf8(line).map_err(|_| Error::InvalidBase64)?);
        output.push('\n');
    }
    output.push_str(END);
    output.push('\n');
    if output.len() > MAX_ARMOR_SIZE {
        return Err(Error::ArmorTooLarge);
    }
    Ok(output)
}

/// Decode canonical SSHSIG armor. LF is required, and the only accepted
/// variants are the canonical final LF or the same armor without that LF.
pub fn decode_armor(input: &str) -> Result<Vec<u8>> {
    if input.len() > MAX_ARMOR_SIZE {
        return Err(Error::ArmorTooLarge);
    }
    let no_final_lf = input.strip_suffix('\n').unwrap_or(input);
    let body = no_final_lf
        .strip_prefix(BEGIN)
        .and_then(|text| text.strip_prefix('\n'))
        .and_then(|text| text.strip_suffix(END))
        .ok_or(Error::InvalidArmor)?;
    if body.is_empty() || body.contains('\r') || body.contains('-') {
        return Err(Error::InvalidArmor);
    }
    let base64 = body.replace('\n', "");
    let blob = STANDARD.decode(base64).map_err(|_| Error::InvalidBase64)?;
    check_blob_size(blob.len())?;
    let canonical = encode_armor(&blob)?;
    let without_final_lf = canonical.strip_suffix('\n').ok_or(Error::InvalidArmor)?;
    if input != canonical && input != without_final_lf {
        return Err(Error::InvalidArmor);
    }
    Ok(blob)
}

fn validate_header(namespace: &[u8], reserved: &[u8], hash_algorithm: &[u8]) -> Result<()> {
    if namespace != b"git" {
        return Err(Error::UnsupportedNamespace);
    }
    if !reserved.is_empty() {
        return Err(Error::NonEmptyReserved);
    }
    if hash_algorithm != b"sha512" {
        return Err(Error::UnsupportedHashAlgorithm);
    }
    Ok(())
}

fn validate_key_and_signature(public_key: &[u8], signature: &[u8]) -> Result<()> {
    let (key_type, key_bytes) = parse_inner_blob(public_key)?;
    let (signature_type, signature_bytes) = parse_inner_blob(signature)?;
    if signature_type != key_type
        || (key_type != ED25519_KEY_TYPE.as_bytes() && key_type != ML_DSA_65_KEY_TYPE.as_bytes())
    {
        return Err(Error::UnknownKeyType);
    }
    match key_type {
        key_type if key_type == ED25519_KEY_TYPE.as_bytes() => {
            if key_bytes.len() != 32 {
                return Err(Error::InvalidPublicKeyLength);
            }
            if signature_bytes.len() != 64 {
                return Err(Error::InvalidSignatureLength);
            }
        }
        key_type if key_type == ML_DSA_65_KEY_TYPE.as_bytes() => {
            if key_bytes.len() != qsg_core::PUBLIC_KEY_SIZE {
                return Err(Error::InvalidMlDsaPublicKeyLength);
            }
            if signature_bytes.len() != qsg_core::SIGNATURE_SIZE {
                return Err(Error::InvalidMlDsaSignatureLength);
            }
        }
        _ => return Err(Error::UnknownKeyType),
    }
    Ok(())
}

fn encode_key_blob(key_type: &str, value: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_string(&mut output, key_type.as_bytes())?;
    write_string(&mut output, value)?;
    Ok(output)
}

fn parse_inner_blob(input: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut reader = Reader::new(input);
    let key_type = reader.string()?;
    let value = reader.string()?;
    if !reader.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok((key_type, value))
}

fn check_blob_size(size: usize) -> Result<()> {
    if size > MAX_BLOB_SIZE {
        Err(Error::BlobTooLarge)
    } else {
        Ok(())
    }
}

fn write_string(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| Error::BlobTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    check_blob_size(output.len())
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::MalformedWire)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(Error::MalformedWire)?;
        self.position = end;
        Ok(value)
    }

    fn uint32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Error::MalformedWire)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.uint32()?).map_err(|_| Error::MalformedWire)?;
        self.take(length)
    }

    fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_string(value: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        write_string(&mut output, value).unwrap();
        output
    }

    fn test_ed_record(public_bytes: &[u8], signature_bytes: &[u8]) -> SshSignature {
        let mut public_key = ssh_string(ED25519_KEY_TYPE.as_bytes());
        public_key.extend(ssh_string(public_bytes));
        let mut signature = ssh_string(ED25519_KEY_TYPE.as_bytes());
        signature.extend(ssh_string(signature_bytes));
        SshSignature {
            public_key,
            namespace: "git".into(),
            reserved: Vec::new(),
            hash_algorithm: "sha512".into(),
            signature,
        }
    }

    fn raw_blob(record: &SshSignature, version: u32) -> Vec<u8> {
        let mut output = MAGIC.to_vec();
        output.extend_from_slice(&version.to_be_bytes());
        for field in [
            record.public_key.as_slice(),
            record.namespace.as_bytes(),
            record.reserved.as_slice(),
            record.hash_algorithm.as_bytes(),
            record.signature.as_slice(),
        ] {
            output.extend_from_slice(&(field.len() as u32).to_be_bytes());
            output.extend_from_slice(field);
        }
        output
    }

    #[test]
    fn signed_data_is_openssh_sshsig_preimage() {
        let actual = build_signed_data("git", b"", "sha512", b"payload").unwrap();
        let digest = Sha512::digest(b"payload");
        let mut expected = MAGIC.to_vec();
        write_string(&mut expected, b"git").unwrap();
        write_string(&mut expected, b"").unwrap();
        write_string(&mut expected, b"sha512").unwrap();
        write_string(&mut expected, &digest).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn malformed_lengths_and_random_inputs_never_panic() {
        use proptest::prelude::*;
        proptest!(|(input in proptest::collection::vec(any::<u8>(), 0..70000))| {
            let _ = decode_blob(&input);
            let _ = decode_armor(std::str::from_utf8(&input).unwrap_or(""));
        });
    }

    #[test]
    fn ed25519_blob_and_armor_round_trip_canonically() {
        let record = test_ed_record(&[7; 32], &[9; 64]);
        let blob = encode_blob(&record).unwrap();
        assert_eq!(decode_blob(&blob).unwrap(), record);
        let armor = encode_armor(&blob).unwrap();
        assert_eq!(decode_armor(&armor).unwrap(), blob);
        assert_eq!(decode_armor(armor.trim_end_matches('\n')).unwrap(), blob);
        assert!(decode_armor(&armor.replace('\n', "\r\n")).is_err());
        assert!(decode_armor(&armor.replace("BEGIN SSH SIGNATURE", "BEGIN SSH MESSAGE")).is_err());
    }

    #[test]
    fn decoder_rejects_each_oversized_field_length() {
        let record = test_ed_record(&[7; 32], &[9; 64]);
        let blob = encode_blob(&record).unwrap();
        let mut length_offsets = Vec::new();
        let mut position = 10;
        for _ in 0..5 {
            length_offsets.push(position);
            let len = u32::from_be_bytes(blob[position..position + 4].try_into().unwrap()) as usize;
            position += 4 + len;
        }
        for offset in length_offsets {
            let mut mutated = blob.clone();
            mutated[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(decode_blob(&mutated).is_err());
        }

        // Also reject each nested key/signature string length in the SSH key blobs.
        let public_start = 14;
        let key_type_len =
            u32::from_be_bytes(blob[public_start..public_start + 4].try_into().unwrap()) as usize;
        let public_value_len_offset = public_start + 4 + key_type_len;
        let signature_start = position - record.signature.len();
        let sig_type_len = u32::from_be_bytes(
            blob[signature_start..signature_start + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let signature_value_len_offset = signature_start + 4 + sig_type_len;
        for offset in [
            public_start,
            public_value_len_offset,
            signature_start,
            signature_value_len_offset,
        ] {
            let mut mutated = blob.clone();
            mutated[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(decode_blob(&mutated).is_err());
        }
    }

    #[test]
    fn decoder_rejects_wrong_version_type_truncation_and_extension() {
        let record = test_ed_record(&[7; 32], &[9; 64]);
        let good = raw_blob(&record, VERSION);
        assert!(matches!(
            decode_blob(&raw_blob(&record, 2)),
            Err(Error::UnsupportedVersion)
        ));
        assert!(matches!(
            decode_blob(&good[..good.len() - 1]),
            Err(Error::MalformedWire)
        ));
        let mut extended = good.clone();
        extended.push(0);
        assert!(matches!(decode_blob(&extended), Err(Error::TrailingBytes)));
        assert!(matches!(
            decode_blob(&[0; MAX_BLOB_SIZE + 1]),
            Err(Error::BlobTooLarge)
        ));

        let mut unknown = record.clone();
        unknown.public_key = [ssh_string(b"ssh-rsa"), ssh_string(&[1; 32])].concat();
        assert!(matches!(
            decode_blob(&raw_blob(&unknown, VERSION)),
            Err(Error::UnknownKeyType)
        ));
    }

    #[test]
    fn rejects_invalid_header_fields() {
        let good = test_ed_record(&[7; 32], &[9; 64]);
        let mut wrong_namespace = good.clone();
        wrong_namespace.namespace = "other".into();
        assert!(matches!(
            encode_blob(&wrong_namespace),
            Err(Error::UnsupportedNamespace)
        ));
        let mut reserved = good.clone();
        reserved.reserved.push(1);
        assert!(matches!(
            encode_blob(&reserved),
            Err(Error::NonEmptyReserved)
        ));
        let mut wrong_hash = good;
        wrong_hash.hash_algorithm = "sha256".into();
        assert!(matches!(
            encode_blob(&wrong_hash),
            Err(Error::UnsupportedHashAlgorithm)
        ));
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(24))]
        #[test]
        fn record_encode_decode_round_trip(public in proptest::collection::vec(proptest::prelude::any::<u8>(), 32), signature in proptest::collection::vec(proptest::prelude::any::<u8>(), 64)) {
            let record = test_ed_record(&public, &signature);
            let encoded = encode_blob(&record).unwrap();
            proptest::prop_assert_eq!(decode_blob(&encoded).unwrap(), record);
            let armor = encode_armor(&encoded).unwrap();
            proptest::prop_assert_eq!(decode_armor(&armor).unwrap(), encoded);
        }
    }
}
