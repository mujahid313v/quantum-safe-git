#![forbid(unsafe_code)]

//! ML-DSA-65 core operations. This crate performs no file or network I/O.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, Generate,
    Keypair, MlDsa65, Signature as MlSignature, SigningKey, VerifyingKey,
};
use thiserror::Error;
use zeroize::Zeroize;

pub const PUBLIC_KEY_SIZE: usize = 1952;
pub const SECRET_KEY_SIZE: usize = 4032;
pub const SIGNATURE_SIZE: usize = 3309;
const MAX_CONTEXT_SIZE: usize = 255;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid {kind} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("context exceeds the ML-DSA limit of 255 bytes")]
    ContextTooLong,
    #[error("ML-DSA signing failed")]
    SigningFailed,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

pub type Result<T> = core::result::Result<T, Error>;

pub struct PublicKey(EncodedVerifyingKey<MlDsa65>);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded =
            EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| Error::InvalidLength {
                kind: "public key",
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            })?;
        Ok(Self(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        // from_bytes validated this exact fixed-width encoding.
        VerifyingKey::<MlDsa65>::decode(&self.0)
    }
}

pub struct SecretKey(ExpandedSigningKeyBytes<MlDsa65>);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = ExpandedSigningKeyBytes::<MlDsa65>::try_from(bytes).map_err(|_| {
            Error::InvalidLength {
                kind: "secret key",
                expected: SECRET_KEY_SIZE,
                actual: bytes.len(),
            }
        })?;
        Ok(Self(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct Signature(EncodedSignature<MlDsa65>);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes =
            EncodedSignature::<MlDsa65>::try_from(bytes).map_err(|_| Error::InvalidLength {
                kind: "signature",
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            })?;
        MlSignature::<MlDsa65>::try_from(bytes.as_slice()).map_err(|_| Error::InvalidSignature)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub fn keygen() -> Result<(PublicKey, SecretKey)> {
    let signing_key = SigningKey::<MlDsa65>::generate();
    let public = signing_key.verifying_key().encode();
    // M1 fixes the exposed secret encoding at the 4032-byte expanded form. The
    // backend marks this internal encoding deprecated in favor of its 32-byte seed.
    #[allow(deprecated)]
    let secret = signing_key.expanded_key().to_expanded();
    Ok((PublicKey(public), SecretKey(secret)))
}

pub fn sign(secret: &SecretKey, message: &[u8], context: &[u8]) -> Result<Signature> {
    if context.len() > MAX_CONTEXT_SIZE {
        return Err(Error::ContextTooLong);
    }
    #[allow(deprecated)]
    // The public API requires the FIPS expanded private-key encoding (4032 bytes).
    let key = ExpandedSigningKey::<MlDsa65>::from_expanded(&secret.0);
    let signature = key
        .sign_deterministic(message, context)
        .map_err(|_| Error::SigningFailed)?;
    Ok(Signature(signature.encode()))
}

pub fn verify(
    public: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> Result<()> {
    if context.len() > MAX_CONTEXT_SIZE {
        return Err(Error::ContextTooLong);
    }
    let signature = MlSignature::<MlDsa65>::try_from(signature.0.as_slice())
        .map_err(|_| Error::InvalidSignature)?;
    if public
        .verifying_key()
        .verify_with_context(message, context, &signature)
    {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn encoding_sizes_match_fips_204() {
        let (pk, sk) = keygen().unwrap();
        let sig = sign(&sk, b"sizes", b"QSGit-v1").unwrap();
        assert_eq!(pk.as_bytes().len(), 1952);
        assert_eq!(sk.as_bytes().len(), 4032);
        assert_eq!(sig.as_bytes().len(), 3309);
    }

    #[test]
    fn public_api_round_trip_and_empty_message() {
        let (pk, sk) = keygen().unwrap();
        let sig = sign(&sk, b"message", b"ctx").unwrap();
        verify(&pk, b"message", &sig, b"ctx").unwrap();
        let parsed_pk = PublicKey::from_bytes(pk.as_bytes()).unwrap();
        let parsed_sk = SecretKey::from_bytes(sk.as_bytes()).unwrap();
        let parsed_sig = Signature::from_bytes(sig.as_bytes()).unwrap();
        verify(&parsed_pk, b"message", &parsed_sig, b"ctx").unwrap();
        assert!(sign(&parsed_sk, b"message", b"ctx").is_ok());
        let empty = sign(&sk, b"", b"").unwrap();
        verify(&pk, b"", &empty, b"").unwrap();
    }

    #[test]
    fn different_key_tampering_and_context_fail() {
        let (pk, sk) = keygen().unwrap();
        let (other, _) = keygen().unwrap();
        let sig = sign(&sk, b"message", b"ctx").unwrap();
        assert!(matches!(
            verify(&other, b"message", &sig, b"ctx"),
            Err(Error::VerificationFailed)
        ));
        assert!(verify(&pk, b"tampered", &sig, b"ctx").is_err());
        assert!(verify(&pk, b"message", &sig, b"wrong").is_err());
    }

    #[test]
    fn parsers_reject_wrong_lengths() {
        assert!(PublicKey::from_bytes(&[0; 1951]).is_err());
        assert!(PublicKey::from_bytes(&[0; 1953]).is_err());
        assert!(SecretKey::from_bytes(&[0; 4031]).is_err());
        assert!(SecretKey::from_bytes(&[0; 4033]).is_err());
        assert!(Signature::from_bytes(&[0; 3308]).is_err());
        assert!(Signature::from_bytes(&[0; 3310]).is_err());
    }

    #[test]
    fn context_limit_is_enforced() {
        let (_, sk) = keygen().unwrap();
        assert!(matches!(
            sign(&sk, b"", &[0; 256]),
            Err(Error::ContextTooLong)
        ));
    }

    #[test]
    fn fallback_deterministic_signing_check() {
        let (_, sk) = keygen().unwrap();
        let first = sign(&sk, b"fixed test message", b"test context").unwrap();
        let second = sign(&sk, b"fixed test message", b"test context").unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]
        #[test]
        fn generated_messages_and_contexts_round_trip(message in proptest::collection::vec(any::<u8>(), 1..256), context in proptest::collection::vec(any::<u8>(), 0..=255), message_bit in 0usize..2040, signature_bit in 0usize..(SIGNATURE_SIZE * 8)) {
            let (pk, sk) = keygen().unwrap();
            let sig = sign(&sk, &message, &context).unwrap();
            prop_assert!(verify(&pk, &message, &sig, &context).is_ok());
            let mut changed_message = message.clone();
            let message_bit = message_bit % (changed_message.len() * 8);
            changed_message[message_bit / 8] ^= 1 << (message_bit % 8);
            prop_assert!(verify(&pk, &changed_message, &sig, &context).is_err());
            let mut changed_signature = sig.as_bytes().to_vec();
            changed_signature[signature_bit / 8] ^= 1 << (signature_bit % 8);
            let changed_signature = Signature::from_bytes(&changed_signature).unwrap();
            prop_assert!(verify(&pk, &message, &changed_signature, &context).is_err());
        }
    }
}
