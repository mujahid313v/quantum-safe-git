#![forbid(unsafe_code)]

//! ML-DSA-65 core operations. This crate performs no file or network I/O.

use getrandom::SysRng;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, Generate,
    Keypair, MlDsa65, Seed as MlDsaSeed, Signature as MlSignature, SigningKey, VerifyingKey,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PUBLIC_KEY_SIZE: usize = 1952;
pub const SECRET_KEY_SIZE: usize = 4032;
pub const SIGNATURE_SIZE: usize = 3309;
pub const SEED_SIZE: usize = 32;
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
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
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

/// Zeroizing 32-byte ML-DSA seed, suitable for encrypted storage.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; SEED_SIZE]);

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
const _: fn() = assert_zeroize_on_drop::<Seed>;

impl Seed {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SEED_SIZE {
            return Err(Error::InvalidLength {
                kind: "seed",
                expected: SEED_SIZE,
                actual: bytes.len(),
            });
        }
        let mut value = Zeroizing::new([0; SEED_SIZE]);
        value.copy_from_slice(bytes);
        Ok(Self(core::mem::take(&mut *value)))
    }

    pub fn as_bytes(&self) -> &[u8; SEED_SIZE] {
        &self.0
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
    let signing_key = SigningKey::<MlDsa65>::try_generate_from_rng(&mut SysRng)
        .map_err(|_| Error::RandomnessUnavailable)?;
    let public = signing_key.verifying_key().encode();
    // M1 fixes the exposed secret encoding at the 4032-byte expanded form. The
    // backend marks this internal encoding deprecated in favor of its 32-byte seed.
    #[allow(deprecated)]
    let secret = signing_key.expanded_key().to_expanded();
    Ok((PublicKey(public), SecretKey(secret)))
}

/// Generate an ML-DSA keypair and return its zeroizing 32-byte seed as well.
pub fn keygen_with_seed() -> Result<(PublicKey, SecretKey, Seed)> {
    let signing_key = SigningKey::<MlDsa65>::try_generate_from_rng(&mut SysRng)
        .map_err(|_| Error::RandomnessUnavailable)?;
    let public = PublicKey(signing_key.verifying_key().encode());
    #[allow(deprecated)]
    let secret = SecretKey(signing_key.expanded_key().to_expanded());
    let backend_seed = Zeroizing::new(signing_key.to_seed());
    let mut seed = Zeroizing::new([0; SEED_SIZE]);
    seed.copy_from_slice(backend_seed.as_slice());
    Ok((public, secret, Seed(core::mem::take(&mut *seed))))
}

/// Reconstruct the ML-DSA keypair from its 32-byte seed.
pub fn keygen_from_seed(seed: &Seed) -> Result<(PublicKey, SecretKey)> {
    let backend_seed = Zeroizing::new(MlDsaSeed::try_from(seed.as_bytes().as_slice()).map_err(
        |_| Error::InvalidLength {
            kind: "seed",
            expected: SEED_SIZE,
            actual: seed.as_bytes().len(),
        },
    )?);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&backend_seed);
    let public = PublicKey(signing_key.verifying_key().encode());
    #[allow(deprecated)]
    let secret = SecretKey(signing_key.expanded_key().to_expanded());
    Ok((public, secret))
}

pub fn sign(secret: &SecretKey, message: &[u8], context: &[u8]) -> Result<Signature> {
    if context.len() > MAX_CONTEXT_SIZE {
        return Err(Error::ContextTooLong);
    }
    #[allow(deprecated)]
    // The public API requires the FIPS expanded private-key encoding (4032 bytes).
    let key = ExpandedSigningKey::<MlDsa65>::from_expanded(&secret.0);
    let signature = key
        .sign_randomized(message, context, &mut SysRng)
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
        assert!(Seed::from_bytes(&[0; 31]).is_err());
        assert!(Seed::from_bytes(&[0; 33]).is_err());
    }

    #[test]
    fn seed_reconstructs_same_keypair() {
        let (public, secret, seed) = keygen_with_seed().unwrap();
        let (reconstructed_public, reconstructed_secret) = keygen_from_seed(&seed).unwrap();
        assert_eq!(public.as_bytes(), reconstructed_public.as_bytes());
        let first = sign(&secret, b"seed reconstruction", b"test").unwrap();
        let second = sign(&reconstructed_secret, b"seed reconstruction", b"test").unwrap();
        verify(
            &reconstructed_public,
            b"seed reconstruction",
            &first,
            b"test",
        )
        .unwrap();
        verify(&public, b"seed reconstruction", &second, b"test").unwrap();
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
    fn production_signing_is_hedged() {
        let (pk, sk) = keygen().unwrap();
        let first = sign(&sk, b"same message", b"test context").unwrap();
        let second = sign(&sk, b"same message", b"test context").unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
        verify(&pk, b"same message", &first, b"test context").unwrap();
        verify(&pk, b"same message", &second, b"test context").unwrap();
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
            match Signature::from_bytes(&changed_signature) {
                Ok(changed_signature) => {
                    prop_assert!(verify(&pk, &message, &changed_signature, &context).is_err());
                }
                Err(Error::InvalidSignature) => {}
                Err(error) => prop_assert!(false, "unexpected signature parse error: {error}"),
            }
        }
    }
}
