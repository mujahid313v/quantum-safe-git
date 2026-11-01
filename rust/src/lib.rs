//! Quantum-Safe Git (QSGit) signing library.
//!
//! Provides post-quantum cryptographic signing and verification
//! primitives (NIST CRYSTALS-Dilithium) for Git commit workflows.

use log::{error, info};

/// Error type for QSGit signing operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The Dilithium3 signature scheme could not be created.
    #[error("failed to create Dilithium3 signature scheme")]
    DilithiumSchemeCreation,
    /// The Dilithium3 key pair could not be generated.
    #[error("failed to generate Dilithium3 key pair")]
    DilithiumKeyGeneration,
    /// The Dilithium3 signing operation failed.
    #[error("Dilithium3 signing operation failed")]
    DilithiumSigning,
    /// The Dilithium3 verification operation failed.
    #[error("Dilithium3 signature verification failed")]
    DilithiumVerification,
}

/// Initializes the environment logger for QSGit.
pub fn init() {
    env_logger::init();
}

/// Signs the given payload with a post-quantum Dilithium-3 signature.
pub fn sign(payload: &[u8]) -> Vec<u8> {
    info!("signing payload of {}", payload.len());

    match sign_dilithium3(payload) {
        Ok(signature) => signature,
        Err(err) => {
            error!("failed to sign payload: {err}");
            Vec::new()
        }
    }
}

/// Verifies a signature against the given payload.
pub fn verify(payload: &[u8], signature: &[u8]) -> bool {
    info!("verifying signature of {}", payload.len());

    match verify_dilithium3(payload, signature) {
        Ok(valid) => valid,
        Err(err) => {
            error!("failed to verify signature: {err}");
            false
        }
    }
}

/// Creates a Dilithium3 signature for the given payload.
fn sign_dilithium3(payload: &[u8]) -> Result<Vec<u8>, Error> {
    let algorithm = oqs::sig::Algorithm::Dilithium3;
    let sig = oqs::sig::Sig::new(algorithm).map_err(|_| Error::DilithiumSchemeCreation)?;
    let (_, secret_key) = sig.keypair().map_err(|_| Error::DilithiumKeyGeneration)?;
    let signature = sig
        .sign(payload, &secret_key)
        .map_err(|_| Error::DilithiumSigning)?;

    Ok(signature.into_vec())
}

/// Verifies a Dilithium3 signature against the given payload.
fn verify_dilithium3(payload: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let algorithm = oqs::sig::Algorithm::Dilithium3;
    let sig = oqs::sig::Sig::new(algorithm).map_err(|_| Error::DilithiumSchemeCreation)?;
    let (public_key, _) = sig.keypair().map_err(|_| Error::DilithiumKeyGeneration)?;
    let signature_obj = sig
        .signature_from_bytes(signature)
        .ok_or(Error::DilithiumVerification)?;

    Ok(sig.verify(payload, signature_obj, &public_key).is_ok())
}

pub mod keymgr;

pub use keymgr::KeyManager;

#[cfg(test)]
mod tests {
    #[test]
    fn test_dilithium3_sign_and_verify_roundtrip() {
        oqs::init();
        let algorithm = oqs::sig::Algorithm::Dilithium3;
        let sig = oqs::sig::Sig::new(algorithm).expect("create Dilithium3 scheme");
        let (public_key, secret_key) = sig.keypair().expect("key pair");
        let message = [0u8; 100];
        let signature = sig.sign(&message, &secret_key).expect("sign payload");
        assert!(sig.verify(&message, &signature, &public_key).is_ok());
    }
}
