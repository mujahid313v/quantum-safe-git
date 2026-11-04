#![forbid(unsafe_code)]

//! Encrypted on-disk ML-DSA-65 seed storage. This crate performs local file I/O.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use qsg_core::{PublicKey, SecretKey, Seed};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 6] = b"QSGKEY";
const VERSION: u8 = 1;
const ALG_ML_DSA_65: u8 = 1;
const KDF_NONE: u8 = 0;
const KDF_ARGON2ID: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SEED_LEN: usize = qsg_core::SEED_SIZE;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 59;
const FILE_LEN: usize = HEADER_LEN + SEED_LEN + TAG_LEN;
const DEFAULT_MEMORY_KIB: u32 = 19_456;
const DEFAULT_ITERATIONS: u32 = 2;
const DEFAULT_LANES: u8 = 1;
const MAX_MEMORY_KIB: u32 = 131_072;
const MAX_ITERATIONS: u32 = 6;
const MAX_LANES: u8 = 4;
const MAX_PASSPHRASE_LEN: usize = 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key name")]
    InvalidName,
    #[error("passphrase must contain 1 to 1024 bytes")]
    InvalidPassphrase,
    #[error("passphrase-less storage requires allow_unencrypted=true")]
    UnencryptedNotAllowed,
    #[error("unsupported key container version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported key algorithm id {0}")]
    UnknownAlgorithm(u8),
    #[error("unsupported KDF id {0}")]
    UnknownKdf(u8),
    #[error("unsupported AEAD id {0}")]
    UnknownAead(u8),
    #[error("truncated or extended key container")]
    InvalidLength,
    #[error("Argon2 parameters are outside accepted bounds")]
    KdfBounds,
    #[error("wrong passphrase or corrupted key container")]
    WrongPassphraseOrCorrupt,
    #[error("private key file is a symbolic link")]
    Symlink,
    #[error("private key already exists; pass overwrite=true to replace it")]
    AlreadyExists,
    #[error("unsafe permissions on {path}; run: chmod {mode} '{path}'")]
    Permissions { path: String, mode: &'static str },
    #[error("malformed public key file")]
    InvalidPublicFile,
    #[error("public key does not match secret key")]
    KeyMismatch,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("invalid key container header")]
    InvalidHeader,
    #[error("comment contains a newline or control character")]
    InvalidComment,
    #[error("qsg-core error: {0}")]
    Core(#[from] qsg_core::Error),
    #[error("qsg-sshsig error: {0}")]
    Sshsig(#[from] qsg_sshsig::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Passphrase bytes held in a zeroizing allocation. Debug output is deliberately absent.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_PASSPHRASE_LEN {
            return Err(Error::InvalidPassphrase);
        }
        Ok(Self(Zeroizing::new(value.to_vec())))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Encrypted,
    Unencrypted,
}

pub struct KeyInfo {
    pub private_path: PathBuf,
    pub public_path: PathBuf,
    pub fingerprint: String,
}

pub struct PublicKeyInfo {
    pub blob: Vec<u8>,
    pub fingerprint: String,
    pub comment: String,
}

/// Create a keypair in `dir`. `passphrase=None` requires the explicit
/// `allow_unencrypted` acknowledgement. Existing files require `overwrite`.
pub fn generate(
    dir: impl AsRef<Path>,
    name: &str,
    passphrase: Option<&Passphrase>,
    comment: &str,
    overwrite: bool,
    allow_unencrypted: bool,
) -> Result<KeyInfo> {
    validate_name(name)?;
    validate_comment(comment)?;
    if passphrase.is_none() && !allow_unencrypted {
        return Err(Error::UnencryptedNotAllowed);
    }
    let dir = dir.as_ref();
    ensure_private_dir(dir)?;
    let private_path = dir.join(name);
    let public_path = PathBuf::from(format!("{}.pub", private_path.display()));
    if !overwrite && (private_path.exists() || public_path.exists()) {
        return Err(Error::AlreadyExists);
    }
    refuse_symlink(&private_path)?;
    let (public, _expanded, seed) = qsg_core::keygen_with_seed()?;
    let blob = qsg_sshsig::encode_ml_dsa65_public_key_blob(&public)?;
    let private = encode_container(seed.as_bytes(), passphrase, None)?;
    let public_text = if comment.is_empty() {
        format!("ssh-mldsa65@qsgit {}\n", STANDARD.encode(&blob))
    } else {
        format!("ssh-mldsa65@qsgit {} {}\n", STANDARD.encode(&blob), comment)
    };
    atomic_write(&private_path, &private, overwrite, true)?;
    if let Err(error) = atomic_write(&public_path, public_text.as_bytes(), overwrite, false) {
        if !overwrite {
            let _ = fs::remove_file(&private_path);
        }
        return Err(error);
    }
    Ok(KeyInfo {
        private_path,
        public_path,
        fingerprint: qsg_sshsig::fingerprint(&blob)?,
    })
}

/// Load the encrypted seed and reconstruct the expanded ML-DSA key in memory.
/// Passphrase-less files require the explicit `allow_unencrypted` acknowledgement.
pub fn load_secret(
    path: impl AsRef<Path>,
    passphrase: Option<&Passphrase>,
    allow_unencrypted: bool,
) -> Result<(PublicKey, SecretKey, KeyKind)> {
    let private_path = private_path(path.as_ref());
    refuse_symlink(&private_path)?;
    check_file_permissions(&private_path)?;
    let mut file = open_private(&private_path)?;
    let metadata = file.metadata()?;
    if metadata.len() as usize != FILE_LEN {
        return Err(Error::InvalidLength);
    }
    let mut bytes = Zeroizing::new(vec![0; FILE_LEN]);
    file.read_exact(&mut bytes)?;
    let (seed_bytes, kind) =
        decode_container(&bytes, passphrase, allow_unencrypted, Bounds::production())?;
    let seed = Seed::from_bytes(&seed_bytes)?;
    let (public, secret) = qsg_core::keygen_from_seed(&seed)?;
    let public_info = read_public(public_path(&private_path))?;
    let blob = qsg_sshsig::encode_ml_dsa65_public_key_blob(&public)?;
    if public_info.blob != blob {
        return Err(Error::KeyMismatch);
    }
    Ok((public, secret, kind))
}

pub fn read_public(path: impl AsRef<Path>) -> Result<PublicKeyInfo> {
    let path = path.as_ref();
    let public_path = if path.extension().is_some_and(|ext| ext == "pub") {
        path.to_path_buf()
    } else {
        public_path(path)
    };
    let text = fs::read_to_string(public_path)?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    if line.contains('\n') || line.contains('\r') {
        return Err(Error::InvalidPublicFile);
    }
    let mut fields = line.splitn(3, ' ');
    if fields.next() != Some("ssh-mldsa65@qsgit") {
        return Err(Error::InvalidPublicFile);
    }
    let encoded = fields.next().ok_or(Error::InvalidPublicFile)?;
    let comment = fields.next().unwrap_or("");
    if comment.chars().any(char::is_control) {
        return Err(Error::InvalidPublicFile);
    }
    let blob = STANDARD
        .decode(encoded)
        .map_err(|_| Error::InvalidPublicFile)?;
    qsg_sshsig::decode_ml_dsa65_public_key_blob(&blob)?;
    let fingerprint = qsg_sshsig::fingerprint(&blob)?;
    Ok(PublicKeyInfo {
        blob,
        fingerprint,
        comment: comment.to_owned(),
    })
}

/// Default configuration directory: XDG_CONFIG_HOME/qsgit or ~/.config/qsgit
/// on Unix; %APPDATA%/qsgit (best effort) on Windows.
pub fn default_config_dir() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Ok(PathBuf::from(xdg).join("qsgit"));
            }
        }
        return Ok(
            PathBuf::from(std::env::var_os("HOME").ok_or(Error::InvalidHeader)?)
                .join(".config/qsgit"),
        );
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(appdata).join("qsgit"));
        }
        return Ok(
            PathBuf::from(std::env::var_os("USERPROFILE").ok_or(Error::InvalidHeader)?)
                .join("AppData/Roaming/qsgit"),
        );
    }
    #[allow(unreachable_code)]
    Err(Error::InvalidHeader)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\'])
        || name.ends_with(".pub")
        || name.chars().any(char::is_control)
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn validate_comment(comment: &str) -> Result<()> {
    if comment.chars().any(char::is_control) {
        Err(Error::InvalidComment)
    } else {
        Ok(())
    }
}

fn private_path(path: &Path) -> PathBuf {
    if path.extension().is_some_and(|ext| ext == "pub") {
        path.with_extension("")
    } else {
        path.to_path_buf()
    }
}

fn public_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", path.display()))
}

#[derive(Clone, Copy)]
struct Bounds {
    min_memory: u32,
    max_memory: u32,
    min_iterations: u32,
    max_iterations: u32,
    max_lanes: u8,
}
impl Bounds {
    fn production() -> Self {
        Self {
            min_memory: DEFAULT_MEMORY_KIB,
            max_memory: MAX_MEMORY_KIB,
            min_iterations: DEFAULT_ITERATIONS,
            max_iterations: MAX_ITERATIONS,
            max_lanes: MAX_LANES,
        }
    }
    #[cfg(test)]
    fn test() -> Self {
        Self {
            min_memory: 8,
            max_memory: 8,
            min_iterations: 1,
            max_iterations: 1,
            max_lanes: 1,
        }
    }
}

fn encode_container(
    seed: &[u8],
    passphrase: Option<&Passphrase>,
    params: Option<(u32, u32, u8)>,
) -> Result<Vec<u8>> {
    if seed.len() != SEED_LEN {
        return Err(Error::InvalidLength);
    }
    let (kdf, memory, iterations, lanes) = match passphrase {
        Some(_) => {
            let (m, t, p) =
                params.unwrap_or((DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_LANES));
            #[cfg(test)]
            let bounds = if params.is_some() {
                Bounds::test()
            } else {
                Bounds::production()
            };
            #[cfg(not(test))]
            let bounds = Bounds::production();
            check_params(m, t, p, bounds)?;
            (KDF_ARGON2ID, m, t, p)
        }
        None => (KDF_NONE, 0, 0, 0),
    };
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&[VERSION, ALG_ML_DSA_65, kdf]);
    header.extend_from_slice(&memory.to_be_bytes());
    header.extend_from_slice(&iterations.to_be_bytes());
    header.push(lanes);
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::Crypto)?;
    getrandom::fill(&mut nonce).map_err(|_| Error::Crypto)?;
    header.extend_from_slice(&salt);
    header.push(AEAD_XCHACHA20_POLY1305);
    header.extend_from_slice(&nonce);
    let key = derive_key(passphrase, kdf, memory, iterations, lanes, &salt)?;
    let cipher_key = Key::try_from(&key[..]).map_err(|_| Error::Crypto)?;
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let cipher_nonce = XNonce::try_from(&nonce[..]).map_err(|_| Error::Crypto)?;
    let encrypted = cipher
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: seed,
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto)?;
    header.extend_from_slice(&encrypted);
    salt.zeroize();
    nonce.zeroize();
    Ok(header)
}

fn decode_container(
    input: &[u8],
    passphrase: Option<&Passphrase>,
    allow_unencrypted: bool,
    bounds: Bounds,
) -> Result<(Zeroizing<Vec<u8>>, KeyKind)> {
    if input.len() != FILE_LEN {
        return Err(Error::InvalidLength);
    }
    if &input[..6] != MAGIC {
        return Err(Error::InvalidHeader);
    }
    if input[6] != VERSION {
        return Err(Error::UnsupportedVersion(input[6]));
    }
    if input[7] != ALG_ML_DSA_65 {
        return Err(Error::UnknownAlgorithm(input[7]));
    }
    let kdf = input[8];
    if kdf != KDF_NONE && kdf != KDF_ARGON2ID {
        return Err(Error::UnknownKdf(kdf));
    }
    let memory = u32::from_be_bytes(input[9..13].try_into().map_err(|_| Error::InvalidLength)?);
    let iterations =
        u32::from_be_bytes(input[13..17].try_into().map_err(|_| Error::InvalidLength)?);
    let lanes = input[17];
    let salt = &input[18..34];
    if input[34] != AEAD_XCHACHA20_POLY1305 {
        return Err(Error::UnknownAead(input[34]));
    }
    let nonce = &input[35..59];
    let kind = if kdf == KDF_ARGON2ID {
        check_params(memory, iterations, lanes, bounds)?;
        if passphrase.is_none() {
            return Err(Error::WrongPassphraseOrCorrupt);
        }
        KeyKind::Encrypted
    } else {
        if memory != 0 || iterations != 0 || lanes != 0 {
            return Err(Error::InvalidHeader);
        }
        if !allow_unencrypted {
            return Err(Error::UnencryptedNotAllowed);
        }
        if passphrase.is_some() {
            return Err(Error::WrongPassphraseOrCorrupt);
        }
        KeyKind::Unencrypted
    };
    let key = derive_key(passphrase, kdf, memory, iterations, lanes, salt)?;
    let cipher_key = Key::try_from(&key[..]).map_err(|_| Error::Crypto)?;
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let cipher_nonce = XNonce::try_from(nonce).map_err(|_| Error::InvalidLength)?;
    let decrypted = Zeroizing::new(
        cipher
            .decrypt(
                &cipher_nonce,
                Payload {
                    msg: &input[HEADER_LEN..],
                    aad: &input[..HEADER_LEN],
                },
            )
            .map_err(|_| Error::WrongPassphraseOrCorrupt)?,
    );
    if decrypted.len() != SEED_LEN {
        return Err(Error::WrongPassphraseOrCorrupt);
    }
    Ok((decrypted, kind))
}

fn derive_key(
    passphrase: Option<&Passphrase>,
    kdf: u8,
    memory: u32,
    iterations: u32,
    lanes: u8,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    match kdf {
        KDF_NONE => {}
        KDF_ARGON2ID => {
            let p = Params::new(memory, iterations, lanes as u32, Some(32))
                .map_err(|_| Error::KdfBounds)?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
            argon
                .hash_password_into(
                    &passphrase.ok_or(Error::WrongPassphraseOrCorrupt)?.0,
                    salt,
                    key.as_mut(),
                )
                .map_err(|_| Error::Crypto)?;
        }
        n => return Err(Error::UnknownKdf(n)),
    }
    Ok(key)
}

fn check_params(memory: u32, iterations: u32, lanes: u8, bounds: Bounds) -> Result<()> {
    if memory < bounds.min_memory
        || memory > bounds.max_memory
        || iterations < bounds.min_iterations
        || iterations > bounds.max_iterations
        || lanes == 0
        || lanes > bounds.max_lanes
        || memory < 8 * lanes as u32
    {
        return Err(Error::KdfBounds);
    }
    Ok(())
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(dir)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Symlink);
        }
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(Error::Permissions {
                path: dir.display().to_string(),
                mode: "700",
            });
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)?;
    Ok(())
}

fn refuse_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(Error::Symlink),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn check_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Symlink);
        }
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(Error::Permissions {
                path: path.display().to_string(),
                mode: "600",
            });
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn open_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::InvalidInput {
            Error::Symlink
        } else {
            Error::Io(e)
        }
    })
}

fn atomic_write(path: &Path, bytes: &[u8], overwrite: bool, private: bool) -> Result<()> {
    #[cfg(not(unix))]
    let _ = private;
    refuse_symlink(path)?;
    if !overwrite && path.exists() {
        return Err(Error::AlreadyExists);
    }
    let parent = path.parent().ok_or(Error::InvalidName)?;
    let mut temp = None;
    for _ in 0..32 {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".qsgit-tmp-{}-{n}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if private { 0o600 } else { 0o644 });
        }
        match options.open(&candidate) {
            Ok(file) => {
                #[cfg(unix)]
                if private {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
                temp = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    let (temporary, mut file) = temp.ok_or(Error::AlreadyExists)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if overwrite {
            fs::rename(&temporary, path)?;
        } else {
            fs::hard_link(&temporary, path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::AlreadyExists
                } else {
                    Error::Io(e)
                }
            })?;
            fs::remove_file(&temporary)?;
        }
        #[cfg(unix)]
        {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests;
