use qsg_keystore::{PublicKeyInfo, read_public as read_keystore_public};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_PUBLIC_FILE: usize = 16 * 1024;

/// Apply the CLI's input bound before delegating public-key parsing to qsg-keystore.
pub fn read_public(path: impl AsRef<Path>) -> Result<PublicKeyInfo, String> {
    let supplied = path.as_ref();
    let public_path = if supplied.extension().is_some_and(|ext| ext == "pub") {
        supplied.to_path_buf()
    } else {
        public_path(supplied)
    };
    let file = std::fs::File::open(&public_path)
        .map_err(|e| format!("could not read public key {}: {e}", public_path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_PUBLIC_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read public key {}: {e}", public_path.display()))?;
    if bytes.len() > MAX_PUBLIC_FILE {
        return Err(format!(
            "public key {} exceeds {MAX_PUBLIC_FILE} byte limit",
            public_path.display()
        ));
    }
    std::str::from_utf8(&bytes)
        .map_err(|_| format!("public key {} is not UTF-8", public_path.display()))?;
    read_keystore_public(supplied).map_err(|e| format!("invalid public key: {e}"))
}

fn public_path(path: &Path) -> PathBuf {
    let mut result = path.to_path_buf();
    result.set_extension("pub");
    result
}
