//! In-memory key manager for development.

use std::collections::HashMap;

/// Simple in-memory key manager for development.
#[derive(Debug, Default)]
pub struct KeyManager {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyManager {
    /// Creates a new in-memory key manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a key by its identifier.
    pub fn load(&self, key_id: &str) -> Vec<u8> {
        self.keys.get(key_id).cloned().unwrap_or_default()
    }

    /// Stores a key.
    pub fn store(&self, key_id: &str, key: &[u8]) {
        self.keys.insert(key_id.to_string(), key.to_vec());
    }
}
