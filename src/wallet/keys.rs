//! Key management for the stealth wallet.
//! **Status**: Stub — full implementation in Phase 3.

#![allow(unused)]

use crate::wallet::bip32::{ExtendedPrivateKey, Network};

/// Trait for abstracting key access.
pub trait KeySource {
    fn get_master_key(&self, network: Network) -> Result<ExtendedPrivateKey, KeyError>;
    fn is_available(&self) -> bool;
}

/// Key stored in encrypted persistent storage.
pub struct StoredKey {
    unlocked: bool,
}

impl StoredKey {
    pub fn new() -> Self { Self { unlocked: false } }
    pub fn lock(&mut self) { self.unlocked = false; }
    pub fn is_unlocked(&self) -> bool { self.unlocked }
}

impl KeySource for StoredKey {
    fn get_master_key(&self, _network: Network) -> Result<ExtendedPrivateKey, KeyError> {
        Err(KeyError::NoSeed)
    }
    fn is_available(&self) -> bool { self.unlocked }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Locked,
    NoSeed,
    DerivationError,
    InvalidKey,
}
