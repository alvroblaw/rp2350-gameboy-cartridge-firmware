//! Key management for the stealth wallet.
//!
//! Defines the `KeySource` trait for abstracting key access (stored keys
//! vs future stateless QR-scanned keys) and provides the `StoredKey`
//! implementation for keys persisted in encrypted storage.
//!
//! **Status**: Stub — full implementation in Phase 3.

#![allow(unused)]

use crate::wallet::bip32::{Bip32Error, ExtendedPrivateKey, Network};

/// Trait for abstracting key access.
///
/// This allows the wallet to work with both stored keys (current Phase 4)
/// and future stateless keys (Phase 6 — QR camera input).
pub trait KeySource {
    /// Get the extended private key for the given network.
    fn get_master_key(&self, network: Network) -> Result<ExtendedPrivateKey, KeyError>;

    /// Check if a key is currently available.
    fn is_available(&self) -> bool;

    /// Export mnemonic word indices.
    fn export_mnemonic_indices(&self) -> Result<[u16; 24], KeyError>;
}

/// A key stored in encrypted persistent storage.
///
/// The seed is encrypted with a key derived from the user's PIN.
/// On unlock, the seed is decrypted into RAM and used for key derivation.
/// On lock, the seed is zeroized from RAM.
///
/// **Status**: Stub — full implementation in Phase 3/4.
pub struct StoredKey {
    /// Whether the key is currently unlocked (seed in RAM).
    unlocked: bool,
}

impl StoredKey {
    /// Create a new empty stored key.
    pub fn new() -> Self {
        Self { unlocked: false }
    }

    /// Lock the key (zeroize seed from RAM).
    pub fn lock(&mut self) {
        self.unlocked = false;
    }

    /// Check if the key is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }
}

impl KeySource for StoredKey {
    fn get_master_key(&self, _network: Network) -> Result<ExtendedPrivateKey, KeyError> {
        if !self.unlocked {
            return Err(KeyError::Locked);
        }
        // TODO: Phase 3 — decrypt seed, derive master key
        Err(KeyError::NoSeed)
    }

    fn is_available(&self) -> bool {
        self.unlocked
    }

    fn export_mnemonic_indices(&self) -> Result<[u16; 24], KeyError> {
        if !self.unlocked {
            return Err(KeyError::Locked);
        }
        // TODO: Phase 3
        Err(KeyError::NoSeed)
    }
}

/// Key management errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Wallet is locked.
    Locked,
    /// No seed stored.
    NoSeed,
    /// Key derivation failed.
    DerivationError,
    /// Invalid key material.
    InvalidKey,
}
