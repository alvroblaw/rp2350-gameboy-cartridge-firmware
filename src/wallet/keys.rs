//! Key management for the stealth wallet.
//!
//! Defines the `KeySource` trait for abstracting key access (stored keys
//! vs future stateless QR-scanned keys) and provides the `StoredKey`
//! implementation for keys persisted in encrypted storage.
//!
//! # Security
//!
//! - `StoredKey` zeroizes the seed on Drop via the `Zeroize` derive.
//! - `from_encrypted` decrypts the seed and stores it in RAM for the
//!   duration of the session.
//! - `lock()` explicitly zeroizes and clears the seed.

#![no_std]
#![allow(unused)]

use zeroize::Zeroize;

use crate::wallet::bip32::{Bip32Error, ExtendedPrivateKey, Network};
use crate::wallet::encrypt::{EncryptedSeed, ZeroizingVec};

/// Trait for abstracting key access.
///
/// This allows the wallet to work with both stored keys (current Phase 4)
/// and future stateless keys (Phase 6 — QR camera input).
pub trait KeySource {
    /// Get the extended master private key for the given network.
    fn get_master_key(&self, network: Network) -> Result<ExtendedPrivateKey, KeyError>;

    /// Check if a key is currently available (unlocked).
    fn is_available(&self) -> bool;

    /// Export the seed entropy bytes (for mnemonic recovery).
    fn export_seed(&self) -> Result<&[u8], KeyError>;

    /// Get the seed length in bytes.
    fn seed_len(&self) -> usize;
}

/// A key stored in encrypted persistent storage.
///
/// The seed is encrypted on the SD card with a key derived from the user's PIN.
/// On unlock, the seed is decrypted into internal RAM and used for key derivation.
/// On lock or Drop, the seed is cryptographically zeroized.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct StoredKey {
    /// The decrypted seed (32 or 64 bytes).
    seed: [u8; 64],
    /// Actual seed length.
    seed_len: u8,
    /// Whether the key is currently unlocked (seed in RAM).
    unlocked: bool,
}

impl StoredKey {
    /// Create a new empty (locked) stored key.
    pub const fn new() -> Self {
        Self {
            seed: [0u8; 64],
            seed_len: 0,
            unlocked: false,
        }
    }

    /// Unlock from an encrypted seed + PIN.
    ///
    /// Decrypts the seed into RAM. On success, the key is available for
    /// signing operations. On failure (wrong PIN), returns error.
    pub fn from_encrypted(
        encrypted: &EncryptedSeed,
        pin: &str,
    ) -> Result<Self, KeyError> {
        let decrypted = encrypted.decrypt(pin).map_err(|_| KeyError::WrongPin)?;
        let mut key = Self {
            seed: [0u8; 64],
            seed_len: decrypted.as_slice().len() as u8,
            unlocked: true,
        };
        key.seed[..key.seed_len as usize].copy_from_slice(decrypted.as_slice());
        Ok(key)
    }

    /// Create from raw seed bytes (for import/mnemonic).
    pub fn from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        if seed.len() > 64 || seed.is_empty() {
            return Err(KeyError::InvalidKey);
        }
        let mut key = Self {
            seed: [0u8; 64],
            seed_len: seed.len() as u8,
            unlocked: true,
        };
        key.seed[..seed.len()].copy_from_slice(seed);
        Ok(key)
    }

    /// Lock the key — zeroize seed from RAM.
    pub fn lock(&mut self) {
        self.seed.zeroize();
        self.seed_len = 0;
        self.unlocked = false;
    }

    /// Check if the key is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// Get the raw seed bytes (only when unlocked).
    pub fn seed(&self) -> Result<&[u8], KeyError> {
        if !self.unlocked {
            return Err(KeyError::Locked);
        }
        Ok(&self.seed[..self.seed_len as usize])
    }
}

impl KeySource for StoredKey {
    fn get_master_key(&self, network: Network) -> Result<ExtendedPrivateKey, KeyError> {
        if !self.unlocked {
            return Err(KeyError::Locked);
        }
        let seed_bytes = &self.seed[..self.seed_len as usize];
        ExtendedPrivateKey::new_master(seed_bytes, network)
            .map_err(|_| KeyError::DerivationError)
    }

    fn is_available(&self) -> bool {
        self.unlocked
    }

    fn export_seed(&self) -> Result<&[u8], KeyError> {
        if !self.unlocked {
            return Err(KeyError::Locked);
        }
        Ok(&self.seed[..self.seed_len as usize])
    }

    fn seed_len(&self) -> usize {
        self.seed_len as usize
    }
}

/// Key management errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum KeyError {
    /// Wallet is locked — unlock with PIN first.
    Locked,
    /// No seed stored on device.
    NoSeed,
    /// Wrong PIN — decryption failed.
    WrongPin,
    /// Key derivation failed.
    DerivationError,
    /// Invalid key material (wrong length, etc.).
    InvalidKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_key_from_seed() {
        let seed = [0xABu8; 32];
        let key = StoredKey::from_seed(&seed).unwrap();
        assert!(key.is_unlocked());
        assert_eq!(key.seed().unwrap(), &seed[..]);
        assert_eq!(key.seed_len(), 32);
    }

    #[test]
    fn test_stored_key_lock() {
        let seed = [0xCDu8; 64];
        let mut key = StoredKey::from_seed(&seed).unwrap();
        assert!(key.is_unlocked());
        key.lock();
        assert!(!key.is_unlocked());
        assert!(key.seed().is_err());
    }

    #[test]
    fn test_stored_key_from_encrypted_roundtrip() {
        let seed = [0x42u8; 64];
        let encrypted = EncryptedSeed::encrypt(&seed, "1234").unwrap();
        let key = StoredKey::from_encrypted(&encrypted, "1234").unwrap();
        assert!(key.is_unlocked());
        assert_eq!(key.seed().unwrap(), &seed[..]);
    }

    #[test]
    fn test_stored_key_wrong_pin() {
        let seed = [0x42u8; 64];
        let encrypted = EncryptedSeed::encrypt(&seed, "1234").unwrap();
        assert!(StoredKey::from_encrypted(&encrypted, "0000").is_err());
    }
}
