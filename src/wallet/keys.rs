//! Key source abstraction for wallet key management.
//!
//! Defines the `KeySource` trait to abstract over where keys come from.
//! Currently implements `StoredKey` (encrypted seed on SD card).
//! Future: `QRScanKey` for stateless mode with camera module.

#![allow(unused)]

use crate::wallet::bip32::{ExtendedPrivateKey, Network};

/// Trait for sources of wallet keys.
///
/// This abstraction allows the wallet to work with stored keys (current)
/// or stateless keys scanned from QR codes (future camera module).
pub trait KeySource {
    /// Initialize the key source (e.g., decrypt seed from storage).
    fn init(&mut self, pin: &[u8]) -> Result<(), KeyError>;

    /// Get the master extended private key.
    fn master_key(&self, network: Network) -> Result<ExtendedPrivateKey, KeyError>;

    /// Check if keys are currently loaded in memory.
    fn is_loaded(&self) -> bool;

    /// Clear all key material from memory (zeroize).
    fn wipe(&mut self);

    /// Export the seed as mnemonic words.
    fn export_mnemonic(&self) -> Result<MnemonicExport, KeyError>;

    /// Export the account-level extended public key.
    fn export_xpub(&self, network: Network) -> Result<[u8; 111], KeyError>;
}

/// A stored key source backed by encrypted seed on SD card.
pub struct StoredKey {
    /// Whether the seed is currently decrypted in memory.
    loaded: bool,
}

impl StoredKey {
    /// Create a new stored key source.
    pub fn new() -> Self {
        Self { loaded: false }
    }

    /// Generate a new random seed and store it encrypted on SD.
    pub fn generate_and_store(
        &mut self,
        pin: &[u8],
    ) -> Result<crate::wallet::bip39::Mnemonic, KeyError> {
        todo!("Generate seed, encrypt, store on SD")
    }

    /// Import an existing mnemonic and store it encrypted on SD.
    pub fn import_and_store(&mut self, mnemonic: &str, pin: &[u8]) -> Result<(), KeyError> {
        todo!("Parse mnemonic, encrypt seed, store on SD")
    }
}

impl KeySource for StoredKey {
    fn init(&mut self, pin: &[u8]) -> Result<(), KeyError> {
        todo!("Read encrypted seed from SD, decrypt with PIN-derived key")
    }

    fn master_key(&self, network: Network) -> Result<ExtendedPrivateKey, KeyError> {
        todo!("Derive master key from decrypted seed")
    }

    fn is_loaded(&self) -> bool {
        self.loaded
    }

    fn wipe(&mut self) {
        self.loaded = false;
        // TODO: zeroize seed material
    }

    fn export_mnemonic(&self) -> Result<MnemonicExport, KeyError> {
        todo!("Convert seed back to mnemonic words")
    }

    fn export_xpub(&self, network: Network) -> Result<[u8; 111], KeyError> {
        todo!("Derive and export xpub")
    }
}

/// Mnemonic export data.
pub struct MnemonicExport {
    /// Word count (12 or 24).
    pub word_count: u8,
    /// Word indices into the BIP-39 wordlist.
    pub word_indices: [u16; 24],
}

/// Key management errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// No seed stored on SD card.
    NoSeedStored,
    /// PIN derivation failed.
    PinError,
    /// Decryption failed (wrong PIN or corrupted data).
    DecryptionFailed,
    /// Key not loaded (must call init first).
    NotLoaded,
    /// SD card I/O error.
    StorageError,
    /// Invalid mnemonic.
    InvalidMnemonic,
}
