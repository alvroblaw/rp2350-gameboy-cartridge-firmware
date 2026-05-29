//! Seed encryption module.
//!
//! Encrypts/decrypts the BIP-39 seed for secure storage on SD card.
//! Uses PBKDF2 for key derivation from PIN, and AES-256-GCM for encryption.
//!
//! **Phase 4 scope** — this module is a stub until encryption is implemented.

#![allow(unused)]

/// Encrypted seed data.
///
/// Contains the encrypted seed bytes, salt, and nonce.
/// Can be serialized to/from SD card.
pub struct EncryptedSeed {
    /// Salt for PBKDF2 key derivation (16 bytes).
    salt: [u8; 16],
    /// Nonce for AES-GCM (12 bytes).
    nonce: [u8; 12],
    /// Encrypted seed bytes (64 bytes + 16 byte GCM tag = 80 bytes).
    ciphertext: [u8; 80],
}

impl EncryptedSeed {
    /// Create a new encrypted seed from a PIN and raw seed.
    ///
    /// Derives an encryption key from the PIN using PBKDF2,
    /// then encrypts the seed with AES-256-GCM.
    pub fn encrypt(pin: &[u8], seed: &[u8; 64]) -> Result<Self, EncryptError> {
        todo!("Phase 4: implement seed encryption with PBKDF2 + AES-256-GCM")
    }

    /// Decrypt the seed using a PIN.
    ///
    /// Returns the raw 64-byte seed, or an error if the PIN is wrong.
    pub fn decrypt(&self, pin: &[u8]) -> Result<[u8; 64], EncryptError> {
        todo!("Phase 4: implement seed decryption")
    }

    /// Serialize to bytes for storage on SD card.
    pub fn to_bytes(&self) -> [u8; 108] {
        let mut buf = [0u8; 108];
        buf[..16].copy_from_slice(&self.salt);
        buf[16..28].copy_from_slice(&self.nonce);
        buf[28..108].copy_from_slice(&self.ciphertext);
        buf
    }

    /// Deserialize from bytes read from SD card.
    pub fn from_bytes(data: &[u8; 108]) -> Self {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        let mut ciphertext = [0u8; 80];
        salt.copy_from_slice(&data[..16]);
        nonce.copy_from_slice(&data[16..28]);
        ciphertext.copy_from_slice(&data[28..108]);
        Self { salt, nonce, ciphertext }
    }
}

/// Encryption errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptError {
    /// Decryption failed (wrong PIN or corrupted data).
    DecryptionFailed,
    /// Key derivation failed.
    KeyDerivationError,
}
