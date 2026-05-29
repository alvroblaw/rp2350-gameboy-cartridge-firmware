//! Seed encryption and decryption for secure storage.
//!
//! Encrypts the BIP-39 seed using a key derived from the user's PIN
//! via PBKDF2-HMAC-SHA256. Uses AES-256-GCM for authenticated encryption.
//! The encrypted seed is stored on the SD card.

#![allow(unused)]

/// Encrypted seed data ready for storage.
pub struct EncryptedSeed {
    /// PBKDF2 salt (16 bytes).
    pub salt: [u8; 16],
    /// AES-256-GCM nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Encrypted seed bytes (64 bytes for BIP-39 seed).
    pub ciphertext: [u8; 64],
    /// GCM authentication tag (16 bytes).
    pub tag: [u8; 16],
    /// PBKDF2 iteration count used.
    pub iterations: u32,
}

impl EncryptedSeed {
    /// Encrypt a seed with a PIN-derived key.
    ///
    /// Uses PBKDF2-HMAC-SHA256 with the given iterations to derive an
    /// AES-256 key from the PIN, then encrypts with AES-256-GCM.
    pub fn encrypt(seed: &[u8; 64], pin: &[u8], iterations: u32) -> Result<Self, EncryptError> {
        todo!("Implement seed encryption")
    }

    /// Decrypt a seed with a PIN-derived key.
    ///
    /// Derives the same AES-256 key from PIN + salt, then decrypts
    /// and verifies the GCM authentication tag.
    pub fn decrypt(&self, pin: &[u8]) -> Result<[u8; 64], EncryptError> {
        todo!("Implement seed decryption")
    }

    /// Serialize to bytes for SD card storage.
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut out = [0u8; 112];
        out[..16].copy_from_slice(&self.salt);
        out[16..28].copy_from_slice(&self.nonce);
        out[28..92].copy_from_slice(&self.ciphertext);
        out[92..108].copy_from_slice(&self.tag);
        out[108..112].copy_from_slice(&self.iterations.to_le_bytes());
        out
    }

    /// Deserialize from SD card bytes.
    pub fn from_bytes(data: &[u8; 112]) -> Result<Self, EncryptError> {
        Ok(Self {
            salt: data[..16].try_into().unwrap(),
            nonce: data[16..28].try_into().unwrap(),
            ciphertext: data[28..92].try_into().unwrap(),
            tag: data[92..108].try_into().unwrap(),
            iterations: u32::from_le_bytes(data[108..112].try_into().unwrap()),
        })
    }
}

/// Default PBKDF2 iteration count.
/// Higher = more secure but slower PIN entry.
/// RP2350 at 266MHz can handle 100k iterations in ~1 second.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Encryption/decription errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptError {
    /// Key derivation failed.
    DerivationError,
    /// Decryption failed (wrong PIN or corrupted data).
    DecryptionFailed,
    /// Authentication tag mismatch (tampered data or wrong PIN).
    AuthFailed,
    /// Encryption failed.
    EncryptionError,
}
