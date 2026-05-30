//! Seed encryption module.
//!
//! Encrypts/decrypts the BIP-39 seed (32 or 64 bytes) for secure storage on SD card.
//! Uses PBKDF2-HMAC-SHA256 for key derivation from PIN (100 000 iterations),
//! and AES-256-GCM for authenticated encryption.
//!
//! # Wire format
//!
//! ```text
//! [salt: 16 bytes][nonce: 12 bytes][ciphertext: N][tag: 16 bytes]
//! ```
//!
//! Overhead is 44 bytes. A 64-byte seed produces a 108-byte `EncryptedSeed`.
//! A 32-byte seed (12-word mnemonic entropy) produces a 76-byte variant.

#![no_std]
#![allow(unused)]

use aes_gcm::aead::{AeadInPlace, KeyInit, Tag};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto_rng::hardware_random;

/// PBKDF2 iteration count for PIN-derived key.
///
/// 100 000 iterations on the RP2350 at 266 MHz takes ~2-3 seconds,
/// providing good resistance against brute-force while remaining usable.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt length in bytes.
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Total overhead: salt + nonce + tag.
pub const OVERHEAD: usize = SALT_LEN + NONCE_LEN + TAG_LEN; // 44

type HmacSha256 = Hmac<Sha256>;

/// Encrypted seed with fixed-size buffer.
///
/// Supports seeds up to 64 bytes (24-word mnemonic).
/// Serialized as `[salt: 16][nonce: 12][ciphertext: N][tag: 16]`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedSeed {
    /// Salt for PBKDF2 key derivation.
    salt: [u8; SALT_LEN],
    /// Nonce for AES-256-GCM.
    nonce: [u8; NONCE_LEN],
    /// Ciphertext + GCM tag (variable length, seed_len + TAG_LEN).
    data: heapless::Vec<u8, 80>,
    /// Original seed length (before encryption).
    seed_len: u8,
}

impl EncryptedSeed {
    /// Encrypt a seed using a PIN.
    ///
    /// Derives a 256-bit encryption key from the PIN via PBKDF2-HMAC-SHA256,
    /// generates a random salt and nonce, then encrypts with AES-256-GCM.
    /// The PIN bytes are zeroized from the derived key after use.
    pub fn encrypt(seed: &[u8], pin: &str) -> Result<Self, EncryptError> {
        if seed.len() > 64 || seed.is_empty() {
            return Err(EncryptError::InvalidSeedLength);
        }

        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        hardware_random(&mut salt).map_err(|_| EncryptError::RngError)?;

        // Derive encryption key from PIN + salt
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2::<HmacSha256>(pin.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        hardware_random(&mut nonce_bytes).map_err(|_| EncryptError::RngError)?;

        // AES-256-GCM encrypt in-place
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| EncryptError::KeyDerivationError)?;
        key.zeroize();

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Allocate ciphertext buffer: seed_len + tag space
        let mut buffer = heapless::Vec::new();
        buffer.extend_from_slice(seed).map_err(|_| EncryptError::InvalidSeedLength)?;

        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|_| EncryptError::EncryptionFailed)?;

        // Append tag
        buffer.extend_from_slice(&tag)
            .map_err(|_| EncryptError::EncryptionFailed)?;

        Ok(Self {
            salt,
            nonce: nonce_bytes,
            data: buffer,
            seed_len: seed.len() as u8,
        })
    }

    /// Decrypt the seed using a PIN.
    ///
    /// Returns the decrypted seed in a [`ZeroizingVec`] that auto-zeroes on drop.
    /// Returns error if the PIN is wrong (GCM authentication will fail).
    pub fn decrypt(&self, pin: &str) -> Result<ZeroizingVec, EncryptError> {
        // Derive key from PIN + salt
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2::<HmacSha256>(pin.as_bytes(), &self.salt, PBKDF2_ITERATIONS, &mut key);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| EncryptError::KeyDerivationError)?;
        key.zeroize();

        let nonce = Nonce::from_slice(&self.nonce);

        // Split data into ciphertext + tag
        let data_len = self.data.len();
        if data_len < TAG_LEN {
            return Err(EncryptError::DecryptionFailed);
        }
        let ct_end = data_len - TAG_LEN;
        let tag_bytes: [u8; TAG_LEN] = self.data[ct_end..].try_into()
            .map_err(|_| EncryptError::DecryptionFailed)?;
        let tag = Tag::<Aes256Gcm>::from(tag_bytes);

        // Copy ciphertext into mutable buffer
        let mut plaintext = ZeroizingVec::new(self.seed_len as usize);
        plaintext.extend_from_slice(&self.data[..ct_end]);

        cipher.decrypt_in_place_detached(nonce, b"", plaintext.buf_mut(), &tag)
            .map_err(|_| EncryptError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Total serialized size (seed_len + OVERHEAD).
    pub fn serialized_len(&self) -> usize {
        self.seed_len as usize + OVERHEAD
    }

    /// Serialize to bytes for SD card storage.
    ///
    /// Format: `[salt: 16][nonce: 12][seed_len: 1][ciphertext+tag: N]`
    pub fn to_bytes(&self) -> heapless::Vec<u8, 109> {
        let total = SALT_LEN + NONCE_LEN + 1 + self.data.len();
        let mut buf = heapless::Vec::new();
        let _ = buf.extend_from_slice(&self.salt);
        let _ = buf.extend_from_slice(&self.nonce);
        let _ = buf.push(self.seed_len);
        let _ = buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize from bytes read from SD card.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EncryptError> {
        if data.len() < SALT_LEN + NONCE_LEN + 1 + TAG_LEN {
            return Err(EncryptError::CorruptedData);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[..SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&data[SALT_LEN..SALT_LEN + NONCE_LEN]);
        let seed_len = data[SALT_LEN + NONCE_LEN];
        let payload = &data[SALT_LEN + NONCE_LEN + 1..];

        if seed_len as usize + TAG_LEN != payload.len() {
            return Err(EncryptError::CorruptedData);
        }

        let mut data_vec = heapless::Vec::new();
        data_vec.extend_from_slice(payload).map_err(|_| EncryptError::CorruptedData)?;

        Ok(Self {
            salt,
            nonce,
            data: data_vec,
            seed_len,
        })
    }

    /// Get the original seed length.
    pub fn seed_len(&self) -> usize {
        self.seed_len as usize
    }
}

/// A vector that zeroizes its contents on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingVec {
    #[zeroize(skip)]
    len: usize,
    buf: [u8; 64],
}

impl ZeroizingVec {
    /// Create a new zeroized vec with pre-allocated capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            len: 0,
            buf: [0u8; 64],
        }
    }

    /// Extend from a slice.
    pub fn extend_from_slice(&mut self, src: &[u8]) {
        let to_copy = src.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + to_copy].copy_from_slice(&src[..to_copy]);
        self.len += to_copy;
    }

    /// Get the data as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Get inner buffer as mutable slice (for in-place decryption).
    pub fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

/// Encryption errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum EncryptError {
    /// Invalid seed length (must be 1-64 bytes).
    InvalidSeedLength,
    /// PBKDF2 key derivation failed.
    KeyDerivationError,
    /// AES-GCM encryption failed.
    EncryptionFailed,
    /// Decryption failed (wrong PIN or corrupted data).
    DecryptionFailed,
    /// Hardware RNG error.
    RngError,
    /// Data is corrupted or malformed.
    CorruptedData,
}

/// Rate limiter for failed PIN attempts.
///
/// Tracks consecutive failed attempts and enforces:
/// - After 3 fails: 30-second lockout
/// - After 10 fails: option to wipe seed
pub struct PinRateLimiter {
    /// Number of consecutive failed attempts.
    failed_attempts: u8,
    /// Timestamp of last failed attempt (millis since boot).
    last_fail_ms: u64,
    /// Whether wipe has been offered.
    wipe_offered: bool,
}

impl PinRateLimiter {
    /// Create a new rate limiter.
    pub const fn new() -> Self {
        Self {
            failed_attempts: 0,
            last_fail_ms: 0,
            wipe_offered: false,
        }
    }

    /// Record a failed attempt. Returns how long to wait (ms) before retrying.
    pub fn record_failure(&mut self, now_ms: u64) -> u64 {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        self.last_fail_ms = now_ms;

        if self.failed_attempts >= 10 {
            self.wipe_offered = true;
            60_000 // 60s lockout after 10 fails
        } else if self.failed_attempts >= 3 {
            30_000 // 30s lockout after 3 fails
        } else {
            1_000 // 1s delay for first few
        }
    }

    /// Record a successful attempt — reset counter.
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.last_fail_ms = 0;
        self.wipe_offered = false;
    }

    /// Check if the lockout has expired.
    pub fn is_locked_out(&self, now_ms: u64) -> bool {
        if self.failed_attempts < 3 {
            return false;
        }
        let wait = if self.failed_attempts >= 10 { 60_000 } else { 30_000 };
        now_ms.saturating_sub(self.last_fail_ms) < wait
    }

    /// Whether to offer the wipe option (10+ fails).
    pub fn should_offer_wipe(&self) -> bool {
        self.wipe_offered
    }

    /// Get remaining failed attempts before next escalation.
    pub fn attempts_until_escalation(&self) -> u8 {
        if self.failed_attempts < 3 {
            3 - self.failed_attempts
        } else if self.failed_attempts < 10 {
            10 - self.failed_attempts
        } else {
            0
        }
    }
}

/// PIN entry flow via GameBoy.
///
/// Manages the RP2350 side of PIN entry:
/// 1. RP2350 sends DISPLAY_PIN_PROMPT to GB ROM
/// 2. User enters PIN on D-pad
/// 3. GB ROM sends PIN_SUBMITTED back
///
/// This struct holds rate-limiting state and the communication channel.
pub struct PinEntry<'a> {
    /// Rate limiter for failed attempts.
    pub rate_limiter: PinRateLimiter,
    /// Maximum PIN length (digits).
    pub max_pin_len: u8,
    /// Minimum PIN length (digits).
    pub min_pin_len: u8,
    /// Placeholder for channel reference (Phase 6 integration).
    _phantom: core::marker::PhantomData<&'a ()>,
}

impl<'a> PinEntry<'a> {
    /// Create a new PIN entry handler.
    pub fn new(min_len: u8, max_len: u8) -> Self {
        Self {
            rate_limiter: PinRateLimiter::new(),
            min_pin_len: min_len,
            max_pin_len: max_len,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Validate PIN length.
    pub fn validate_pin(&self, pin: &str) -> Result<(), PinError> {
        let len = pin.len();
        if len < self.min_pin_len as usize {
            return Err(PinError::TooShort);
        }
        if len > self.max_pin_len as usize {
            return Err(PinError::TooLong);
        }
        // Check all digits
        for c in pin.chars() {
            if !c.is_ascii_digit() {
                return Err(PinError::NonDigit);
            }
        }
        Ok(())
    }

    /// Default: 4-8 digit PIN.
    pub fn default_config() -> Self {
        Self::new(4, 8)
    }
}

/// PIN validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum PinError {
    /// PIN too short.
    TooShort,
    /// PIN too long.
    TooLong,
    /// PIN contains non-digit characters.
    NonDigit,
}

/// Constant-time comparison of two byte slices.
///
/// Compares all bytes without short-circuiting, preventing timing
/// attacks on PIN or key comparisons. Returns `true` if slices are equal.
///
/// **Important**: if slices have different lengths, returns `false`
/// immediately (length is not secret for PINs — only the content matters).
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time comparison of two PIN strings.
///
/// Wrapper around `constant_time_eq` for PIN strings.
/// PIN digits are zeroized from the comparison buffers after use.
#[inline]
pub fn constant_time_pin_compare(a: &str, b: &str) -> bool {
    let result = constant_time_eq(a.as_bytes(), b.as_bytes());
    // Scrub stack after comparison
    crate::wallet::secure_memory::secure_scrub_stack();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_64() {
        let seed = [0xABu8; 64];
        let pin = "1234";
        let encrypted = EncryptedSeed::encrypt(&seed, pin).unwrap();
        let decrypted = encrypted.decrypt(pin).unwrap();
        assert_eq!(decrypted.as_slice(), &seed[..]);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_32() {
        let seed = [0xCDu8; 32];
        let pin = "9999";
        let encrypted = EncryptedSeed::encrypt(&seed, pin).unwrap();
        let decrypted = encrypted.decrypt(pin).unwrap();
        assert_eq!(decrypted.as_slice(), &seed[..]);
    }

    #[test]
    fn test_wrong_pin_fails() {
        let seed = [0x42u8; 64];
        let encrypted = EncryptedSeed::encrypt(&seed, "1234").unwrap();
        assert!(encrypted.decrypt("0000").is_err());
    }

    #[test]
    fn test_serialize_deserialize() {
        let seed = [0xEFu8; 64];
        let encrypted = EncryptedSeed::encrypt(&seed, "5555").unwrap();
        let bytes = encrypted.to_bytes();
        let restored = EncryptedSeed::from_bytes(&bytes).unwrap();
        let decrypted = restored.decrypt("5555").unwrap();
        assert_eq!(decrypted.as_slice(), &seed[..]);
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = PinRateLimiter::new();
        assert!(!rl.is_locked_out(0));
        rl.record_failure(0);
        rl.record_failure(100);
        assert!(!rl.is_locked_out(200)); // < 3 fails, no lockout
        rl.record_failure(200);
        assert!(rl.is_locked_out(201)); // 3 fails, locked for 30s
        assert!(!rl.is_locked_out(30_201)); // 30s passed
        rl.record_success();
        assert_eq!(rl.failed_attempts, 0);
    }

    #[test]
    fn test_pin_validation() {
        let pe = PinEntry::default_config();
        assert!(pe.validate_pin("1234").is_ok());
        assert!(pe.validate_pin("12345678").is_ok());
        assert!(pe.validate_pin("123").is_err()); // too short
        assert!(pe.validate_pin("123456789").is_err()); // too long
        assert!(pe.validate_pin("12a4").is_err()); // non-digit
    }
}
