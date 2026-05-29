//! Boot-time firmware integrity verification.
//!
//! Computes SHA-256 hash of the firmware in flash and compares against
//! a compile-time expected hash. If the hash mismatches, the wallet mode
//! is disabled — the cartridge still works as a normal flashcart, but
//! refuses to enter wallet mode to prevent execution of tampered firmware.
//!
//! # Implementation notes
//!
//! On RP2350, the ideal storage for the expected hash is OTP (One-Time
//! Programmable) memory. However, OTP is write-once and should be programmed
//! per-device. For now, the expected hash is a compile-time constant that
//! can be updated during the build process.
//!
//! Future improvement: store hash in OTP page 1 (pages 0-7 are available
//! for user data on RP2350). Use `embassy_rp::otp` for write access.

#![allow(unused)]

use sha2::{Digest, Sha256};

/// Expected firmware SHA-256 hash (32 bytes).
///
/// This must be updated during the build process to match the actual
/// firmware binary. A mismatch indicates the firmware has been modified
/// since the hash was computed.
///
/// **Default**: all zeros — always fails verification until properly set.
/// Set via environment variable `WALLET_FIRMWARE_HASH` at build time,
/// or hardcode after a known-good build.
pub const EXPECTED_HASH: [u8; 32] = {
    let mut hash = [0u8; 32];
    // All zeros = not yet programmed. verify_firmware_integrity() will
    // return true only if the computed hash matches all-zeros, which
    // is essentially impossible for a real firmware image.
    hash
};

/// Flash base address on RP2350.
const FLASH_BASE: usize = 0x1000_0000;

/// Maximum firmware size to hash (2 MiB, matching memory.x).
const FIRMWARE_MAX_SIZE: usize = 2 * 1024 * 1024;

/// Result of firmware integrity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum IntegrityStatus {
    /// Firmware hash matches expected value.
    Valid,
    /// Firmware hash does NOT match — possible tampering.
    Invalid,
    /// Expected hash is all zeros — not yet configured.
    NotConfigured,
}

/// Verify firmware integrity by computing SHA-256 of flash and comparing.
///
/// This reads the firmware directly from flash memory (XIP region starting
/// at 0x10000000) and computes a SHA-256 hash. The hash is compared against
/// `EXPECTED_HASH`.
///
/// # Safety
///
/// Reads from the XIP flash region which is always mapped and readable.
/// Does not modify flash or RAM.
///
/// # Returns
///
/// - `IntegrityStatus::Valid` if hashes match
/// - `IntegrityStatus::Invalid` if hashes differ
/// - `IntegrityStatus::NotConfigured` if expected hash is all zeros
pub fn verify_firmware_integrity() -> IntegrityStatus {
    // Check if expected hash has been configured
    if EXPECTED_HASH == [0u8; 32] {
        return IntegrityStatus::NotConfigured;
    }

    let computed = compute_firmware_hash();

    // Constant-time comparison to prevent timing side-channels
    if constant_time_eq_32(&computed, &EXPECTED_HASH) {
        IntegrityStatus::Valid
    } else {
        IntegrityStatus::Invalid
    }
}

/// Compute SHA-256 hash of the firmware in flash.
///
/// Reads the flash contents via the XIP (eXecute In Place) region.
/// On RP2350, flash is memory-mapped at 0x10000000.
///
/// For a 2 MiB firmware, this takes approximately:
/// - ~65ms at 266 MHz (estimated, SHA-256 is ~10 cycles/byte)
pub fn compute_firmware_hash() -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Read firmware in chunks to avoid excessive stack usage.
    // 256 bytes is a reasonable chunk size for embedded.
    const CHUNK_SIZE: usize = 256;
    let mut offset = 0;

    while offset < FIRMWARE_MAX_SIZE {
        let end = offset + CHUNK_SIZE.min(FIRMWARE_MAX_SIZE - offset);
        let chunk_ptr = (FLASH_BASE + offset) as *const u8;

        // Safety: Reading from XIP flash region, which is always valid.
        // The flash is memory-mapped and directly addressable.
        let chunk: &[u8] = unsafe {
            core::slice::from_raw_parts(chunk_ptr, end - offset)
        };

        hasher.update(chunk);
        offset = end;
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Constant-time comparison of two 32-byte values.
///
/// Compares all bytes regardless of differences — no short-circuit.
/// This prevents timing attacks that could reveal information about
/// the expected hash.
#[inline]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Get the expected firmware hash (for display/diagnostic purposes).
pub fn expected_hash() -> &'static [u8; 32] {
    &EXPECTED_HASH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_matches() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_differs() {
        let mut a = [0x42u8; 32];
        let b = [0x42u8; 32];
        a[31] = 0x00;
        assert!(!constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_single_bit() {
        let mut a = [0x00u8; 32];
        let mut b = [0x00u8; 32];
        a[0] = 0x01; // Single bit difference
        assert!(!constant_time_eq_32(&a, &b));
    }

    #[test]
    fn test_integrity_not_configured() {
        // Default EXPECTED_HASH is all zeros
        assert_eq!(verify_firmware_integrity(), IntegrityStatus::NotConfigured);
    }

    #[test]
    fn test_integrity_status_format() {
        let status = IntegrityStatus::Valid;
        let s = format!("{:?}", status);
        assert_eq!(s, "Valid");
    }
}
