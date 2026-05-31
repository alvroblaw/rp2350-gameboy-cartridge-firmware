//! RP2350 GameBoy Cartridge Firmware
//!
//! Library crate exposing wallet and crypto modules for host-side testing.
//! The `embedded` feature (default) includes hardware-specific modules.

#![cfg_attr(feature = "embedded", no_std)]

// Wallet modules — always available
pub mod wallet;
pub mod comm;

/// Crypto RNG — hardware on embedded, mock on host
#[cfg(feature = "embedded")]
pub mod crypto_rng;

#[cfg(not(feature = "embedded"))]
#[no_mangle]
pub extern "Rust" fn _defmt_acquire() {}

#[cfg(not(feature = "embedded"))]
#[no_mangle]
pub extern "Rust" fn _defmt_release() {}

#[cfg(not(feature = "embedded"))]
#[no_mangle]
pub extern "Rust" fn _defmt_write(_bytes: &[u8]) {}

#[cfg(not(feature = "embedded"))]
#[no_mangle]
pub extern "Rust" fn _defmt_timestamp(_fmt: defmt::Formatter<'_>) {}

#[cfg(not(feature = "embedded"))]
pub mod crypto_rng {
    //! Mock hardware RNG for host-side testing.

    /// Fill buffer with deterministic pseudo-random bytes.
    pub fn hardware_random(buf: &mut [u8]) -> Result<(), RngError> {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(42);
        }
        Ok(())
    }

    pub struct CryptoRng {
        initialized: bool,
    }

    impl CryptoRng {
        pub const fn new() -> Self {
            Self { initialized: false }
        }
        pub fn init(&mut self) -> Result<(), RngError> {
            self.initialized = true;
            Ok(())
        }
        pub fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), RngError> {
            if !self.initialized {
                return Err(RngError::NotInitialized);
            }
            hardware_random(buf)
        }
        pub fn random_16(&mut self) -> Result<[u8; 16], RngError> {
            let mut buf = [0u8; 16];
            self.fill_bytes(&mut buf)?;
            Ok(buf)
        }
        pub fn random_32(&mut self) -> Result<[u8; 32], RngError> {
            let mut buf = [0u8; 32];
            self.fill_bytes(&mut buf)?;
            Ok(buf)
        }
        pub fn is_initialized(&self) -> bool {
            self.initialized
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RngError {
        NotInitialized,
        HardwareUnavailable,
        InsufficientEntropy,
    }
}
