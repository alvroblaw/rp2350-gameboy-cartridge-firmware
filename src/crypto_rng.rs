//! Hardware entropy source for cryptographic operations.
//!
//! Combines multiple entropy sources on the RP2350 for true random number
//! generation:
//!
//! 1. **Ring Oscillator (ROSC)**: Phase noise from the ring oscillator
//! 2. **ADC noise**: Least significant bits of ADC readings with floating input
//! 3. **Boot entropy**: Random state captured early in boot
//!
//! Output is whitened using SHA-256 to produce uniform random bytes.

#![allow(unused)]

/// Hardware random number generator.
pub struct CryptoRng {
    /// Entropy pool buffer.
    pool: [u8; 64],
    /// Whether the pool has been initialized.
    initialized: bool,
}

impl CryptoRng {
    /// Create a new hardware RNG instance.
    pub fn new() -> Self {
        Self {
            pool: [0u8; 64],
            initialized: false,
        }
    }

    /// Initialize the entropy pool from hardware sources.
    ///
    /// Reads from ROSC and ADC noise, mixes with SHA-256.
    pub async fn init(&mut self) -> Result<(), RngError> {
        todo!("Initialize entropy from ROSC + ADC noise")
    }

    /// Fill a buffer with random bytes.
    ///
    /// Consumes entropy from the pool and refills as needed.
    /// Each call to fill() re-mixes the pool with fresh hardware entropy.
    pub async fn fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), RngError> {
        todo!("Fill buffer with random bytes from entropy pool")
    }

    /// Generate a 32-byte random value (for BIP-39 entropy).
    pub async fn random_32_bytes(&mut self) -> Result<[u8; 32], RngError> {
        let mut buf = [0u8; 32];
        self.fill_bytes(&mut buf).await?;
        Ok(buf)
    }

    /// Generate a 16-byte random value (for 12-word mnemonic).
    pub async fn random_16_bytes(&mut self) -> Result<[u8; 16], RngError> {
        let mut buf = [0u8; 16];
        self.fill_bytes(&mut buf).await?;
        Ok(buf)
    }

    /// Re-seed the entropy pool from hardware.
    async fn reseed(&mut self) -> Result<(), RngError> {
        todo!("Read fresh hardware entropy and mix into pool")
    }
}

/// Read raw entropy bits from the ROSC.
///
/// The RP2350 ring oscillator has phase jitter that provides
/// true random bits. We sample the ROSC counter at irregular
/// intervals and extract the LSB.
fn read_rosc_entropy(buf: &mut [u8]) -> Result<(), RngError> {
    todo!("Read ROSC phase noise")
}

/// Read entropy from ADC noise.
///
/// Configure an ADC channel with a floating input and read
/// the least significant bits, which contain thermal noise.
fn read_adc_entropy(buf: &mut [u8]) -> Result<(), RngError> {
    todo!("Read ADC thermal noise LSBs")
}

/// Whiten entropy using SHA-256.
///
/// Takes raw entropy bytes and hashes them to produce
/// uniformly distributed random bytes.
fn whiten(entropy: &[u8]) -> [u8; 32] {
    todo!("SHA-256 hash of entropy input")
}

/// RNG errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// Hardware entropy source not available.
    HardwareUnavailable,
    /// Insufficient entropy collected.
    InsufficientEntropy,
    /// Hash computation failed.
    HashError,
}
