//! Bitcoin stealth wallet module for the RP2350 GameBoy cartridge.
//!
//! Provides BIP-39 mnemonic generation, BIP-32 HD key derivation, PSBT signing,
//! address generation, encrypted seed storage, and key management.
//! All code is `no_std` compatible for embedded execution on the RP2350B.
//!
//! # Module structure
//!
//! - `bip39` — Mnemonic generation, parsing, and seed derivation
//! - `bip32` — HD key derivation (master key, child keys, paths)
//! - `keys`  — KeySource trait and StoredKey implementation
//! - `address` — Bitcoin address generation (SegWit, P2SH, legacy)
//! - `psbt`  — PSBT parsing and signing (Phase 5)
//! - `encrypt` — Seed encryption with PBKDF2 + AES-256-GCM
//! - `storage` — Encrypted seed persistence on SD card

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod encrypt;
pub mod keys;
pub mod psbt;
pub mod storage;

// Re-export key types for convenience
pub use address::{Address, AddressType};
pub use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Network};
pub use bip39::{Mnemonic, WordCount};
pub use encrypt::{EncryptedSeed, PinEntry, PinRateLimiter, ZeroizingVec};
pub use keys::{KeySource, StoredKey, KeyError};
pub use storage::SeedStorage;
