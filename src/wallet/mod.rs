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
//! - `secure_memory` — Secure wrappers that zeroize on Drop

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod encrypt;
pub mod keys;
pub mod psbt;
pub mod secure_memory;
pub mod state;
#[cfg(feature = "embedded")]
pub mod storage;

// Re-export key types for convenience
#[allow(unused_imports)]
pub use address::{Address, AddressType};
#[allow(unused_imports)]
pub use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Network};
#[allow(unused_imports)]
pub use bip39::{Mnemonic, WordCount};
#[allow(unused_imports)]
pub use encrypt::{EncryptedSeed, PinEntry, PinRateLimiter, ZeroizingVec};
#[allow(unused_imports)]
pub use keys::{KeyError, KeySource, StoredKey};
#[allow(unused_imports)]
pub use secure_memory::{secure_scrub_stack, SecureArray, SecureBox, SecureSlice};
#[allow(unused_imports)]
pub use state::{WalletError, WalletState, WalletStatus};
#[cfg(feature = "embedded")]
#[allow(unused_imports)]
pub use storage::SeedStorage;
