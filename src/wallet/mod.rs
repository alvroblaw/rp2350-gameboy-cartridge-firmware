//! Bitcoin stealth wallet module.
//!
//! Provides BIP-39, BIP-32, PSBT signing, address generation, encrypted
//! seed storage, and key management. All `no_std` compatible.

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod encrypt;
pub mod keys;
pub mod psbt;
pub mod storage;

pub use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Network};
pub use bip39::Mnemonic;
