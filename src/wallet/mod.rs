//! Bitcoin stealth wallet module for the RP2350 GameBoy cartridge.
//!
//! Provides BIP-39 mnemonic generation, BIP-32 HD key derivation, PSBT signing,
//! address generation, encrypted seed storage, and key management.
//! All code is `no_std` compatible for embedded execution on the RP2350B.

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod encrypt;
pub mod keys;
pub mod psbt;
pub mod storage;
