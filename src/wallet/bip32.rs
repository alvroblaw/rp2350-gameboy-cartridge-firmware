//! BIP-32 Hierarchical Deterministic key derivation.
//!
//! **Status**: Stub — full implementation in Phase 3.

#![allow(unused)]

/// Hardened key derivation start index.
pub const HARDENED: u32 = 0x8000_0000;

/// Bitcoin network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Extended private key (BIP-32).
pub struct ExtendedPrivateKey {
    pub secret_bytes: [u8; 32],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_index: u32,
    pub network: Network,
}

impl ExtendedPrivateKey {
    pub fn new_master(_seed: &[u8], _network: Network) -> Result<Self, Bip32Error> {
        Err(Bip32Error::InvalidSeed)
    }
    pub fn derive_child(&self, _index: u32) -> Result<Self, Bip32Error> {
        Err(Bip32Error::InvalidPrivateKey)
    }
    pub fn derive_path(&self, _path: &str) -> Result<Self, Bip32Error> {
        Err(Bip32Error::InvalidPrivateKey)
    }
    pub fn public_key_bytes(&self) -> [u8; 33] { [0u8; 33] }
    pub fn to_xpub(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            public_key_bytes: self.public_key_bytes(),
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
            network: self.network,
        }
    }
}

/// Extended public key (BIP-32).
pub struct ExtendedPublicKey {
    pub public_key_bytes: [u8; 33],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_index: u32,
    pub network: Network,
}

/// BIP-32 errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip32Error {
    InvalidSeedLength,
    InvalidSeed,
    InvalidPrivateKey,
    HmacError,
    InvalidPath,
    InvalidChildIndex,
}
