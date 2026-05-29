//! Bitcoin address generation.
//!
//! Generates receive addresses from derived public keys.
//! Supports native SegWit (bech32), SegWit-P2SH (base58), and legacy (base58).

#![allow(unused)]

use crate::wallet::bip32::Network;

/// Address type for generation and display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Native SegWit (bc1q... / tb1q...).
    NativeSegWit,
    /// SegWit wrapped in P2SH (3... / 2...).
    SegWitP2Sh,
    /// Legacy P2PKH (1... / m/n...).
    Legacy,
}

/// A generated Bitcoin address.
pub struct Address {
    /// The address string bytes.
    data: [u8; 112],
    /// Length of the address string.
    len: u8,
    /// Address type.
    addr_type: AddressType,
}

impl Address {
    /// Generate a native SegWit (bech32) address from a compressed public key.
    pub fn native_segwit(pubkey: &[u8; 33], network: Network) -> Result<Self, AddressError> {
        todo!("Implement bech32 address generation")
    }

    /// Generate a SegWit-P2SH address from a compressed public key.
    pub fn segwit_p2sh(pubkey: &[u8; 33], network: Network) -> Result<Self, AddressError> {
        todo!("Implement P2SH-SegWit address generation")
    }

    /// Generate a legacy P2PKH address from a compressed public key.
    pub fn legacy(pubkey: &[u8; 33], network: Network) -> Result<Self, AddressError> {
        todo!("Implement P2PKH address generation")
    }

    /// Get the address as a string slice.
    pub fn as_str(&self) -> &str {
        todo!("Return address string")
    }

    /// Get the address type.
    pub fn address_type(&self) -> AddressType {
        self.addr_type
    }
}

/// Address generation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Hash computation failed.
    HashError,
    /// Encoding failed (bech32/base58).
    EncodingError,
    /// Invalid public key.
    InvalidPublicKey,
}
