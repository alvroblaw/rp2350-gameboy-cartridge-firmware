//! Bitcoin address generation.
//!
//! Generates receive addresses from derived public keys.
//! Supports native SegWit (bech32), SegWit-P2SH, and legacy P2PKH.
//!
//! **Status**: Stub — full implementation in Phase 3.

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

/// Maximum address string length.
const MAX_ADDR_LEN: usize = 112;

/// A generated Bitcoin address.
#[derive(Clone)]
pub struct Address {
    /// The address string.
    data: heapless::String<MAX_ADDR_LEN>,
    /// Address type.
    addr_type: AddressType,
}

impl Address {
    /// Generate a native SegWit (bech32) address from a compressed public key.
    ///
    /// BIP-84: HASH160(pubkey) → witness program version 0 → bech32 encode.
    pub fn native_segwit(_pubkey: &[u8; 33], _network: Network) -> Result<Self, AddressError> {
        // TODO: Phase 3 — implement bech32 encoding
        Err(AddressError::EncodingError)
    }

    /// Generate a SegWit-P2SH address from a compressed public key.
    pub fn segwit_p2sh(_pubkey: &[u8; 33], _network: Network) -> Result<Self, AddressError> {
        // TODO: Phase 3
        Err(AddressError::EncodingError)
    }

    /// Generate a legacy P2PKH address from a compressed public key.
    pub fn legacy(_pubkey: &[u8; 33], _network: Network) -> Result<Self, AddressError> {
        // TODO: Phase 3
        Err(AddressError::EncodingError)
    }

    /// Get the address as a string slice.
    pub fn as_str(&self) -> &str {
        &self.data
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
    /// Bech32 or base58 encoding failed.
    EncodingError,
    /// Invalid public key.
    InvalidPublicKey,
    /// Key derivation failed.
    DerivationError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_segwit_stub_returns_encoding_error() {
        let pubkey = [0x02u8; 33];
        let result = Address::native_segwit(&pubkey, Network::Mainnet);
        assert!(matches!(result, Err(AddressError::EncodingError)));
    }

    #[test]
    fn segwit_p2sh_stub_returns_encoding_error() {
        let pubkey = [0x03u8; 33];
        let result = Address::segwit_p2sh(&pubkey, Network::Testnet);
        assert!(matches!(result, Err(AddressError::EncodingError)));
    }

    #[test]
    fn legacy_stub_returns_encoding_error() {
        let pubkey = [0x02u8; 33];
        let result = Address::legacy(&pubkey, Network::Mainnet);
        assert!(matches!(result, Err(AddressError::EncodingError)));
    }
}
