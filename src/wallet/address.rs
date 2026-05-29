//! Bitcoin address generation. **Status**: Stub — Phase 3.

#![allow(unused)]

use crate::wallet::bip32::Network;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType { NativeSegWit, SegWitP2Sh, Legacy }

pub struct Address {
    data: heapless::String<112>,
    addr_type: AddressType,
}

impl Address {
    pub fn native_segwit(_pubkey: &[u8; 33], _network: Network) -> Result<Self, AddressError> {
        Err(AddressError::EncodingError)
    }
    pub fn as_str(&self) -> &str { &self.data }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError { HashError, EncodingError, InvalidPublicKey, DerivationError }
