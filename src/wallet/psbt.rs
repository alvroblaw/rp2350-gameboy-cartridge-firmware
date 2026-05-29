//! PSBT (Partially Signed Bitcoin Transaction) parsing and signing.
//!
//! Handles PSBT v0 and v2 for signing transactions on the device.
//! The flow is:
//! 1. Receive unsigned PSBT from host (via USB)
//! 2. Parse and display transaction details (amount, destination, fee)
//! 3. User confirms via GameBoy buttons
//! 4. Sign each input with the derived private key
//! 5. Return signed PSBT to host
//!
//! **Phase 5 scope** — this module is a stub until PSBT signing is implemented.

#![allow(unused)]

/// A parsed PSBT transaction ready for display and signing.
pub struct ParsedPsbt {
    /// Number of inputs.
    input_count: u8,
    /// Number of outputs.
    output_count: u8,
    /// Total input amount (satoshis).
    input_amount: u64,
    /// Total output amount (satoshis).
    output_amount: u64,
    /// Fee in satoshis.
    fee: u64,
}

impl ParsedPsbt {
    /// Parse a raw PSBT from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PsbtError> {
        todo!("Phase 5: implement PSBT parsing")
    }

    /// Get the number of inputs.
    pub fn input_count(&self) -> u8 {
        self.input_count
    }

    /// Get the number of outputs.
    pub fn output_count(&self) -> u8 {
        self.output_count
    }

    /// Get the fee in satoshis.
    pub fn fee(&self) -> u64 {
        self.fee
    }

    /// Get the total amount being sent (output amount minus change).
    pub fn amount_sent(&self) -> u64 {
        self.output_amount
    }
}

/// Sign a parsed PSBT with the given key.
///
/// Returns the signed PSBT bytes, ready to send back to the host.
pub fn sign_psbt(
    psbt: &ParsedPsbt,
    _signing_key: &[u8; 32],
) -> Result<arrayvec::ArrayVec<u8, 2048>, PsbtError> {
    todo!("Phase 5: implement PSBT signing")
}

/// PSBT operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtError {
    /// PSBT magic bytes not found or invalid.
    InvalidMagic,
    /// PSBT version not supported.
    UnsupportedVersion,
    /// Invalid PSBT structure.
    InvalidStructure,
    /// Missing required field.
    MissingField,
    /// Signing failed.
    SigningError,
    /// Output buffer too small for signed PSBT.
    BufferTooSmall,
}
