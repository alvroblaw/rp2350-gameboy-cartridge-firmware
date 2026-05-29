//! PSBT (Partially Signed Bitcoin Transaction) parsing and signing.
//!
//! Parses PSBT v0 and v2 formats received via USB, displays transaction
//! details for user verification on the GameBoy screen, and signs inputs
//! using derived private keys.

#![allow(unused)]

/// A parsed PSBT ready for display and signing.
pub struct ParsedPsbt {
    /// Number of inputs.
    input_count: u8,
    /// Number of outputs.
    output_count: u8,
    /// Total fee in satoshis.
    fee_sat: u64,
    /// Lock time.
    lock_time: u32,
}

/// Transaction output for display purposes.
pub struct TxOutput {
    /// Destination address (bech32 or base58).
    address: [u8; 112],
    /// Address string length.
    address_len: u8,
    /// Amount in satoshis.
    amount_sat: u64,
    /// Whether this is a change output (back to our wallet).
    is_change: bool,
}

/// Transaction input information.
pub struct TxInput {
    /// Previous transaction hash (32 bytes).
    prev_txid: [u8; 32],
    /// Previous output index.
    prev_vout: u32,
    /// Derivation path for signing.
    derivation_path: [u32; 8],
    /// Path length.
    path_len: u8,
}

impl ParsedPsbt {
    /// Parse a PSBT from raw bytes.
    ///
    /// Supports both PSBT v0 (BIP-174) and v2 (BIP-370).
    pub fn parse(data: &[u8]) -> Result<Self, PsbtError> {
        todo!("Implement PSBT parsing")
    }

    /// Get the displayable outputs for user verification.
    pub fn outputs(&self) -> &[TxOutput] {
        todo!("Extract outputs for display")
    }

    /// Get the inputs that need signing.
    pub fn inputs(&self) -> &[TxInput] {
        todo!("Extract inputs for signing")
    }

    /// Get the total output amount going to external addresses (excl. change).
    pub fn external_amount(&self) -> u64 {
        todo!("Calculate total external output amount")
    }

    /// Sign all inputs with the appropriate derived keys.
    ///
    /// Uses BIP-143 sighash for SegWit inputs.
    pub fn sign(&mut self, key_source: &dyn crate::wallet::keys::KeySource) -> Result<(), PsbtError> {
        todo!("Implement PSBT signing")
    }

    /// Serialize the signed PSBT back to bytes.
    pub fn to_bytes(&self) -> Result<PsbtBytes, PsbtError> {
        todo!("Serialize signed PSBT")
    }

    /// Get a summary string for display on GameBoy (amount, fee, address preview).
    pub fn display_summary(&self) -> PsbtSummary {
        todo!("Build display summary")
    }
}

/// Fixed-size PSBT byte buffer (PSBTs can be large).
pub struct PsbtBytes {
    pub data: [u8; 2048],
    pub len: u16,
}

/// Compact PSBT summary for GameBoy display.
pub struct PsbtSummary {
    /// Amount going to external address (satoshis).
    pub amount: u64,
    /// Fee in satoshis.
    pub fee: u64,
    /// Destination address (truncated for display).
    pub address_preview: [u8; 20],
}

/// PSBT operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtError {
    /// Invalid PSBT magic bytes.
    InvalidMagic,
    /// Unsupported PSBT version.
    UnsupportedVersion,
    /// Parse error in PSBT fields.
    ParseError,
    /// No inputs to sign.
    NoInputs,
    /// Signing failed (key derivation or secp256k1 error).
    SigningError,
    /// PSBT too large for buffer.
    TooLarge,
    /// Missing required field.
    MissingField,
    /// Serialization error.
    SerializeError,
}
