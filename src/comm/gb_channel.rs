//! GameBoy ↔ RP2350 communication protocol via SRAM.
//!
//! Implements a bidirectional message channel between the GameBoy ROM
//! (wallet UI) and the RP2350 firmware (wallet logic). Uses specific
//! SRAM addresses as command/response registers.
//!
//! ## Protocol
//!
//! The GameBoy ROM writes commands to a fixed SRAM region. The RP2350
//! MBC handler detects writes and processes them. Responses are written
//! back to a separate SRAM region that the ROM polls.
//!
//! ## Frame format
//!
//! ```text
//! [MAGIC: u8][CMD: u8][LEN: u16][PAYLOAD: N bytes][CHECKSUM: u16]
//! ```
//!
//! See PROTOCOL.md for full specification.

#![allow(unused)]

/// Magic byte for wallet protocol frames.
pub const FRAME_MAGIC: u8 = 0xB7;

/// SRAM address where the GB ROM writes commands (offset from SRAM base).
pub const CMD_REGISTER_ADDR: usize = 0x1F00;

/// SRAM address where the RP2350 writes responses.
pub const RSP_REGISTER_ADDR: usize = 0x1F40;

/// SRAM address for shared status byte.
pub const STATUS_BYTE_ADDR: usize = 0x1FF0;

/// Maximum payload size per frame.
pub const MAX_PAYLOAD_SIZE: usize = 488;

/// Wallet protocol commands (sent from GB ROM to RP2350).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Generate a new random seed.
    GenerateSeed = 0x01,
    /// Import an existing seed from mnemonic words.
    ImportSeed = 0x02,
    /// Get the account-level extended public key.
    GetXpub = 0x03,
    /// Get a receive address at the given index.
    GetAddress = 0x04,
    /// Sign a PSBT (received via USB, displayed on GB).
    SignPsbt = 0x05,
    /// Export the seed as mnemonic words.
    ExportSeed = 0x06,
    /// Wipe the seed from storage.
    Wipe = 0x07,
    /// Lock the wallet (zeroize keys).
    Lock = 0x08,
    /// Unlock the wallet with PIN.
    Unlock = 0x09,
    /// Set or change the PIN.
    SetPin = 0x0A,
}

impl Command {
    /// Parse a command from a byte value.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::GenerateSeed),
            0x02 => Some(Self::ImportSeed),
            0x03 => Some(Self::GetXpub),
            0x04 => Some(Self::GetAddress),
            0x05 => Some(Self::SignPsbt),
            0x06 => Some(Self::ExportSeed),
            0x07 => Some(Self::Wipe),
            0x08 => Some(Self::Lock),
            0x09 => Some(Self::Unlock),
            0x0A => Some(Self::SetPin),
            _ => None,
        }
    }
}

/// Wallet protocol response codes (sent from RP2350 to GB ROM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    /// Command completed successfully.
    Ok = 0x00,
    /// Generic error.
    Error = 0x01,
    /// Invalid command.
    InvalidCommand = 0x02,
    /// Wrong PIN.
    WrongPin = 0x03,
    /// Wallet is locked.
    Locked = 0x04,
    /// No seed stored.
    NoSeed = 0x05,
    /// PSBT signing rejected by user.
    Rejected = 0x06,
    /// Checksum mismatch.
    ChecksumError = 0x07,
}

/// A protocol frame for the GB↔RP2350 channel.
pub struct Frame {
    /// Command or response code.
    pub cmd: u8,
    /// Payload length.
    pub len: u16,
    /// Payload data.
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

impl Frame {
    /// Parse a frame from SRAM bytes.
    pub fn from_sram(data: &[u8]) -> Result<Self, ChannelError> {
        todo!("Parse and validate frame from SRAM region")
    }

    /// Serialize a frame to SRAM bytes.
    pub fn to_sram(&self) -> [u8; MAX_PAYLOAD_SIZE + 5] {
        todo!("Serialize frame with magic, header, payload, and checksum")
    }
}

/// GB communication channel handler.
pub struct GbChannel {
    /// Pointer to the SRAM base for the wallet region.
    sram_base: *mut u8,
}

impl GbChannel {
    /// Create a new GB channel with the given SRAM base address.
    pub fn new(sram_base: *mut u8) -> Self {
        Self { sram_base }
    }

    /// Check if a command is pending from the GB ROM.
    pub fn has_command(&self) -> bool {
        todo!("Check status byte in SRAM")
    }

    /// Read the pending command frame.
    pub fn read_command(&self) -> Result<Frame, ChannelError> {
        todo!("Read command frame from SRAM")
    }

    /// Write a response frame to SRAM.
    pub fn write_response(&self, code: ResponseCode, payload: &[u8]) -> Result<(), ChannelError> {
        todo!("Write response frame to SRAM and set status byte")
    }
}

/// Channel errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Invalid magic byte.
    InvalidMagic,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
    /// Checksum mismatch.
    ChecksumMismatch,
    /// SRAM access error.
    AccessError,
}
