//! Communication module for the stealth wallet.
//!
//! Handles bidirectional communication between the RP2350 firmware
//! and external interfaces: the GameBoy (via SRAM/MBC registers) and
//! USB host (for PSBT signing operations).

pub mod gb_channel;
pub mod usb_protocol;

// Re-export the primary types from gb_channel for convenience.
pub use gb_channel::{
    ChannelError, Command, Frame, GbChannel, ResponseCode,
    MAX_PAYLOAD_SIZE, CMD_REGION_ADDR, RSP_REGION_ADDR, STATUS_BYTE_ADDR,
    EXT_PAYLOAD_ADDR, FRAME_MAGIC,
    crc16_ccitt,
};
