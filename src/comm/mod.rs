//! Communication module for the stealth wallet.
//!
//! Handles bidirectional communication between the RP2350 firmware
//! and external interfaces: the GameBoy (via SRAM/MBC registers) and
//! USB host (for PSBT signing operations).

pub mod gb_channel;
pub mod usb_protocol;

// Re-export the primary types from gb_channel for convenience.
#[allow(unused_imports)]
pub use gb_channel::{
    crc16_ccitt, ChannelError, Command, Frame, GbChannel, ResponseCode,
    CMD_REGION_ADDR, EXT_PAYLOAD_ADDR, FRAME_MAGIC, MAX_PAYLOAD_SIZE,
    RSP_REGION_ADDR, STATUS_BYTE_ADDR,
};
