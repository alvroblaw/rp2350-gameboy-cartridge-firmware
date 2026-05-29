//! Communication module for the stealth wallet.
//!
//! Handles bidirectional communication between the RP2350 firmware
//! and external interfaces: the GameBoy (via SRAM/MBC registers) and
//! USB host (for PSBT signing operations).

pub mod gb_channel;
pub mod usb_protocol;
