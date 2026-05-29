//! USB host protocol for PSBT signing.
//!
//! Implements a custom USB protocol for communication with a host computer
//! (e.g., Specter Desktop, Sparrow, Electrum). The host sends unsigned PSBTs,
//! the wallet displays them on the GameBoy screen for user verification,
//! and returns signed PSBTs after confirmation.
//!
//! Uses embassy-usb CDC serial emulation for broad compatibility.

#![allow(unused)]

/// USB protocol commands (from host to wallet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbCommand {
    /// Send an unsigned PSBT for signing.
    SendPsbt = 0x01,
    /// Request the signed PSBT result.
    GetSignedPsbt = 0x02,
    /// Request the wallet's xpub.
    GetXpub = 0x03,
    /// Request firmware version.
    GetFirmwareVersion = 0x04,
    /// Cancel current operation.
    Cancel = 0xFF,
}

/// USB protocol response codes (from wallet to host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbResponse {
    /// Acknowledge command received.
    Ack = 0x01,
    /// PSBT signed successfully, data follows.
    SignedPsbt = 0x02,
    /// Xpub data follows.
    Xpub = 0x03,
    /// Firmware version string follows.
    FirmwareVersion = 0x04,
    /// User rejected the signing request.
    Rejected = 0xE0,
    /// Error processing command.
    Error = 0xE1,
    /// Device busy (waiting for user input on GB screen).
    Busy = 0xE2,
}

/// USB protocol handler.
pub struct UsbProtocol {
    /// Whether a PSBT signing operation is in progress.
    signing_in_progress: bool,
}

impl UsbProtocol {
    /// Create a new USB protocol handler.
    pub fn new() -> Self {
        Self {
            signing_in_progress: false,
        }
    }

    /// Process an incoming USB message.
    pub fn process_message(&mut self, data: &[u8]) -> UsbResponse {
        todo!("Parse USB message and dispatch to handler")
    }

    /// Handle a SendPsbt command from the host.
    pub fn handle_send_psbt(&mut self, psbt_data: &[u8]) -> Result<(), UsbError> {
        todo!("Queue PSBT for display on GB, wait for user confirmation")
    }

    /// Handle a GetXpub command from the host.
    pub fn handle_get_xpub(&self) -> Result<[u8; 111], UsbError> {
        todo!("Return the account xpub")
    }

    /// Handle a GetFirmwareVersion command.
    pub fn handle_get_firmware_version(&self) -> [u8; 4] {
        // TODO: use build-time version constants
        [0, 0, 1, 0] // v0.0.1-alpha
    }

    /// Get the current signing state.
    pub fn is_signing(&self) -> bool {
        self.signing_in_progress
    }
}

/// USB protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbError {
    /// Invalid message format.
    InvalidMessage,
    /// PSBT parse error.
    PsbtError,
    /// Wallet is locked.
    Locked,
    /// No seed available.
    NoSeed,
    /// Timeout waiting for user input.
    Timeout,
    /// USB communication error.
    CommError,
}
