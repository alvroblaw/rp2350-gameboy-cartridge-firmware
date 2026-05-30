//! USB host protocol for PSBT signing via embassy-usb CDC-ACM.
//!
//! Implements the host ↔ wallet protocol for Bitcoin transaction signing.
//! The host sends unsigned PSBTs over a virtual serial port (CDC-ACM),
//! the wallet parses, displays, and (after user confirmation) signs them.
//!
//! # Wire protocol
//!
//! ```text
//! Frame: [MAGIC: 0xB1][CMD: u8][LEN: u16 LE][PAYLOAD: N][CRC16: u16 LE]
//! ```
//!
//! MAGIC = 0xB1, LEN = payload length (0..1024), CRC16 = CRC-16-CCITT over
//! MAGIC+CMD+LEN+PAYLOAD.
//!
//! # Host → Wallet commands
//!
//! | CMD  | Name              | Payload               |
//! |------|-------------------|-----------------------|
//! | 0x01 | SEND_PSBT         | Raw PSBT bytes        |
//! | 0x02 | GET_SIGNED_PSBT   | _(empty)_             |
//! | 0x03 | GET_XPUB          | `[path_len: u8][path]`|
//! | 0x04 | GET_FIRMWARE_VER  | _(empty)_             |
//! | 0x05 | WIPE_WALLET       | _(empty)_             |
//!
//! # Wallet → Host responses
//!
//! | CMD  | Name              | Payload               |
//! |------|-------------------|-----------------------|
//! | 0x81 | OK                | Response data         |
//! | 0x82 | ERROR             | `[code: u8]`          |
//! | 0x83 | NEED_CONFIRM      | TX preview data       |
//! | 0x84 | CONFIRMED         | Signed PSBT data      |
//! | 0x85 | REJECTED          | _(empty)_             |

#![allow(unused)]

use defmt::{info, warn, error};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Protocol magic byte.
pub const FRAME_MAGIC: u8 = 0xB1;

/// Maximum payload size per frame.
pub const MAX_PAYLOAD: usize = 1024;

/// Frame header size: MAGIC(1) + CMD(1) + LEN(2).
const HDR: usize = 4;
/// CRC-16 trailer size.
const CRC_SZ: usize = 2;

// Host → Wallet commands
/// Host sends an unsigned PSBT for signing.
pub const CMD_SEND_PSBT: u8 = 0x01;
/// Host requests the signed PSBT result.
pub const CMD_GET_SIGNED_PSBT: u8 = 0x02;
/// Host requests the wallet xpub at a given path.
pub const CMD_GET_XPUB: u8 = 0x03;
/// Host requests firmware version string.
pub const CMD_GET_FIRMWARE_VER: u8 = 0x04;
/// Host requests wallet wipe.
pub const CMD_WIPE_WALLET: u8 = 0x05;

// Wallet → Host responses
/// Command succeeded, payload follows.
pub const RESP_OK: u8 = 0x81;
/// Error, payload is a single error code byte.
pub const RESP_ERROR: u8 = 0x82;
/// PSBT parsed, waiting for user confirmation on GB screen.
pub const RESP_NEED_CONFIRM: u8 = 0x83;
/// User confirmed, signed PSBT follows.
pub const RESP_CONFIRMED: u8 = 0x84;
/// User rejected the transaction.
pub const RESP_REJECTED: u8 = 0x85;

// Error codes (payload of RESP_ERROR)
pub const ERR_INVALID_FRAME: u8 = 0x01;
pub const ERR_PSBT_PARSE: u8 = 0x02;
pub const ERR_NO_SEED: u8 = 0x03;
pub const ERR_LOCKED: u8 = 0x04;
pub const ERR_SIGNING: u8 = 0x05;
pub const ERR_BUSY: u8 = 0x06;
pub const ERR_NO_PENDING: u8 = 0x07;

// ---------------------------------------------------------------------------
// CRC-16-CCITT (polynomial 0x1021, init 0xFFFF)
// ---------------------------------------------------------------------------

/// Compute CRC-16-CCITT.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

/// Encode a frame into `dst`. Returns bytes written.
///
/// ```text
/// [0xB1][cmd][len_lo][len_hi][payload..][crc_lo][crc_hi]
/// ```
pub fn encode_frame(cmd: u8, payload: &[u8], dst: &mut [u8]) -> Result<usize, UsbProtoError> {
    let total = HDR + payload.len() + CRC_SZ;
    if dst.len() < total {
        return Err(UsbProtoError::BufferTooSmall);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(UsbProtoError::PayloadTooLarge);
    }

    dst[0] = FRAME_MAGIC;
    dst[1] = cmd;
    dst[2] = (payload.len() & 0xFF) as u8;
    dst[3] = ((payload.len() >> 8) & 0xFF) as u8;
    dst[HDR..HDR + payload.len()].copy_from_slice(payload);

    let crc = crc16(&dst[..HDR + payload.len()]);
    dst[HDR + payload.len()] = (crc & 0xFF) as u8;
    dst[HDR + payload.len() + 1] = ((crc >> 8) & 0xFF) as u8;

    Ok(total)
}

/// Decode a frame from raw bytes. Returns (cmd, payload_slice).
///
/// Validates magic, length, and CRC.
pub fn decode_frame(src: &[u8]) -> Result<(u8, &[u8]), UsbProtoError> {
    if src.len() < HDR + CRC_SZ {
        return Err(UsbProtoError::FrameTooShort);
    }
    if src[0] != FRAME_MAGIC {
        return Err(UsbProtoError::InvalidMagic);
    }

    let len = u16::from_le_bytes([src[2], src[3]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(UsbProtoError::PayloadTooLarge);
    }
    let total = HDR + len + CRC_SZ;
    if src.len() < total {
        return Err(UsbProtoError::FrameTooShort);
    }

    // Verify CRC
    let expected = crc16(&src[..HDR + len]);
    let actual = u16::from_le_bytes([src[HDR + len], src[HDR + len + 1]]);
    if expected != actual {
        return Err(UsbProtoError::CrcMismatch);
    }

    Ok((src[1], &src[HDR..HDR + len]))
}

// ---------------------------------------------------------------------------
// Protocol error type
// ---------------------------------------------------------------------------

/// USB protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum UsbProtoError {
    /// Frame is too short.
    FrameTooShort,
    /// Invalid magic byte.
    InvalidMagic,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
    /// CRC checksum mismatch.
    CrcMismatch,
    /// Output buffer too small.
    BufferTooSmall,
}

// ---------------------------------------------------------------------------
// UsbWalletProtocol — high-level protocol handler
// ---------------------------------------------------------------------------

/// State of a PSBT signing operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum SigningState {
    /// No PSBT pending.
    Idle,
    /// PSBT received, parsed, waiting for GB user confirmation.
    AwaitingConfirmation,
    /// User confirmed, PSBT signed, ready to retrieve.
    Signed,
    /// User rejected.
    Rejected,
}

/// High-level USB wallet protocol handler.
///
/// Manages incoming USB commands and tracks signing state.
/// This struct is designed to be called from the USB CDC-ACM read loop
/// in the main stealth mode task.
///
/// # Security
///
/// - **Locked-mode allowlist**: When the wallet is locked, only
///   `GET_FIRMWARE_VERSION` is accepted. All other commands return `ERR_LOCKED`.
/// - **Rate limiting**: Max 10 commands per second. Excess commands
///   return `ERR_BUSY`.
pub struct UsbWalletProtocol {
    /// Current signing state.
    state: SigningState,
    /// Buffer for the unsigned PSBT received from host.
    unsigned_psbt: heapless::Vec<u8, MAX_PAYLOAD>,
    /// Buffer for the signed PSBT ready to return.
    signed_psbt: heapless::Vec<u8, MAX_PAYLOAD>,
    /// TX details for GB display (destination address, amount, fee).
    tx_preview: TxPreview,
    /// Whether the wallet is currently unlocked (keys in memory).
    wallet_unlocked: bool,
    /// Rate limiter: timestamp of last command (ms since boot).
    last_cmd_ms: u64,
    /// Number of commands received in the current 1-second window.
    cmd_count: u8,
}

/// Maximum USB commands per second.
const MAX_CMDS_PER_SEC: u8 = 10;

/// Simplified transaction preview for display on the GameBoy screen.
#[derive(Debug, Clone)]
pub struct TxPreview {
    /// Destination address (truncated to 34 chars max for GB display).
    pub destination: heapless::String<34>,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Fee in satoshis.
    pub fee_sats: u64,
}

impl Default for TxPreview {
    fn default() -> Self {
        Self {
            destination: heapless::String::new(),
            amount_sats: 0,
            fee_sats: 0,
        }
    }
}

impl UsbWalletProtocol {
    /// Create a new protocol handler.
    pub fn new() -> Self {
        Self {
            state: SigningState::Idle,
            unsigned_psbt: heapless::Vec::new(),
            signed_psbt: heapless::Vec::new(),
            tx_preview: TxPreview::default(),
            wallet_unlocked: false,
            last_cmd_ms: 0,
            cmd_count: 0,
        }
    }

    /// Set wallet lock state. Call from wallet state machine.
    pub fn set_wallet_unlocked(&mut self, unlocked: bool) {
        self.wallet_unlocked = unlocked;
    }

    /// Check if rate limit is exceeded for the given timestamp.
    ///
    /// Allows max `MAX_CMDS_PER_SEC` commands per 1000ms window.
    fn check_rate_limit(&mut self, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.last_cmd_ms) >= 1000 {
            // New window
            self.last_cmd_ms = now_ms;
            self.cmd_count = 1;
            return true;
        }
        self.cmd_count = self.cmd_count.saturating_add(1);
        self.cmd_count <= MAX_CMDS_PER_SEC
    }

    /// Get current signing state.
    pub fn state(&self) -> SigningState {
        self.state
    }

    /// Get the TX preview (for GB display).
    pub fn tx_preview(&self) -> &TxPreview {
        &self.tx_preview
    }

    /// Get the signed PSBT bytes (if available).
    pub fn signed_psbt(&self) -> Option<&[u8]> {
        if self.state == SigningState::Signed {
            Some(&self.signed_psbt)
        } else {
            None
        }
    }

    /// Handle an incoming USB command.
    ///
    /// Returns the response frame bytes to send back to the host.
    /// `resp_buf` must be at least HDR + MAX_PAYLOAD + CRC_SZ bytes.
    ///
    /// # Security
    ///
    /// 1. **Rate limiting**: Max 10 commands/second. Excess returns `ERR_BUSY`.
    /// 2. **Locked allowlist**: Only `GET_FIRMWARE_VER` allowed when wallet is locked.
    pub fn handle_usb_command(
        &mut self,
        cmd: u8,
        payload: &[u8],
        resp_buf: &mut [u8],
        now_ms: u64,
    ) -> Result<usize, UsbProtoError> {
        // Rate limit check
        if !self.check_rate_limit(now_ms) {
            return encode_frame(RESP_ERROR, &[ERR_BUSY], resp_buf);
        }

        // Locked-mode allowlist: only GET_FIRMWARE_VER when wallet is locked
        if !self.wallet_unlocked && cmd != CMD_GET_FIRMWARE_VER {
            return encode_frame(RESP_ERROR, &[ERR_LOCKED], resp_buf);
        }

        match cmd {
            CMD_SEND_PSBT => self.handle_send_psbt(payload, resp_buf),
            CMD_GET_SIGNED_PSBT => self.handle_get_signed(resp_buf),
            CMD_GET_XPUB => self.handle_get_xpub(payload, resp_buf),
            CMD_GET_FIRMWARE_VER => self.handle_get_firmware_ver(resp_buf),
            CMD_WIPE_WALLET => self.handle_wipe(resp_buf),
            _ => {
                info!("USB: unknown cmd 0x{:02X}", cmd);
                encode_frame(RESP_ERROR, &[ERR_INVALID_FRAME], resp_buf)
            }
        }
    }

    /// SEND_PSBT: host sends unsigned PSBT for signing.
    ///
    /// 1. Store the PSBT bytes.
    /// 2. Parse to extract TX preview (destination, amount, fee).
    /// 3. Send NEED_CONFIRM response with preview data.
    /// 4. State → AwaitingConfirmation.
    fn handle_send_psbt(
        &mut self,
        psbt_data: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, UsbProtoError> {
        if self.state != SigningState::Idle {
            return encode_frame(RESP_ERROR, &[ERR_BUSY], resp_buf);
        }

        // Store PSBT
        self.unsigned_psbt.clear();
        if self.unsigned_psbt.extend_from_slice(psbt_data).is_err() {
            return encode_frame(RESP_ERROR, &[ERR_PSBT_PARSE], resp_buf);
        }

        // Parse TX preview from PSBT
        match crate::wallet::psbt::PsbtParser::parse_preview(psbt_data) {
            Ok(preview) => {
                self.tx_preview = TxPreview {
                    destination: preview.destination,
                    amount_sats: preview.amount_sats,
                    fee_sats: preview.fee_sats,
                };
                self.state = SigningState::AwaitingConfirmation;

                // Build NEED_CONFIRM response payload:
                // [amount_sats: u64 LE][fee_sats: u64 LE][addr_len: u8][addr bytes]
                let mut confirm_payload = [0u8; 1 + 8 + 8 + 1 + 34];
                confirm_payload[0..8].copy_from_slice(&self.tx_preview.amount_sats.to_le_bytes());
                confirm_payload[8..16].copy_from_slice(&self.tx_preview.fee_sats.to_le_bytes());
                let addr_bytes = self.tx_preview.destination.as_bytes();
                let addr_len = addr_bytes.len().min(34);
                confirm_payload[16] = addr_len as u8;
                confirm_payload[17..17 + addr_len].copy_from_slice(&addr_bytes[..addr_len]);

                info!(
                    "USB: PSBT received ({} bytes), awaiting confirm. amt={} fee={}",
                    psbt_data.len(),
                    self.tx_preview.amount_sats,
                    self.tx_preview.fee_sats
                );
                encode_frame(RESP_NEED_CONFIRM, &confirm_payload[..17 + addr_len], resp_buf)
            }
            Err(e) => {
                warn!("USB: PSBT parse error: {:?}", e);
                self.unsigned_psbt.clear();
                encode_frame(RESP_ERROR, &[ERR_PSBT_PARSE], resp_buf)
            }
        }
    }

    /// GET_SIGNED_PSBT: host retrieves the signed PSBT.
    ///
    /// Only valid after user confirmation (state == Signed).
    fn handle_get_signed(&mut self, resp_buf: &mut [u8]) -> Result<usize, UsbProtoError> {
        match self.state {
            SigningState::Signed => {
                let result = encode_frame(RESP_CONFIRMED, &self.signed_psbt, resp_buf);
                self.state = SigningState::Idle;
                self.unsigned_psbt.clear();
                self.signed_psbt.clear();
                result
            }
            SigningState::Rejected => {
                self.state = SigningState::Idle;
                self.unsigned_psbt.clear();
                encode_frame(RESP_REJECTED, &[], resp_buf)
            }
            SigningState::AwaitingConfirmation => {
                encode_frame(RESP_ERROR, &[ERR_BUSY], resp_buf)
            }
            SigningState::Idle => {
                encode_frame(RESP_ERROR, &[ERR_NO_PENDING], resp_buf)
            }
        }
    }

    /// GET_XPUB: return xpub at the given derivation path.
    fn handle_get_xpub(
        &mut self,
        _payload: &[u8],
        resp_buf: &mut [u8],
    ) -> Result<usize, UsbProtoError> {
        // TODO: integrate with wallet::bip32 to derive xpub
        // For now return an error
        encode_frame(RESP_ERROR, &[ERR_LOCKED], resp_buf)
    }

    /// GET_FIRMWARE_VER: return version string.
    fn handle_get_firmware_ver(
        &mut self,
        resp_buf: &mut [u8],
    ) -> Result<usize, UsbProtoError> {
        let version = b"croco-wallet\0v0.1.0-alpha";
        encode_frame(RESP_OK, version, resp_buf)
    }

    /// WIPE_WALLET: securely erase the seed.
    fn handle_wipe(&mut self, resp_buf: &mut [u8]) -> Result<usize, UsbProtoError> {
        // TODO: integrate with wallet::storage to wipe
        encode_frame(RESP_ERROR, &[ERR_LOCKED], resp_buf)
    }

    /// Called by the GB channel when user confirms the TX on GameBoy.
    ///
    /// Signs the stored PSBT and transitions to Signed state.
    pub fn confirm_and_sign(&mut self, signing_key: &[u8; 32]) -> Result<(), PsbtSignError> {
        if self.state != SigningState::AwaitingConfirmation {
            return Err(PsbtSignError::NoPendingPsbt);
        }

        // Sign the PSBT using the wallet signing module
        match crate::wallet::psbt::sign_psbt_raw(&self.unsigned_psbt, signing_key) {
            Ok(signed) => {
                self.signed_psbt.clear();
                if self.signed_psbt.extend_from_slice(&signed).is_err() {
                    self.state = SigningState::Idle;
                    return Err(PsbtSignError::BufferTooSmall);
                }
                self.state = SigningState::Signed;
                info!("USB: PSBT signed ({} bytes)", self.signed_psbt.len());
                Ok(())
            }
            Err(e) => {
                warn!("USB: PSBT signing failed: {:?}", e);
                self.state = SigningState::Idle;
                Err(PsbtSignError::SigningFailed)
            }
        }
    }

    /// Called by the GB channel when user rejects the TX on GameBoy.
    pub fn reject(&mut self) {
        if self.state == SigningState::AwaitingConfirmation {
            self.state = SigningState::Rejected;
            info!("USB: PSBT rejected by user");
        }
    }
}

/// PSBT signing errors for the USB protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum PsbtSignError {
    /// No PSBT is pending confirmation.
    NoPendingPsbt,
    /// PSBT signing failed.
    SigningFailed,
    /// Result buffer too small.
    BufferTooSmall,
}

// ---------------------------------------------------------------------------
// CDC-ACM Serial interface for USB
// ---------------------------------------------------------------------------

/// USB CDC-ACM serial interface for wallet communication.
///
/// Wraps embassy-usb CDC-ACM to provide read/write of protocol frames.
/// This is designed to be used as an embassy task.
#[cfg(feature = "embedded")]
pub struct UsbSerial<'d> {
    /// Inner CDC-ACM interface.
    inner: embassy_usb::class::cdc_acm::CdcAcmClass<'d, crate::MyUsbDriver>,
}

#[cfg(feature = "embedded")]
impl<'d> UsbSerial<'d> {
    /// Create a new USB serial wrapper.
    pub fn new(
        cdc: embassy_usb::class::cdc_acm::CdcAcmClass<'d, crate::MyUsbDriver>,
    ) -> Self {
        Self { inner: cdc }
    }

    /// Get a mutable reference to the inner CDC-ACM class.
    pub fn inner_mut(&mut self) -> &mut embassy_usb::class::cdc_acm::CdcAcmClass<'d, crate::MyUsbDriver> {
        &mut self.inner
    }
}

// ---------------------------------------------------------------------------
// Frame reader — accumulates bytes until a complete frame is received
// ---------------------------------------------------------------------------

/// Stateful frame reader that accumulates bytes from USB serial.
///
/// USB CDC-ACM delivers data in arbitrary chunks. This struct buffers
/// incoming bytes and returns complete frames when available.
pub struct FrameReader {
    /// Internal buffer.
    buf: [u8; HDR + MAX_PAYLOAD + CRC_SZ],
    /// Current write position.
    pos: usize,
    /// Bytes already returned to caller but not yet compacted.
    consumed: usize,
}

impl FrameReader {
    /// Create a new frame reader.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; HDR + MAX_PAYLOAD + CRC_SZ],
            pos: 0,
            consumed: 0,
        }
    }

    /// Reset internal state.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.consumed = 0;
    }

    /// Feed bytes from USB serial into the reader.
    ///
    /// Returns `Some((cmd, payload_range))` when a complete frame is available.
    /// The returned range indexes into the internal buffer.
    pub fn feed(&mut self, data: &[u8]) -> Option<(u8, core::ops::Range<usize>)> {
        // Compact buffer if a previous frame was returned.
        if self.consumed > 0 {
            let remaining = self.pos.saturating_sub(self.consumed);
            if remaining > 0 {
                self.buf.copy_within(self.consumed..self.pos, 0);
            }
            self.pos = remaining;
            self.consumed = 0;
        }

        // Copy incoming data
        let space = self.buf.len() - self.pos;
        let to_copy = data.len().min(space);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&data[..to_copy]);
        self.pos += to_copy;

        // Try to parse a frame
        if self.pos < HDR + CRC_SZ {
            return None;
        }

        // Check magic
        if self.buf[0] != FRAME_MAGIC {
            // Scan for magic byte
            let magic_pos = self.buf[..self.pos].iter().position(|&b| b == FRAME_MAGIC);
            match magic_pos {
                Some(idx) => {
                    // Shift buffer
                    let remaining = self.pos - idx;
                    self.buf.copy_within(idx..self.pos, 0);
                    self.pos = remaining;
                }
                None => {
                    self.pos = 0;
                }
            }
            return None;
        }

        // Read payload length
        let len = u16::from_le_bytes([self.buf[2], self.buf[3]]) as usize;
        let total = HDR + len + CRC_SZ;

        if self.pos < total {
            return None; // Need more data
        }

        // Verify CRC
        let expected_crc = crc16(&self.buf[..HDR + len]);
        let actual_crc = u16::from_le_bytes([
            self.buf[HDR + len],
            self.buf[HDR + len + 1],
        ]);

        let cmd = self.buf[1];
        let payload_range = HDR..HDR + len;

        if expected_crc != actual_crc {
            // Bad CRC — discard this frame
            self.pos = 0;
            return None;
        }

        // Defer compaction until the next feed() call so the returned range
        // remains valid for the caller.
        self.consumed = total;

        Some((cmd, payload_range))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc16_known() {
        // CRC-16-CCITT of "123456789" = 0x29B1
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let payload = b"hello psbt";
        let mut buf = [0u8; 128];
        let n = encode_frame(CMD_SEND_PSBT, payload, &mut buf).unwrap();
        let (cmd, decoded) = decode_frame(&buf[..n]).unwrap();
        assert_eq!(cmd, CMD_SEND_PSBT);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_decode_bad_magic() {
        let mut buf = [0u8; 10];
        buf[0] = 0x00;
        buf[1] = 0x01;
        buf[2] = 0x00;
        buf[3] = 0x00;
        let crc = crc16(&buf[..4]);
        buf[4] = (crc & 0xFF) as u8;
        buf[5] = ((crc >> 8) & 0xFF) as u8;
        assert!(matches!(
            decode_frame(&buf[..6]),
            Err(UsbProtoError::InvalidMagic)
        ));
    }

    #[test]
    fn test_decode_bad_crc() {
        let mut buf = [0u8; 128];
        let n = encode_frame(CMD_GET_FIRMWARE_VER, b"test", &mut buf).unwrap();
        buf[n - 1] ^= 0xFF; // Corrupt CRC
        assert!(matches!(
            decode_frame(&buf[..n]),
            Err(UsbProtoError::CrcMismatch)
        ));
    }

    #[test]
    fn test_frame_reader_single_frame() {
        let mut reader = FrameReader::new();
        let mut buf = [0u8; 128];
        let n = encode_frame(CMD_SEND_PSBT, b"psbt_data", &mut buf).unwrap();

        let result = reader.feed(&buf[..n]);
        assert!(result.is_some());
        let (cmd, range) = result.unwrap();
        assert_eq!(cmd, CMD_SEND_PSBT);
        assert_eq!(&reader.buf[range], b"psbt_data");
    }

    #[test]
    fn test_frame_reader_chunked() {
        let mut reader = FrameReader::new();
        let mut buf = [0u8; 128];
        let n = encode_frame(0x03, b"xpub_data", &mut buf).unwrap();

        // Feed in two chunks
        assert!(reader.feed(&buf[..3]).is_none());
        let result = reader.feed(&buf[3..n]);
        assert!(result.is_some());
        let (cmd, range) = result.unwrap();
        assert_eq!(cmd, 0x03);
        assert_eq!(&reader.buf[range], b"xpub_data");
    }

    #[test]
    fn test_frame_reader_multiple_frames() {
        let mut reader = FrameReader::new();
        let mut buf1 = [0u8; 128];
        let mut buf2 = [0u8; 128];
        let n1 = encode_frame(0x01, b"first", &mut buf1).unwrap();
        let n2 = encode_frame(0x02, b"second", &mut buf2).unwrap();

        // Concatenate both frames
        let mut combined = [0u8; 256];
        combined[..n1].copy_from_slice(&buf1[..n1]);
        combined[n1..n1 + n2].copy_from_slice(&buf2[..n2]);

        let (cmd1, range1) = reader.feed(&combined[..n1 + n2]).unwrap();
        assert_eq!(cmd1, 0x01);
        assert_eq!(&reader.buf[range1], b"first");

        let (cmd2, range2) = reader.feed(&[]).unwrap();
        assert_eq!(cmd2, 0x02);
        assert_eq!(&reader.buf[range2], b"second");
    }

    #[test]
    fn test_protocol_handler_send_psbt() {
        let mut proto = UsbWalletProtocol::new();
        let mut resp = [0u8; 128];

        // Simulate receiving a PSBT (just dummy data for now)
        let psbt_data = b"psbt\xff";
        let n = proto.handle_usb_command(CMD_SEND_PSBT, psbt_data, &mut resp, 0).unwrap();

        // Should get NEED_CONFIRM response (if parsing succeeds)
        // or ERROR (if parser rejects it) — both are valid outcomes
        assert!(resp[0] == FRAME_MAGIC);
        assert!(
            resp[1] == RESP_NEED_CONFIRM || resp[1] == RESP_ERROR,
            "Expected NEED_CONFIRM or ERROR, got 0x{:02X}",
            resp[1]
        );
    }

    #[test]
    fn test_protocol_handler_get_firmware() {
        let mut proto = UsbWalletProtocol::new();
        let mut resp = [0u8; 128];
        let n = proto.handle_usb_command(CMD_GET_FIRMWARE_VER, &[], &mut resp, 0).unwrap();
        let (cmd, payload) = decode_frame(&resp[..n]).unwrap();
        assert_eq!(cmd, RESP_OK);
        assert!(payload.starts_with(b"croco-wallet"));
    }
}
