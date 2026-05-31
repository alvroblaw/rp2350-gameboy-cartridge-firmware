//! GameBoy ↔ RP2350 communication protocol via SRAM.
//!
//! Implements a bidirectional message channel between the GameBoy ROM
//! (wallet UI) and the RP2350 firmware (wallet logic). Uses specific
//! SRAM addresses as command/response registers.
//!
//! ## Protocol
//!
//! The GameBoy ROM writes commands to a fixed SRAM region. The RP2350
//! polls the status byte and reads commands when pending. Responses are
//! written back to a separate SRAM region that the ROM polls.
//!
//! ## Frame format
//!
//! ```text
//! [MAGIC: u8][CMD: u8][LEN: u16 LE][PAYLOAD: N bytes][CHECKSUM: u16 LE]
//! ```
//!
//! Total frame size: 5 + LEN bytes (max 493 bytes).
//!
//! ## SRAM memory map
//!
//! | Offset    | Size  | Purpose                    |
//! |-----------|-------|----------------------------|
//! | 0x1F00    | 64 B  | Command region (GB→RP2350) |
//! | 0x1F40    | 64 B  | Response region (RP2350→GB)|
//! | 0x1F80    | 112 B | Extended payload buffer    |
//! | 0x1FF0    | 1 B   | Status byte                |
//! | 0x1FF1-FF | 15 B  | Reserved                   |
//!
//! See PROTOCOL.md for full specification.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic byte for wallet protocol frames.
pub const FRAME_MAGIC: u8 = 0xB7;

/// SRAM address where the GB ROM writes commands (offset from SRAM base).
pub const CMD_REGION_ADDR: usize = 0x1F00;
/// Command region size.
pub const CMD_REGION_SIZE: usize = 64;

/// SRAM address where the RP2350 writes responses (offset from SRAM base).
pub const RSP_REGION_ADDR: usize = 0x1F40;
/// Response region size.
pub const RSP_REGION_SIZE: usize = 64;

/// SRAM address for extended payload buffer.
pub const EXT_PAYLOAD_ADDR: usize = 0x1F80;
/// Extended payload buffer size.
pub const EXT_PAYLOAD_SIZE: usize = 112;

/// SRAM address for shared status byte.
pub const STATUS_BYTE_ADDR: usize = 0x1FF0;

/// Maximum payload size (CMD_REGION + EXT_PAYLOAD minus frame header overhead).
pub const MAX_PAYLOAD_SIZE: usize = CMD_REGION_SIZE + EXT_PAYLOAD_SIZE;

/// Frame header size: MAGIC(1) + CMD(1) + LEN(2).
const FRAME_HEADER_SIZE: usize = 4;
/// Frame trailer size: CRC16(2).
const FRAME_CRC_SIZE: usize = 2;
/// Total frame overhead.
const FRAME_OVERHEAD: usize = FRAME_HEADER_SIZE + FRAME_CRC_SIZE;

// Status byte bits
const STATUS_CMD_PENDING: u8 = 0x01;
const STATUS_RSP_READY: u8 = 0x02;
#[allow(dead_code)]
const STATUS_ERROR: u8 = 0x04;
#[allow(dead_code)]
const STATUS_BUSY: u8 = 0x08;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Wallet protocol commands (sent from GB ROM to RP2350).
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
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
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
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

#[allow(dead_code)]
impl ResponseCode {
    /// Check if this code represents success.
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl core::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ---------------------------------------------------------------------------
// CRC-16-CCITT
// ---------------------------------------------------------------------------

/// Compute CRC-16-CCITT (polynomial 0x1021, init 0xFFFF).
///
/// Software implementation matching the algorithm specified in PROTOCOL.md.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
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
// Frame
// ---------------------------------------------------------------------------

/// A protocol frame for the GB↔RP2350 channel.
///
/// Frames have a fixed structure: magic byte, command/status byte,
/// little-endian payload length, payload bytes, and CRC-16 trailer.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Command or response code byte.
    pub cmd: u8,
    /// Payload length.
    pub len: u16,
    /// Payload data (only `len` bytes are valid).
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

impl Frame {
    /// Create a new frame with the given command byte and payload.
    pub fn new(cmd: u8, payload: &[u8]) -> Result<Self, ChannelError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ChannelError::PayloadTooLarge);
        }
        let mut buf = [0u8; MAX_PAYLOAD_SIZE];
        buf[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            cmd,
            len: payload.len() as u16,
            payload: buf,
        })
    }

    /// Create a response frame from a ResponseCode and optional payload.
    pub fn new_response(code: ResponseCode, payload: &[u8]) -> Result<Self, ChannelError> {
        Self::new(code as u8, payload)
    }

    /// Total encoded frame size in bytes.
    pub fn encoded_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.len as usize + FRAME_CRC_SIZE
    }

    /// Encode this frame into `dst`. Returns the number of bytes written.
    pub fn encode_to(&self, dst: &mut [u8]) -> usize {
        let total = self.encoded_size();
        assert!(dst.len() >= total, "encode_to: destination buffer too small");

        dst[0] = FRAME_MAGIC;
        dst[1] = self.cmd;
        dst[2] = (self.len & 0xFF) as u8;
        dst[3] = ((self.len >> 8) & 0xFF) as u8;
        dst[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + self.len as usize]
            .copy_from_slice(&self.payload[..self.len as usize]);

        // CRC covers MAGIC + CMD + LEN + PAYLOAD
        let crc = crc16_ccitt(&dst[..FRAME_HEADER_SIZE + self.len as usize]);
        dst[FRAME_HEADER_SIZE + self.len as usize] = (crc & 0xFF) as u8;
        dst[FRAME_HEADER_SIZE + self.len as usize + 1] = ((crc >> 8) & 0xFF) as u8;

        total
    }

    /// Decode a frame from a byte slice.
    ///
    /// Validates magic byte, length constraints, and CRC checksum.
    pub fn decode(src: &[u8]) -> Result<Self, ChannelError> {
        if src.len() < FRAME_HEADER_SIZE + FRAME_CRC_SIZE {
            return Err(ChannelError::InvalidFrame);
        }
        if src[0] != FRAME_MAGIC {
            return Err(ChannelError::InvalidMagic);
        }

        let cmd = src[1];
        let len = u16::from_le_bytes([src[2], src[3]]) as usize;

        let total = FRAME_HEADER_SIZE + len + FRAME_CRC_SIZE;
        if src.len() < total {
            return Err(ChannelError::InvalidFrame);
        }
        if len > MAX_PAYLOAD_SIZE {
            return Err(ChannelError::PayloadTooLarge);
        }

        // Verify CRC
        let expected_crc = crc16_ccitt(&src[..FRAME_HEADER_SIZE + len]);
        let actual_crc = u16::from_le_bytes([
            src[FRAME_HEADER_SIZE + len],
            src[FRAME_HEADER_SIZE + len + 1],
        ]);
        if expected_crc != actual_crc {
            return Err(ChannelError::ChecksumMismatch);
        }

        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..len].copy_from_slice(&src[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + len]);

        Ok(Frame {
            cmd,
            len: len as u16,
            payload,
        })
    }

    /// Get the command enum from this frame, if it's a valid command.
    pub fn command(&self) -> Option<Command> {
        Command::from_byte(self.cmd)
    }

    /// Get the payload as a slice.
    pub fn payload_slice(&self) -> &[u8] {
        &self.payload[..self.len as usize]
    }
}

// ---------------------------------------------------------------------------
// GbChannel — the main communication interface
// ---------------------------------------------------------------------------

/// GB communication channel handler.
///
/// Manages reads/writes to the shared SRAM regions used for wallet
/// communication between the GameBoy ROM and the RP2350 firmware.
///
/// # Safety invariants
///
/// - `sram_base` must point to a valid, uniquely-owned region of at least
///   0x2000 bytes (8 KiB, one GB SRAM bank).
/// - The region at `STATUS_BYTE_ADDR` offset must be accessible.
/// - The command and response regions must not overlap.
/// - In normal flashcart mode, the MBC handler manages SRAM bank switching.
///   The wallet channel must only be active in stealth mode where the wallet
///   ROM is loaded and the MBC is configured to expose the correct SRAM bank.
pub struct GbChannel {
    /// Pointer to the SRAM base for the current bank.
    sram_base: *mut u8,
}

impl GbChannel {
    /// Create a new GB channel with the given SRAM base address.
    ///
    /// # Safety
    ///
    /// `sram_base` must point to a valid writable memory region of at least
    /// 0x2000 bytes. The caller must guarantee exclusive access to this
    /// memory region for the lifetime of this `GbChannel`.
    pub fn new(sram_base: *mut u8) -> Self {
        Self { sram_base }
    }

    // -----------------------------------------------------------------------
    // Raw SRAM access helpers
    // -----------------------------------------------------------------------

    /// Read a byte from SRAM at the given offset.
    #[inline]
    unsafe fn read_byte(&self, offset: usize) -> u8 {
        core::ptr::read_volatile(self.sram_base.add(offset))
    }

    /// Write a byte to SRAM at the given offset.
    #[inline]
    unsafe fn write_byte(&self, offset: usize, value: u8) {
        core::ptr::write_volatile(self.sram_base.add(offset), value);
    }

    /// Read `count` bytes from SRAM starting at `offset` into `dst`.
    unsafe fn read_bytes(&self, offset: usize, dst: &mut [u8], count: usize) {
        for i in 0..count {
            dst[i] = core::ptr::read_volatile(self.sram_base.add(offset + i));
        }
    }

    /// Write `src` bytes to SRAM starting at `offset`.
    unsafe fn write_bytes(&self, offset: usize, src: &[u8]) {
        for (i, &b) in src.iter().enumerate() {
            core::ptr::write_volatile(self.sram_base.add(offset + i), b);
        }
    }

    // -----------------------------------------------------------------------
    // Status byte management
    // -----------------------------------------------------------------------

    /// Read the status byte from SRAM.
    fn read_status(&self) -> u8 {
        unsafe { self.read_byte(STATUS_BYTE_ADDR) }
    }

    /// Write the status byte to SRAM.
    fn write_status(&self, value: u8) {
        unsafe { self.write_byte(STATUS_BYTE_ADDR, value) };
    }

    /// Check if a command is pending from the GB ROM.
    pub fn has_command(&self) -> bool {
        (self.read_status() & STATUS_CMD_PENDING) != 0
    }

    /// Check if a response is ready for the GB ROM to read.
    #[allow(dead_code)]
    pub fn has_response(&self) -> bool {
        (self.read_status() & STATUS_RSP_READY) != 0
    }

    // -----------------------------------------------------------------------
    // Command reading (RP2350 reads commands written by GB ROM)
    // -----------------------------------------------------------------------

    /// Read the pending command frame from the command region.
    ///
    /// 1. Reads raw frame bytes from command region (0x1F00) + extended
    ///    payload buffer (0x1F80) if needed.
    /// 2. Validates magic byte, length, and CRC checksum.
    /// 3. Clears the command-pending bit in the status byte.
    ///
    /// Returns `Err(ChannelError::NoCommandPending)` if no command is pending.
    pub fn read_command(&self) -> Result<Frame, ChannelError> {
        if !self.has_command() {
            return Err(ChannelError::NoCommandPending);
        }

        // Read the command region (first 64 bytes of the frame).
        let mut raw = [0u8; MAX_PAYLOAD_SIZE + FRAME_OVERHEAD];
        unsafe {
            self.read_bytes(CMD_REGION_ADDR, &mut raw, CMD_REGION_SIZE);
        }

        // Parse header to determine total frame size.
        if raw[0] != FRAME_MAGIC {
            self.clear_command_flag();
            return Err(ChannelError::InvalidMagic);
        }

        let payload_len = u16::from_le_bytes([raw[2], raw[3]]) as usize;

        // If payload extends beyond the command region, read from extended buffer.
        if FRAME_HEADER_SIZE + payload_len > CMD_REGION_SIZE {
            let overflow = FRAME_HEADER_SIZE + payload_len - CMD_REGION_SIZE;
            if overflow <= EXT_PAYLOAD_SIZE {
                unsafe {
                    self.read_bytes(EXT_PAYLOAD_ADDR, &mut raw[CMD_REGION_SIZE..], overflow);
                }
            }
        }

        let total_needed = FRAME_HEADER_SIZE + payload_len + FRAME_CRC_SIZE;
        if total_needed > raw.len() {
            self.clear_command_flag();
            return Err(ChannelError::PayloadTooLarge);
        }

        let frame = Frame::decode(&raw[..total_needed])?;
        self.clear_command_flag();
        Ok(frame)
    }

    /// Clear the command-pending flag.
    fn clear_command_flag(&self) {
        let status = self.read_status();
        self.write_status(status & !STATUS_CMD_PENDING);
    }

    // -----------------------------------------------------------------------
    // Response writing (RP2350 writes responses for GB ROM to read)
    // -----------------------------------------------------------------------

    /// Write a response frame to the response region.
    ///
    /// 1. Encodes the response as a frame with magic byte and CRC.
    /// 2. Writes frame to response region (0x1F40) + extended buffer (0x1F80)
    ///    if needed.
    /// 3. Sets the response-ready bit in the status byte.
    pub fn write_response(&self, code: ResponseCode, payload: &[u8]) -> Result<(), ChannelError> {
        let frame = Frame::new_response(code, payload)?;

        // Encode the full frame into a temporary buffer.
        let mut buf = [0u8; MAX_PAYLOAD_SIZE + FRAME_OVERHEAD];
        let total = frame.encode_to(&mut buf);

        // Write to response region (first 64 bytes).
        let rsp_bytes = total.min(RSP_REGION_SIZE);
        unsafe {
            self.write_bytes(RSP_REGION_ADDR, &buf[..rsp_bytes]);
        }

        // If the frame overflows, write the rest to extended buffer.
        if total > RSP_REGION_SIZE {
            unsafe {
                self.write_bytes(EXT_PAYLOAD_ADDR, &buf[RSP_REGION_SIZE..total]);
            }
        }

        // Set response-ready flag.
        let status = self.read_status();
        self.write_status(status | STATUS_RSP_READY);

        Ok(())
    }

    /// Clear the response-ready flag.
    #[allow(dead_code)]
    pub fn clear_response(&self) {
        let status = self.read_status();
        self.write_status(status & !STATUS_RSP_READY);
    }

    // -----------------------------------------------------------------------
    // Convenience polling
    // -----------------------------------------------------------------------

    /// Poll for a pending command. Returns `Some(Frame)` if available.
    ///
    /// Primary method for the stealth mode command loop.
    pub fn poll_command(&self) -> Option<Frame> {
        self.read_command().ok()
    }

    // -----------------------------------------------------------------------
    // Initialization and cleanup
    // -----------------------------------------------------------------------

    /// Initialize the communication channel.
    ///
    /// Clears all SRAM regions used by the protocol and resets the status
    /// byte to zero. Call once when entering stealth wallet mode.
    pub fn init(&self) {
        for i in 0..CMD_REGION_SIZE {
            unsafe { self.write_byte(CMD_REGION_ADDR + i, 0) };
        }
        for i in 0..RSP_REGION_SIZE {
            unsafe { self.write_byte(RSP_REGION_ADDR + i, 0) };
        }
        for i in 0..EXT_PAYLOAD_SIZE {
            unsafe { self.write_byte(EXT_PAYLOAD_ADDR + i, 0) };
        }
        self.write_status(0);
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Channel errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
#[allow(dead_code)]
pub enum ChannelError {
    /// No command is currently pending.
    NoCommandPending,
    /// Invalid magic byte in frame.
    InvalidMagic,
    /// Frame is too short or malformed.
    InvalidFrame,
    /// Payload exceeds maximum size.
    PayloadTooLarge,
    /// CRC checksum mismatch.
    ChecksumMismatch,
    /// SRAM access error.
    AccessError,
}

// ---------------------------------------------------------------------------
// Tests (std only — not compiled for firmware)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc16_empty() {
        assert_eq!(crc16_ccitt(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc16_known() {
        // CRC-16-CCITT of "123456789" should be 0x29B1
        let crc = crc16_ccitt(b"123456789");
        assert_eq!(crc, 0x29B1);
    }

    #[test]
    fn test_frame_roundtrip() {
        let payload = b"hello wallet";
        let frame = Frame::new(0x01, payload).unwrap();
        let mut buf = [0u8; 512];
        let n = frame.encode_to(&mut buf);
        let decoded = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.cmd, 0x01);
        assert_eq!(decoded.len as usize, payload.len());
        assert_eq!(decoded.payload_slice(), payload);
    }

    #[test]
    fn test_frame_empty_payload() {
        let frame = Frame::new(0x08, &[]).unwrap();
        let mut buf = [0u8; 512];
        let n = frame.encode_to(&mut buf);
        let decoded = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(decoded.cmd, 0x08);
        assert_eq!(decoded.len, 0);
        assert!(decoded.payload_slice().is_empty());
    }

    #[test]
    fn test_frame_bad_magic() {
        let mut buf = [0u8; 10];
        buf[0] = 0x00; // wrong magic
        buf[1] = 0x01;
        buf[2] = 0x00;
        buf[3] = 0x00;
        let crc = crc16_ccitt(&buf[..4]);
        buf[4] = (crc & 0xFF) as u8;
        buf[5] = ((crc >> 8) & 0xFF) as u8;
        assert!(matches!(Frame::decode(&buf[..6]), Err(ChannelError::InvalidMagic)));
    }

    #[test]
    fn test_frame_bad_crc() {
        let frame = Frame::new(0x01, b"test").unwrap();
        let mut buf = [0u8; 512];
        let n = frame.encode_to(&mut buf);
        buf[n - 1] ^= 0xFF;
        assert!(matches!(Frame::decode(&buf[..n]), Err(ChannelError::ChecksumMismatch)));
    }

    #[test]
    fn test_command_from_byte() {
        assert_eq!(Command::from_byte(0x01), Some(Command::GenerateSeed));
        assert_eq!(Command::from_byte(0x0A), Some(Command::SetPin));
        assert_eq!(Command::from_byte(0xFF), None);
    }

    #[test]
    fn test_response_code_is_ok() {
        assert!(ResponseCode::Ok.is_ok());
        assert!(!ResponseCode::Error.is_ok());
        assert!(!ResponseCode::WrongPin.is_ok());
    }

    #[test]
    fn test_payload_too_large() {
        let big = [0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(matches!(Frame::new(0x01, &big), Err(ChannelError::PayloadTooLarge)));
    }
}
