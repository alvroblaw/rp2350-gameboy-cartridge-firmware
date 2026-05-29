# GB↔RP2350 Communication Protocol

## Overview

Bidirectional communication between the GameBoy ROM (wallet UI) and the RP2350 firmware (wallet logic) through shared SRAM addresses. The MBC emulation layer on the RP2350 detects writes to specific addresses and processes wallet commands.

## Physical Layer

- **Medium**: SRAM accessed via MBC registers (0xA000-0xBFFF)
- **Access**: GB ROM writes to specific SRAM offsets; RP2350 MBC handler intercepts
- **Timing**: Synchronous — GB writes command, polls for response
- **Byte order**: Little-endian

## Frame Format

All frames use the same structure for both commands and responses:

```
Offset  Size   Field       Description
──────  ────   ─────────   ───────────────────────────────
0x00    1      MAGIC       Fixed value 0xB7
0x01    1      CMD/STATUS  Command ID (request) or status code (response)
0x02    2      LEN         Payload length in bytes (u16 LE)
0x04    N      PAYLOAD     Command/response payload (0-488 bytes)
0x04+N  2      CHECKSUM    CRC-16-CCITT over MAGIC+CMD+LEN+PAYLOAD
```

**Total frame size**: 5 + N bytes (max 493 bytes)

### SRAM Memory Map

```
Address Range    Size   Purpose
──────────────   ────   ──────────────────────────────
0x1F00-0x1F3F    64B    Command region (GB → RP2350)
0x1F40-0x1F7F    64B    Response region (RP2350 → GB)
0x1F80-0x1FEF    112B   Extended payload buffer
0x1FF0           1B     Status byte
  Bit 0: Command pending (1 = GB has written a command)
  Bit 1: Response ready (1 = RP2350 has written a response)
  Bit 2: Error flag
  Bit 3: Busy flag
0x1FF1-0x1FFF    15B    Reserved
```

## Command Table

| ID   | Name          | Request Payload            | Response Payload              |
|------|---------------|----------------------------|-------------------------------|
| 0x01 | GENERATE_SEED | `[word_count: u8]` (12/24) | `[word_indices: N×u16]`       |
| 0x02 | IMPORT_SEED   | `[word_indices: N×u16]`    | (empty on success)            |
| 0x03 | GET_XPUB      | `[network: u8]` (0=main)   | `[xpub_bytes: 111]`           |
| 0x04 | GET_ADDRESS   | `[index: u32][addr_type: u8]` | `[address_str: N]`         |
| 0x05 | SIGN_PSBT     | (triggered via USB)        | `[psbt_preview: N]`          |
| 0x06 | EXPORT_SEED   | (empty)                    | `[word_indices: N×u16]`       |
| 0x07 | WIPE          | `[confirm: u8]` (0xA5)     | (empty on success)            |
| 0x08 | LOCK          | (empty)                    | (empty on success)            |
| 0x09 | UNLOCK        | `[pin_digits: N]`          | `[attempts_remaining: u8]`    |
| 0x0A | SET_PIN       | `[pin_digits: N]`          | (empty on success)            |

## Error Codes

| Code | Name             | Description |
|------|------------------|-------------|
| 0x00 | OK               | Command completed successfully |
| 0x01 | ERROR            | Generic error |
| 0x02 | INVALID_COMMAND  | Unknown command ID |
| 0x03 | WRONG_PIN        | Incorrect PIN provided |
| 0x04 | LOCKED           | Wallet is locked, unlock first |
| 0x05 | NO_SEED          | No seed stored on device |
| 0x06 | REJECTED         | User rejected the operation |
| 0x07 | CHECKSUM_ERROR   | Frame checksum mismatch |

## Sequence Diagrams

### Generate New Seed

```
GB ROM                    SRAM                    RP2350
  │                        │                        │
  │── GENERATE_SEED ─────►│── CMD written ────────►│
  │   (word_count=12)      │    (0x1F00)            │
  │                        │                        │── Generate entropy
  │                        │                        │── Derive mnemonic
  │                        │                        │── Encrypt & store seed
  │                        │◄── RSP written ────────│
  │◄── Response ──────────│    (word_indices)       │
  │   (12 word indices)    │                        │
  │                        │                        │
  │── Display words ──► (GB screen)                 │
```

### PSBT Signing Flow

```
USB Host            RP2350              SRAM                GB ROM
  │                   │                   │                   │
  │── Send PSBT ─────►│                   │                   │
  │                   │── Parse PSBT      │                   │
  │                   │── SIGN_PSBT ─────►│── CMD written ───►│
  │                   │   (psbt_preview)  │                   │── Display TX
  │   (ACK + Busy) ◄─│                   │                   │   (amount, addr)
  │                   │                   │                   │
  │                   │                   │◄── User confirms ─│
  │                   │◄── RSP (OK) ──────│   (button A)      │
  │                   │                   │                   │
  │                   │── Sign PSBT       │                   │
  │◄── Signed PSBT ──│                   │                   │
  │                   │                   │                   │
```

### Unlock Wallet with PIN

```
GB ROM                    SRAM                    RP2350
  │                        │                        │
  │── UNLOCK ─────────────►│── CMD written ────────►│
  │   (pin_digits)         │                        │── Derive key from PIN
  │                        │                        │── Decrypt seed from SD
  │                        │                        │
  │                        │◄── RSP written ────────│
  │◄── Response ──────────│                        │
  │   (OK or WRONG_PIN)    │                        │
  │                        │                        │
  │── If OK: show main menu                         │
  │── If WRONG: show retry (attempts left)          │
```

## Checksum Algorithm

CRC-16-CCITT (polynomial 0x1021, init 0xFFFF):

```rust
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in data {
        crc ^= (*byte as u16) << 8;
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
```

## Flow Control

1. GB writes command frame to CMD region (0x1F00)
2. GB sets status byte bit 0 (command pending)
3. RP2350 polls status byte, reads command when pending
4. RP2350 clears bit 0, processes command
5. RP2350 writes response frame to RSP region (0x1F40)
6. RP2350 sets status byte bit 1 (response ready)
7. GB polls status byte, reads response when ready
8. GB clears bit 1

For payloads larger than 64 bytes, the extended payload buffer (0x1F80-0x1FEF) is used. The LEN field indicates total payload size, and data beyond 64 bytes is read from/written to the extended buffer.
