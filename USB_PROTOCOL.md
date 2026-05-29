# USB Protocol: Host ↔ Wallet Communication

## Overview

The wallet communicates with a host computer via USB for PSBT signing operations. The protocol runs over a CDC serial emulation interface provided by embassy-usb, making it compatible with any OS without custom drivers.

## Physical Interface

- **USB**: Full-speed (12 Mbps) via RP2350 USB peripheral
- **Interface**: CDC ACM serial emulation
- **VID/PID**: 0x2E8A / 0x0009 (Raspberry Pi, same as existing firmware)
- **Baud rate**: Irrelevant (USB virtual serial)

## Message Framing

All USB messages use a simple length-prefixed frame format:

```
Offset  Size   Field       Description
──────  ────   ─────────   ───────────────────────────────
0x00    1      SOP         Start of packet: 0xAA
0x01    1      CMD         Command or response code
0x02    2      LEN         Payload length (u16 LE, max 2048)
0x04    N      PAYLOAD     Command/response data
0x04+N  1      EOP         End of packet: 0x55
```

## Commands (Host → Wallet)

| Code | Name               | Payload In           | Payload Out            |
|------|--------------------|----------------------|------------------------|
| 0x01 | SEND_PSBT          | Raw PSBT bytes       | ACK (0x01) or ERROR    |
| 0x02 | GET_SIGNED_PSBT    | (empty)              | Signed PSBT bytes      |
| 0x03 | GET_XPUB           | `[network: u8]`      | xpub string (111 bytes)|
| 0x04 | GET_FIRMWARE_VERSION| (empty)             | `[major, minor, patch]`|

## Response Codes (Wallet → Host)

| Code | Name             | Description |
|------|------------------|-------------|
| 0x01 | ACK              | Command received, processing |
| 0x02 | SIGNED_PSBT      | Signed PSBT data follows |
| 0x03 | XPUB             | xpub string follows |
| 0x04 | FIRMWARE_VERSION | Version bytes follow |
| 0xE0 | REJECTED         | User rejected signing on GB screen |
| 0xE1 | ERROR            | Error processing command |
| 0xE2 | BUSY             | Waiting for user input on GB screen |

## Signing Flow

```
Host                                 Wallet (RP2350)              GB Screen
  │                                       │                         │
  │── SEND_PSBT (raw PSBT bytes) ────────►│                         │
  │                                       │── Parse PSBT            │
  │                                       │── Send to GB via SRAM   │
  │◄── ACK ───────────────────────────────│                         │
  │                                       │                         │
  │                                       │                         │── Show TX details
  │   (poll GET_SIGNED_PSBT or wait)      │                         │   (amount, fee,
  │                                       │                         │    destination)
  │── GET_SIGNED_PSBT ───────────────────►│                         │
  │                                       │── Check GB response     │
  │   ┌─── If user confirmed:             │                         │
  │   │                                   │                         │── "Confirm? A=Yes B=No"
  │   │◄── SIGNED_PSBT (signed data) ─────│── Sign inputs           │
  │   │                                   │                         │
  │   └─── If user rejected:              │                         │
  │                                       │                         │
  │    ◄── REJECTED ──────────────────────│                         │
  │                                       │                         │
```

## Example: Python Communication

```python
import serial
import struct

SOP = 0xAA
EOP = 0x55

CMD_SEND_PSBT = 0x01
CMD_GET_SIGNED_PSBT = 0x02
CMD_GET_XPUB = 0x03
CMD_GET_FIRMWARE_VERSION = 0x04

def send_message(ser, cmd: int, payload: bytes = b""):
    """Send a framed message to the wallet."""
    frame = struct.pack("<BBH", SOP, cmd, len(payload)) + payload + bytes([EOP])
    ser.write(frame)

def recv_message(ser) -> tuple[int, bytes]:
    """Receive a framed response from the wallet."""
    header = ser.read(4)
    sop, cmd, length = struct.unpack("<BBH", header)
    assert sop == SOP, f"Invalid SOP: {sop:#x}"
    payload = ser.read(length) if length > 0 else b""
    eop = ser.read(1)[0]
    assert eop == EOP, f"Invalid EOP: {eop:#x}"
    return cmd, payload

def sign_psbt(port: str, psbt_bytes: bytes) -> bytes:
    """Send a PSBT for signing and return the signed PSBT."""
    with serial.Serial(port, timeout=30) as ser:
        # Send the unsigned PSBT
        send_message(ser, CMD_SEND_PSBT, psbt_bytes)
        cmd, _ = recv_message(ser)
        assert cmd == 0x01, f"Expected ACK, got {cmd:#x}"
        print("PSBT sent. Check GameBoy screen to confirm...")

        # Poll for signed PSBT
        send_message(ser, CMD_GET_SIGNED_PSBT)
        cmd, data = recv_message(ser)

        if cmd == 0x02:  # SIGNED_PSBT
            return data
        elif cmd == 0xE0:  # REJECTED
            raise Exception("User rejected the transaction on the GameBoy screen")
        else:
            raise Exception(f"Unexpected response: {cmd:#x}")

def get_xpub(port: str, network: int = 0) -> str:
    """Get the wallet's account xpub."""
    with serial.Serial(port, timeout=5) as ser:
        send_message(ser, CMD_GET_XPUB, bytes([network]))
        cmd, data = recv_message(ser)
        assert cmd == 0x03, f"Expected XPUB, got {cmd:#x}"
        return data.decode("ascii")

def get_firmware_version(port: str) -> str:
    """Get the wallet firmware version."""
    with serial.Serial(port, timeout=5) as ser:
        send_message(ser, CMD_GET_FIRMWARE_VERSION)
        cmd, data = recv_message(ser)
        assert cmd == 0x04, f"Expected VERSION, got {cmd:#x}"
        major, minor, patch = data[0], data[1], data[2]
        return f"v{major}.{minor}.{patch}"

# Usage example:
# signed = sign_psbt("/dev/ttyACM0", open("unsigned.psbt", "rb").read())
# print("Signed PSBT:", signed.hex())
```

## Host Software Compatibility

### Target Compatibility

| Software | Integration Method | Status |
|----------|--------------------|--------|
| **Sparrow Wallet** | HWI (Hardware Wallet Interface) via USB serial | Planned |
| **Specter Desktop** | HWI or direct USB serial | Planned |
| **Electrum** | Plugin or direct serial | Future |
| **Custom scripts** | Direct serial protocol (see above) | Supported |

### HWI Compatibility

For maximum compatibility with existing wallet software, we should implement the
[Hardware Wallet Interface (HWI)](https://github.com/bitcoin-core/HWI) protocol.
This requires:
1. Standard enumeration as a HID or serial device
2. Support for `getmasterxpub`, `signtx`, `getaddress` commands
3. PSBT v0 format support
