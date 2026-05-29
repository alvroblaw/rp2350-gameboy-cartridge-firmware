# Architecture: Bitcoin Stealth Wallet on RP2350 GameBoy Cartridge

## System Overview

A Bitcoin hardware wallet hidden inside a GameBoy cartridge. The cartridge functions as a normal flashcart for playing GameBoy games. A hidden activation mechanism triggers **stealth wallet mode**, turning the GameBoy into a cold signing device with:

- **Seed generation** from hardware entropy (ROSC + ADC noise)
- **Encrypted seed storage** on SD card
- **Transaction signing** via PSBT (Partially Signed Bitcoin Transaction)
- **USB communication** with host wallet software (Sparrow, Specter, Electrum)
- **GameBoy as UI** — all interaction through the GB screen and controls

### Stealth Concept

```
┌─────────────────────────────────────────────────┐
│              GameBoy Cartridge                    │
│                                                   │
│  Normal boot ──► Flashcart mode                   │
│    • Load ROM list from SD                        │
│    • Play games                                   │
│    • Save/load game saves                         │
│    • Indistinguishable from normal flashcart      │
│                                                   │
│  Secret trigger ──► Stealth wallet mode            │
│    • Load wallet ROM into HyperRAM                │
│    • GB screen = wallet UI                        │
│    • D-pad + A/B = navigation + confirmation      │
│    • USB = host communication for PSBT signing    │
└─────────────────────────────────────────────────┘
```

## Hardware Constraints

| Component | Details | Wallet Impact |
|-----------|---------|---------------|
| **RP2350B** | Dual Cortex-M33 @ 266MHz, 320KB SRAM | Fast crypto, limited RAM |
| **HyperRAM** | External, accessed via PIO | Large ROM/buffer space, not for secrets |
| **SD Card** | SPI, FAT32 via embedded-sdmmc | Encrypted seed storage |
| **GameBoy Bus** | PIO-driven MBC emulation | Communication channel (SRAM registers) |
| **USB** | embassy-usb, CDC serial | PSBT signing with host |
| **LED** | WS2812, SPI | Status feedback |
| **RTC** | MCP795xx with battery backup | Timestamps |

### Memory Layout

```
RP2350 Memory Map:
┌─────────────────────────────────────────────┐
│ FLASH (2MB)                                  │
│   ├─ .start_block / boot info               │
│   ├─ .text (firmware code)                  │
│   ├─ .rodata (constants, BIP-39 wordlist)   │
│   └─ .bi_entries                            │
├─────────────────────────────────────────────┤
│ SRAM (320KB, striped SRAM0-SRAM7)           │
│   ├─ .bss / .data (static vars)            │
│   ├─ Stack (core0 + core1)                  │
│   ├─ Heap (wallet operations)               │
│   └─ Wallet key scratch space              │
├─────────────────────────────────────────────┤
│ GB_ROM_MEMORY (64KB)                        │
│   └─ GameBoy ROM image (wallet ROM / game)  │
├─────────────────────────────────────────────┤
│ GB_SAVE_RAM (128KB)                         │
│   ├─ GameBoy save data                      │
│   └─ Wallet communication registers         │
│       ├─ CMD region (0x1F00-0x1F3F)         │
│       ├─ RSP region (0x1F40-0x1F7F)         │
│       └─ STATUS byte (0x1FF0)               │
├─────────────────────────────────────────────┤
│ SRAM4 (4KB, direct mapped)                  │
│ SRAM5 (4KB, direct mapped)                  │
│   └─ Reserved for wallet key material       │
├─────────────────────────────────────────────┤
│ HyperRAM (external)                         │
│   └─ ROM data, large buffers                │
└─────────────────────────────────────────────┘
```

## Module Architecture

```
src/
├── main.rs                  Entry point + dual boot dispatch
├── stealth.rs               Boot mode detection (button hold / SD file)
├── crypto_rng.rs            Hardware entropy (ROSC + ADC + SHA-256)
│
├── wallet/                  Core wallet logic
│   ├── mod.rs               Module root
│   ├── bip39.rs             Mnemonic generation & parsing
│   ├── bip32.rs             HD key derivation (BIP-32/44/84)
│   ├── keys.rs              KeySource trait (stored vs stateless)
│   ├── psbt.rs              PSBT parse + sign
│   ├── address.rs           Address generation (bech32/base58)
│   ├── encrypt.rs           Seed encryption (PBKDF2 + AES-256-GCM)
│   └── storage.rs           Encrypted seed persistence on SD
│
├── comm/                    External communication
│   ├── mod.rs               Module root
│   ├── gb_channel.rs        GB↔RP2350 SRAM protocol
│   └── usb_protocol.rs      USB host protocol for PSBT signing
│
├── gb_pio.rs                [existing] PIO GameBoy bus interface
├── gb_mbc.rs                [existing] MBC emulation
├── gb_dma.rs                [existing] DMA for ROM/RAM access
├── gb_bootloader.rs         [existing] GB bootloader ROM loader
├── gb_savefile.rs           [existing] Save file management
├── gb_rtc.rs                [existing] RTC emulation
├── hyperram.rs              [existing] HyperRAM driver
├── mcp795xx.rs              [existing] RTC chip driver
├── rom_info.rs              [existing] ROM header parsing
├── ws2812_spi.rs            [existing] LED driver
├── picotool_reset.rs        [existing] USB reset handler
├── rp2350_core_voltage.rs   [existing] Voltage regulation
├── dma_helper.rs            [existing] DMA utilities
└── production_data.rs       [existing] Production data
```

## Boot Flow

```
Power On
    │
    ▼
RP2350 Init (clocks, peripherals)
    │
    ├─ Check stealth trigger (button held >2s)
    │   │
    │   ├─ NO ──► Normal Mode
    │   │         ├─ Load GB bootloader ROM
    │   │         ├─ Start MBC PIO state machines
    │   │         ├─ Scan SD for ROMs
    │   │         └─ Normal flashcart operation
    │   │
    │   └─ YES ──► Stealth Mode
    │             ├─ Load wallet ROM into HyperRAM
    │             ├─ Start MBC PIO (wallet ROM active)
    │             ├─ Init crypto RNG
    │             ├─ Check for encrypted seed on SD
    │             ├─ Start GB communication channel
    │             ├─ Start USB protocol handler
    │             └─ Wait for GB commands / USB messages
    │
    ▼
Core 0: MBC bus emulation (same in both modes)
Core 1: Mode-specific tasks
    Normal: Save file management
    Stealth: Wallet operations + USB handling
```

## Communication Architecture

### GB ↔ RP2350 (via SRAM)

The wallet ROM and RP2350 firmware communicate through specific SRAM addresses:

```
GB ROM (wallet UI)          SRAM                    RP2350 (wallet logic)
     │                       │                            │
     │── Write command ──►  0x1F00 ──►  MBC detects     │
     │                       │          write in PIO       │
     │                       │              │              │
     │                       │              ▼              │
     │                       │          Process cmd ──────►│
     │                       │                             │
     │                       │◄── Write response ──────────┤
     │◄── Poll 0x1F40 ──── 0x1F40                         │
     │                       │                             │
     └── Update screen       │                    ┌────────┘
                             │                    │
                             │              ┌─────┴─────┐
                             │              │ USB Host  │
                             │              │ (PSBT)    │
                             │              └───────────┘
```

### USB ↔ Host Computer

```
Host (Sparrow/Specter)      USB                RP2350              GB Screen
     │                       │                    │                    │
     │── Send PSBT ────────►│── Parse ──────────►│                    │
     │                       │                    │── Display TX ────►│
     │                       │                    │                    │
     │                       │                    │◄── Confirm (A) ───│
     │                       │                    │                    │
     │                       │◄── Signed PSBT ───│                    │
     │◄── Signed PSBT ──────│                    │                    │
```

## Security Model

### In Scope
- Seed encrypted at rest (PBKDF2 + AES-256-GCM)
- PIN-based authentication (rate limited)
- Key material zeroized after use
- PSBT verification before signing (user confirms on GB screen)
- Stealth: wallet mode not detectable without knowing the trigger

### Out of Scope (Future)
- Secure boot / firmware signature verification
- ARM TrustZone isolation
- Side-channel attack mitigation (timing, power analysis)
- Stateless mode with camera (QR seed scanning)
- Hardware tamper detection

### Threats and Mitigations

| Threat | Mitigation |
|--------|-----------|
| Physical SD extraction | Seed encrypted, PIN-derived key |
| Forensic firmware analysis | Wallet code always present (just not active); plausible deniability via stealth |
| USB attack surface | Minimal protocol, no arbitrary code execution |
| Shoulder surfing | PIN input via D-pad, dots shown |
| Bruteforce PIN | Rate limiting + lockout after N failures |
| Bus sniffing | SRAM communication only during wallet mode; key material never on SRAM bus |

## Future: Stateless Mode

The architecture supports a future **stateless mode** where:

1. A camera module is connected to the RP2350 (SPI or PIO)
2. User scans a QR code containing the seed phrase
3. Wallet derives keys, signs transaction, displays signed PSBT as QR
4. Seed is never stored — only in RAM during the session
5. Wipe on power-off

The `KeySource` trait in `wallet/keys.rs` abstracts over stored vs. scanned keys.
