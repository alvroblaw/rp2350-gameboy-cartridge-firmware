# Build and Flash Guide

## Prerequisites

### 1. Rust Toolchain

```bash
# Install rustup (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add the RP2350 target (Cortex-M33, hard-float ABI)
rustup target add thumbv8m.main-none-eabihf

# Install flip-link for overflow protection
cargo install flip-link
```

### 2. picotool

Required for flashing the firmware via USB.

```bash
# Clone and build picotool
git clone https://github.com/raspberrypi/pico-sdk.git
git clone https://github.com/raspberrypi/picotool.git
cd picotool
mkdir build && cd build
cmake .. -DPICO_SDK_PATH=../../pico-sdk
make -j$(nproc)
sudo make install
```

### 3. GBDK (GameBoy Development Kit)

Required for building the GameBoy bootloader ROM (C code in `gb-bootloader/`).

```bash
# Download GBDK from https://github.com/gbdk-2020/gbdk-2020/releases
# Set the GBDK_PATH environment variable:
export GBDK_PATH=/path/to/gbdk-2020
```

### 4. Dev Container (Alternative)

The easiest way to build is using the provided Dev Container:

1. Install VS Code + [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
2. Open the repository in VS Code
3. When prompted, reopen in container
4. All dependencies are pre-installed

## Building

### Debug Build

```bash
cargo build
```

Output: `target/thumbv8m.main-none-eabihf/debug/rp2350-gameboy-cartridge`

### Release Build

```bash
cargo build --release
```

Output: `target/thumbv8m.main-none-eabihf/release/rp2350-gameboy-cartridge`

### Environment Variables

The build uses these environment variables for version info (set in `.cargo/config.toml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `VERSION_MAJOR` | 255 | Major version (u8) |
| `VERSION_MINOR` | 255 | Minor version (u8) |
| `VERSION_PATCH` | 255 | Patch version (u8) |
| `RELEASE_TYPE` | "U" | Release type character |

Override for a specific version:
```bash
VERSION_MAJOR=0 VERSION_MINOR=1 VERSION_PATCH=0 RELEASE_TYPE=A cargo build --release
```

## Flashing

### Via USB (picotool)

1. Connect the cartridge to your computer via USB
2. Hold the **BOOTSEL** button while plugging in (or use picotool to reset)

```bash
# Flash and execute
picotool load -u -v -x -t elf target/thumbv8m.main-none-eabihf/release/rp2350-gameboy-cartridge -f
```

Flags:
- `-u`: Update (skip unchanged flash sectors)
- `-v`: Verify after writing
- `-x`: Execute after loading
- `-t elf`: Input type is ELF
- `-f`: Force if firmware is running

### Via SWD (Debug Probe)

For development with a debug probe (e.g., Picoprobe):

```bash
# Using probe-rs
cargo install probe-rs-tools
probe-rs run --chip RP2350 target/thumbv8m.main-none-eabihf/debug/rp2350-gameboy-cartridge
```

## Testing

### Unit Tests (host machine)

Wallet logic that doesn't depend on hardware can be tested with `cargo test`.
Since the main crate is `no_std`, wallet tests should be in a separate test crate
or use conditional compilation.

```bash
# Future: when wallet test crate exists
cargo test -p wallet-tests
```

### Integration Testing

For testing the wallet with actual hardware:

1. Flash the firmware
2. Connect via USB serial
3. Use the Python script from `USB_PROTOCOL.md` to send commands
4. Verify responses on GameBoy screen

### Debugging

- **Serial output**: Firmware logs via UART (defmt format, 115200 baud)
- **defmt**: `DEFMT_LOG=debug` (set in `.cargo/config.toml`)
- **Probe**: SWD debug probe for step-through debugging

## CI

The project uses GitHub Actions for:

- **CI** (`.github/workflows/ci.yml`): Build check on push/PR
- **Release** (`.github/workflows/release.yml`): Build release artifacts on tag

## Project Structure

```
.
├── src/                    Firmware source (Rust, no_std)
│   ├── main.rs            Entry point
│   ├── wallet/            Bitcoin wallet modules
│   ├── comm/              Communication protocols
│   ├── stealth.rs         Boot mode detection
│   ├── crypto_rng.rs      Hardware entropy
│   └── ...                Existing flashcart modules
├── gb-bootloader/         GameBoy bootloader (C, GBDK)
├── pio/                   PIO program files
├── memory.x               Linker script (memory layout)
├── .cargo/config.toml     Build configuration
├── Cargo.toml             Rust dependencies
├── build.rs               Build script (GB ROM compilation)
├── ARCHITECTURE.md        System architecture
├── PROTOCOL.md            GB↔RP2350 communication protocol
├── USB_PROTOCOL.md        USB host protocol
├── THREAT_MODEL.md        Security threat model
└── BUILD.md               This file
```
