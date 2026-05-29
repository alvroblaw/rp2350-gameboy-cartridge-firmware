//! Stealth mode detection and wallet command loop.
//!
//! Detects whether the cartridge should boot into normal GameBoy mode
//! (flashcart) or stealth wallet mode. The trigger mechanism is holding
//! the physical button on the cartridge during boot.
//!
//! ## Detection method
//!
//! **Primary**: Physical button on the cartridge (GPIO4 / PIN_4), held for
//! >2 seconds at boot time. The button is active LOW (pulled up).
//!
//! ## Why raw SIO + pad registers?
//!
//! The detection configures the pad pull-up and reads GPIO via SIO registers
//! directly, without creating an `Input` peripheral. This way the pin token
//! (`p.PIN_4`) remains available to be passed to `core1_task` for normal
//! savegame button handling in flashcart mode.

use embassy_time::{Duration, Timer};

use crate::comm::gb_channel::{Command, Frame, GbChannel, ResponseCode};
use crate::ws2812_spi::Ws2812Led;

/// Minimum hold time (ms) to trigger stealth mode.
/// Prevents accidental triggers from brief button presses during insertion.
const STEALTH_HOLD_MS: u64 = 2000;

/// GPIO pin number for the physical button (PIN_4 = GPIO4).
const BUTTON_PIN: u32 = 4;

/// Result of stealth mode detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum BootMode {
    /// Normal flashcart mode — load GB bootloader, list ROMs, play games.
    Normal,
    /// Stealth wallet mode — LED green, enter wallet command loop.
    Stealth,
}

/// Enable internal pull-up on the button pin via pad registers.
///
/// Uses the `rp-pac` typed register access (GpioCtrl) for correctness.
/// Configures: input enable + pull-up, no pull-down.
/// Does NOT claim the pin as a peripheral.
#[inline]
fn enable_button_pullup() {
    let pad = embassy_rp::pac::PADS_BANK0.gpio(BUTTON_PIN as usize);
    let mut ctrl = pad.read();
    ctrl.set_ie(true);   // Input enable
    ctrl.set_pue(true);  // Pull-up enable
    ctrl.set_pde(false); // No pull-down
    ctrl.set_od(false);  // No output disable
    pad.write_value(ctrl);
}

/// Read the button state via raw SIO GPIO input register.
///
/// Returns `true` if the button is pressed (pin is LOW, active-low button).
#[inline]
fn is_button_pressed() -> bool {
    let gpio_in: u32 = embassy_rp::pac::SIO.gpio_in(0).read();
    // Button is active LOW with pull-up: pressed = bit clear
    (gpio_in & (1 << BUTTON_PIN)) == 0
}

/// Detect the boot mode based on hardware signals.
///
/// Configures pull-up on the button pin and checks if it's held down
/// for the required duration. Uses raw register access — does not
/// claim the pin as a peripheral.
///
/// Must be called early in the boot process, **before** the GB bootloader
/// runs and **before** the GB bus is activated.
///
/// # Returns
/// * `BootMode::Stealth` if button held for >= STEALTH_HOLD_MS
/// * `BootMode::Normal` otherwise
pub async fn detect_boot_mode() -> BootMode {
    // Enable internal pull-up so the pin reads HIGH when released
    enable_button_pullup();

    // Small delay to let the pull-up settle
    Timer::after(Duration::from_millis(10)).await;

    // If button is already pressed at boot, start timing
    if is_button_pressed() {
        // Wait the required hold duration
        Timer::after(Duration::from_millis(STEALTH_HOLD_MS)).await;
        // Check if still held after the duration
        if is_button_pressed() {
            return BootMode::Stealth;
        }
    }
    BootMode::Normal
}

/// Run the stealth wallet mode.
///
/// Initializes the GB↔RP2350 communication channel and enters a
/// command polling loop. The RP2350 reads commands from the shared
/// SRAM region, dispatches them to wallet logic (stubs for now),
/// and writes responses back.
///
/// The `sram_base` pointer must point to the GB save RAM region
/// (typically `_s_gb_save_ram` from `memory.x`), which is where
/// the wallet ROM will read/write commands and responses.
///
/// This function never returns (diverges).
pub async fn run_stealth_mode(
    led: &mut dyn Ws2812Led,
    sram_base: *mut u8,
) -> ! {
    defmt::info!("Stealth mode activated - wallet mode");
    defmt::info!("Initializing GB communication channel...");

    // Visual confirmation: green LED
    led.write(&smart_leds::RGB8::new(0, 32, 0));

    // Initialize the communication channel.
    let channel = GbChannel::new(sram_base);
    channel.init();

    defmt::info!("GB channel initialized. Entering wallet command loop.");

    // Main wallet command loop.
    loop {
        if let Some(frame) = channel.poll_command() {
            let response = dispatch_wallet_command(&frame);
            match &response {
                Ok((code, _)) => {
                    defmt::info!("Wallet cmd 0x{:02X} -> {:?}", frame.cmd, code);
                }
                Err(code) => {
                    defmt::warn!("Wallet cmd 0x{:02X} error: {:?}", frame.cmd, code);
                }
            }

            let result = match &response {
                Ok((code, payload)) => channel.write_response(*code, payload),
                Err(code) => channel.write_response(*code, &[]),
            };

            if let Err(_e) = result {
                defmt::error!("Failed to write response");
            }
        }

        // Brief yield to avoid busy-waiting.
        Timer::after(Duration::from_millis(10)).await;
    }
}

/// Dispatch a wallet command frame to the appropriate handler.
///
/// Each command is matched and dispatched to its handler.
/// Handlers are currently stubs that return `ResponseCode::Error`.
fn dispatch_wallet_command(frame: &Frame) -> Result<(ResponseCode, &'static [u8]), ResponseCode> {
    let cmd = frame.command().ok_or(ResponseCode::InvalidCommand)?;

    match cmd {
        Command::GenerateSeed => {
            // TODO Phase 3: generate entropy, derive mnemonic, encrypt & store
            defmt::info!("STUB: GenerateSeed (word_count hint: {})", frame.len);
            Err(ResponseCode::Error)
        }
        Command::ImportSeed => {
            // TODO Phase 3: parse word indices, validate, derive seed, store
            defmt::info!("STUB: ImportSeed ({} bytes payload)", frame.len);
            Err(ResponseCode::Error)
        }
        Command::GetXpub => {
            // TODO Phase 3: derive master key, return xpub bytes
            defmt::info!("STUB: GetXpub");
            Err(ResponseCode::Error)
        }
        Command::GetAddress => {
            // TODO Phase 3: derive child key, encode address
            defmt::info!("STUB: GetAddress");
            Err(ResponseCode::Error)
        }
        Command::SignPsbt => {
            // TODO Phase 5: parse PSBT preview, prompt user confirmation, sign
            defmt::info!("STUB: SignPsbt");
            Err(ResponseCode::Error)
        }
        Command::ExportSeed => {
            // TODO Phase 3: decrypt seed, convert to word indices
            defmt::info!("STUB: ExportSeed");
            Err(ResponseCode::Error)
        }
        Command::Wipe => {
            // TODO Phase 4: securely erase encrypted seed from storage
            defmt::info!("STUB: Wipe");
            Err(ResponseCode::Error)
        }
        Command::Lock => {
            // TODO Phase 3: zeroize in-memory keys, set locked state
            defmt::info!("STUB: Lock");
            Err(ResponseCode::Error)
        }
        Command::Unlock => {
            // TODO Phase 4: derive key from PIN, decrypt seed
            defmt::info!("STUB: Unlock");
            Err(ResponseCode::Error)
        }
        Command::SetPin => {
            // TODO Phase 4: set or change the encryption PIN
            defmt::info!("STUB: SetPin");
            Err(ResponseCode::Error)
        }
    }
}
