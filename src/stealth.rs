//! Stealth mode detection.
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
    /// Stealth wallet mode — LED green, wait for USB wallet commands.
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
    // OE is 0 after reset for all GPIOs, so pin is already an input.
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
/// In this initial implementation:
/// - LED turns green to visually confirm wallet mode
/// - Logs stealth activation via defmt
/// - Enters an infinite loop (placeholder for future USB wallet commands)
///
/// This function never returns (diverges).
pub async fn run_stealth_mode(led: &mut dyn crate::ws2812_spi::Ws2812Led) -> ! {
    defmt::info!("Stealth mode activated - wallet mode");
    defmt::info!("Waiting for USB wallet commands...");

    // Visual confirmation: green LED
    led.write(&smart_leds::RGB8::new(0, 32, 0));

    // Placeholder: infinite loop for future wallet USB command processing
    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}
