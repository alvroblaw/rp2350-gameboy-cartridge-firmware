//! Stealth mode detection.
//!
//! Detects whether the cartridge should boot into normal GameBoy mode
//! (flashcart) or stealth wallet mode. The trigger mechanism is holding
//! a specific button combination during boot.
//!
//! ## Detection methods
//!
//! 1. **Primary**: Physical button on the cartridge (held for >2 seconds at boot)
//! 2. **Secondary**: Specific file presence on SD card
//!
//! In normal mode, the firmware behaves identically to the original
//! flashcart firmware — no wallet functionality is visible.

#![allow(unused)]

use embassy_rp::gpio::{Input, Pull};
use embassy_time::{Duration, Timer};

/// Minimum hold time (ms) to trigger stealth mode.
const STEALTH_HOLD_MS: u64 = 2000;

/// Result of stealth mode detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// Normal flashcart mode — load GB bootloader, list ROMs.
    Normal,
    /// Stealth wallet mode — load wallet ROM, initialize wallet.
    Stealth,
}

/// Detect the boot mode based on hardware signals.
///
/// Checks if the physical button is held down for the required duration.
/// Must be called early in the boot process, before the GB bus is activated.
pub async fn detect_boot_mode(button: &mut Input<'_>) -> BootMode {
    // If button is already low (pressed) at boot, start timing
    if button.is_low() {
        // Wait and check if still held
        Timer::after(Duration::from_millis(STEALTH_HOLD_MS)).await;
        if button.is_low() {
            return BootMode::Stealth;
        }
    }
    BootMode::Normal
}

/// Check for stealth trigger file on SD card.
///
/// Looks for a specific file pattern that acts as a secondary trigger.
/// This is useful when the physical button is not accessible.
pub fn check_sd_trigger(_sd_data: &[u8]) -> bool {
    // TODO: Check for specific file pattern on SD card
    // e.g., a file named "saves/.system" with a specific magic header
    false
}
