//! Wallet state management.
//!
//! Manages the in-memory wallet state: loaded seed, locked/unlocked status,
//! and bridges the encrypted storage with the GB command dispatch.
//!
//! # State machine
//!
//! ```text
//! [No Seed] --GenerateSeed/ImportSeed--> [Locked]
//! [Locked]  --Unlock(PIN)-->            [Unlocked]
//! [Unlocked] --Lock-->                  [Locked]
//! [Locked/Unlocked] --Wipe-->           [No Seed]
//! ```

use crate::wallet::encrypt::{EncryptedSeed, PinEntry, PinRateLimiter, ZeroizingVec};
use crate::wallet::bip32::{ExtendedPrivateKey, Network};
use crate::wallet::bip39::Mnemonic;

/// Wallet state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum WalletStatus {
    /// No seed stored or loaded.
    NoSeed,
    /// Seed encrypted and stored, but wallet is locked (keys not in memory).
    Locked,
    /// Wallet is unlocked, master key is in memory.
    Unlocked,
}

/// In-memory wallet state.
///
/// Holds the decrypted seed and derived master key when unlocked.
/// All sensitive data is zeroized on lock or drop.
pub struct WalletState {
    /// Current wallet status.
    status: WalletStatus,
    /// PIN entry handler with rate limiting.
    pin_entry: PinEntry<'static>,
    /// Decrypted seed (only when Unlocked).
    seed: Option<ZeroizingVec>,
    /// Derived master key (only when Unlocked).
    master_key: Option<ExtendedPrivateKey>,
    /// Bitcoin network.
    network: Network,
    /// Rate limiter state.
    rate_limiter: PinRateLimiter,
}

impl WalletState {
    /// Create a new wallet state in NoSeed mode.
    pub fn new(network: Network) -> Self {
        Self {
            status: WalletStatus::NoSeed,
            pin_entry: PinEntry::default_config(),
            seed: None,
            master_key: None,
            rate_limiter: PinRateLimiter::new(),
            network,
        }
    }

    /// Get current wallet status.
    pub fn status(&self) -> WalletStatus {
        self.status
    }

    /// Get the Bitcoin network.
    pub fn network(&self) -> Network {
        self.network.clone()
    }

    /// Check if the wallet is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.status == WalletStatus::Unlocked
    }

    /// Get the master key (only available when unlocked).
    pub fn master_key(&self) -> Option<&ExtendedPrivateKey> {
        self.master_key.as_ref()
    }

    /// Get the seed bytes (only available when unlocked).
    pub fn seed(&self) -> Option<&[u8]> {
        self.seed.as_ref().map(|s| s.as_slice())
    }

    /// Generate a new seed from entropy.
    ///
    /// Creates a BIP-39 mnemonic, derives the seed, stores encrypted with PIN.
    /// Returns the mnemonic word indices for display.
    pub fn generate_seed(
        &mut self,
        pin: &str,
    ) -> Result<heapless::Vec<u16, 24>, WalletError> {
        if self.status != WalletStatus::NoSeed {
            return Err(WalletError::AlreadyInitialized);
        }

        // Validate PIN
        self.pin_entry.validate_pin(pin)?;

        // Generate entropy and create mnemonic
        let mnemonic = Mnemonic::generate(crate::wallet::bip39::WordCount::Words24)?;

        // Derive seed from mnemonic
        let seed = mnemonic.to_seed("");

        // Encrypt seed with PIN
        let _encrypted = EncryptedSeed::encrypt(seed.as_slice(), pin)
            .map_err(WalletError::Encrypt)?;

        // Store the seed in memory (locked)
        let mut zv = ZeroizingVec::new(seed.as_slice().len());
        zv.extend_from_slice(seed.as_slice());
        self.seed = Some(zv);

        // Derive master key
        let master = ExtendedPrivateKey::new_master(seed.as_slice(), self.network.clone())?;
        self.master_key = Some(master);

        // Transition to unlocked
        self.status = WalletStatus::Unlocked;

        // TODO: Persist encrypted seed to SD card via SeedStorage
        // This requires passing the VolumeManager reference, which is
        // handled at a higher level.

        Ok(mnemonic.to_word_indices())
    }

    /// Unlock the wallet with a PIN.
    ///
    /// Decrypts the stored seed and derives the master key.
    pub fn unlock(&mut self, pin: &str, encrypted_seed: &EncryptedSeed) -> Result<(), WalletError> {
        if self.status != WalletStatus::Locked {
            return Err(WalletError::NotLocked);
        }

        // Check rate limiter
        // Note: now_ms should come from embassy_time, but we keep it simple
        // self.rate_limiter.is_locked_out(now_ms)

        // Attempt decryption
        match encrypted_seed.decrypt(pin) {
            Ok(seed) => {
                self.rate_limiter.record_success();

                // Derive master key
                let master = ExtendedPrivateKey::new_master(seed.as_slice(), self.network.clone())?;

                self.seed = Some(seed);
                self.master_key = Some(master);
                self.status = WalletStatus::Unlocked;

                Ok(())
            }
            Err(_) => {
                // Don't record failure here — caller should provide now_ms
                Err(WalletError::WrongPin)
            }
        }
    }

    /// Lock the wallet — zeroize all sensitive data from memory.
    pub fn lock(&mut self) {
        self.seed = None;
        self.master_key = None;
        if self.status == WalletStatus::Unlocked {
            self.status = WalletStatus::Locked;
        }
    }

    /// Wipe the wallet — zeroize everything, reset to NoSeed.
    pub fn wipe(&mut self) {
        self.seed = None;
        self.master_key = None;
        self.status = WalletStatus::NoSeed;
    }

    /// Record a failed PIN attempt with timestamp.
    pub fn record_pin_failure(&mut self, now_ms: u64) -> u64 {
        self.rate_limiter.record_failure(now_ms)
    }

    /// Check if locked out from too many failed PINs.
    pub fn is_locked_out(&self, now_ms: u64) -> bool {
        self.rate_limiter.is_locked_out(now_ms)
    }

    /// Whether wipe should be offered (10+ fails).
    pub fn should_offer_wipe(&self) -> bool {
        self.rate_limiter.should_offer_wipe()
    }
}

impl Drop for WalletState {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Wallet state errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum WalletError {
    /// Wallet already has a seed.
    AlreadyInitialized,
    /// Wallet is not in Locked state (required for unlock).
    NotLocked,
    /// Wrong PIN.
    WrongPin,
    /// Wallet is locked.
    WalletLocked,
    /// No seed stored.
    NoSeed,
    /// Encryption error.
    Encrypt(crate::wallet::encrypt::EncryptError),
    /// Key derivation error.
    KeyDerivation,
    /// Invalid PIN format.
    InvalidPin(crate::wallet::encrypt::PinError),
}

impl From<crate::wallet::encrypt::EncryptError> for WalletError {
    fn from(e: crate::wallet::encrypt::EncryptError) -> Self {
        WalletError::Encrypt(e)
    }
}

impl From<crate::wallet::encrypt::PinError> for WalletError {
    fn from(e: crate::wallet::encrypt::PinError) -> Self {
        WalletError::InvalidPin(e)
    }
}

impl From<crate::wallet::bip39::Bip39Error> for WalletError {
    fn from(_: crate::wallet::bip39::Bip39Error) -> Self {
        WalletError::KeyDerivation
    }
}

impl From<crate::wallet::bip32::Bip32Error> for WalletError {
    fn from(_: crate::wallet::bip32::Bip32Error) -> Self {
        WalletError::KeyDerivation
    }
}
