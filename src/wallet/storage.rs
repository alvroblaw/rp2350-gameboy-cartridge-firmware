//! Encrypted seed persistence on SD card.
//!
//! Stores and retrieves encrypted seed data on the SD card filesystem.
//! The seed file is stored with a non-obvious filename to support
//! the stealth wallet concept (plausible deniability).

#![allow(unused)]

use crate::wallet::encrypt::EncryptedSeed;

/// Seed storage on SD card.
pub struct SeedStorage {
    /// Whether a seed file exists on the SD card.
    has_seed: bool,
}

impl SeedStorage {
    /// Create a new seed storage instance.
    pub fn new() -> Self {
        Self { has_seed: false }
    }

    /// Check if a seed file exists on the SD card.
    pub fn seed_exists(&self) -> bool {
        self.has_seed
    }

    /// Read the encrypted seed from the SD card.
    pub fn read_seed(&self) -> Result<EncryptedSeed, StorageError> {
        todo!("Read encrypted seed file from SD card")
    }

    /// Write the encrypted seed to the SD card.
    pub fn write_seed(&mut self, seed: &EncryptedSeed) -> Result<(), StorageError> {
        todo!("Write encrypted seed file to SD card")
    }

    /// Delete the seed file from the SD card (secure wipe).
    pub fn delete_seed(&mut self) -> Result<(), StorageError> {
        todo!("Overwrite and delete seed file from SD card")
    }
}

/// Stealth filename for the seed file.
/// Disguised as a GameBoy save file to avoid suspicion.
pub const SEED_FILENAME: &str = "saves/system.sav";

/// Storage operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// SD card not present or not initialized.
    NoSdCard,
    /// Filesystem error.
    FsError,
    /// Seed file not found.
    SeedNotFound,
    /// Seed file corrupted (wrong size).
    CorruptedSeed,
    /// Write error.
    WriteError,
    /// Read error.
    ReadError,
}
