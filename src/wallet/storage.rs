//! Encrypted seed persistence on SD card.
//!
//! Stores and retrieves the encrypted seed on the SD card.
//! The seed file is disguised to avoid detection (stealth requirement).
//!
//! **Phase 4 scope** — this module is a stub until storage is implemented.

#![allow(unused)]

/// Seed storage manager.
///
/// Handles reading and writing encrypted seed data to SD card.
/// The file is stored with a disguised name (e.g., as a GameBoy save file).
pub struct SeedStorage {
    /// Whether a seed file exists on the SD card.
    has_seed: bool,
}

impl SeedStorage {
    /// Create a new seed storage instance.
    pub const fn new() -> Self {
        Self { has_seed: false }
    }

    /// Check if a seed file exists on the SD card.
    pub fn has_seed(&self) -> bool {
        self.has_seed
    }

    /// Store an encrypted seed to SD card.
    ///
    /// The seed is written to a disguised file location.
    pub fn store(&mut self, encrypted: &[u8; 108]) -> Result<(), StorageError> {
        todo!("Phase 4: implement seed storage on SD card")
    }

    /// Load the encrypted seed from SD card.
    pub fn load(&self) -> Result<[u8; 108], StorageError> {
        todo!("Phase 4: implement seed loading from SD card")
    }

    /// Delete the seed file from SD card (secure wipe).
    pub fn wipe(&mut self) -> Result<(), StorageError> {
        todo!("Phase 4: implement secure seed deletion")
    }
}

/// Storage errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// No seed file found.
    NotFound,
    /// SD card I/O error.
    IoError,
    /// File system error.
    FsError,
    /// Corrupted seed file.
    Corrupted,
}
