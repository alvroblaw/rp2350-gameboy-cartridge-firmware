//! Encrypted seed persistence on SD card.
//!
//! Stores and retrieves the encrypted seed on the SD card, disguised as a
//! GameBoy save file. The file name and location mimic a legitimate save so
//! that casual browsing of the SD card reveals nothing unusual.
//!
//! # Stealth
//!
//! The seed is stored at `saves/PKMN_BLUE.sav` — a path that looks like a
//! Pokémon Blue save file. The content is the raw encrypted seed bytes, not
//! a valid GB save, but this is indistinguishable without parsing.
//!
//! # Dependencies
//!
//! Uses `embedded_sdmmc` via the existing `VolumeManager` integration.
//! All operations are `no_std`.

#![no_std]
#![allow(unused)]

use embedded_sdmmc::{DirEntry, ModeFlags, Volume, VolumeManager};
use defmt::{info, warn, error};

use crate::wallet::encrypt::{EncryptedSeed, EncryptError};

/// Disguised file path for the encrypted seed on SD card.
///
/// Looks like a normal GameBoy save file.
const SEED_DIR: &str = "saves";
const SEED_FILENAME: &str = "PKMN_BLUE";
const SEED_EXTENSION: &str = "sav";

/// Maximum serialized encrypted seed size (64-byte seed + 44 overhead + 1 seed_len byte).
const MAX_SEED_FILE_SIZE: usize = 109;

/// Seed storage errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum StorageError {
    /// No seed file found.
    NotFound,
    /// SD card I/O error.
    IoError,
    /// File system error (directory not found, etc.).
    FsError,
    /// Corrupted seed file (wrong size, bad magic).
    Corrupted,
    /// Encryption error during store/load.
    EncryptError(EncryptError),
}

impl From<EncryptError> for StorageError {
    fn from(e: EncryptError) -> Self {
        StorageError::EncryptError(e)
    }
}

/// Seed storage manager.
///
/// Handles reading and writing encrypted seed data to SD card.
/// Parameterized over the volume manager type for testability.
pub struct SeedStorage<'vol> {
    /// Reference to the SD card volume manager.
    volume: Volume<'vol>,
}

impl<'vol> SeedStorage<'vol> {
    /// Create a new seed storage from an open volume.
    pub fn new(volume: Volume<'vol>) -> Self {
        Self { volume }
    }

    /// Store an encrypted seed to SD card.
    ///
    /// Writes the serialized encrypted seed to the disguised file location.
    /// Overwrites any existing seed file.
    pub fn store(&mut self, encrypted: &EncryptedSeed) -> Result<(), StorageError> {
        let bytes = encrypted.to_bytes();

        // Open or create the saves directory
        let mut root_dir = self.volume.open_root_dir().map_err(|_| StorageError::FsError)?;

        // Try to open/create the saves directory
        let dir_exists = root_dir.open_dir(SEED_DIR).is_ok();
        if !dir_exists {
            root_dir.create_dir(SEED_DIR).map_err(|_| StorageError::FsError)?;
        }

        // Open (or create) the seed file
        let mut file = root_dir
            .open_file_in_dir(
                SEED_DIR,
                SEED_FILENAME,
                ModeFlags::CREATE_OR_TRUNCATE_WITH_WRITE,
            )
            .map_err(|e| {
                warn!("Failed to open seed file: {:?}", defmt::Debug2Format(&e));
                StorageError::IoError
            })?;

        // Write the encrypted seed bytes
        file.write(&bytes).map_err(|e| {
            warn!("Failed to write seed: {:?}", defmt::Debug2Format(&e));
            StorageError::IoError
        })?;

        info!("Seed stored ({} bytes)", bytes.len());
        Ok(())
    }

    /// Load the encrypted seed from SD card.
    ///
    /// Reads the disguised file and deserializes into an `EncryptedSeed`.
    pub fn load(&mut self) -> Result<EncryptedSeed, StorageError> {
        let mut root_dir = self.volume.open_root_dir().map_err(|_| StorageError::FsError)?;

        let mut file = root_dir
            .open_file_in_dir(
                SEED_DIR,
                SEED_FILENAME,
                ModeFlags::READ_ONLY,
            )
            .map_err(|e| {
                warn!("Seed file not found: {:?}", defmt::Debug2Format(&e));
                StorageError::NotFound
            })?;

        // Read the file contents into a buffer
        let mut buf = [0u8; MAX_SEED_FILE_SIZE];
        let mut total = 0;
        loop {
            match file.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if total >= MAX_SEED_FILE_SIZE {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Error reading seed file: {:?}", defmt::Debug2Format(&e));
                    return Err(StorageError::IoError);
                }
            }
        }

        if total == 0 {
            return Err(StorageError::Corrupted);
        }

        EncryptedSeed::from_bytes(&buf[..total]).map_err(|e| {
            warn!("Failed to deserialize seed: {:?}", defmt::Debug2Format(&e));
            StorageError::Corrupted
        })
    }

    /// Secure wipe: overwrite the seed file with zeros, then delete it.
    ///
    /// This prevents forensic recovery of the encrypted seed from the SD card.
    pub fn wipe(&mut self) -> Result<(), StorageError> {
        let mut root_dir = self.volume.open_root_dir().map_err(|_| StorageError::FsError)?;

        // First, try to overwrite with zeros
        if let Ok(mut file) = root_dir.open_file_in_dir(
            SEED_DIR,
            SEED_FILENAME,
            ModeFlags::WRITE_ONLY,
        ) {
            let zeros = [0u8; MAX_SEED_FILE_SIZE];
            let _ = file.write(&zeros);
            info!("Seed file overwritten with zeros");
        }

        // Then delete the file
        root_dir
            .delete_file_in_dir(SEED_DIR, SEED_FILENAME)
            .map_err(|e| {
                warn!("Failed to delete seed file: {:?}", defmt::Debug2Format(&e));
                StorageError::IoError
            })?;

        info!("Seed file wiped and deleted");
        Ok(())
    }

    /// Check if a seed file exists on the SD card.
    pub fn has_seed(&mut self) -> bool {
        let root_dir = match self.volume.open_root_dir() {
            Ok(d) => d,
            Err(_) => return false,
        };

        // Try to open the file for reading
        root_dir
            .open_file_in_dir(SEED_DIR, SEED_FILENAME, ModeFlags::READ_ONLY)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_path_format() {
        // Verify the disguise looks legit
        assert_eq!(SEED_FILENAME, "PKMN_BLUE");
        assert_eq!(SEED_EXTENSION, "sav");
        assert_eq!(SEED_DIR, "saves");
    }
}
