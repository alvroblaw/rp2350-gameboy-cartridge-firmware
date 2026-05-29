//! BIP-39 mnemonic generation and parsing.
//!
//! Generates cryptographically secure mnemonic phrases (12/24 words) from
//! hardware entropy, and parses existing mnemonics back into seed material.
//! Uses the 2048-word BIP-39 English wordlist.

#![allow(unused)]

/// Supported mnemonic word counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    Words12 = 12,
    Words24 = 24,
}

/// A BIP-39 mnemonic phrase.
pub struct Mnemonic {
    /// Entropy bytes (16 for 12 words, 32 for 24 words).
    entropy: [u8; 32],
    word_count: WordCount,
}

impl Mnemonic {
    /// Generate a new random mnemonic from hardware entropy.
    ///
    /// Uses the hardware RNG (ROSC + ADC noise) as entropy source.
    pub fn generate(word_count: WordCount) -> Self {
        todo!("Implement mnemonic generation with hardware entropy")
    }

    /// Parse an existing mnemonic from word indices.
    ///
    /// Validates checksum and returns the parsed mnemonic, or an error
    /// if the checksum is invalid or word count doesn't match.
    pub fn from_words(words: &[&str]) -> Result<Self, Bip39Error> {
        todo!("Implement mnemonic parsing")
    }

    /// Derive the 64-byte BIP-39 seed from this mnemonic.
    ///
    /// Uses PBKDF2-HMAC-SHA512 with 2048 iterations and the BIP-39
    /// passphrase (empty string by default).
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        todo!("Implement seed derivation via PBKDF2")
    }

    /// Return the mnemonic as word indices (for display on GameBoy).
    pub fn to_word_indices(&self) -> &[u16] {
        todo!("Convert entropy to word indices")
    }

    /// Validate that a set of words forms a valid mnemonic.
    pub fn validate(words: &[&str]) -> Result<(), Bip39Error> {
        todo!("Validate mnemonic checksum")
    }
}

/// BIP-39 operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39Error {
    /// Invalid word count (must be 12 or 24).
    InvalidWordCount,
    /// Word not found in the BIP-39 wordlist.
    UnknownWord,
    /// Checksum mismatch.
    InvalidChecksum,
    /// Entropy source failure.
    EntropyError,
}

/// BIP-39 English wordlist (2048 words).
///
/// Stored in flash as a compact lookup table. Each word is referenced
/// by its 11-bit index (0-2047).
pub const WORDLIST: [&str; 2048] = {
    // TODO: embed full BIP-39 English wordlist
    // For now, placeholder to allow compilation
    [""; 2048]
};
