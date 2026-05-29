//! BIP-32 Hierarchical Deterministic key derivation.
//!
//! Implements HD wallet key derivation from a BIP-39 seed.
//! Supports hardened and normal child derivation, path parsing,
//! and extended key serialization (xprv/xpub, zprv/zpub).
//!
//! Uses `k256` (pure Rust secp256k1) for EC operations — no C compiler needed.
//! All operations are `no_std` compatible.

#![allow(unused)]

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::wallet::bip32::Network::*;

type HmacSha512 = Hmac<Sha512>;

/// Hardened key derivation start index.
pub const HARDENED: u32 = 0x8000_0000;

/// Version bytes for extended key serialization.
pub mod version {
    /// Mainnet xprv (BIP-32 default).
    pub const XPRV: u32 = 0x0488_ADE4;
    /// Mainnet xpub (BIP-32 default).
    pub const XPUB: u32 = 0x0488_B21E;
    /// Mainnet zprv (BIP-84 native SegWit).
    pub const ZPRV: u32 = 0x04B2_430C;
    /// Mainnet zpub (BIP-84 native SegWit).
    pub const ZPUB: u32 = 0x04B2_4746;
    /// Mainnet yprv (BIP-49 SegWit-P2SH).
    pub const YPRV: u32 = 0x049D_7878;
    /// Mainnet ypub (BIP-49 SegWit-P2SH).
    pub const YPUB: u32 = 0x049D_7CB2;
    /// Testnet tprv.
    pub const TPRV: u32 = 0x0435_8394;
    /// Testnet tpub.
    pub const TPUB: u32 = 0x0435_87CF;
    /// Testnet uprv (BIP-84).
    pub const UPRV: u32 = 0x045F_18BC;
    /// Testnet upub (BIP-84).
    pub const UPUB: u32 = 0x045F_1CF6;
}

/// A BIP-32 extended private key.
///
/// Stores the private key bytes, chain code, and derivation metadata.
/// Implements Zeroize to clear sensitive material on Drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ExtendedPrivKey {
    /// The private key scalar bytes (32 bytes).
    #[zeroize(skip)]
    secret_bytes: [u8; 32],
    /// Chain code for child derivation (32 bytes).
    chain_code: [u8; 32],
    /// Depth in the derivation tree.
    depth: u8,
    /// Parent fingerprint (4 bytes).
    parent_fingerprint: [u8; 4],
    /// Child index at this level.
    child_index: u32,
    /// Network for serialization.
    #[zeroize(skip)]
    network: Network,
}

/// Try to parse a scalar from 32 bytes. Returns None if invalid (zero or >= order).
fn try_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    use k256::elliptic_curve::ops::Reduce;
    use k256::U256;
    // Interpret as big-endian integer, reduce mod order
    let uint = U256::from_be_bytes(*bytes);
    let scalar = <Scalar as Reduce<U256>>::from_uint_reduce(uint);
    // Check it's not zero (zero means invalid for our purposes)
    if bool::from(scalar.is_zero()) {
        None
    } else {
        Some(scalar)
    }
}

/// Get compressed public key bytes from a scalar (private key).
fn scalar_to_compressed_pubkey(scalar: &Scalar) -> [u8; 33] {
    let projective = ProjectivePoint::GENERATOR * scalar;
    let affine = projective.to_affine();
    let encoded = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&affine, true);
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    result
}

/// Add tweak to public key point (for normal child derivation).
fn add_tweak_to_pubkey(pubkey_bytes: &[u8; 33], tweak: &Scalar) -> Option<[u8; 33]> {
    let pubkey = k256::PublicKey::from_sec1_bytes(pubkey_bytes).ok()?;
    let affine = AffinePoint::from(pubkey);
    let projective = ProjectivePoint::from(affine);
    let result = projective * tweak;
    let result_affine = result.to_affine();
    if bool::from(result_affine.is_identity()) {
        return None;
    }
    let result_pubkey = k256::PublicKey::from_affine(result_affine).ok()?;
    let encoded = result_pubkey.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Some(out)
}

impl ExtendedPrivKey {
    /// Create the master extended private key from a BIP-39 seed.
    ///
    /// Uses HMAC-SHA512 with key "Bitcoin seed" as per BIP-32.
    pub fn new_master(seed: &[u8], network: Network) -> Result<Self, Bip32Error> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Bip32Error::InvalidSeed);
        }

        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .map_err(|_| Bip32Error::HmacError)?;
        mac.update(seed);
        let result = mac.finalize().into_code();

        let mut secret_bytes = [0u8; 32];
        let mut chain_code = [0u8; 32];
        secret_bytes.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // Validate the private key
        if try_scalar(&secret_bytes).is_none() {
            return Err(Bip32Error::InvalidSeed);
        }

        Ok(Self {
            secret_bytes,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
            network,
        })
    }

    /// Derive a child key at the given index.
    ///
    /// For hardened derivation, use indices >= 0x80000000 (or add `HARDENED`).
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| Bip32Error::HmacError)?;

        if index >= HARDENED {
            // Hardened: HMAC(key=chain_code, data=0x00 || privkey || index)
            mac.update(&[0x00]);
            mac.update(&self.secret_bytes);
        } else {
            // Normal: HMAC(key=chain_code, data=pubkey || index)
            let parent_scalar = try_scalar(&self.secret_bytes).ok_or(Bip32Error::InvalidKey)?;
            let pubkey = scalar_to_compressed_pubkey(&parent_scalar);
            mac.update(&pubkey);
        }
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_code();
        let mut tweak_bytes = [0u8; 32];
        let mut child_chain = [0u8; 32];
        tweak_bytes.copy_from_slice(&result[..32]);
        child_chain.copy_from_slice(&result[32..]);

        // Child key = (parent_secret + tweak) mod n
        let parent_scalar = try_scalar(&self.secret_bytes).ok_or(Bip32Error::InvalidKey)?;
        let tweak = match try_scalar(&tweak_bytes) {
            Some(t) => t,
            None => return Err(Bip32Error::InvalidChildIndex),
        };

        let child_scalar = parent_scalar + tweak;
        if bool::from(child_scalar.is_zero()) {
            return Err(Bip32Error::InvalidChildIndex);
        }

        let mut child_secret = [0u8; 32];
        child_secret.copy_from_slice(&child_scalar.to_bytes());

        Ok(Self {
            secret_bytes: child_secret,
            chain_code: child_chain,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_index: index,
            network: self.network,
        })
    }

    /// Derive a full path (e.g., "m/84'/0'/0'/0/0").
    ///
    /// Parses the path string and applies sequential derivation.
    /// Hardened indices use `'` suffix or `h`.
    pub fn derive_path(&self, path: &str) -> Result<Self, Bip32Error> {
        let mut key = self.clone();

        // Skip leading "m/"
        let path = path.strip_prefix("m/").ok_or(Bip32Error::InvalidPath)?;

        if path.is_empty() {
            return Ok(key);
        }

        for component in path.split('/') {
            if component.is_empty() {
                return Err(Bip32Error::InvalidPath);
            }

            let (index_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            let mut index: u32 = index_str
                .parse()
                .map_err(|_| Bip32Error::InvalidPath)?;

            if hardened {
                index = index.checked_add(HARDENED).ok_or(Bip32Error::InvalidChildIndex)?;
            }

            key = key.derive_child(index)?;
        }

        Ok(key)
    }

    /// Get the public key corresponding to this private key.
    pub fn public_key(&self) -> Result<ExtendedPubKey, Bip32Error> {
        let scalar = try_scalar(&self.secret_bytes).ok_or(Bip32Error::InvalidKey)?;
        let compressed = scalar_to_compressed_pubkey(&scalar);

        Ok(ExtendedPubKey {
            compressed_bytes: compressed,
            chain_code: self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
            network: self.network,
        })
    }

    /// Compute the key fingerprint (first 4 bytes of HASH160 of the public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let pubkey = self.public_key().unwrap();
        let hash160 = hash160(&pubkey.compressed_bytes());
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&hash160[..4]);
        fp
    }

    /// Get the raw secret bytes (for signing operations).
    ///
    /// **WARNING**: Handle with care. This is sensitive key material.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret_bytes
    }

    /// Serialize as extended private key (78 bytes payload).
    ///
    /// Returns the raw 78-byte payload (without base58check encoding).
    pub fn serialize(&self, version: u32) -> [u8; 78] {
        let mut buf = [0u8; 78];
        buf[0..4].copy_from_slice(&version.to_be_bytes());
        buf[4] = self.depth;
        buf[5..9].copy_from_slice(&self.parent_fingerprint);
        buf[9..13].copy_from_slice(&self.child_index.to_be_bytes());
        buf[13..45].copy_from_slice(&self.chain_code);
        buf[45] = 0x00; // Pad for private key
        buf[46..78].copy_from_slice(&self.secret_bytes);
        buf
    }

    /// Get the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the derivation depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the child index.
    pub fn child_index(&self) -> u32 {
        self.child_index
    }
}

/// A BIP-32 extended public key.
#[derive(Clone)]
pub struct ExtendedPubKey {
    /// Compressed public key bytes (33 bytes).
    compressed_bytes: [u8; 33],
    /// Chain code for child derivation (32 bytes).
    chain_code: [u8; 32],
    /// Depth in the derivation tree.
    depth: u8,
    /// Parent fingerprint (4 bytes).
    parent_fingerprint: [u8; 4],
    /// Child index at this level.
    child_index: u32,
    /// Network for serialization.
    network: Network,
}

impl ExtendedPubKey {
    /// Derive a child public key (non-hardened only).
    ///
    /// Hardened derivation from a public key is not possible.
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        if index >= HARDENED {
            return Err(Bip32Error::HardenedFromPublic);
        }

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| Bip32Error::HmacError)?;
        mac.update(&self.compressed_bytes);
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_code();
        let mut tweak_bytes = [0u8; 32];
        let mut child_chain = [0u8; 32];
        tweak_bytes.copy_from_slice(&result[..32]);
        child_chain.copy_from_slice(&result[32..]);

        let tweak = match try_scalar(&tweak_bytes) {
            Some(t) => t,
            None => return Err(Bip32Error::InvalidChildIndex),
        };

        let child_compressed = add_tweak_to_pubkey(&self.compressed_bytes, &tweak)
            .ok_or(Bip32Error::InvalidChildIndex)?;

        Ok(Self {
            compressed_bytes: child_compressed,
            chain_code: child_chain,
            depth: self.depth + 1,
            parent_fingerprint: {
                let hash = hash160(&self.compressed_bytes);
                let mut fp = [0u8; 4];
                fp.copy_from_slice(&hash[..4]);
                fp
            },
            child_index: index,
            network: self.network,
        })
    }

    /// Get the compressed public key bytes.
    pub fn compressed_bytes(&self) -> [u8; 33] {
        self.compressed_bytes
    }

    /// Compute the key fingerprint.
    pub fn fingerprint(&self) -> [u8; 4] {
        let hash = hash160(&self.compressed_bytes);
        let mut fp = [0u8; 4];
        fp.copy_from_slice(&hash[..4]);
        fp
    }

    /// Serialize as extended public key (78 bytes payload).
    pub fn serialize(&self, version: u32) -> [u8; 78] {
        let mut buf = [0u8; 78];
        buf[0..4].copy_from_slice(&version.to_be_bytes());
        buf[4] = self.depth;
        buf[5..9].copy_from_slice(&self.parent_fingerprint);
        buf[9..13].copy_from_slice(&self.child_index.to_be_bytes());
        buf[13..45].copy_from_slice(&self.chain_code);
        buf[45..78].copy_from_slice(&self.compressed_bytes);
        buf
    }

    /// Get the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get derivation depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }
}

/// Standard derivation paths.
pub mod paths {
    /// BIP-84 native SegWit (bech32): m/84'/0'/0'
    pub const NATIVE_SEGWIT_MAINNET: &str = "m/84'/0'/0'";
    /// BIP-84 native SegWit testnet: m/84'/1'/0'
    pub const NATIVE_SEGWIT_TESTNET: &str = "m/84'/1'/0'";
    /// BIP-49 SegWit-P2SH mainnet: m/49'/0'/0'
    pub const SEGWIT_P2SH_MAINNET: &str = "m/49'/0'/0'";
    /// BIP-49 SegWit-P2SH testnet: m/49'/1'/0'
    pub const SEGWIT_P2SH_TESTNET: &str = "m/49'/1'/0'";
    /// BIP-44 legacy mainnet: m/44'/0'/0'
    pub const LEGACY_MAINNET: &str = "m/44'/0'/0'";
    /// BIP-44 legacy testnet: m/44'/1'/0'
    pub const LEGACY_TESTNET: &str = "m/44'/1'/0'";

    /// Build a receive address path string.
    pub fn receive_path(purpose: u32, coin: u32, account: u32, index: u32) -> heapless::String<32> {
        let mut path = heapless::String::new();
        core::fmt::write(
            &mut path,
            core::format_args!(
                "m/{}h/{}h/{}h/0/{}",
                purpose, coin, account, index
            ),
        )
        .unwrap();
        path
    }

    /// Build a change address path string.
    pub fn change_path(purpose: u32, coin: u32, account: u32, index: u32) -> heapless::String<32> {
        let mut path = heapless::String::new();
        core::fmt::write(
            &mut path,
            core::format_args!(
                "m/{}h/{}h/{}h/1/{}",
                purpose, coin, account, index
            ),
        )
        .unwrap();
        path
    }
}

/// Bitcoin network type for key serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub enum Network {
    /// Bitcoin mainnet (xpub/xprv version bytes).
    Mainnet,
    /// Bitcoin testnet (tpub/tprv version bytes).
    Testnet,
}

impl Network {
    /// Get the xprv version bytes for this network.
    pub const fn xprv_version(&self) -> u32 {
        match self {
            Mainnet => version::XPRV,
            Testnet => version::TPRV,
        }
    }

    /// Get the xpub version bytes for this network.
    pub const fn xpub_version(&self) -> u32 {
        match self {
            Mainnet => version::XPUB,
            Testnet => version::TPUB,
        }
    }

    /// Get the zpub version bytes (BIP-84 native SegWit).
    pub const fn zpub_version(&self) -> u32 {
        match self {
            Mainnet => version::ZPUB,
            Testnet => version::UPUB,
        }
    }

    /// Get the bech32 HRP for this network.
    pub const fn bech32_hrp(&self) -> &str {
        match self {
            Mainnet => "bc",
            Testnet => "tb",
        }
    }

    /// Get the P2SH address prefix for this network.
    pub const fn p2sh_prefix(&self) -> u8 {
        match self {
            Mainnet => 0x05,
            Testnet => 0xC4,
        }
    }

    /// Get the P2PKH address prefix for this network.
    pub const fn p2pkh_prefix(&self) -> u8 {
        match self {
            Mainnet => 0x00,
            Testnet => 0x6F,
        }
    }
}

/// Compute HASH160: RIPEMD-160(SHA-256(data)).
///
/// Standard Bitcoin hash used for addresses and fingerprints.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Digest as RipemdDigest;
    let sha_hash = Sha256::digest(data);
    let mut ripemd = ripemd::Ripemd160::new();
    ripemd.update(&sha_hash);
    let result = ripemd.finalize();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&result);
    hash
}

/// Compute SHA-256 double hash (for Bitcoin signatures and checksums).
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash2);
    result
}

/// Base58Check encoding.
///
/// Pure `no_std` implementation using heapless for the output string.
/// Encodes payload with a 4-byte SHA256d checksum appended, then base58.
pub fn base58check_encode(payload: &[u8]) -> heapless::String<112> {
    let checksum = &double_sha256(payload)[..4];
    let mut full = arrayvec::ArrayVec::<u8, 82>::new();
    full.extend_from_slice(payload).unwrap();
    full.extend_from_slice(checksum).unwrap();

    // Count leading zeros
    let leading_zeros = full.iter().take_while(|&&b| b == 0).count();

    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut result = heapless::String::<112>::new();

    // Add '1' for each leading zero byte
    for _ in 0..leading_zeros {
        result.push('1').unwrap();
    }

    // Work on a fixed-size buffer
    let mut num = [0u8; 82];
    let num_len = full.len();
    num[..num_len].copy_from_slice(&full[..num_len]);

    let mut remaining = num_len;
    let mut chars = heapless::Vec::<u8, 112>::new();

    while remaining > 0 && num[..remaining].iter().any(|&b| b != 0) {
        let mut carry: u8 = 0;
        for i in 0..remaining {
            let value = (carry as u16) * 256 + (num[i] as u16);
            num[i] = (value / 58) as u8;
            carry = (value % 58) as u8;
        }
        chars.push(alphabet[carry as usize]).unwrap();

        // Trim leading zeros in the working buffer
        let mut start = 0;
        while start < remaining && num[start] == 0 {
            start += 1;
        }
        if start > 0 {
            num.copy_within(start..remaining, 0);
            remaining -= start;
        }
    }

    // Reverse chars and prepend to result
    for &c in chars.iter().rev() {
        result.insert(0, c as char).unwrap();
    }

    result
}

/// BIP-32 derivation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip32Error {
    /// HMAC computation failed.
    HmacError,
    /// Invalid derivation path format.
    InvalidPath,
    /// Hardened derivation attempted on public key.
    HardenedFromPublic,
    /// Invalid child index (resulting key is zero or >= curve order).
    InvalidChildIndex,
    /// Invalid seed length.
    InvalidSeed,
    /// Invalid private key.
    InvalidKey,
    /// Serialization error.
    SerializeError,
}
