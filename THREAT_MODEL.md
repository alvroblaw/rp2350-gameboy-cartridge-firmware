# Threat Model: Bitcoin Stealth Wallet on RP2350 GameBoy Cartridge

## Assets

| Asset | Location | Value |
|-------|----------|-------|
| **BIP-39 seed** | Encrypted on SD card; decrypted in SRAM during use | Critical — controls all funds |
| **PIN** | Only in user's memory; processed in SRAM | High — protects seed at rest |
| **Derived private keys** | Ephemeral in SRAM during signing | High — can sign transactions |
| **Extended public key (xpub)** | Generated on demand; may be cached | Medium — reveals balances + addresses |
| **Firmware binary** | Flash memory | Medium — contains wallet logic |
| **Encryption key** | Derived from PIN in SRAM during session | High — can decrypt seed |

## Attackers

### Attacker 1: Casual Observer
- **Capability**: Physical access to GameBoy + cartridge
- **Goal**: Discover that the cartridge is a wallet
- **Threat Level**: LOW (stealth is primary defense)

### Attacker 2: Thief
- **Capability**: Steals the cartridge, has a computer
- **Goal**: Extract seed/funds
- **Threat Level**: MEDIUM

### Attacker 3: Forensic Analyst
- **Capability**: Full lab equipment, SD card forensics, firmware extraction
- **Goal**: Prove wallet exists, extract seed
- **Threat Level**: HIGH

### Attacker 4: Malicious USB Host
- **Capability**: Sends crafted USB packets
- **Goal**: Exploit firmware bugs, extract keys
- **Threat Level**: MEDIUM

### Attacker 5: Supply Chain
- **Capability**: Modifies firmware before deployment
- **Goal**: Backdoor the wallet
- **Threat Level**: LOW (user builds from source)

## Threats and Mitigations

### T1: Physical Seed Extraction from SD Card

**Threat**: Attacker removes SD card, reads encrypted seed file.
**Impact**: CRITICAL (if they can decrypt it)
**Mitigation**:
- Seed encrypted with AES-256-GCM using PIN-derived key (PBKDF2, 100k iterations)
- File disguised as a save game file
- Without PIN, seed is cryptographically protected
**Residual risk**: Bruteforce PIN if weak (4 digits = 10k combinations)

### T2: Firmware Analysis Reveals Wallet

**Threat**: Someone dumps the flash and finds wallet code.
**Impact**: MEDIUM (stealth broken, but seed still encrypted)
**Mitigation**:
- Wallet mode only activates with secret trigger
- In normal mode, firmware behaves identically to original flashcart
- Plausible deniability: "It's just a flashcart with extra features"
**Residual risk**: Wallet code is clearly visible in firmware binary

### T3: SRAM Key Extraction (Cold Boot)

**Threat**: Attacker powers off cartridge and dumps SRAM before it decays.
**Impact**: HIGH (keys in memory)
**Mitigation**:
- Zeroize key material immediately after use
- Keys only in memory during active wallet session
- SRAM4/SRAM5 (direct-mapped banks) used for key material — cleared on wipe
**Residual risk**: Physical cold boot attacks possible with specialized equipment

### T4: Malicious USB Commands

**Threat**: Host sends crafted USB packets to exploit parser bugs.
**Impact**: HIGH (potential code execution)
**Mitigation**:
- Minimal USB protocol surface — only 4 commands
- Strict frame validation (SOP/EOP, length limits)
- No dynamic memory allocation in USB handler
- PSBT parser must be fuzz-tested
**Residual risk**: Parser bugs could cause crashes or unexpected behavior

### T5: PIN Bruteforce

**Threat**: Attacker with encrypted seed tries all PINs.
**Impact**: CRITICAL (seed compromised)
**Mitigation**:
- Rate limiting: exponential backoff after failed attempts
- Lockout after configurable failed attempts (default: 10)
- Optional: wipe seed after N failures (configurable)
- PBKDF2 with 100k iterations makes each attempt ~1s on RP2350
**Residual risk**: 4-digit PIN with 10k attempts at 1s each = ~3 hours max

### T6: Side-Channel Attacks

**Threat**: Timing/power analysis during crypto operations.
**Impact**: MEDIUM (key recovery)
**Mitigation**:
- Use constant-time crypto implementations where available
- secp256k1 library should be side-channel aware
**Residual risk**: No formal side-channel audit planned

### T7: GameBoy Bus Sniffing

**Threat**: Someone monitors the GB cartridge bus during wallet operation.
**Impact**: LOW (addresses and amounts visible, not keys)
**Mitigation**:
- Private keys never transmitted over GB bus
- Only display data and commands go over SRAM channel
**Residual risk**: Transaction amounts and addresses observable

### T8: Firmware Downgrade

**Threat**: Attacker flashes older firmware with known vulnerabilities.
**Impact**: MEDIUM
**Mitigation**:
- Firmware can be signed (RP2350 supports secure boot)
- User should verify firmware integrity
**Residual risk**: Secure boot not enabled by default

## Residual Risks

1. **Weak PIN**: User chooses "1234" — all encryption defeated. Mitigation: minimum PIN length enforcement + entropy check.
2. **Physical access during session**: If attacker gets cartridge while wallet is unlocked, keys are in SRAM. Mitigation: auto-lock timeout.
3. **SD card loss**: If SD card is separated from cartridge, seed backup is lost. Mitigation: encourage mnemonic backup on paper.
4. **No secure element**: RP2350 does not have a secure element like modern hardware wallets. Keys are software-protected only.

## Future Improvements

### Short-term (before mainnet use)
- [ ] Minimum PIN length (6+ digits) with entropy check
- [ ] Auto-lock timeout (5 minutes of inactivity)
- [ ] PSBT parser fuzz testing
- [ ] Firmware integrity hash verification at boot

### Medium-term (v2)
- [ ] Secure boot with signed firmware
- [ ] ARM TrustZone isolation for wallet code
- [ ] Optional BIP-39 passphrase (25th word) for plausible deniability
- [ ] HWI compatibility for standard wallet software integration

### Long-term (v3 — stateless mode)
- [ ] Camera module for QR code seed scanning
- [ ] Stateless operation: seed only in RAM during session
- [ ] QR code output for signed PSBTs
- [ ] Air-gapped operation (no USB needed)
