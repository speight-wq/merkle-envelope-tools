# Merkle Envelope Tools — Threat Model

## What This Tool Is

An offline transaction signing system using Merkle proofs with PoW attestation. Designed for air-gapped cold storage of BSV.

**Important:** This is NOT full SPV as described in the Bitcoin whitepaper. We verify Merkle inclusion and Proof-of-Work, but do not verify longest chain or cumulative work. We trust the envelope source to provide headers from the real chain.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  ONLINE ENVIRONMENT (untrusted)                             │
│  ┌─────────────┐      ┌─────────────┐                       │
│  │ WhatsOnChain│ ──── │  Generator  │                       │
│  │    API      │      │   .html     │                       │
│  └─────────────┘      └──────┬──────┘                       │
│                              │ Merkle Envelope (JSON)       │
└──────────────────────────────┼──────────────────────────────┘
                               │ AIR GAP (USB/QR/manual)
┌──────────────────────────────┼──────────────────────────────┐
│  OFFLINE ENVIRONMENT (trusted)                              │
│                              ▼                              │
│                       ┌─────────────┐                       │
│                       │  Verifier   │                       │
│                       │   .html     │                       │
│                       └──────┬──────┘                       │
│                              │ Verified envelope            │
│                              ▼                              │
│  ┌─────────────┐      ┌─────────────┐                       │
│  │ Private Key │ ──── │   Signer    │                       │
│  │   (WIF)     │      │   .html     │                       │
│  └─────────────┘      └──────┬──────┘                       │
│                              │ Signed TX (hex)              │
└──────────────────────────────┼──────────────────────────────┘
                               │ AIR GAP
┌──────────────────────────────┼──────────────────────────────┐
│  ONLINE ENVIRONMENT                                         │
│                              ▼                              │
│                       ┌─────────────┐                       │
│                       │  Broadcast  │                       │
│                       │ (WoC/node)  │                       │
│                       └─────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

---

## What It Protects Against

| Threat | Protection | How |
|--------|------------|-----|
| **Remote key theft** | ✓ Strong | Private key never touches networked device |
| **Malware on online machine** | ✓ Strong | Key never present on compromised machine |
| **Fake transaction data** | ✓ Strong | Merkle proof + PoW validated offline |
| **Fake block headers (easy)** | ✓ Strong | Hash must meet difficulty target |
| **Inflated UTXO value** | ✓ Strong | Value extracted from validated rawTx |
| **Man-in-the-middle API** | ✓ Strong | All responses cryptographically verified |
| **CVE-2012-2459** | ✓ Strong | Duplicate merkle nodes rejected |
| **Trivial difficulty attack** | ✓ Strong | Target must be ≤ genesis difficulty |

---

## What It Does NOT Protect Against

| Threat | Risk | Why |
|--------|------|-----|
| **Compromised offline machine** | CRITICAL | If attacker has code execution on signing machine, key is exposed |
| **Supply chain attack on tool** | CRITICAL | Malicious HTML file could exfiltrate key via QR/signed TX |
| **Visual address spoofing** | HIGH | User must manually verify destination address |
| **Clipboard hijacking (offline)** | HIGH | Malware could swap destination address |
| **Physical observation** | HIGH | Shoulder surfing, cameras can capture key/screen |
| **Spent UTXO** | MEDIUM | Valid envelope for already-spent output (TX will fail to broadcast, no fund loss) |
| **Orphan block proof** | LOW | Valid proof from orphaned block (TX will fail, no fund loss) |
| **Reorg attack** | LOW | Deep reorg could invalidate proof (wait for 6+ confirmations) |
| **Side-channel attacks** | LOW | JS BigInt timing could theoretically leak key bits |
| **Browser vulnerabilities** | MEDIUM | Zero-day in offline browser could compromise signing |

---

## Environment Assumptions

### For Security Guarantees to Hold:

1. **Offline machine is actually offline**
   - No WiFi, Bluetooth, or any network capability
   - No connection since before key was loaded
   - Ideally: dedicated device, live-booted OS

2. **Tool files are authentic**
   - Downloaded from trusted source
   - Verified via checksum/signature
   - Not modified after download

3. **Offline machine is malware-free**
   - Clean OS install or verified live boot
   - No untrusted software installed
   - No previous exposure to threats

4. **Physical security**
   - No cameras observing screen
   - No observers during signing
   - Secure disposal of any written keys

5. **User performs verification**
   - Checks destination address character-by-character
   - Verifies amount before signing
   - Confirms fee is reasonable

---

## Attacker Profiles

### Script Kiddie
- **Goal:** Steal funds via malware
- **Capability:** Off-the-shelf keyloggers, clipboard hijackers
- **Defeated by:** Air gap (key never on networked machine)

### Sophisticated Remote Attacker
- **Goal:** Steal funds via compromised API or MITM
- **Capability:** Control WhatsOnChain responses, inject fake proofs
- **Defeated by:** Envelope validation (PoW, merkle proofs, rawTx verification)

### Nation-State / APT
- **Goal:** Targeted key theft
- **Capability:** Supply chain compromise, hardware implants, zero-days
- **Partially defeated by:** Air gap limits exfiltration
- **NOT defeated by:** Compromised tool files, hardware implants

### Physical Attacker
- **Goal:** Key theft via physical access
- **Capability:** Device theft, observation, coercion
- **NOT defeated by:** This tool (use hardware wallet, multisig, passphrase)

---

## What Air-Gapping Actually Guarantees

### It DOES Guarantee:
- Private key bits never traverse a network
- Remote attackers cannot directly access signing machine
- Malware on online machine cannot touch keys

### It Does NOT Guarantee:
- Offline machine is trustworthy
- Tool code is uncompromised
- User will verify addresses correctly
- Physical security of the device
- Key was generated securely

---

## Recommendations

### Minimum (Casual Use)
- [ ] Verify file checksums after download
- [ ] Use dedicated browser profile (no extensions)
- [ ] Visually verify full destination address
- [ ] Keep offline machine disconnected during use

### Standard (Significant Funds)
- [ ] Use dedicated offline device
- [ ] Live-boot from verified USB (Tails, etc.)
- [ ] Verify tool files via multiple sources
- [ ] Wait for 6+ confirmations before signing
- [ ] Check block height against public explorers

### Paranoid (High-Value Cold Storage)
- [ ] Air-gapped machine never connected to internet
- [ ] Manually type tool code or verify byte-by-byte
- [ ] Use Faraday bag during signing
- [ ] Consider multisig instead of single-key
- [ ] Hardware wallet for actual signing

---

## Summary

| Aspect | Rating |
|--------|--------|
| Protection from remote key theft | ★★★★★ |
| Protection from malicious API | ★★★★★ |
| Protection from local compromise | ★☆☆☆☆ |
| Protection from supply chain | ★☆☆☆☆ |
| Protection from physical attack | ☆☆☆☆☆ |

**Bottom line:** This tool makes remote key theft extremely difficult. It does nothing against local compromise or physical attacks. The air gap is only as secure as the offline environment.
