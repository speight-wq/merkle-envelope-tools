# Merkle Envelope Tools

Offline BSV transaction signing with Merkle proof verification.

> *"A user only needs to keep a copy of the block headers of the longest proof-of-work chain, which he can get by querying network nodes until he's convinced he has the longest chain, and obtain the Merkle branch linking the transaction to the block it's timestamped in."*
> — Satoshi Nakamoto, Bitcoin Whitepaper §8 (2008)

---

## What This Tool Does

Merkle Envelope Tools implements the Merkle proof verification and Proof-of-Work validation components of SPV (Simplified Payment Verification). It does not implement peer discovery or longest-chain comparison.

1. **Generate cryptographic proof bundles** — Package a UTXO with its raw transaction, Merkle proof, and block header
2. **Verify proofs offline** — Confirm transaction inclusion via Merkle proof and block validity via PoW
3. **Sign transactions air-gapped** — Designed so private keys need not touch a networked device when the documented workflow is followed
4. **Optionally verify header chains** — Download and verify block headers to confirm UTXOs exist in blocks with cumulative proof-of-work

The envelope format packages everything needed to verify a UTXO: raw transaction, Merkle proof, block header. Self-contained and portable.

---

## What This Tool Does NOT Do

- **Does not sync the blockchain** — Uses pre-generated proofs, not live chain data
- **Does not query multiple sources** — Envelope generation and header download use WhatsOnChain API only; no cross-validation against other nodes or APIs
- **Does not discover longest chain** — Verifies headers form a valid PoW chain from checkpoint; does not compare chain tips across multiple sources to determine longest chain as described in Bitcoin Whitepaper §8
- **Does not protect against compromised offline machines** — If attacker has code execution, keys are exposed
- **Does not guarantee constant-time operations** — Browser-based JavaScript cannot ensure side-channel resistance
- **Does not support P2SH or multisig** — P2PKH only (addresses starting with "1")
- **Does not support testnet** — Mainnet only

---

## Quick Start

```
┌────────────────────────────────────────────────────────────────┐
│  ONLINE: Generate Envelope + Headers                           │
│  1. Open generator.html                                        │
│  2. Enter address or TXID to fetch UTXOs                       │
│  3. Download envelope JSON                                     │
│  4. (Optional) Open headers-generator.html                     │
│  5. Download headers.bin for header chain verification         │
└────────────────────────────────────────────────────────────────┘
                              │
                              │ Transfer via USB
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  OFFLINE: Sign Transaction                                     │
│  1. Open signer.html (disconnect from internet first)          │
│  2. Load headers.bin (optional, for header chain verification) │
│  3. Load envelope(s)                                           │
│  4. Enter WIF private key                                      │
│  5. Set destination address and amount                         │
│  6. Review and confirm                                         │
│  7. Copy or download signed transaction hex                    │
└────────────────────────────────────────────────────────────────┘
                              │
                              │ Transfer via USB
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  ONLINE: Broadcast                                             │
│  • Paste hex at whatsonchain.com/broadcast                     │
│  • Or submit to any BSV node                                   │
└────────────────────────────────────────────────────────────────┘
```

---

## Tool Reference

### generator.html (Online)

Creates Merkle envelopes for confirmed BSV transactions.

**Modes:**
- **By TXID** — Single transaction lookup
- **By Address** — All UTXOs for an address

**Output:** JSON envelope containing rawTx, Merkle proof, and block header.

---

### headers-generator.html (Online)

Downloads block headers for header chain verification.

**Input:** Start height and header count  
**Output:** `headers.bin` — binary file containing verified header chain

**Usage:**
1. Run on online machine
2. Transfer `headers.bin` to offline machine via USB
3. Load in signer.html Step 0 for header chain verification

---

### verifier.html (Offline)

Independently verifies Merkle envelopes.

**Note:** The Signer performs this verification automatically. Use the standalone Verifier for inspection or auditing.

**Validates:**
- Proof-of-work (block header meets difficulty target)
- Merkle proof (transaction included in block)
- Transaction structure (valid format, bounds)
- Schema completeness

---

### signer.html (Offline)

Signs transactions using verified Merkle envelopes as proof of funds.

**Input:** Envelope + WIF private key + destination address + amount  
**Output:** Signed raw transaction hex ready to broadcast

**Verification modes:**

| Mode | Headers Required | What's Verified |
|------|------------------|-----------------|
| Basic | No | Merkle proof + PoW of envelope's block |
| With Header Chain | Yes (headers.bin) | Merkle proof + PoW + block exists in verified header chain from checkpoint |

**Features:**
- Multi-input transactions (UTXO consolidation, same-key only)
- Tiered confirmation dialogs (>0.1, >1, >10 BSV)
- Network status detection (warns if online)
- Clipboard auto-clear (60 seconds)

---

### tests.html (Offline)

Cryptographic test suite with 38 test vectors across SHA-256, RIPEMD-160, secp256k1, Base58Check, Merkle proofs, and PoW validation.

Run before use to verify cryptographic integrity.

---

## Security Model

### Trust Assumptions

**You trust:**
1. The embedded checkpoint is correct (see below)
2. WhatsOnChain API provided honest data at envelope generation time
3. Generating cumulative PoW exceeding the real chain is economically infeasible
4. Your offline machine is not compromised

**Checkpoint trust anchor:**

The tool anchors header chain verification to block 880,000:
```
hash: 0000000000000000067ef53e9c4bf1297d0860a36b81b0e03ad0be6fb719788d
```

**This checkpoint is an unverified trust anchor.** The tool cannot validate it independently. If this hash is incorrect or has been tampered with, all header chain verification is compromised. Users must verify this checkpoint through external sources before relying on header chain verification.

**Why block 880,000:** Recent enough to minimize headers needed for current transactions, old enough to have deep confirmation (56,000+ blocks as of January 2025).

**To independently verify:**
1. Query multiple block explorers (whatsonchain.com, blockchair.com/bitcoin-sv)
2. Query your own BSV node: `bitcoin-cli getblockhash 880000`
3. Compare against the hash in `lib/headers.js`

If sources disagree, do not use this tool until resolved.

**You verify:**
1. Transaction is in the Merkle tree (cryptographic proof)
2. Block header meets difficulty target (PoW verification)
3. Block exists in header chain from checkpoint (if headers.bin loaded)
4. TXID matches hash of raw transaction

### Threat Protection

| Threat | Protection |
|--------|------------|
| Remote key theft | Workflow designed to keep private key off networked devices |
| Malicious API responses | All envelope data cryptographically verified |
| Fake transaction proofs | Merkle proof validated against block header |
| Fake block headers | Must meet PoW difficulty target |
| Inflated UTXO values | Value extracted from verified rawTx |

See [Limitations](#limitations) for threats this tool does not protect against.

### Security Hardening (v2.0.0)

- CVE-2012-2459 protection — Rejects duplicate Merkle nodes
- Minimum difficulty enforcement — Rejects trivially easy targets
- Header chain verification — Validates prevBlock linkage
- Maximum satoshi validation — Prevents integer overflow (21M BSV cap)
- Signature self-verification — Verifies signatures before output
- P2PKH script validation — Explicitly validates output script format
- Strict type validation — No implicit coercion on envelope fields
- BigInt arithmetic — All satoshi calculations use BigInt
- Constant-time comparison — Hash comparisons resist timing attacks
- Duplicate outpoint detection — Rejects multi-input with same UTXO
- Fee sanity bounds — Rejects fees >10% of input value
- Merkle proof depth limit — Rejects proofs >64 levels (DoS protection)
- Immutable structures — Parsed envelopes frozen after validation
- Content Security Policy — All pages include CSP headers

See [THREAT-MODEL.md](THREAT-MODEL.md) for complete analysis.

---

## Envelope Format

```json
{
  "format": "merkle-envelope",
  "version": 1,
  "txid": "abc123...",
  "vout": 0,
  "satoshis": 100000,
  "rawTx": "0100000001...",
  "blockHash": "000000000000...",
  "blockHeader": "00000020...",
  "proof": [
    { "hash": "abc123...", "pos": "R" },
    { "hash": "def456...", "pos": "L" }
  ],
  "confirmations": 1000
}
```

**Fields:**
- `rawTx` — Full transaction hex (for TXID verification and value extraction)
- `blockHeader` — 80-byte header hex (for PoW and Merkle root verification)
- `proof` — Merkle branch with position indicators (L/R)
- `satoshis` — Output value (verified against rawTx)

The format works with any API providing raw transaction hex, Merkle proof, and block header.

---

## Integrity Verification

**Always verify file hashes before entering private keys.**

### File Hashes (v2.0.0)

| File | SHA-256 |
|------|---------|
| lib/crypto.js | `b2a91262f01994555e5e713cccb9d607c29b48ac5725f9bbce10df084ead0ab2` |
| lib/encoding.js | `22ea32359c2fd34aa9e421d99a2386f200e861bc7a364709745476d4091f57c1` |
| lib/secp256k1.js | `fc2d03baff7e802a8aed8e49a59c6b044089f9f585e1a1c9fe281b73da0e3e2b` |
| lib/sighash.js | `297151d898312ac0287abac527902ab4dec22804bbe1b782d4785bbbe789892f` |
| lib/headers.js | `9d515bfd07591e4499ccff54e0b39b2a48587aafac64c40c630b79147d44efb4` |
| generator.html | `f6384a48761b44e4177907bf4d91f8874f048116e9b9c0b970ca4e5189eb3c8c` |
| headers-generator.html | `deef130a41ab70141ba96070764ed45de65112978443c2240716adafcdf93ae1` |
| verifier.html | `3258fb9c69ac95e390756527082062fb520bafea6ee5dd7e1061170176a4c0d5` |
| signer.html | `f818018f082a60aab47082dbb3903764e494a9c9422050a2462f2920c579e7ad` |
| tests.html | `578049d5d7c26eaf05a2282216443208211ad0230dd454fd3ab19f2091b41929` |

### How to Verify

```bash
# macOS/Linux
shasum -a 256 lib/*.js signer.html generator.html verifier.html headers-generator.html tests.html

# Windows PowerShell  
Get-FileHash lib\*.js,signer.html,generator.html,verifier.html,headers-generator.html,tests.html -Algorithm SHA256
```

If hashes don't match, **do not use the files**.

> **Note:** The hash shown in each page's footer is a runtime hash of the browser's parsed DOM, which differs from the file hash due to browser normalization. Always verify using the command-line method above.

---

## Limitations

### Functional Limitations

- **P2PKH only** — Standard addresses starting with "1" (no P2SH/multisig)
- **Same-key inputs** — Multi-input requires all UTXOs controlled by one key
- **Mainnet only** — No testnet support
- **Single API source** — Generator uses WhatsOnChain; no multi-source verification

### Architectural Limitations

- **Checkpoint trust** — Header chain verification anchors to an embedded checkpoint that must be independently verified
- **No longest chain discovery** — Verifies headers form a valid chain from checkpoint, does not compare against other sources to find longest chain
- **Periodic header updates** — Headers file must be regenerated to verify recent transactions
- **Browser-based cryptography** — Cannot guarantee constant-time operations or secure memory wipe

### Unprotected Threats

- **Compromised offline machine** — If attacker has code execution, private key is exposed
- **Supply chain attack** — Verify file hashes before use
- **Physical observation** — Shoulder surfing, cameras
- **User error** — Always verify destination address character-by-character

See [docs/ANTI-FEATURES.md](docs/ANTI-FEATURES.md) for features intentionally not implemented.

---

## Cryptography

Pure JavaScript, no external JavaScript dependencies:

| Component | Implementation |
|-----------|----------------|
| Hash functions | SHA-256, RIPEMD-160, hash160, hash256 |
| Signatures | secp256k1 ECDSA with RFC 6979 deterministic k, low-S normalized (BIP 146) |
| Sighash | BSV sighash (BIP143-derived with SIGHASH_FORKID) |
| Address encoding | Base58Check |
| Verification | Merkle proofs, Proof-of-Work validation |

All implementations tested against standard test vectors. See [TEST-VECTORS.md](TEST-VECTORS.md).

---

## Project Structure

```
merkle-envelope-tools/
├── lib/
│   ├── crypto.js          # SHA-256, RIPEMD-160, HMAC, hash256, hash160
│   ├── encoding.js        # Hex, Base58Check, varInt, endian conversions
│   ├── secp256k1.js       # Curve ops, RFC 6979 signing, DER, WIF
│   ├── sighash.js         # BSV sighash preimage construction
│   └── headers.js         # Header parsing, PoW, Merkle proofs
├── generator.html         # Online envelope generation
├── headers-generator.html # Online header chain download
├── verifier.html          # Offline envelope verification
├── signer.html            # Offline transaction signing
├── tests.html             # Cryptographic test suite
├── README.md
├── THREAT-MODEL.md
├── TEST-VECTORS.md
└── docs/
    ├── SIDE-CHANNELS.md
    └── ANTI-FEATURES.md
```

---

## Alternative APIs

The envelope format works with any API providing:
- Raw transaction hex
- Merkle proof (nodes + index)
- Block header (80 bytes)

Alternatives to WhatsOnChain:
- GorillaPool API
- TAAL API
- Self-hosted ElectrumX

---

## Audit Status

**This code has not been independently audited.**

Review the source before use with significant funds. The test suite validates cryptographic correctness but cannot guarantee absence of all bugs.

---

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

This software handles cryptographic keys and financial transactions. Loss of funds due to bugs, misuse, or misunderstanding is possible. Users assume all risk.

---

## Links

- [WhatsOnChain Broadcast](https://whatsonchain.com/broadcast)
- [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)

---

## Changelog

See version history for detailed changes.

### v2.0.0
- Refactored crypto into shared library modules (52% code reduction)
- Single audit point for all cryptographic primitives
- Removed QR generator (attack surface reduction)

### v1.1.0
- Header chain verification
- Multi-input transaction support
- CVE-2012-2459 protection
- Security hardening (difficulty enforcement, satoshi validation, signature self-verification)
