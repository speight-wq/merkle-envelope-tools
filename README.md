# Merkle Envelope Tools

Offline BSV transaction signing with Merkle proof verification.

## What It Does

1. **Generate proof bundles** — Package UTXOs with raw transaction, Merkle proof, and block header
2. **Verify proofs offline** — Confirm transaction inclusion and block validity via PoW
3. **Sign transactions air-gapped** — Private keys never touch networked devices
4. **Optionally verify header chains** — Confirm blocks exist in a PoW-verified chain from checkpoint

**What it does NOT do:** Sync blockchain, query multiple sources, discover longest chain, protect compromised machines, guarantee constant-time operations, support P2SH/multisig/testnet.

---

## Workflow

```
ONLINE                          OFFLINE                         ONLINE
─────────────────────────────   ─────────────────────────────   ──────────────
generator.html                  signer.html                     Broadcast
 → Enter address/TXID            → Load headers.bin (optional)   → whatsonchain.com/broadcast
 → Download envelope.json        → Load envelope(s)              → Or any BSV node
                                 → Enter WIF private key
headers-generator.html           → Set destination + amount
 → Download headers.bin          → Download signed tx hex
         │                                │
         └────── USB transfer ────────────┘
```

---

## Tools

| Tool | Network | Purpose |
|------|---------|---------|
| generator.html | Online | Create Merkle envelopes from TXID or address |
| headers-generator.html | Online | Download verified header chain |
| signer.html | Offline | Sign transactions using envelopes |
| verifier.html | Offline | Standalone envelope verification |
| tests.html | Offline | 58 cryptographic test vectors |
| tests-mainnet.html | Offline | Real mainnet transaction verification |
| verify_vectors.py | Offline | Python verification script (no dependencies) |

---

## Envelope Format

```json
{
  "txid": "abc123...",
  "vout": 0,
  "satoshis": 100000,
  "rawTx": "0100000001...",
  "blockHeader": "00000020...",
  "proof": [{ "hash": "...", "pos": "R" }, { "hash": "...", "pos": "L" }]
}
```

Both `vout` and (`blockHeader` + `proof`) are required. No silent defaults.

---

## Security Model

**You trust:**
- Embedded checkpoint is correct
- WhatsOnChain API provided honest data at generation time
- Your offline machine is not compromised

**You verify:**
- Transaction in Merkle tree (cryptographic proof)
- Block meets difficulty target (PoW)
- Block in header chain from checkpoint (if headers.bin loaded)
- TXID matches raw transaction hash

**Checkpoint (block 935,000):**
```
hash: 000000000000000014dd029be96be37223e04f66f379dc4eed0f071a73c1f7aa
nBits: 0x1d2a0000
```

Verify independently via `bitcoin-cli getblockhash 935000` or multiple block explorers before trusting high-value transactions.

**Difficulty floor:** 8x tolerance from checkpoint nBits. Attacker needs ~12.5% of network hashrate to forge valid-difficulty header.

---

## Security Hardening (v2.0.2)

- **Fail-closed defaults** — Chain verification on by default
- **Blocking errors** — "Not in chain" blocks signing
- **No silent defaults** — `vout` required, header+proof both required
- **Key hygiene** — Private key cleared after signing
- **Fee bounds** — Max 10% of input value, max 1000 sat/byte
- **Full validation** — Base58Check addresses, difficulty floor at download
- **Deterministic signing** — RFC6979 with signature self-verification
- **CVE-2012-2459 protection** — Comprehensive Merkle proof validation:
  - Adjacent duplicate hash rejection
  - Wildcard (`*`) blocked by default in untrusted proofs
  - Wildcard position/level validation when enabled
  - Prototype pollution protection via `hasOwnProperty` checks
- **Depth limiting** — Max Merkle depth 32 (supports 4B tx/block, prevents DoS)
- **TXID verification** — `SHA256d(rawTx) == claimed_txid` checked before signing
- **ScriptPubKey validation** — User's key must match UTXO's pubkeyhash

---

## File Hashes (v2.0.2)

Verify before entering private keys:

```bash
# macOS/Linux
shasum -a 256 lib/*.js signer.html generator.html verifier.html headers-generator.html tests.html tests-mainnet.html

# Windows PowerShell
Get-ChildItem lib\*.js, signer.html, generator.html, verifier.html, headers-generator.html, tests.html, tests-mainnet.html | Get-FileHash -Algorithm SHA256
```

| File | SHA-256 |
|------|---------|
| lib/crypto.js | `b2a91262f01994555e5e713cccb9d607c29b48ac5725f9bbce10df084ead0ab2` |
| lib/encoding.js | `22ea32359c2fd34aa9e421d99a2386f200e861bc7a364709745476d4091f57c1` |
| lib/secp256k1.js | `fc2d03baff7e802a8aed8e49a59c6b044089f9f585e1a1c9fe281b73da0e3e2b` |
| lib/sighash.js | `297151d898312ac0287abac527902ab4dec22804bbe1b782d4785bbbe789892f` |
| lib/headers.js | `3be36c561c47dae60a57f20371627471d735367b45ad3b96b30cdc01e57f3363` |
| lib/snapshot.js | `03e4010677d5bfe40d1273be6e075c760c380b2ada6c471d7a743f6f303c6954` |
| lib/mainnet-vectors.js | `de0fed524c288ccdc527946d4f2e29e436b1841ea31d6f308bfa1ebf2d436d4c` |
| generator.html | `02a05959e6033a2af01cc5a849ebf12ac92cba25e5579d028531a1f5a026a48d` |
| headers-generator.html | `d3aeab7c2eb5d51ae64743e22b3f4f9e0beea241b6546344e2a7297b88bb4093` |
| signer.html | `d0575d48fcaa3ca8253f5d1ce465c4a9cc2d7691bbd81d943195f9b667e85def` |
| verifier.html | `94808ce94287052e7c419b3bb485f4e5509fd62a75df381ee7f80e8ae45f2b6b` |
| tests.html | `a44857f9f0ae23aecef5a52213f9a70582c5c0ea26bee02df00aa5cb3ab565a2` |
| tests-mainnet.html | `c1872076891d63889de21d333c1d51d2dc2532a637a1626e907966dfe44bd03f` |
| verify_vectors.py | `03691964efcd255b7fcd5f62b9e7f7bf69d46e5d61cb31dc96ff83a97d7692a6` |

---

## Limitations

- **P2PKH only** — Addresses starting with "1"
- **Same-key inputs** — Multi-input requires single controlling key
- **Mainnet only**
- **Single API source** — WhatsOnChain
- **Periodic header updates** — Regenerate headers.bin for recent transactions
- **Browser crypto** — Cannot guarantee constant-time or secure memory wipe

---

## Cryptography

Pure JavaScript, no external dependencies:

- SHA-256, RIPEMD-160, hash256, hash160
- secp256k1 ECDSA with RFC 6979, low-S (BIP 146)
- BSV sighash (SIGHASH_FORKID)
- Base58Check encoding
- Merkle proof verification

All tested against standard vectors. See TEST-VECTORS.md.

---

## Mainnet Test Vectors

Real BSV transactions verified end-to-end:

| Block | Description | Verifications |
|-------|-------------|---------------|
| Block 0 | Genesis block coinbase | TXID, PoW, block hash, coinbase message |
| Block 1 | First mined block | TXID, PoW, block hash, chain linkage |
| Block 170 | First P2P transaction (Satoshi → Hal Finney) | PoW, block hash, Merkle proof |

**Cross-verification sources:**
- WhatsOnChain: `whatsonchain.com/block-height/{N}`
- Blockchair: `blockchair.com/bitcoin-sv/block/{N}`
- BSV node: `bitcoin-cli getblockhash {N}`
- Local computation: `python3 verify_vectors.py`

See docs/CROSS-VERIFICATION.md for step-by-step independent verification.

---

## Project Structure

```
lib/
  crypto.js         # Hash functions
  encoding.js       # Hex, Base58, varInt
  secp256k1.js      # Signing, WIF
  sighash.js        # BSV sighash
  headers.js        # PoW, Merkle proofs
  snapshot.js       # Header snapshots
  mainnet-vectors.js # Real BSV test vectors
docs/
  CROSS-VERIFICATION.md  # Independent verification guide
  ANTI-FEATURES.md       # Design decisions
  SIDE-CHANNELS.md       # Security considerations
generator.html      # Online envelope generation
headers-generator.html
signer.html         # Offline signing
verifier.html       # Standalone verification
tests.html          # Unit test suite
tests-mainnet.html  # Mainnet verification tests
verify_vectors.py   # Python verification (standalone)
```

---

## License

MIT. **Use at your own risk.** This software handles cryptographic keys and financial transactions. Not independently audited.

---

[WhatsOnChain Broadcast](https://whatsonchain.com/broadcast) · [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)
