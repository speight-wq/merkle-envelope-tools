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
 → Toggle Chain Mode (optional)  → Load envelope(s)              → Or any BSV node
 → Download envelope.json        → Enter WIF private key
                                 → Set destination + amount
headers-generator.html           → Download signed tx hex
 → Download headers.bin                  │
         │                               │
         └────── USB transfer ───────────┘

                                VERIFY / AUDIT
                                ─────────────────────────────
                                verifier.html → Quick pass/fail
                                explorer.html → Forensic analysis
                                chain.html    → Lineage verification
```

---

## Tools

| Tool | Network | Purpose |
|------|---------|---------|
| generator.html | Online | Create Merkle envelopes (single or chain mode) |
| headers-generator.html | Online | Download verified header chain |
| signer.html | Offline | Sign transactions using envelopes |
| verifier.html | Offline | Standalone envelope verification |
| explorer.html | Offline | Forensic SPV proof analysis and audit |
| chain.html | Offline | Deterministic lineage verification |
| tests.html | Offline | 58 cryptographic test vectors |
| tests-mainnet.html | Offline | Real mainnet transaction verification |
| verify_vectors.py | Offline | Python verification script (no dependencies) |

**Chain Mode:** Toggle "Chain Mode" in generator.html to recursively fetch ancestor transactions (1-5 hops). Outputs an array of envelopes ordered child → ancestor, ready for chain.html verification.

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

**Universal Sample (Block 170 — Satoshi → Hal Finney):**
All tools include this sample for testing. Works in explorer.html, verifier.html, and chain.html:
```json
{
  "txid": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
  "rawTx": "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000",
  "blockHeader": "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70",
  "proof": [{"hash": "82501c1178fa0b222c1f3d474ec726b832013f0a532b44bb620cce8624a5feb1", "pos": "L"}],
  "blockHeight": 170
}
```

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

## File Hashes (v2.1.0)

Verify before entering private keys:

```bash
# macOS/Linux
shasum -a 256 lib/*.js signer.html generator.html verifier.html headers-generator.html explorer.html tests.html tests-mainnet.html

# Windows PowerShell
Get-ChildItem lib\*.js, signer.html, generator.html, verifier.html, headers-generator.html, explorer.html, tests.html, tests-mainnet.html | Get-FileHash -Algorithm SHA256
```

| File | SHA-256 |
|------|---------|
| lib/crypto.js | `b2a91262f01994555e5e713cccb9d607c29b48ac5725f9bbce10df084ead0ab2` |
| lib/encoding.js | `22ea32359c2fd34aa9e421d99a2386f200e861bc7a364709745476d4091f57c1` |
| lib/secp256k1.js | `fc2d03baff7e802a8aed8e49a59c6b044089f9f585e1a1c9fe281b73da0e3e2b` |
| lib/sighash.js | `297151d898312ac0287abac527902ab4dec22804bbe1b782d4785bbbe789892f` |
| lib/headers.js | `3be36c561c47dae60a57f20371627471d735367b45ad3b96b30cdc01e57f3363` |
| lib/snapshot.js | `03e4010677d5bfe40d1273be6e075c760c380b2ada6c471d7a743f6f303c6954` |
| lib/mainnet-vectors.js | `33c961cd0227eeb0d347ba82cf0e19184b1bbb559c121071652cde4c28ea29e1` |
| generator.html | `baff7530903f9ddb197a725df0a2fcfbb8cb6b35f91758582bc51cce797049e8` |
| headers-generator.html | `552d2a4f4b6a22fcd647f1337c8b823c00acbc3d402d194fa8570d24ce76da2e` |
| signer.html | `b3fd8b6e3a6e8aabbd6c9cf0e528f5d73295dcea58cca9af8ba7f2a22cf329d8` |
| verifier.html | `934e4cfc7b0366ccad88fa86a441ab426a09cd9df86577606ac657d2f45db11c` |
| explorer.html | `d5bf2f975643ea7e256cf4989f2f1d575e2780d6bac357fa187141377650beb5` |
| chain.html | `4b6e0a8e305f9f9879b5b635327e70e111d4865b1777b090656d7654dec7eb0f` |
| tests.html | `4f6f6edbd62a8b8d29814773195eaf1159ccbfc1f681bdf9d2f62f5cd62c6830` |
| tests-mainnet.html | `3f17b7771c2f7ed81845ab0eba92d411a150925584b6a589de2b41a05c3278c1` |
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

## SPV Proof Explorer

`explorer.html` is a forensic-grade SPV verification instrument for auditing Merkle proofs.

**Features:**
- **Byte-level transparency** — Full concatenation hex, double SHA256 rounds exposed
- **Explicit direction logic** — Shows sibling position (L/R) and operation order
- **Block header breakdown** — Parsed fields: version, prevBlock, merkleRoot, timestamp, bits, nonce
- **Failure diagnostics** — Exact byte divergence, likely cause analysis
- **Deterministic hashes** — Input fingerprint, verification hash, replay ID for cross-system consistency
- **Audit mode toggle** — Standard (clean) vs Audit (full raw data)
- **Export** — JSON and text reports with all computation steps

**Use cases:**
- Dispute resolution — Prove transaction inclusion with exportable evidence
- Technical audits — Step-by-step hash verification
- Debugging — Identify exactly where/why a proof fails
- Education — Watch Merkle verification happen

---

## Proof Chain

`chain.html` — Protocol v1.0.0 deterministic lineage verification.

**Verification Phases (per spec):**
1. Structural validation — Hex encoding, field lengths, proof format
2. Ordering validation — Detect REVERSED or UNLINKED chains
3. Per-hop verification — TXID, PoW, Merkle (fail-fast)
4. Linkage verification — Child input references parent TXID
5. Value continuity — Parent output ≥ child claimed satoshis
6. Hash derivation — Canonical serialization → deterministic hashes

**Canonical Serialization:**
```
hop_serialized = txid (32) || vout (4, LE) || satoshis (8, LE) ||
                 rawTx || rawTx_length (4, LE) || blockHeader (80) ||
                 proof_count (2, LE) || [hash (32) || pos (1)]...
```

**Hash Derivations:**
| Hash | Derivation |
|------|------------|
| `hopVerificationHash` | SHA256(hop_serialized) |
| `inputFingerprint` | SHA256(chain_serialized)[0:16] |
| `chainVerificationHash` | SHA256(concat(hopHashes)) |

**Failure Types:**
- `STRUCTURE_INVALID` — Malformed envelope
- `ORDERING_INVALID` — REVERSED or UNLINKED
- `TXID_MISMATCH` — SHA256d(rawTx) ≠ claimed
- `POW_INVALID` — Block hash ≥ target
- `MERKLE_MISMATCH` — Computed root ≠ header root
- `LINKAGE_BROKEN` — No input references parent
- `VALUE_MISMATCH` — Parent output < child claimed

**Determinism Guarantee:**
Same input bytes → identical hashes across all implementations. No timestamps, randomness, or environment-dependent values in hash derivations.

See `CHAIN-PROTOCOL-SPEC.md` for complete specification.

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
explorer.html       # Forensic SPV proof analysis
chain.html          # Deterministic lineage verification
tests.html          # Unit test suite
tests-mainnet.html  # Mainnet verification tests
verify_vectors.py   # Python verification (standalone)
CHAIN-PROTOCOL-SPEC.md  # Proof Chain Protocol v1.0.0
```

---

## License

MIT. **Use at your own risk.** This software handles cryptographic keys and financial transactions. Not independently audited.

---

[WhatsOnChain Broadcast](https://whatsonchain.com/broadcast) · [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)
