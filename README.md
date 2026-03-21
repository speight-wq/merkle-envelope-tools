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

## Verification Instruments

This toolkit includes two verification instruments. Both are deterministic: identical inputs produce identical outputs across environments, implementations, and time.

These tools do not just return "valid" or "invalid." They produce a reproducible cryptographic fingerprint of the verification process itself — enabling independent verification, dispute resolution and automated integrity checks without trusting any API or third party.

---

## SPV Proof Explorer

`explorer.html` — Single transaction forensic verification.

Verifies one SPV envelope with full byte-level transparency. Every computation step is exposed, hashed, and exportable.

**Verification Transparency**
- Complete Merkle path visualization with concatenation order
- Double SHA256 rounds shown independently  
- Block header parsed into constituent fields
- Sibling position (L/R) explicitly rendered at each level

**Deterministic Outputs**
- **Input Fingerprint** — SHA256 of raw input, truncated to 32 hex chars
- **Verification Hash** — SHA256 of all computation outputs
- **Replay ID** — Derived identifier for cross-system consistency

**Forensic Diagnostics**
- Byte-level diff on hash mismatches
- Failure localization to exact proof level
- Likely cause analysis with actionable detail
- Audit mode toggle for full raw data exposure

**Block Validation**
- Header hash computation (SHA256d)
- PoW verification against decoded nBits target
- Timestamp, version, and nonce extraction

**Export:** JSON and text reports containing all intermediate values, suitable for audit trails and dispute evidence.

---

## Proof Chain Verifier

`chain.html` — Multi-hop ancestry verification.

Verifies a chain of linked transactions from child to ancestor. Confirms that value flowed through a cryptographically valid path, with each hop independently verified for SPV integrity and correct linkage.

**Verification Phases**

| Phase | Check |
|-------|-------|
| 1. Structure | Hex encoding, field lengths, proof array format |
| 2. Ordering | Chain flows child → ancestor, detect REVERSED/UNLINKED |
| 3. Per-Hop SPV | TXID, PoW, Merkle proof (fail-fast on first failure) |
| 4. Linkage | Child input must reference parent TXID + vout |
| 5. Value Continuity | Parent output ≥ child claimed satoshis |
| 6. Hash Derivation | Canonical serialization → deterministic chain hash |

**Deterministic Outputs**
- **hopVerificationHash** — Per-hop integrity fingerprint
- **inputFingerprint** — SHA256 of serialized chain (first 16 bytes)
- **chainVerificationHash** — SHA256 of concatenated hop hashes

---

## Deterministic Hash Layer

All verification outputs derive from canonical byte serialization. No timestamps, randomness, or environment-dependent values enter the hash computation.

**Canonical Hop Serialization**
```
hop_serialized =
    txid (32 bytes, no reversal)
    vout (4 bytes, LE)
    satoshis (8 bytes, LE; 0xFF...FF if absent)
    rawTx (variable)
    rawTx_length (4 bytes, LE)
    blockHeader (80 bytes)
    proof_count (2 bytes, LE)
    [hash (32 bytes) || position (1 byte: 0x00=L, 0x01=R)] × N
```

**Hash Derivations**

| Output | Derivation |
|--------|------------|
| `hopVerificationHash` | `SHA256(hop_serialized)` |
| `inputFingerprint` | `SHA256(chain_serialized)[0:16]` |
| `chainVerificationHash` | `SHA256(hopHash[0] \|\| hopHash[1] \|\| ... \|\| hopHash[N])` |

Two independent implementations following this specification will produce byte-identical outputs for the same input.

---

## Failure Types

| Code | Trigger |
|------|---------|
| `STRUCTURE_INVALID` | Malformed envelope, invalid hex, wrong field length |
| `ORDERING_INVALID` | Chain not ordered child → ancestor (REVERSED or UNLINKED) |
| `TXID_MISMATCH` | SHA256d(rawTx) ≠ claimed txid |
| `POW_INVALID` | Block hash ≥ difficulty target |
| `MERKLE_MISMATCH` | Computed Merkle root ≠ header Merkle root |
| `LINKAGE_BROKEN` | Child input does not reference parent TXID |
| `VALUE_MISMATCH` | Parent output value < child claimed satoshis |

Verification halts at the first failure. The failure type, hop index, and diagnostic detail are returned for forensic analysis.

---

## Determinism Guarantee

Given identical input bytes, these tools produce identical:
- `hopVerificationHash` for each hop
- `inputFingerprint` for the chain
- `chainVerificationHash` for the full verification

**Prohibited in hash derivation:**
- Timestamps
- Random values  
- Floating-point arithmetic
- Environment-dependent data
- Non-deterministic iteration order

This guarantee enables:
- Cross-system verification comparison
- Automated regression testing
- Dispute resolution with cryptographic evidence
- Long-term audit trails

---

## Why This Matters

Most verification tools return a binary result: valid or invalid. The computation is opaque. The process cannot be independently reproduced. You trust the tool.

These instruments take a different approach:

1. **Transparent** — Every intermediate hash, concatenation, and comparison is exposed
2. **Reproducible** — Same input produces same fingerprint, anywhere, anytime
3. **Independently verifiable** — No API calls, no external dependencies, no hidden steps
4. **Forensic-grade** — Outputs are suitable for audit trails, dispute resolution, and legal evidence

The verification fingerprint is not metadata. It is a cryptographic commitment to the exact computation that occurred. If two parties run the same input and get the same fingerprint, they have mathematically proven they performed identical verification.

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
