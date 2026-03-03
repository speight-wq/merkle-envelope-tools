# Independent Cross-Verification Guide

This document provides step-by-step instructions to independently verify that each test vector in `lib/mainnet-vectors.js` matches real BSV mainnet data.

**Verification Principle:** Trust no single source. Each value should be verifiable through multiple independent methods: block explorers, direct computation, and protocol specification.

---

## Quick Reference: Verification Tools

| Tool | URL | Purpose |
|------|-----|---------|
| WhatsOnChain | https://whatsonchain.com | BSV block explorer |
| Blockchair | https://blockchair.com/bitcoin-sv | Multi-chain explorer |
| Blockchain.com | https://www.blockchain.com/explorer | BTC explorer (early blocks identical) |
| BSV Node | Run locally | Ground truth |
| Python/Node | Local computation | Hash verification |

---

## Vector 1: Genesis Block (Block 0)

**Claimed Values:**
```
TXID:        4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
Block Hash:  000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
Block Height: 0
nBits:       0x1d00ffff (difficulty 1)
```

### Step 1: Verify genesis block hash (Protocol Constant)

**This is a protocol constant.** Every Bitcoin-derived chain (BTC, BCH, BSV) shares the same genesis block.

**Reference sources:**
- Bitcoin whitepaper implementation
- Any BSV node: `bitcoin-cli getblockhash 0`
- https://whatsonchain.com/block-height/0
- https://blockchair.com/bitcoin-sv/block/0

### Step 2: Compute TXID from raw transaction

**Genesis coinbase raw tx:**
```
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
```

**Compute TXID (Python):**
```python
import hashlib

raw_tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

tx_bytes = bytes.fromhex(raw_tx)
hash1 = hashlib.sha256(tx_bytes).digest()
hash2 = hashlib.sha256(hash1).digest()
txid = hash2[::-1].hex()

print(f"TXID: {txid}")
# Expected: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
```

### Step 3: Verify coinbase message

The genesis coinbase contains the famous message:

```
The Times 03/Jan/2009 Chancellor on brink of second bailout for banks
```

**Extract from script:**
```python
raw_tx_bytes = bytes.fromhex(raw_tx)
message = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
assert message.encode('ascii') in raw_tx_bytes
print("✓ Coinbase message verified")
```

### Step 4: Verify single-tx block Merkle property

**For a block with one transaction:**
- Merkle root == TXID (no hashing required)

**Verify:**
```python
genesis_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

# Extract merkle root (bytes 36-68, reversed for display)
header_bytes = bytes.fromhex(genesis_header)
merkle_internal = header_bytes[36:68]
merkle_root = merkle_internal[::-1].hex()

print(f"Merkle root: {merkle_root}")
print(f"TXID:        {txid}")
assert merkle_root == txid
print("✓ Single-tx block: TXID == Merkle root")
```

### Step 5: Verify genesis block header hash

**Genesis header (80 bytes):**
```
0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c
```

**Compute:**
```python
genesis_header = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"

header_bytes = bytes.fromhex(genesis_header)
hash1 = hashlib.sha256(header_bytes).digest()
hash2 = hashlib.sha256(hash1).digest()
block_hash = hash2[::-1].hex()

print(f"Genesis hash: {block_hash}")
# Expected: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
```

---

## Vector 2: Block 1 (First Mined Block)

**Claimed Values:**
```
TXID:        0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098
Block Hash:  00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
Block Height: 1
PrevHash:    000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f (genesis)
```

### Step 1: Verify block exists

**WhatsOnChain:**
```
https://whatsonchain.com/block-height/1
```

**Blockchair:**
```
https://blockchair.com/bitcoin-sv/block/1
```

### Step 2: Compute TXID from raw transaction

**Block 1 coinbase raw tx:**
```
01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000
```

**Compute:**
```python
raw_tx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"

tx_bytes = bytes.fromhex(raw_tx)
hash1 = hashlib.sha256(tx_bytes).digest()
hash2 = hashlib.sha256(hash1).digest()
txid = hash2[::-1].hex()

print(f"TXID: {txid}")
# Expected: 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098
```

### Step 3: Verify block header and chain linkage

**Block 1 header:**
```
010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299
```

**Verify:**
```python
block1_header = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299"

header_bytes = bytes.fromhex(block1_header)

# Compute block hash
hash1 = hashlib.sha256(header_bytes).digest()
hash2 = hashlib.sha256(hash1).digest()
block_hash = hash2[::-1].hex()
print(f"Block 1 hash: {block_hash}")
# Expected: 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048

# Extract and verify prevHash links to genesis
prev_hash_internal = header_bytes[4:36]
prev_hash_display = prev_hash_internal[::-1].hex()
print(f"PrevHash: {prev_hash_display}")
# Expected: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f (genesis)
```

---

## Vector 3: Block 170 (First Person-to-Person Transaction)

**Claimed Values:**
```
Block Hash:   00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
Block Height: 170
Merkle Root:  7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff
Time:         1231731025 (2009-01-12 03:30:25 UTC)
nBits:        0x1d00ffff
Nonce:        1889418792
```

**Transactions in block:**
- Coinbase: `b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082`
- Satoshi→Hal: `f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16`

### Step 1: Verify block exists and contains famous transaction

**WhatsOnChain:**
```
https://whatsonchain.com/block-height/170
https://whatsonchain.com/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
```

**Historical reference:**
- Guinness World Records: https://www.guinnessworldrecords.com/world-records/696243-first-bitcoin-transaction
- This is the famous first Bitcoin transfer from Satoshi Nakamoto to Hal Finney (10 BTC)

### Step 2: Verify block header hash

**Block 170 header (80 bytes):**
```
0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70
```

**Compute:**
```python
block170_header = "0100000055bd840a78798ad0da853f68974f3d183e2bd1db6a842c1feecf222a00000000ff104ccb05421ab93e63f8c3ce5c2c2e9dbb37de2764b3a3175c8166562cac7d51b96a49ffff001d283e9e70"

header_bytes = bytes.fromhex(block170_header)
hash1 = hashlib.sha256(header_bytes).digest()
hash2 = hashlib.sha256(hash1).digest()
block_hash = hash2[::-1].hex()

print(f"Block 170 hash: {block_hash}")
# Expected: 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee
```

### Step 3: Verify Merkle root and 2-transaction proof

**Block 170 has 2 transactions:**
```
tx0 (coinbase): b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082
tx1 (transfer): f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
```

**Compute Merkle root:**
```python
# TXIDs in internal byte order
tx0 = bytes.fromhex("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082")[::-1]
tx1 = bytes.fromhex("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")[::-1]

# Merkle root = SHA256d(tx0 || tx1)
concat = tx0 + tx1
hash1 = hashlib.sha256(concat).digest()
hash2 = hashlib.sha256(hash1).digest()
merkle_root = hash2[::-1].hex()

print(f"Computed Merkle root: {merkle_root}")
# Expected: 7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff
```

### Step 4: Verify Merkle proof for coinbase

**Proof that tx0 (coinbase) is in the block:**
- Start with: `b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082`
- Sibling (right): `f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16`
- Compute: SHA256d(tx0 || tx1) = merkle root

```python
# Verify proof
current = bytes.fromhex("b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082")[::-1]
sibling = bytes.fromhex("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")[::-1]

# Sibling is on RIGHT, so: hash(current || sibling)
concat = current + sibling
hash1 = hashlib.sha256(concat).digest()
hash2 = hashlib.sha256(hash1).digest()
computed_root = hash2[::-1].hex()

expected_root = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
assert computed_root == expected_root
print("✓ Merkle proof valid")
```

---

## Checkpoint Verification (Block 935,000)

**Claimed Values:**
```
Height:  935,000
Hash:    000000000000000014dd029be96be37223e04f66f379dc4eed0f071a73c1f7aa
nBits:   0x1d2a0000
```

### Step 1: Verify block exists at height

**WhatsOnChain:**
```
https://whatsonchain.com/block-height/935000
```

### Step 2: Verify block hash

**API:**
```bash
curl https://api.whatsonchain.com/v1/bsv/main/block/height/935000
```

**Verify hash matches:** `000000000000000014dd029be96be37223e04f66f379dc4eed0f071a73c1f7aa`

### Step 3: Compute target from nBits

```python
nbits = 0x1d2a0000
exponent = 0x1d  # 29
mantissa = 0x2a0000

target = mantissa << (8 * (exponent - 3))
print(f"Target: {target:064x}")

# Verify block hash is below target
block_hash = "000000000000000014dd029be96be37223e04f66f379dc4eed0f071a73c1f7aa"
hash_int = int(block_hash, 16)
print(f"Hash < Target: {hash_int < target}")
```

---

## Complete Verification Script

Run this Python script to verify all vectors locally:

```bash
python3 verify_vectors.py
```

The script performs 18 independent checks:
- TXID computation from raw transactions
- Block hash computation from headers
- Proof-of-work verification
- Merkle root extraction
- Merkle proof validation
- Chain linkage verification
- Invalid vector rejection tests

---

## Verification Checklist

Use this checklist when verifying each vector:

### For each transaction:
- [ ] TXID exists on WhatsOnChain
- [ ] TXID exists on Blockchair (independent source)
- [ ] Block height matches explorer data
- [ ] If raw tx provided: `SHA256d(rawTx)` reversed == TXID

### For each block header:
- [ ] `SHA256d(header)` reversed == claimed block hash
- [ ] Block hash exists at claimed height on explorer
- [ ] Merkle root extracted from header matches explorer data
- [ ] nBits extracted from header matches explorer data
- [ ] Block hash < target derived from nBits

### For each Merkle proof:
- [ ] Proof structure matches API response
- [ ] Walking proof from TXID produces header's Merkle root
- [ ] No duplicate adjacent nodes (CVE-2012-2459)

---

## Node-Level Verification (Highest Assurance)

For maximum trust, run a BSV node and verify directly:

```bash
# Get block hash at height
bitcoin-cli getblockhash 170

# Get block header
bitcoin-cli getblockheader 00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee

# Get raw transaction
bitcoin-cli getrawtransaction f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16

# Get transaction Merkle proof
bitcoin-cli gettxoutproof '["f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"]'
```

---

## Summary

| Vector | Block | Primary Source | Secondary Source | Computation Check |
|--------|-------|----------------|------------------|-------------------|
| Vector 1 | 0 (Genesis) | Protocol spec | Any node | SHA256d rawTx → TXID |
| Vector 2 | 1 | WhatsOnChain | Blockchair | SHA256d header → hash, chain linkage |
| Vector 3 | 170 | Historical record | Guinness | Merkle proof, PoW |
| Checkpoint | 935,000 | WhatsOnChain | BSV node | nBits → target → PoW |

**Trust model:** If WhatsOnChain, Blockchair, your local computation, and (optionally) a BSV node all agree, the data is correct.

**Note on early blocks:** Blocks 0, 1, and 170 are identical across BTC, BCH, and BSV since they predate any chain splits. This means BTC block explorers can also be used to verify these vectors.

---

## Quick Verification

```bash
# Run Python verification (no dependencies required)
python3 verify_vectors.py

# Expected output:
# ======================================================================
# ✓ ALL 18 TESTS PASSED
# ======================================================================
```

**Important:** Merkle proof sibling hashes are stored in **internal byte order** (little-endian), not display format. This matches the Bitcoin protocol's internal representation.
