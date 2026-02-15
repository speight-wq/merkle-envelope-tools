# Cryptographic Test Vectors

This document specifies the canonical test vectors used by `tests.html` to verify cryptographic correctness.

These values are **permanent invariants** — deterministic outputs of standardized algorithms on trivial inputs, or protocol-defined constants. They require no external database, API, or website to verify.

Any correct implementation MUST produce these exact values. Failure indicates a broken implementation.

---

## SHA-256

**Source:** FIPS 180-4 (Secure Hash Standard), NIST

| Input | SHA-256 Output |
|-------|----------------|
| `""` (empty string, 0 bytes) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"abc"` (3 bytes: 0x61 0x62 0x63) | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |

**Verification:** Implementable from FIPS 180-4 pseudocode alone.

---

## RIPEMD-160

**Source:** Dobbertin, Bosselaers, Preneel — "RIPEMD-160: A Strengthened Version of RIPEMD" (1996)

| Input | RIPEMD-160 Output |
|-------|-------------------|
| `""` (empty string, 0 bytes) | `9c1185a5c5e9fc54612808977ee8f548b2258d31` |
| `"abc"` (3 bytes: 0x61 0x62 0x63) | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` |

**Verification:** Implementable from original paper appendix.

---

## hash160

**Definition:** `hash160(x) = RIPEMD-160(SHA-256(x))`

This is a Bitcoin protocol convention, not a separate standard.

| Input | hash160 Output |
|-------|----------------|
| `""` (empty) | `b472a266d0bd89c13706a4132ccfb16f7c3b9fcb` |

**Derivation:**
```
SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
RIPEMD-160(above) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
```

---

## secp256k1 Curve Parameters

**Source:** SEC 2: Recommended Elliptic Curve Domain Parameters, Version 2.0, Section 2.4.1 (Certicom Research, 2010)

### Generator Point G

| Format | Value |
|--------|-------|
| Compressed | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| x-coordinate | `79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| y-coordinate | `483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8` |

The `02` prefix indicates y is even.

### Curve Constants

| Parameter | Value |
|-----------|-------|
| p (field prime) | `0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f` |
| n (group order) | `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141` |
| a | `0` |
| b | `7` |

**Verification:** These are specified constants, not computed values.

---

## Bitcoin Genesis Block

**Source:** Bitcoin protocol definition (2009), embedded in all Bitcoin-derived implementations

| Field | Value |
|-------|-------|
| Block hash | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` |
| Merkle root | `4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b` |
| Timestamp | `1231006505` (2009-01-03 18:15:05 UTC) |
| nBits | `0x1d00ffff` |
| Nonce | `2083236893` |

### Raw Header (80 bytes, hex)

```
01000000
0000000000000000000000000000000000000000000000000000000000000000
3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a
29ab5f49
ffff001d
1dac2b7c
```

**Derivation:** `hash256(header)` reversed for display = genesis block hash.

**Note:** This block is identical across BTC, BCH, and BSV — all chains share the same genesis.

---

## Base58Check Alphabet

**Source:** Bitcoin protocol convention

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

58 characters. Excluded: `0`, `O`, `I`, `l` (ambiguous in some fonts).

---

## Proof-of-Work Target Encoding (nBits)

**Definition:** Compact representation of 256-bit target.

| nBits | Expanded Target | Notes |
|-------|-----------------|-------|
| `0x1d00ffff` | `0x00ffff * 2^(8*(0x1d-3))` | Genesis difficulty (easiest valid) |

**Formula:** For nBits = `0xEEMMMMMMM`:
- Exponent: `EE` (first byte)
- Mantissa: `MMMMMM` (lower 3 bytes)
- Target: `mantissa * 2^(8*(exponent-3))`

A block is valid if `hash256(header) <= target`.

---

## Protocol Constants

| Constant | Value | Notes |
|----------|-------|-------|
| MAX_SATOSHIS | `2,100,000,000,000,000` | 21M BTC × 10^8 sats |
| DUST_THRESHOLD | `546` satoshis | Policy, not consensus |
| P2PKH_SCRIPT_SIZE | `25` bytes | `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` |
| SIGHASH_ALL \| FORKID | `0x41` | BSV signature hash type |

---

## Verification Independence

These vectors can be verified without internet access:

1. Implement SHA-256 from FIPS 180-4
2. Implement RIPEMD-160 from the 1996 paper
3. Compute `hash256(genesis_header)` from the 80-byte header above
4. Confirm G matches SEC 2 Section 2.4.1

No trust in any website, repository, or third party is required.

---

## References

| Standard | Document |
|----------|----------|
| SHA-256 | FIPS 180-4: Secure Hash Standard (NIST, 2015) |
| RIPEMD-160 | Dobbertin/Bosselaers/Preneel, Fast Software Encryption (1996) |
| secp256k1 | SEC 2 v2.0: Recommended Elliptic Curve Domain Parameters (Certicom, 2010) |
| Bitcoin protocol | Bitcoin: A Peer-to-Peer Electronic Cash System (Nakamoto, 2008) |
| BIP 143 | Transaction Signature Verification for Version 0 Witness Program |

These documents define the algorithms. The test vectors above are deterministic consequences of those definitions.
