 # Merkle Envelope Tools

**Deterministic SPV verification and forensic audit instruments for Bitcoin SV.**

This project implements a fully offline, reproducible verification layer for Bitcoin transactions.

It does not just return “valid” or “invalid.”

It produces a **cryptographic fingerprint of the entire verification process** — enabling independent validation, cross-system reproducibility and forensic auditability without trusting any API, node or third party.

If verification cannot be reproduced, it is not verification — it is trust.

## What It Does

1. **Generate proof bundles** — Package UTXOs with raw transaction, Merkle proof, and block header
2. **Verify proofs offline** — Confirm transaction inclusion and block validity via PoW
3. **Sign transactions air-gapped** — Private keys never touch networked devices
4. **Optionally verify header chains** — Confirm blocks exist in a PoW-verified chain from checkpoint
5. **Interoperate with the ecosystem** — Emit and verify standard **BUMP** (BRC-74) and **BEEF / Atomic BEEF** (BRC-62 / BRC-95) proofs, byte-for-byte compatible with `@bsv/sdk`

**What it does NOT do:** Sync blockchain, query multiple sources, discover longest chain, protect compromised machines, guarantee constant-time operations, support P2SH/multisig/testnet.

---

## Workflow

```
ONLINE                          OFFLINE                         ONLINE
─────────────────────────────   ─────────────────────────────   ──────────────
generator.html                  signer.html                     Broadcast
 → Enter address/TXID            → Load headers.bin (optional)   → whatsonchain.com/broadcast
 → Toggle Chain Mode (optional)  → Load envelope(s)              → Or any BSV node
 → Emits proof + BUMP            → Enter WIF private key
 → Download envelope.json        → Set destination + amount
                                 → Download signed tx hex
headers-generator.html           → Download signed tx hex
 → Download headers.bin                  │
         │                               │
         └────── USB transfer ───────────┘

                                VERIFY / AUDIT
                                ─────────────────────────────
                                verifier.html → Quick pass/fail (+ chain inclusion)
                                explorer.html → Forensic analysis (+ chain inclusion)
                                chain.html    → Lineage verification
```

---

## Tools

| Tool | Network | Purpose |
|------|---------|---------|
| generator.html | Online | Create Merkle envelopes (single or chain mode); emits legacy proof + BUMP |
| headers-generator.html | Online | Download verified header chain |
| signer.html | Offline | Sign transactions using envelopes |
| verifier.html | Offline | Standalone envelope verification (proof / BUMP / BEEF + chain inclusion) |
| explorer.html | Offline | Forensic SPV proof analysis and audit |
| chain.html | Offline | Deterministic lineage verification |
| tests.html | Offline | 82 cryptographic test vectors (incl. BUMP/BEEF/chain-inclusion) |
| tests-mainnet.html | Offline | Real mainnet transaction verification |
| verify_vectors.py | Offline | Python verification script (no dependencies) |

**Chain Mode:** Toggle "Chain Mode" in generator.html to recursively fetch ancestor transactions (1-5 hops). Outputs an array of envelopes ordered child → ancestor, ready for chain.html verification.

---

## Ecosystem Interoperability — BUMP & BEEF

The verification layer speaks the BSV ecosystem's standard proof formats, so proofs move both ways between these tools and any BRC-100 / `@bsv/sdk` wallet.

| Format | Spec | Where used |
|--------|------|------------|
| **BUMP** — BSV Unified Merkle Path | BRC-74 | `lib/bump.js` — compact Merkle path; emitted by generator, verified by verifier/explorer |
| **BEEF** — Background Evaluation Extended Format | BRC-62 | `lib/beef.js` — proof-carrying transaction container |
| **Atomic BEEF** — single-subject BEEF | BRC-95 | `lib/beef.js` — the single-transaction profile that fits cold-storage signing |

Both modules are **pure vanilla JavaScript, zero dependencies**, consistent with the rest of the toolkit. The verifier accepts, in priority order, `bump` → `beef` / `atomicBeef` → the legacy `proof` array; **existing envelopes continue to verify unchanged**.

- `lib/bump.js` — `fromHex` / `toHex` / `merkleRoot` / `selfTest`, with an injectable double-SHA256 hook so it can reuse existing crypto.
- `lib/beef.js` — `parse` / `build` / `verifyMined` / `wrapAtomic`, topologically ordering the transaction graph on write.

The generator converts each WhatsOnChain TSC proof to a BUMP and **self-verifies it against the block header's Merkle root before attaching it** — if it doesn't reconstruct, the envelope keeps its legacy proof and logs a warning rather than emitting a bad BUMP.

Load order in HTML: `crypto.js` → `encoding.js` → `headers.js` → `bump.js` → `beef.js`.

---

## Envelope Format

```json
{
  "txid": "abc123...",
  "vout": 0,
  "satoshis": 100000,
  "rawTx": "0100000001...",
  "blockHeader": "00000020...",
  "proof": [{ "hash": "...", "pos": "R" }, { "hash": "...", "pos": "L" }],
  "bump": "fe...."
}
```

Both `vout` and (`blockHeader` + `proof`) are required. No silent defaults. The `bump` field (BRC-74 hex) is optional and, when present, is preferred over `proof`. A `beef` or `atomicBeef` hex field is also accepted in place of `proof`.

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
- Block in header chain from checkpoint (if headers.bin loaded — now in signer, verifier **and** explorer)
- TXID matches raw transaction hash

**Loaded-chain integrity (v2.3.0).** When a `headers.bin` is loaded, the chain is
now bound to the network in two ways it previously was not:
- **Anchor is enforced, not advisory.** `verifyHeaderChain` *rejects* (fails closed) a
  chain whose anchor block does not equal the embedded checkpoint. Previously the
  anchor mismatch was surfaced as text and the chain was still used.
- **Every chain header must clear the difficulty floor.** The floor is applied inside
  the header-chain loop, not just to standalone envelope headers, so cheaply-forged
  low-difficulty headers spliced onto a genuine anchor are rejected rather than
  admitted to the inclusion index.
- **A chain that fails to load fails the verdict closed.** If a supplied `headers.bin`
  fails verification, the tools no longer silently fall back to the softer
  "no chain loaded" (isolation) state; they refuse until a valid chain is loaded or
  the file is removed.

**Checkpoint (block 939,999 — the anchor of `headers.bin`):**
```
height: 939999
hash:   00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12
nBits:  0x18227b71   (block 939999 difficulty, ~2^189, difficulty 31.886e9)
```

This replaces the earlier placeholder (`935000` / `0x1d2a0000`), whose `nBits` encoded a target *looser than difficulty-1* and made the difficulty floor toothless. The value above was derived from and verified against a real `headers.bin` (anchor 939,999 + PoW-valid header 940,000): the floor is now ~2^192, which rejects difficulty-1 (~2^223) and forces ~2^64 work to forge. `checkpointFloorStatus()` reports `sane: true`.

**Verify BOTH `hash` and `nBits` independently** (e.g. whatsonchain block 939999 / 940000) before trusting high-value transactions. Internal PoW validity alone does not prove canonicality — ~one BSV block of work is within a resourced attacker's reach, so the hardcoded anchor is a *trust* anchor that you must confirm against multiple explorers. `headers.js` emits a `console.warn` if the configured `nBits` ever makes the floor looser than difficulty-1.

**Difficulty floor:** 8x tolerance from checkpoint nBits, enforced on **standalone envelope headers** and on the **tip of a loaded chain** (v2.3.0). Because a forged header anywhere in a chain forces every later header (including the tip) to be re-forged, requiring the tip to clear the floor blocks trivially-forged low-difficulty chains while avoiding false rejection of legitimate chains that contain a genuine intermediate difficulty drop. A loaded chain may only make the floor stricter (raise-only): a forged low-difficulty tip can never lower the bar for standalone headers. The floor is a **heuristic**, not consensus difficulty — its strength depends on `CHECKPOINT.nBits` being a real, current value (verify it). On BSV, **chain inclusion against a loaded, checkpoint-anchored, PoW-verified header chain is the stronger check.**

**Chain inclusion — honest states.** verifier.html and explorer.html report one of these, and never collapse them:
- **verified** — block hash is in the loaded, checkpoint-anchored chain (height reported); the verdict reads as a full "inclusion proven" pass
- **not in chain** — a chain is loaded but this header is absent → **verdict fails closed**
- **not verified (isolation)** — no chain loaded → PoW proven in isolation, inclusion *not* claimed. As of v2.3.0 this renders as a distinct **amber "inclusion NOT proven"** verdict, not the same green as a chain-verified pass, so a passing isolation result cannot be misread as a confirmed transaction.
- **load failed** — a supplied `headers.bin` failed to verify → **verdict fails closed** (no silent downgrade to isolation)

---

## Security Hardening

### v2.3.0 — external review remediation

**Header-chain trust (highest severity)**
- **Checkpoint anchor enforced.** `verifyHeaderChain` now throws when the loaded chain's
  anchor ≠ the embedded checkpoint (opt out only via explicit `{ requireCheckpoint: false }`).
  Previously accepted with an advisory "no checkpoint match" label.
- **Difficulty floor inside the chain loop**; **raise-only dynamic floor** so a forged
  low-difficulty tip cannot lower the standalone-header floor.
- **Fail closed on chain-load failure** in verifier / explorer / signer, instead of
  silently reverting to isolation.

**Verdict presentation**
- verifier.html now invokes the difficulty floor as a hard gate (it previously did not),
  and renders isolation passes as a distinct amber "inclusion NOT proven" verdict.
- explorer.html renders isolation passes amber (distinct from chain-verified green).

**Reproducibility identifiers (explorer.html)**
- Input Fingerprint / Verification Hash / Replay ID are now computed over a **canonical**
  input (lowercased hex, fixed proof field order, length-prefixed framing), so the same
  logical envelope yields the same identifiers regardless of hex casing, JSON key order,
  whitespace, or optional-field presentation. The two identifiers now share one basis.

**chain.html**
- Now uses the shared `headers.js` consensus primitives (removing a private target/PoW
  copy that lacked `exp<=3` handling and could throw on crafted nBits); applies the
  CVE-2012-2459 proof-safety guard and a per-hop difficulty floor; `verifyHop` fails
  closed on crafted input.
- Value continuity no longer treats the self-declared `satoshis` field as a trusted
  claim; the on-chain parent output value is authoritative and any mismatch is advisory.

**Parsers (`bump.js` / `beef.js`)**
- Bounds-checked readers, strict hex (no `NaN→0x00` coercion), and consume-all assertions
  so truncated / trailing-garbage streams are rejected rather than under-parsed.
- `beef.verifyMined` now **requires** an `isValidRoot` callback (no silent-accept) and
  reports `allProvenValid: false` when nothing is proven or any tx is unproven.

**Second-pass remediation (post remediation of the above)**
- **Explorer difficulty floor now gates the verdict** (was advisory) — a sub-floor forged
  header now fails in explorer exactly as in verifier/chain, removing a cross-consumer
  inconsistency and a residual amber-"PASSED" over-assurance surface.
- **Reproducibility identifiers**: proof `pos` is canonicalized **verbatim** (case-sensitive,
  no default). The previous `(pos||'R').toUpperCase()` was more lenient than the structure
  validator, so a structurally-invalid proof could share a Replay ID with a valid one;
  identifier-equality now tracks verdict-equality. Fingerprint scope (verified evidence:
  txid/header/proof) is documented in the report.
- **chain.html accepts a single envelope object** (not just an array), so the generator format carries through to chain.html without hand-wrapping in `[ ]`; non-object input is still rejected.
- **chain.html value parse is now BigInt** (was `parseInt`→Number) — no precision loss above
  2^53 sat; also fixed a field-rename bug that printed "undefined sats".
- **Difficulty floor moved from per-header to tip-enforcement** — blocks forged
  low-difficulty chains without falsely rejecting legitimate chains that contain a genuine
  intermediate difficulty drop.

**Checkpoint & snapshot remediation (real-data pass)**
- **Checkpoint corrected to a verified anchor.** The placeholder `935000` / `0x1d2a0000`
  (target looser than difficulty-1 → toothless floor) is replaced with block **939,999**
  (`…bb54ef12`) / `nBits 0x18227b71` (block 939999's own value), verified against a real `headers.bin` and confirmed on a block explorer (difficulty 31.886e9).
  The floor is now ~2^192 and rejects difficulty-1. Fixed in `headers.js`, `mainnet-vectors.js`,
  and `verify_vectors.py`. `checkpointFloorStatus()` now reports `sane: true`. **Verify the
  hash and nBits against independent explorers before production use.**
- **`snapshot.js` difficulty floor** changed from a per-header walk-down (which let a signed
  snapshot ramp difficulty down ≤8× per step) to a fixed tip floor, matching `headers.js`.
- **`snapshot.js` signature path fixed** — it called a nonexistent lowercase `global.secp256k1`
  and passed byte arrays where hex strings were expected, so `createSnapshot`/`verifySnapshot`
  could never complete a signature (fail-closed crash). Now uses `SECP256K1` with hex I/O and
  DER signatures; create→verify round-trips, with untrusted-signer and tamper rejection tested.

### v2.2.0

**Ecosystem proof formats (BUMP / BEEF)**
- Added `lib/bump.js` (BRC-74) and `lib/beef.js` (BRC-62 / BRC-95), pure JS, zero dependencies
- Generator emits a self-verified `bump` alongside the legacy proof; verifier accepts BUMP / BEEF / legacy
- Byte-for-byte conformance with `@bsv/sdk` (see Validation & Testing)

**Audit (explorer.html) hardened to fail closed**
- Verdict now requires **all** objective checks — structure, proof-safety (CVE-2012-2459), PoW, Merkle-root match, and chain inclusion — not the root match alone. Previously a structurally anomalous proof that still hit the root could be reported VALID; it no longer can.
- Consensus math consolidated onto shared `headers.js` primitives (`targetFromNBits`, `verifyPoW`) — the audit no longer keeps a private copy of target/PoW logic that could drift. (In v2.2.0 this covered explorer.html only; `chain.html` was consolidated in v2.3.0.)
- **Honest scope**: the report states plainly that it proves PoW-in-isolation, not most-work-chain inclusion, and surfaces the difficulty floor and chain-inclusion state explicitly rather than implying them with a green check.
- **Reproducibility documented**: the exact construction of Input Fingerprint, Verification Hash, Replay ID and Step Checkpoint is printed in the report so a third party can recompute them.

**Chain inclusion wired into verifier and explorer**
- Optional `headers.bin` loader (same `verifyHeaderChain` path as the signer)
- Three-state result (verified / not-in-chain / not-verified); "not in chain" fails the verdict

### v2.0.2

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

## Validation & Testing

The proof layer is validated three independent ways. **This is internal differential testing plus reference-conformance testing — not a third-party security audit** (see License).

| Harness | What it checks |
|---------|----------------|
| `validate.js` | Differential test of `bump.js` / `beef.js` against an **independent Bitcoin Merkle oracle** (Node native crypto, zero shared code) across ~20 tree shapes (2 → 4096 leaves, odd/prime/power-of-two, index 0), plus 200 random BEEF transaction chains round-tripped byte-identical |
| `conformance-sdk.js` | **Byte-for-byte conformance against `@bsv/sdk`** — same BUMP serialization, same computed roots, same BEEF round-trip (`npm install @bsv/sdk && node conformance-sdk.js`) |
| `test-integration.js` | Runs verifier.html's real logic end-to-end on a BUMP envelope (valid / tampered / legacy) |
| `test-generator.js` | 160 TSC→BUMP conversions vs the oracle, plus a full generator → verifier round trip |
| `test-audit.js` | Reproduces the audit's own Verification Hash / Replay ID exactly; proves the duplicate-sibling proof the old audit called VALID now fails closed |
| `test-chain.js` | The three chain-inclusion states in both audit and verifier (verified / not-in-chain / not-verified) |
| `test-browser-suite.js` | Runs the new `tests.html` BUMP/BEEF/chain/adversarial blocks headlessly against the real libs (24 assertions) |
| `test-mainnet-bump.js` | Confirms Block 170's legacy proof converts to a BUMP that reconstructs the real mainnet root, cross-checked against an independent oracle (3 assertions) |
| `test-audit-fixes.js` (v2.3.0) | Checkpoint-anchor enforcement, raise-only floor, BUMP/BEEF bounds/strict-hex/consume-all, and the `verifyMined` callback contract (14 assertions) |
| `test-adversarial.js` (v2.3.0) | Grinds a genuinely PoW-valid but **sub-floor** header onto the real checkpoint anchor and asserts the chain is rejected by the in-loop floor; plus fingerprint-canonicalization invariance and delimiter-collision framing (8 assertions) |

Combined, the integration and browser harnesses run **~395 assertions** on top of **4,357 differential-oracle checks** in `validate.js`, all passing. The in-browser `tests.html` (82 vectors) and `tests-mainnet.html` now also exercise BUMP/BEEF, chain-inclusion, adversarial proofs, and one real-mainnet BUMP verification. The BUMP/BEEF modules have additionally been confirmed against live WhatsOnChain proofs end-to-end (generator emits → verifier accepts). Running `conformance-sdk.js` on your own machine, ideally with a few of your own captured vectors added, is the recommended pre-deployment check.

---

## File Hashes (v2.3.0)

Verify before entering private keys:

```bash
# macOS/Linux
shasum -a 256 lib/*.js signer.html generator.html verifier.html headers-generator.html explorer.html chain.html tests.html tests-mainnet.html

# Windows PowerShell
Get-ChildItem lib\*.js, signer.html, generator.html, verifier.html, headers-generator.html, explorer.html, chain.html, tests.html, tests-mainnet.html | Get-FileHash -Algorithm SHA256
```

| File | SHA-256 | Status |
|------|---------|--------|
| lib/crypto.js | `b2a91262f01994555e5e713cccb9d607c29b48ac5725f9bbce10df084ead0ab2` | unchanged |
| lib/encoding.js | `22ea32359c2fd34aa9e421d99a2386f200e861bc7a364709745476d4091f57c1` | unchanged |
| lib/secp256k1.js | `fc2d03baff7e802a8aed8e49a59c6b044089f9f585e1a1c9fe281b73da0e3e2b` | unchanged |
| lib/sighash.js | `297151d898312ac0287abac527902ab4dec22804bbe1b782d4785bbbe789892f` | unchanged |
| lib/headers.js | `97ed1fe4b1b8ba046415a3d38987e247924bc69c16172bcab60bb740b766c271` | **updated (v2.3.0)** |
| lib/bump.js | `b7fa41901c13ae2bbd570f78c889932954d414fb7e42129e0e3a3e64cad814e8` | **updated (v2.3.0)** |
| lib/beef.js | `3d1af54158e79a2cea3bcf69507e217810165d627986f4fdb698331d73d779b2` | **updated (v2.3.0)** |
| lib/snapshot.js | `5c391e376a4f2b2183f9e726db1e207e319ca976fba9c0fd5c9aea5179bd5442` | **updated (v2.3.0)** |
| lib/mainnet-vectors.js | `b202b86e12f8d340f2f862845182838581b0643e65b338d57ce8ee93e6ca0155` | **updated (v2.3.0)** |
| generator.html | `2b356505680bc266d77ab75ce6ad8b48d49c891cd9fc29a52cf5bc0fb255af6b` | **updated (v2.2.0)** |
| headers-generator.html | `44fa51df0cec8ebc6cb1d5a4e0927e95f9c03a3f1c7d01c9506174378b93a5e1` | **updated (v2.3.0)** |
| signer.html | `c4a85cffc27bd3721959d357e4c0fc272756089b37beca0b7c47792497338933` | **updated (v2.3.0)** |
| verifier.html | `4b8b008a338deedf53bacc8cc00109252beb7499686755c7769b186b01b59fda` | **updated (v2.3.0)** |
| explorer.html | `2f03ee2c486cc92facd2fbaea78019b38ae9a830366cde900dba89257b943c51` | **updated (v2.3.0)** |
| chain.html | `1732d2aa6962efd408b392d4cba09798352bfe867578fd7842e429470c5fa7cf` | **updated (v2.3.0)** |
| tests.html | `79f51d56b03eee76c3fd56d5a3a351854e1f243a00c9a5fdf47eed754a574e44` | **updated (v2.2.0)** |
| tests-mainnet.html | `264b74b2c3a410a509e4bc524d080ee7098e83837b8953e10352bb20dd4592e8` | **updated (v2.3.0)** |
| verify_vectors.py | `6c015ddc2510139d886cc954c8b30cdd6c951aa93bc0a73cfb33602577d99be9` | **updated (v2.3.0)** |

> The seven files marked **updated (v2.3.0)** are the patched build in this bundle and
> their hashes were recomputed from those exact bytes. The remaining rows are carried
> over from v2.2.0 (those files were not modified in this release). The four unchanged
> `lib/*.js` hashes (crypto, encoding, secp256k1, sighash) were re-verified and match.
>
> Hashes are for this reference build. **Regenerate and re-check against your own shipped
> files after any modification** — including if you re-apply these changes to your own
> tree, since whitespace/line-ending differences change the hash. The point of the table
> is that you confirm the bytes you run, not that you trust this list.

---

## Limitations

- **P2PKH only** — Addresses starting with "1"
- **Same-key inputs** — Multi-input requires single controlling key
- **No multisig** — Single-key signing only (m-of-n is not implemented)
- **Mainnet only**
- **Single API source** — WhatsOnChain
- **Loaded-chain trust** — Chain inclusion is verified against a header chain *you supply and re-verify on load*; the chain still originates from an external source. Regenerate headers.bin for recent transactions.
- **Browser crypto** — Cannot guarantee constant-time or secure memory wipe

---

## Cryptography

Pure JavaScript, no external dependencies:

- SHA-256, RIPEMD-160, hash256, hash160
- secp256k1 ECDSA with RFC 6979, low-S (BIP 146)
- BSV sighash (SIGHASH_FORKID)
- Base58Check encoding
- Merkle proof verification
- BUMP (BRC-74) Merkle path; BEEF / Atomic BEEF (BRC-62 / BRC-95) containers

All tested against standard vectors and cross-checked against `@bsv/sdk`. See TEST-VECTORS.md and Validation & Testing above.

---

## Verification Instruments

This toolkit includes two verification instruments. Both are deterministic: identical inputs produce identical outputs across environments, implementations, and time.

---

## SPV Proof Explorer

`explorer.html` — Single transaction forensic verification.

Verifies one SPV envelope with full byte-level transparency. Every computation step is exposed, hashed, and exportable.

**Verification Transparency**
- Complete Merkle path visualization with concatenation order
- Double SHA256 rounds shown independently
- Block header parsed into constituent fields
- Sibling position (L/R) explicitly rendered at each level

**Verification Checks (fail-closed verdict)**
- Structure, proof-safety (CVE-2012-2459), PoW, difficulty floor, and Merkle-root match must all pass (the difficulty floor **gates** the verdict as of v2.3.0, consistent with verifier.html and chain.html — it is no longer advisory)
- Chain inclusion reported as verified (height) / not-in-chain (fails) / not-verified (no chain); a passing isolation result renders as a distinct amber "inclusion NOT proven" verdict, not green

**Assurance Scope**
- States explicitly that the audit proves PoW-in-isolation, not most-work-chain inclusion, unless a chain is loaded

**Deterministic Outputs**
- **Input Fingerprint** — SHA256 of the **canonical** input (lowercased hex, proof
  normalized to fixed `{hash,pos}` order, every field length-prefixed as `<len>:<value>`),
  truncated to 32 hex chars. Canonicalization (v2.3.0) makes the identifier stable across
  hex casing, JSON key order, whitespace, and optional-field presentation.
- **Verification Hash** — SHA256 of the same canonical input plus the deterministic
  computation steps
- **Replay ID** — Verification Hash truncated to 16 chars, for cross-system consistency
- Construction of each is documented in the report itself for independent recomputation

**Forensic Diagnostics**
- Byte-level diff on hash mismatches
- Failure localization to exact proof level
- Likely cause analysis with actionable detail
- Audit mode toggle for full raw data exposure

**Block Validation**
- Header hash computation (SHA256d)
- PoW verification against decoded nBits target (via shared `headers.js`)
- Timestamp, version, and nonce extraction

**Export:** JSON and text reports containing all intermediate values, suitable for audit trails and dispute evidence.

---

## Proof Chain Verifier

`chain.html` — Multi-hop ancestry verification.

Verifies a chain of linked transactions from child to ancestor. Each hop is independently verified for SPV integrity (TXID, PoW-in-isolation, difficulty floor, CVE-2012-2459-safe Merkle proof) and correct linkage (each child input references the parent TXID). It establishes that a linked path of confirmed transactions exists and reports the on-chain value of each spent parent output; it does **not** prove global value conservation across all of a transaction's inputs, and does not evaluate Bitcoin Script.

**Verification Phases**

| Phase | Check |
|-------|-------|
| 1. Structure | Hex encoding, field lengths, proof array format |
| 2. Ordering | Chain flows child → ancestor, detect REVERSED/UNLINKED |
| 3. Per-Hop SPV | TXID, PoW, Merkle proof (fail-fast on first failure) |
| 4. Linkage | Child input must reference parent TXID + vout |
| 5. Value Continuity | Referenced parent output exists; its on-chain value (parsed as **BigInt**, no precision loss) is reported. Self-declared `satoshis` is advisory only, not trusted |
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
| `VALUE_MISMATCH` | Referenced parent output index does not exist (self-declared satoshis mismatch is advisory, not a failure) |
| `NOT_IN_CHAIN` | Header absent from a loaded header chain |

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

Most verification tools return a binary result: valid or invalid.

The computation is opaque.
The process cannot be independently reproduced.
You trust the output.

This project takes a different approach.

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
  headers.js        # PoW, Merkle proofs, header chain, difficulty floor
  bump.js           # BUMP (BRC-74) Merkle path — reader/writer/root
  beef.js           # BEEF / Atomic BEEF (BRC-62 / BRC-95) container
  snapshot.js       # Header snapshots
  mainnet-vectors.js # Real BSV test vectors
docs/
  CROSS-VERIFICATION.md  # Independent verification guide
  ANTI-FEATURES.md       # Design decisions
  SIDE-CHANNELS.md       # Security considerations
generator.html      # Online envelope generation (emits proof + BUMP)
headers-generator.html
signer.html         # Offline signing
verifier.html       # Standalone verification (proof / BUMP / BEEF + chain inclusion)
explorer.html       # Forensic SPV proof analysis (fail-closed audit + chain inclusion)
chain.html          # Deterministic lineage verification
tests.html          # Unit test suite
tests-mainnet.html  # Mainnet verification tests
verify_vectors.py   # Python verification (standalone)
test/
  validate.js         # Differential test vs independent Merkle oracle
  conformance-sdk.js  # Byte-for-byte conformance vs @bsv/sdk
  test-integration.js # verifier.html BUMP end-to-end
  test-generator.js   # TSC→BUMP + generator→verifier round trip
  test-audit.js       # audit hardening + identifier reproduction
  test-chain.js       # chain-inclusion three-state logic
  test-browser-suite.js # runs tests.html BUMP/BEEF/chain/adversarial in Node
  test-mainnet-bump.js  # Block 170 legacy proof -> BUMP -> real mainnet root
  test-audit-fixes.js   # v2.3.0 fixes: checkpoint/floor/parser/verifyMined
  test-adversarial.js   # v2.3.0: forged sub-floor chain rejection + canonicalization
```

---

## License

MIT. **Use at your own risk.** This software handles cryptographic keys and financial transactions. **Not independently security-audited.** An external code review informed the v2.3.0 hardening above and its regression tests; a targeted review that finds and helps fix issues is **not** the same as, and is not a substitute for, a full independent third-party security audit. Validation to date is that review plus internal differential testing and `@bsv/sdk` conformance testing (see Validation & Testing). Commission an independent audit before relying on this for high-value transactions.

---

[WhatsOnChain Broadcast](https://whatsonchain.com/broadcast) · [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)
