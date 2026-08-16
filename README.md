# Merkle Envelope Tools

**Deterministic, fully offline SPV verification and forensic audit instruments for Bitcoin SV.**

Package a transaction with its Merkle proof and block header, then verify inclusion and proof-of-work with no node, API, or third party — and get a reproducible record of *what was verified and what was not*. The tools speak the ecosystem's standard proof formats (**BUMP** BRC-74, **BEEF / Atomic BEEF** BRC-62 / BRC-95), so proofs move both ways with any `@bsv/sdk` wallet. Pure vanilla JavaScript, zero dependencies.

The principle throughout: a green check that can't be independently reproduced is not verification, it's trust. So every tool states the exact scope of what it proved and refuses to imply more.

---

## Tools

| Tool | Network | Purpose |
|------|---------|---------|
| `generator.html` | Online | Create Merkle envelopes (single or chain mode); emits legacy proof + BUMP |
| `headers-generator.html` | Online | Download a checkpoint-anchored `headers.bin` |
| `signer.html` | Offline | Sign transactions from envelopes (air-gapped; keys never touch a networked device) |
| `verifier.html` | Offline | Quick pass/fail verification (proof / BUMP / BEEF + chain inclusion) |
| `explorer.html` | Offline | Forensic SPV proof analysis with a deterministic verification record |
| `chain.html` | Offline | Multi-hop lineage verification (also accepts a single envelope) |
| `tests.html` | Offline | 82 in-browser test vectors (BUMP / BEEF / chain-inclusion) |
| `tests-mainnet.html` | Offline | 31 real-mainnet verification tests |
| `verify_vectors.py` | Offline | Standalone Python vector checker (stdlib only) |

**Workflow:** `generator.html` (online) → USB → `signer.html` (offline) → USB → broadcast (online). Verify or audit any envelope offline with `verifier.html`, `explorer.html`, or `chain.html`. Load order in HTML: `crypto.js` → `encoding.js` → `headers.js` → `bump.js` → `beef.js`.

---

## Envelope format

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

`vout` and (`blockHeader` + `proof`) are required — no silent defaults. `bump` (BRC-74 hex) is optional and preferred over `proof` when present; a `beef` / `atomicBeef` hex field is also accepted. The verifier tries, in order, `bump` → `beef` / `atomicBeef` → legacy `proof`. Existing envelopes verify unchanged. A single envelope object may be pasted anywhere an array is accepted (including `chain.html`).

BUMP/BEEF live in `lib/bump.js` and `lib/beef.js`. The generator converts each source proof to a BUMP and **self-verifies it against the header's Merkle root before attaching it** — if it doesn't reconstruct, it keeps the legacy proof and warns rather than emitting a bad BUMP. `beef.js parse` validates the Atomic-BEEF subject per BRC-95 (subject must be present, the last transaction, and the container may hold only its ancestors) and fails closed otherwise.

---

## Trust model & limitations

This is the important part. Read it before relying on a verdict.

**You trust:** the embedded checkpoint is the real block; the data source was honest at generation time; your offline machine is not compromised.

**You verify (cryptographically):** the transaction is in the Merkle tree; the block meets its own PoW target; TXID matches `SHA256d(rawTx)`; and, if a `headers.bin` is loaded, the block is in a checkpoint-anchored, PoW-linked header chain.

**Checkpoint (block 939,999 — the anchor of `headers.bin`):**
```
height: 939999
hash:   00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12
nBits:  0x18227b71   (difficulty 31.886e9, target ~2^189)
```
The checkpoint is a **single-source trust anchor.** Internal PoW validity does not prove canonicality — on BSV, ~one block of work is within a resourced attacker's reach. **Independently confirm both the hash and the `nBits`** on multiple explorers (e.g. whatsonchain block 939999 / 940000) before trusting high-value transactions. `headers.js` exposes `checkpointFloorStatus()` and emits a `console.warn` if the configured `nBits` ever makes the difficulty floor looser than difficulty-1.

**Difficulty floor — a heuristic, not consensus.** Enforced **per header** on standalone envelope headers and on **every** header of a loaded chain (target ≤ checkpoint difficulty × 8). Because `chainInclusion()` can report *any* admitted header as "verified," the floor must hold for every header — not just the tip — so one expensive floor-difficulty header can't be amortized across many cheap forged intermediates. Forging inclusion therefore costs ≥ ~one floor-difficulty block of PoW (a heuristic bound, not economic finality). A loaded chain may only make the floor *stricter* (raise-only); a low-difficulty tip can never lower the bar. Accepted trade-off: a legitimate chain containing a header genuinely >8× easier than the checkpoint (a real BSV hashrate crash) is rejected — this **fails closed to isolation**, never to a false "verified." Retarget-aware (DAA) validation is out of scope.

**Chain-inclusion states — never collapsed:**
- **verified** — block is in the loaded, checkpoint-anchored chain (green, "inclusion proven").
- **not in chain** — a chain is loaded but this block is absent → **fails closed** (red).
- **isolation** — no chain loaded → PoW proven in isolation; inclusion *not* claimed → distinct **amber** verdict, never the green of a chain-verified pass.
- **load failed** — a supplied `headers.bin` failed to verify → **fails closed** (no silent downgrade to isolation).

**What is NOT established (anti-claims):**
- **Most-work chain.** "Verified" means membership in a checkpoint-anchored linked chain, not that it is the most-work honest chain. Cumulative work is computed but not compared.
- **Non-spend / current UTXO status.** SPV proves a transaction was mined; it cannot prove an output is unspent. Any "unspent" claim needs a source that indexes spends.
- **Pre-checkpoint transactions.** The chain runs *forward* from the checkpoint (939,999 →). A transaction in a block **before** the checkpoint can never be chain-verified with this checkpoint — it is permanently isolation-only. A post-checkpoint transaction requires a contiguous `headers.bin` from 939,999 to its block.

**Also not covered:** blockchain sync, multi-source discovery, protection of a compromised machine, constant-time guarantees, P2SH / multisig / testnet, and Bitcoin Script / value-conservation evaluation for unmined BEEF ancestors.

---

## Design invariants

- **A verdict is a pure function of every input it depends on — and must be invalidated when any of them changes.** The envelope *and* the loaded header chain are both inputs. `explorer.html` locks a verdict for reproducibility; loading or changing the header chain invalidates that lock and recomputes, so a displayed verdict always matches the currently-loaded evidence. (This invariant came from a real bug: a locked isolation verdict once persisted on screen while a different chain was shown beside it.)
- **Known deviation from the invariant (open):** the Replay ID / Verification Hash currently commit to the envelope evidence only, *not* to which chain was loaded or the inclusion outcome — so an isolation verdict and a not-in-chain verdict for the same envelope share a Replay ID. This is the same root cause as the bug above (an identifier keyed on a subset of its inputs) and is documented here rather than hidden until fixed.
- **Fail closed.** Ambiguity, malformed input, a failed chain load, or a sub-floor header resolve to rejection or isolation — never to a false "verified."
- **One implementation per rule.** Consensus math (PoW, target, floor, chain inclusion) lives in `headers.js` and is shared by every consumer, so tools cannot drift.

---

## Verification & testing

- `lib/bump.js`, `lib/beef.js` — module self-tests (`node lib/bump.js`, `node lib/beef.js`).
- `test/test-audit-fixes.js` — 14 checks: checkpoint enforcement, raise-only floor, parser strictness, `verifyMined` contract.
- `test/test-adversarial.js` — 35 checks: forged low-difficulty chain (real PoW grind) rejected, fingerprint canonicalization, checkpoint sanity, snapshot round-trip, Atomic-BEEF subject validation, and per-header floor policy (including end-to-end wiring that a sub-floor intermediate is unreachable via `chainInclusion`).
- `tests.html` — 82 in-browser vectors. `tests-mainnet.html` — 31 real-mainnet tests.
- `test/verify-real-envelope.js` — verifies a real mainnet envelope end-to-end.

All suites pass against the current build; conformance is also differential-tested against `@bsv/sdk`. This is not a substitute for independent review (see License).

---

## File hashes

Verify before entering private keys. Regenerate from your own shipped files after any change — whitespace and line endings change the hash:

```
# macOS/Linux
shasum -a 256 lib/*.js *.html *.py
# Windows PowerShell
Get-FileHash -Algorithm SHA256 lib\*.js, *.html, *.py
```

| File | SHA-256 |
|------|---------|
| lib/crypto.js | `b2a91262f01994555e5e713cccb9d607c29b48ac5725f9bbce10df084ead0ab2` |
| lib/encoding.js | `22ea32359c2fd34aa9e421d99a2386f200e861bc7a364709745476d4091f57c1` |
| lib/secp256k1.js | `fc2d03baff7e802a8aed8e49a59c6b044089f9f585e1a1c9fe281b73da0e3e2b` |
| lib/sighash.js | `297151d898312ac0287abac527902ab4dec22804bbe1b782d4785bbbe789892f` |
| lib/headers.js | `f9840135cf8da953e2da710a02206927b24d2f972a4d8f9dd9fef29ed1bb8f0a` |
| lib/bump.js | `b7fa41901c13ae2bbd570f78c889932954d414fb7e42129e0e3a3e64cad814e8` |
| lib/beef.js | `7b85bcd2e75c723269a2038333f256d2e9e8aa87b00d2859a53ca1d8c624ae53` |
| lib/snapshot.js | `5c391e376a4f2b2183f9e726db1e207e319ca976fba9c0fd5c9aea5179bd5442` |
| lib/mainnet-vectors.js | `b202b86e12f8d340f2f862845182838581b0643e65b338d57ce8ee93e6ca0155` |
| generator.html | `2b356505680bc266d77ab75ce6ad8b48d49c891cd9fc29a52cf5bc0fb255af6b` |
| headers-generator.html | `44fa51df0cec8ebc6cb1d5a4e0927e95f9c03a3f1c7d01c9506174378b93a5e1` |
| signer.html | `c4a85cffc27bd3721959d357e4c0fc272756089b37beca0b7c47792497338933` |
| verifier.html | `4b8b008a338deedf53bacc8cc00109252beb7499686755c7769b186b01b59fda` |
| explorer.html | `f7ed30cd2879acd0f3baad680de2cd7bc0eb9fac30c3cb2e6a600cc08f7bf90b` |
| chain.html | `1732d2aa6962efd408b392d4cba09798352bfe867578fd7842e429470c5fa7cf` |
| tests.html | `79f51d56b03eee76c3fd56d5a3a351854e1f243a00c9a5fdf47eed754a574e44` |
| tests-mainnet.html | `264b74b2c3a410a509e4bc524d080ee7098e83837b8953e10352bb20dd4592e8` |
| verify_vectors.py | `6c015ddc2510139d886cc954c8b30cdd6c951aa93bc0a73cfb33602577d99be9` |

The point of the table is that you confirm the bytes you run — not that you trust this list.

---

## Changelog (highlights)

Full detail, with per-finding rationale and tests, is in `AUDIT-FIXES.md`.

**v2.3.0 — review remediation and hardening**
- **Checkpoint corrected and enforced.** Real block 939,999 / `0x18227b71` (was a placeholder whose `nBits` made the floor toothless). `verifyHeaderChain` fails closed on anchor mismatch; a `console.warn` fires if the floor is ever looser than difficulty-1.
- **Difficulty floor: per-header enforcement**, raise-only dynamic floor; forging inclusion costs ≥ ~one floor-difficulty block.
- **Isolation vs inclusion** rendered distinctly across all consumers; chain-load failure fails closed; verdicts recompute when the chain changes.
- **Reproducibility identifiers canonicalized** (lowercased hex, verbatim proof position, length-prefixed framing) so identifier equality tracks verdict equality.
- **Parsers hardened** (bounds-checked readers, strict hex, consume-all); `beef.verifyMined` requires a root callback; **Atomic-BEEF subject validated** per BRC-95.
- **`chain.html`** consolidated onto shared consensus primitives; BigInt satoshi parsing; CVE-2012-2459 guard; single-envelope input.
- **`snapshot.js`** signature path repaired; fixed-tip floor.

**v2.2.0** — BUMP / BEEF / Atomic-BEEF interoperability with `@bsv/sdk`; CVE-2012-2459 proof-safety guard; consensus math consolidated onto `headers.js`.
**v2.0.2** — chain inclusion in verifier / explorer; fail-closed defaults.

---

## License

MIT. **Use at your own risk.** This software handles cryptographic keys and financial transactions. **Not independently security-audited** — validation to date is internal differential testing, `@bsv/sdk` conformance testing, and an internal audit that informed the v2.3.0 hardening. A targeted review that finds and fixes issues is not the same as, and is not a substitute for, a full independent third-party audit. Commission one before relying on this for high-value transactions.
