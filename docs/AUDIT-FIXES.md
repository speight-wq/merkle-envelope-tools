# Audit Fixes — Merkle Envelope Tools

Patches for the ten findings from the security review. Grouped by file, with the
finding each addresses and how it was verified. **Scope caveat:** these are
audit fixes verified where executable in Node (v22); they are **not** an
independent professional security audit. The four HTML files' behavioral changes
are syntax-checked and logic-reviewed but still need a real browser test pass.

## Verification summary

| Check | Result |
|---|---|
| `lib/bump.js` self-test | PASS |
| `lib/beef.js` self-test | PASS |
| `test/test-audit-fixes.js` (items 1,2,7,9) | 14/14 PASS |
| `test/test-adversarial.js` (forged chain + canonicalization + precision) | 12/12 PASS |
| Second-pass remediation (findings A/B/C/D) | applied + tested |
| Real-envelope validation (`test/verify-real-envelope.js`) | valid mainnet envelope accepted; surfaced checkpoint-floor finding |
| `tests.html` (82 vectors, run in Node) | 82/82 PASS against patched libs + new checkpoint |
| `tests-mainnet.html` (31 tests, run in Node) | 31/31 PASS after fixing hardcoded checkpoint height + adding cross-checks |
| Fourth-audit M1: Atomic-BEEF subject validation (BRC-95) | fixed + 6 tests (subject present/last/only-ancestors) |
| Difficulty-floor policy: per-header enforcement (reverts tip-only) | `enforceChainFloor()` + 5 policy tests (G1–G5); forged-chain + real-940000 still pass |
| `node --check` on all 4 HTML inline scripts | PASS |
| Differential vs original `headers.js` | original **accepts** forged low-difficulty chain; patched **rejects** it |

The differential is the headline result: a `headers.bin` anchored at the REAL
checkpoint (935000) but carrying one genuinely PoW-valid, sub-floor header is
accepted by the original code (`checkpointVerified=true`, forged block enters
`hashIndex`) and rejected by the patched code with a floor error.

---

## lib/headers.js — items 1, 2 (highest severity; shared by all consumers)

**Item 1 — enforce the checkpoint anchor.** `verifyHeaderChain` now throws when the
loaded chain's anchor ≠ the embedded checkpoint, instead of returning an advisory
`checkpointVerified` flag that all three callers ignored. Opt out only via explicit
`verifyHeaderChain(bytes, CP, { requireCheckpoint: false })`.

**Item 2 — difficulty floor inside the chain loop + raise-only dynamic floor.**
Every chain header must now clear `STATIC_FLOOR_TARGET` (rejecting cheaply-forged
low-difficulty headers spliced onto a genuine anchor). `getEffectiveFloor()` now
returns the *harder* of static/dynamic, so a forged low-difficulty tip can no longer
lower the standalone envelope floor via `setDynamicFloor`.

## lib/bump.js — item 9

Bounds-checked `Reader` (`u8`/`bytes` throw past end); strict `fromHex` (rejects
odd-length/non-hex instead of coercing `NaN → 0x00`); `fromHex` (BUMP) asserts the
whole buffer is consumed (no trailing garbage).

## lib/beef.js — items 7, 9

Bounds-checked `Reader`; strict `fromHex`; `parse` asserts full consumption.
`verifyMined` now **requires** the `isValidRoot` callback (no more silent-accept when
omitted; explicit `verifyMined.UNSAFE_SKIP_ROOT_CHECK` sentinel for the rare skip),
and `allProvenValid` is false when nothing is proven or any tx is unproven.

## verifier.html — items 3, 4

- Invokes `validateHeaderDifficulty` as a **hard gate** (previously the floor was
  never called here — a difficulty-1 forged header passed on PoW-in-isolation alone).
- Three-state verdict: green "INCLUSION PROVEN" only with a verified chain; amber
  "INCLUSION NOT PROVEN (PoW in isolation)" otherwise; red on failure.
- A supplied-but-failed header chain now **fails closed** rather than silently
  reverting to the softer "unknown"/isolation state.

## explorer.html — items 3, 4, 7

- **Item 7:** reproducibility identifiers canonicalized before hashing —
  lowercased hex, proof normalized to fixed `{hash,pos}` order, every field
  length-prefixed (`<len>:<value>`) so no field boundary can collide. `inputFingerprint`
  and `verificationHash` now share one basis; the printed recipe is updated to match.
  (Previously: `txid_raw + JSON.stringify(proof) + header` — sensitive to hex casing,
  JSON key order, whitespace, optional fields, and inconsistent between the two IDs.)
- **Item 3:** an isolation pass renders **amber** ("PoW IN ISOLATION — inclusion NOT
  proven"), distinct from a green chain-verified pass.
- **Item 4:** chain-load failure fails the verdict closed.

## signer.html — item 4

A supplied chain that fails to verify now **refuses header-bearing inputs** unless the
user explicitly checks "Skip chain verification." (The signer already floor-gated,
threw on `not_in_chain`, and cleared the key after signing — those were sound.)

## chain.html — items 5, 6, 8

- **Item 5:** removed the private, divergent PoW/target math (it lacked `exp<=3`
  handling and threw `RangeError` on `exp<3`); now uses shared
  `verifyPoW`/`validateHeaderDifficulty`/`targetFromNBits`/`hashHeader` from
  `headers.js`. `verifyHop` is wrapped so crafted input fails closed to a structured
  result instead of an uncaught throw.
- **Item 6:** applies `checkMerkleProofSafe` (CVE-2012-2459) and per-node proof
  structure validation before the Merkle loop — guards the other tools already had and
  `chain.html` omitted entirely. Adds a difficulty-floor gate per hop.
- **Item 8:** value continuity no longer trusts the self-declared `child.satoshis`
  (attacker-controlled); the on-chain parent output value at the linkage vout is
  authoritative, a mismatch is advisory (not a pass/fail implying conservation), and
  the "value flowed" framing is softened. The 8-byte output value is parsed as **BigInt**
  (no precision loss above 2^53 sat) as of the second-pass remediation below.

## Second-pass remediation (post-remediation self-audit)

A second adversarial pass over these fixes found gaps — including some introduced by the
fixes themselves — now addressed:

- **A (explorer floor advisory → gating).** `explorer.html` now includes the difficulty
  floor in `r.result.valid`, so a sub-floor forged header fails there exactly as in
  verifier/chain. Removes a cross-consumer inconsistency and an amber-"PASSED" surface.
- **B (canonicalizer more lenient than validator).** Proof `pos` is now canonicalized
  verbatim (case-sensitive, no `||'R'` default), so a structurally-invalid proof can no
  longer share a Replay ID with a valid one. Regression tests added.
- **C (value precision + display bug).** `chain.html` parses the output value as BigInt;
  fixed the `claimedSatoshis`/`childClaimed` field mismatch that printed "undefined sats".
- **D (in-loop static floor over-strict).** The floor is enforced on the chain **tip**
  rather than every header, preserving forgery-blocking (a forged chain has a forged,
  sub-floor tip) while no longer falsely rejecting legitimate intermediate difficulty drops.

## HIGH — Checkpoint difficulty misconfigured (the floor was toothless) — RESOLVED

Surfaced by running a **real mainnet envelope** through the patched libraries, then fixed
using a **real `headers.bin`** the maintainer provided (anchor 939,999 + PoW-valid header
940,000).

- The former checkpoint `nBits = 0x1d2a0000` gave a floor ~2^232 — *looser than
  difficulty-1* (~2^223) — so difficulty-1 headers (grindable, ~2^32 work) passed it. FP-2's
  protection was inert in production even though the code enforced the floor correctly.
- **Fix:** checkpoint set to block **939,999** (`00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12`),
  `nBits = 0x18227ea6` (real BSV difficulty ~2^189, verified against the provided headers.bin:
  PoW valid, links to anchor, tip clears the floor). Floor is now ~2^192; difficulty-1 is
  rejected; `checkpointFloorStatus()` → `sane: true`. Updated in `headers.js`,
  `mainnet-vectors.js`, `verify_vectors.py`. Tested end-to-end (D2/D3): the real headers.bin
  verifies against the enforced checkpoint and resolves chain inclusion at height 940,000.
- **Residual (maintainer action):** the anchor hash and nBits must still be confirmed against
  independent explorers — ~one BSV block of work is within a resourced attacker's reach, so
  PoW validity alone does not prove canonicality. The hardcoded anchor is a *trust* anchor.

**Independently confirmed on a block explorer (block 939,999).** The maintainer verified:
next block #940000 = `…15ab789000…1dd63e7` (matches the hash computed from `headers.bin`,
transitively confirming the 939,999 anchor via 940000's committed `prevBlock`); and difficulty
**31.886 × 10⁹**. This also corrected `nBits`: block 939,999's real value is **`0x18227b71`**
(difficulty 31.886e9 — an exact match), not the adjacent block 940000's `0x18227ea6` that had
been used as a proxy. Both give the same ~2^192 floor; the checkpoint now carries its own block's
value so an independent verifier's cross-check matches. Fixed in `headers.js`,
`mainnet-vectors.js`, `verify_vectors.py`.

## MEDIUM/LOW — snapshot.js (found this pass; not in the shipping verification tools) — FIXED

`snapshot.js` is referenced only by `tests.html`, and its tests only exercised early-reject
paths, so these went unnoticed:

- **Difficulty floor walked *down* per header** (`currentFloorTarget = target * 8n`), letting a
  signed snapshot ramp difficulty down ≤8× per step into a low-difficulty tail. Changed to a
  fixed tip floor (matches headers.js finding-D).
- **Signature path was non-functional** — called a nonexistent lowercase `global.secp256k1`
  (the export is `SECP256K1`) and passed `Uint8Array`s where hex strings were expected. Any
  snapshot reaching the signature step threw an uncaught `TypeError` (fail-closed crash, never a
  false accept), and `createSnapshot` could not run at all. Rewritten to use `SECP256K1` with
  hex I/O and DER signatures. Round-trip, untrusted-signer, and tamper cases now tested (E).

**Still not code-changed (documented residuals):** signer signs in isolation when no chain is
loaded (by-design optional-chain anti-feature); explorer identifier scope excludes unverified
fields (rawTx/vout/satoshis — documented in the report); SHA-256 remains implemented in more
than one place (chain.html computes its Merkle root with its own inline SHA-256d — functionally
equivalent, all vectors pass, latent drift risk); and the four HTML tools remain
browser-untested (the verification *logic* has been exercised in Node, including the real
envelope and both `tests.html` (82/82) and `tests-mainnet.html` (31/31), but not the live
DOM/verdict rendering).

## Fourth audit — Atomic-BEEF subject validation (M1, BRC-95)

`beef.js parse` read the Atomic-BEEF `atomicSubject` from the `0x01010101` prefix but never
validated it — so `atomicSubject` was an unvalidated, attacker-controlled claim: any txid
(even one absent from the container, or one the enclosed proofs don't cover) could be asserted
as "the transaction this Atomic BEEF proves." Not reachable via the shipped HTML tools (they
verify `envelope.txid`), but a false-attribution primitive for any library/conformance consumer.

**Fix:** `validateAtomicSubject(txs, subjectTxid)` (exported, unit-testable), called from `parse`
whenever the stream is Atomic BEEF. It fails closed on three BRC-95 violations: subject not
present in the container; subject not the last transaction; and any included tx that is neither
the subject nor an ancestor of it (reachability through the input DAG). The valid BRC-62 vector
and both browser suites (82/82, 31/31) still pass. Tests added (`test-adversarial.js` group F):
F1 subject-not-last rejected, F2 subject-absent rejected, F3b unrelated-tx rejected, plus
positive controls (valid subject parses; subject + genuine ancestor validates).

**Note:** the fourth audit found **no MAJOR** finding. Its other items are not code-changed here —
m1 (tip-only floor reasoning/test) and m3 (no most-work check) are correctness-of-reasoning /
documentation items, not exploitable defects. It was, again, author-adjacent self-review — an
independent implementer is still owed.

## HIGH — Checkpoint difficulty is misconfigured (the floor is toothless)

Surfaced by running a **real mainnet envelope** through the patched libraries
(`test/verify-real-envelope.js`). The envelope itself verifies perfectly (txid, legacy
proof, BUMP, PoW, block hash, CVE guard, floor all pass — the fixes produce no false
negatives). But the real block header carries `nBits = 0x18267614` (target ~2^189), while
the **embedded checkpoint** claims `nBits = 0x1d2a0000` (target ~2^229):

- The static floor is checkpoint-target × 8 ≈ **2^232**.
- Bitcoin/BSV **difficulty-1** target is ≈ **2^223** — *smaller* than the floor.
- Therefore **difficulty-1 headers pass the floor.** An attacker can grind difficulty-1
  headers (~2^32 work each — seconds to minutes) and clear it. FP-2's protection is inert
  *in production* even though the code enforces the floor correctly.
- The checkpoint's own **hash** (`0000000000000000 14dd…`, ≈2^188) proves the real block
  did ~2^68 of work, so the real `nBits` target is ~2^188 (exponent ~`0x18`), **not** 2^229.
  The stored `nBits` is a placeholder ~40 bits too loose.

**This is a data/config error, not a code error, and no code guard substitutes for the
correct value.** Required fix (author, needs the network): set `CHECKPOINT.nBits` to block
935,000's real value (verify on whatsonchain — it will be ~`0x18xxxxxx`). Once corrected,
the floor rejects difficulty-1 (2^223 > ~2^192) and forces ~2^64 work to forge.

**Code guard added** (`checkpointFloorStatus()` in headers.js, exported + tested): detects
when the floor is looser than difficulty-1 and emits a loud `console.warn` at load, so the
tool never silently presents a toothless floor as protection. With the shipped checkpoint
it reports `sane: false`; it flips to `sane: true` once the real nBits is set. The UIs
should surface this status; today they do not.

## Item 10 — tests added

- `test/test-audit-fixes.js` — checkpoint enforcement, raise-only floor, BUMP/BEEF
  strictness/consume-all, `verifyMined` contract.
- `test/test-adversarial.js` — forged sub-floor chain at the real checkpoint (grinds a
  valid PoW nonce, asserts rejection by the floor) and fingerprint canonicalization
  invariance/collision-framing.

**Not yet covered:** BUMP/BEEF structural fuzzing, and browser-level behavioral tests
of the four HTML tools (verdict states, chain-load-failure fail-closed, explorer
identifier stability in-page). These need a headless-browser harness.

## Note on file hashes

The README's `File Hashes (v2.2.0)` table is now stale for every patched file.
Regenerate before publishing:
`shasum -a 256 lib/*.js verifier.html explorer.html signer.html chain.html`
