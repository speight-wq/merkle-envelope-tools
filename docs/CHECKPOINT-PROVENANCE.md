# Checkpoint Provenance

The checkpoint is this project's **single trust anchor**. Every `VERIFIED` and
`VERIFIED-ISOLATION` outcome the tools emit is conditional on it. This document records where
it came from, what can be checked without trusting anyone, what remains undocumented, and what
must be recorded if it ever changes.

It deliberately separates four things that are easy to conflate: what is **known**, what is
**independently verifiable right now**, what is **undocumented**, and what is **unprovable from
inside this repository**. Nothing here is inferred to fill a gap — where the record is silent,
this document says so.

---

## Current checkpoint

```
height  939999
hash    00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12
nBits   0x18227b71
```

Hardcoded in five places, which `test/test-checkpoint-consistency.js` asserts agree on all
three fields:

| # | Definition | Role |
|---|---|---|
| 1 | `lib/headers.js` | Canonical; shared by every browser tool. Sets the difficulty floor and the chain anchor check |
| 2 | `lib/mainnet-vectors.js` | `CHECKPOINT_VERIFICATION`, used by the browser test pages |
| 3 | `headers-node/verify.js` | Spec-derived verifier #1 |
| 4 | `headers-node-independent/verify.js` | Spec-derived verifier #2 |
| 5 | `verify_vectors.py` | Python cross-verification vectors |

Definitions 3 and 4 are **independent reimplementations** and deliberately do not import the
production constant: doing so would destroy the independence that makes their agreement with
the production code meaningful. Each requires only Node's `crypto`. The consistency test is the
mechanism that keeps them aligned, not a shared import.

---

## A. What is known

Recorded in `docs/AUDIT-FIXES.md:118–145`, which is the primary source for everything in this
section.

**Why this checkpoint exists.** The former anchor's `nBits = 0x1d2a0000` produced a difficulty
floor of roughly 2²³², **looser than difficulty-1** (~2²²³). Grindable difficulty-1 headers
cleared it, so the floor rejected nothing real and the protection was inert in production even
though the code enforced it correctly. The checkpoint was moved to block 939,999, whose real
difficulty gives a floor around 2¹⁹².

**Where the values came from.** A real `headers.bin` the maintainer provided, containing anchor
939,999 and a proof-of-work-valid header for 940,000.

**How it was confirmed.** Via the successor block: block 940,000's hash
(`…15ab789000…1dd63e7`) matched the value computed from that `headers.bin`, *transitively
confirming the 939,999 anchor through 940,000's committed `prevBlock` field*, and the difficulty
was confirmed as **31.886 × 10⁹**.

**A correction inside the record.** `nBits` was initially set to `0x18227ea6` — block
**940,000's** value, used as a proxy for its predecessor. It was corrected to block 939,999's
own value, `0x18227b71` (difficulty 31.886 × 10⁹, an exact match). Both yield the same ~2¹⁹²
floor, so the floor's behaviour did not change; the point of the correction is that the
checkpoint now carries its own block's value, so an independent verifier cross-checking block
939,999 against an explorer sees a match rather than a neighbouring block's figure.

**The caveat the record already states**, reproduced because it remains the single most
important sentence about this anchor:

> ~one BSV block of work is within a resourced attacker's reach, so PoW validity alone does not
> prove canonicality. The hardcoded anchor is a *trust* anchor.

---

## B. What can be independently verified right now

### Offline, with no network and no trust in anyone

| Check | Where | What it shows |
|---|---|---|
| All five definitions agree on height, full hash and `nBits` | `node test/test-checkpoint-consistency.js` | No drift between copies |
| `headers.bin` anchor prefix matches the checkpoint | `verify_vectors.py` CP.1 | The shipped chain file and the constant agree |
| Block 940,000's `prevBlock` commits to the checkpoint hash | `verify_vectors.py` CP.2 | A successor header cryptographically references this anchor |
| Block 940,000 satisfies its own proof-of-work | `verify_vectors.py` CP.3 | That reference is backed by real work |
| Block 940,000's difficulty is within the ×8 floor | `verify_vectors.py` CP.4 | CP.3 cannot be satisfied by a grindable low-difficulty header |
| The checkpoint hash is below the target its own `nBits` implies | `verify_vectors.py` CP.5, and Step 3 of `docs/CROSS-VERIFICATION.md` | Hash and `nBits` are mutually consistent — a pair failing this could not be the same block |

Together these mean a forged anchor would need a proof-of-work-valid header at
near-checkpoint difficulty pointing at it. That costs hashpower, not a text editor.

**They are nonetheless internal consistency, not external authenticity.** The successor header
is shipped in this repository alongside the value it confirms, so anyone able to alter one could
alter both. See §D.

### Online, by you

`docs/CROSS-VERIFICATION.md` §"Checkpoint Verification (Block 939,999)" gives the procedure:
look up height 939,999 on an explorer, compare the hash, and compute the target from `nBits`.
A working API endpoint is included. **This is the step that ties the anchor to the outside
world, and it is the one step this repository cannot perform for you.**

---

## C. What remains undocumented

Stated plainly rather than reconstructed. None of the following can be recovered from the
repository, and this document does not guess at them.

| Item | Status |
|---|---|
| **Date** of the independent confirmation | Not recorded |
| **Which** explorer(s) were used | `docs/AUDIT-FIXES.md:138` says "a block explorer" — singular and unnamed. The residual note at line 132 refers to "independent explorers", plural, as a requirement. Whether one or several were actually consulted is **ambiguous in the record** |
| **How many** independent sources agreed | Not stated |
| **Reproducible source records** | None. No archived API response, no saved hash of a response, nothing a third party could re-examine |
| **Who approves** a checkpoint change | Not documented anywhere in the project |

The honest reading is that the confirmation described in §A was performed and is credible, but
is **not independently re-examinable** from what the repository preserves. A reader who wants
assurance must redo it (§B, online) rather than audit the original.

---

## D. What is unprovable from inside this repository

No test, document or script in this project can establish that:

- block 939,999 exists on the BSV network;
- `00000000000000000e7aea9b454b4acc945e6ae5883ca7254809e538bb54ef12` is its hash;
- `0x18227b71` is its `nBits`;
- the block is on the most-work chain.

These are not gaps awaiting a better test. They are outside what an offline verifier can reach,
by definition: every artifact available to it ships in the same repository as the value in
question. **The only control is a human confirming the anchor against sources of their own
choosing.** Everything in §B raises the cost of a forgery; none of it removes this requirement.

This project has also had **no independent third-party security audit**, and the specification
and both spec-derived verifiers share one author. Agreement between them demonstrates internal
consistency, not external correctness.

---

## E. What to record if the checkpoint changes

**There is currently no rotation procedure.** This section is the record that should be produced
if one is ever carried out; it is not itself a procedure, and writing one is outstanding work.

### The consequence nobody had written down

**Rotating the checkpoint invalidates every previously issued evidence digest.** The checkpoint
is committed into `canonicalInput` (`explorer.html`, the `frame('checkpoint')` field), so the
Input Fingerprint and Verification Hash both depend on it. Measured over identical evidence
under two different checkpoints:

```
Replay ID under the current checkpoint : 76df3820a608849e292ff2add3207980
Replay ID under a rotated checkpoint   : 3e39347af2f0d5058348573b5e4ecc8e
```

The evidence did not change; the digest did. This is correct design — the digest should commit
to the policy that produced the verdict — but it means rotation is a **migration event**, not a
constant update.

Two distinct things must not be conflated:

- **Changing the active trust anchor** governs what the verifier accepts *now*. After a change,
  a `headers.bin` anchored to the old checkpoint is rejected, fail-closed.
- **Preserving the ability to verify historical evidence** is separate. An artifact issued under
  checkpoint *N* reproduces only under a verifier configured with checkpoint *N*. With a single
  hardcoded constant and no version record, that capability is lost at rotation.

Whether the verifier should *support* historical anchors is a design decision with genuine
security tension — an old anchor is a weaker anchor — and is not settled here.

### Minimum record for any future change

For each checkpoint, retired or active:

1. Height, full hash, `nBits`, and the difficulty floor it implies.
2. The date it was selected, and the date it became active.
3. Every source consulted, **named**, with the exact URL or endpoint queried and the relevant
   response fields — enough that a third party can repeat the query.
4. How many independent sources were consulted and whether they agreed; any that disagreed.
5. The successor-header linkage used (which block, its hash, its `prevBlock`, its `nBits`).
6. Who performed the confirmation and who approved the change.
7. Confirmation that all five definitions in the table above were updated in the same commit,
   and that `node test/test-checkpoint-consistency.js` passes.
8. An explicit statement of what the record does **not** establish (§D applies to every
   checkpoint, not just this one).
9. The previous checkpoint's values, retained here rather than deleted, with the dates it was
   active — so a holder of an older artifact can identify which anchor produced it.

### Retired checkpoints

| Height | Hash | nBits | Active from | Until | Why retired |
|---|---|---|---|---|---|
| 935000 | *not recorded* | `0x1d2a0000` | *not recorded* | *not recorded* | Difficulty floor was looser than difficulty-1, making the floor inert (`docs/AUDIT-FIXES.md:118–132`) |

The gaps in that row are themselves the argument for this document: the previous anchor's hash
and active dates were not preserved when it was replaced, so artifacts issued under it cannot
now be attributed to it with certainty.

---

## Related

- `docs/CROSS-VERIFICATION.md` — the step-by-step independent confirmation procedure
- `docs/AUDIT-FIXES.md:118–145` — the primary provenance record
- `THREAT-MODEL.md` — "Wrong or compromised trust anchor"
- `test/test-checkpoint-consistency.js` — drift detection across all five definitions
- `verify_vectors.py` — CP.1–CP.5, the offline linkage checks
