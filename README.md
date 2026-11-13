# Merkle Envelope Tools

Offline SPV verification and forensic audit tools for Bitcoin SV. No node. No network. No
trusted server.

Given a transaction, its Merkle proof, and block-header evidence, the tool determines exactly
what that evidence establishes - and keeps distinct claims distinct, so weaker evidence is
never silently promoted to stronger proof. Vanilla JavaScript, zero dependencies.

## What it proves

Each verification resolves these independently, then composes them into one typed verdict:

- **Transaction identity** - `txid == SHA256d(rawTx)`.
- **Merkle inclusion** - the proof folds to the block header's merkle root (BUMP / BEEF / legacy).
- **Proof-of-work** - `SHA256d(header) <= target(nBits)`.
- **Difficulty-floor policy** - the header's target is within a bounded multiple of the checkpoint's.
- **Chain membership** - the header is in a checkpoint-anchored, PoW-linked chain, when one is loaded.

A proof that holds with no chain loaded returns `VERIFIED-ISOLATION` (PoW and inclusion in a
block proven; on-chain membership not claimed), never the `VERIFIED` of a chain-confirmed
result. Malformed or insufficient evidence fails closed.

All three verification surfaces emit one shared outcome vocabulary - `VERIFIED`,
`VERIFIED-ISOLATION`, `FAILED`, `POLICY-REJECTED`, `MALFORMED`, `INDETERMINATE`, and
`NOT-ESTABLISHED` - under one frozen precedence, so the same evidence does not produce a
different-shaped verdict depending on which tool you opened. A regression suite drives all three
on identical evidence and asserts they agree; that suite exists because they once did not.

## Why it exists

"Verified" usually means "a server I trusted said so," and SPV tools routinely conflate distinct
claims - that a transaction exists, that it was mined, that it is on the most-work chain, that
its outputs are unspent. These do not follow from one proof. This tool keeps them separate and
labels the exact scope of every verdict. The rule it is built on: a green check you cannot
independently reproduce is not verification, it is trust.

## Quick start

Everything is offline and dependency-free. Open a tool in a browser:

- `verifier.html` - pass/fail verification (BUMP / BEEF / legacy proof + optional chain).
- `explorer.html` - forensic proof analysis with a deterministic verification record.
- `chain.html` - multi-hop lineage verification.
- `signer.html` - air-gapped P2PKH signing (see `docs/ANTI-FEATURES.md`, `docs/SIDE-CHANNELS.md`).
- `generator.html` / `headers-generator.html` - build envelopes / fetch a checkpoint-anchored `headers.bin` (online).

Run the test suite (Node >= 18; no install, no network):

```
npm test
```

## Verification model

PoW, target, difficulty-floor, and chain-membership verification lives once in `lib/headers.js`
and is shared by every tool; the block hash is always the computed `SHA256d(blockHeader)`, never
a self-declared value. The outcome vocabulary and its precedence ladder are shared from the same
module, so a verdict label is derived in one place rather than re-invented per tool. The label is
derived from per-claim signals and changes no accept/reject decision. The single trust anchor is the embedded checkpoint (block 939,999); a
loaded `headers.bin` must anchor to it or it fails closed, and is never silently downgraded to
isolation. Every file is self-contained, so a verdict reproduces across machines - confirm you
are running the reviewed bytes with `shasum -a 256 lib/*.js *.html`.

Where the anchor came from, what can be checked offline, and what only you can confirm are in
`docs/CHECKPOINT-PROVENANCE.md`; `npm test` asserts that all five hardcoded copies of it agree,
which is drift detection and not evidence of authenticity.

The complete normative semantics - byte order, `nBits` decoding, the outcome taxonomy and its
precedence, the evaluation boundary, evidence identity, and the `headers.bin` anchoring
algorithm - are in `VERIFICATION-SEMANTICS-SPEC.md`. Every bundled mainnet vector can be
reproduced independently against block explorers, direct computation, or a node; see
`docs/CROSS-VERIFICATION.md`.

Scope note: `verifier.html` and `chain.html` bind `rawTx` (`txid == SHA256d(rawTx)`);
`explorer.html` deliberately does not, claiming TXID inclusion rather than transaction-byte
inclusion.

## What it does not prove

- **Most-work / canonical chain.** Membership in a checkpoint-anchored chain is not most-work-chain status; cumulative work is computed, not compared.
- **Unspent / current UTXO status.** SPV proves a transaction was mined, not that an output is still unspent.
- **Consensus validity.** No script execution or consensus-rule checking. This is not a consensus validator.
- **Pre-checkpoint transactions.** The chain runs forward from 939,999; earlier blocks are permanently isolation-only.

## Interoperability

Reads and writes BUMP (BRC-74) and BEEF V1 / Atomic-BEEF (BRC-62 / BRC-95), so proofs move both
ways with any wallet that reads BRC-62 V1.

BEEF **V2** (BRC-96) is **not** supported and is rejected fail-closed on the version marker, so
a V2 stream is never partially parsed. This is deliberate rather than a gap: V2 changes the
meaning of each transaction's format byte and adds `02` "txid only" entries, which carry no raw
transaction, no BUMP index and no proof. The specification treats those as implicitly valid and
has children spending their outputs treat the inputs as fully validated — an assumption this
tool will not make, since verifying every transaction from raw bytes and a Merkle proof is the
point of it.

Practical consequence: `@bsv/sdk` serialises **V2 by default** (its `Beef` class defaults to
`BEEF_V2`), so a BEEF produced by it must be written as V1 to be read here. Proofs sent the
other way are fine — the SDK reads both versions.

## Security & testing

`npm test` runs 24 suites - deterministic unit, adversarial, and differential - each as its own
process, including two spec-derived verifiers that reimplement the semantics from the
specification and reproduce the reference with zero divergences, plus an independent Node-crypto
Merkle oracle. Beyond that, the byte-level parsers have been exercised by a deterministic,
seed/replay **500,000-mutation campaign** across BUMP, block headers / PoW, `headers.bin`,
envelopes, and BEEF / Atomic-BEEF, and the shipped `explorer.html`, `verifier.html`, and
`chain.html` verification paths are fuzzed with negative controls that prove the harness can
detect a planted false acceptance. The parser and shipped-path fuzzers found and helped fix real
production defects; findings and rationale are in `docs/AUDIT-FIXES.md`.

**Regression negative controls.** Two suites run a second time against immutable pre-fix
fixtures under `test/fixtures/` holding the exact bytes of the code before a defect was
corrected, and must *detect* that original defect. These are distinct from the fuzzers' planted
false-accept controls: they prove the regression assertions still catch the specific bug they
were written for, rather than having quietly decayed into passing against anything. Each control
pins its fixture's SHA-256, re-checks that the fixture still exhibits the defect, and requires a
minimum number of detections, so a tampered fixture, a replaced fixture, or a weakened assertion
set fails the run rather than reporting a hollow pass. Both are registered in `npm test`.

An earlier generation of these controls read their baseline with `git show HEAD:<file>`. Once
each fix was committed, `HEAD` *was* the fix, so they compared the fix against itself, printed
success-shaped output while detecting nothing, and were not registered in the runner, so nothing
ran them. The fixture approach removes the dependency on Git history, on the identity of `HEAD`,
and on the network.

**Signer key-state cleanup.** `signer.html` runs its key-state cleanup on all relevant exit
paths - success, thrown build, cancellation, and a secondary DOM fault during error rendering -
and removes reachable application references to the decoded key. This is not secure memory
erasure: it is subject to the JavaScript string-retention limitations documented in
`docs/SIDE-CHANNELS.md`, which this project cannot overcome from script. The WIF input is
deliberately retained after a build failure to support retry, with the decoded key cleared.

### Independent implementation agreement

BEEF semantics are independently reproduced by a from-scratch interpreter that shares no BEEF
parsing, transaction, encoding, or cryptographic implementation with the production verifier
(its only dependency is Node's SHA-256). Differential testing across deterministic hostile
inputs and valid multi-ancestor and Atomic-BEEF corpora found no structural or cryptographic
divergence: the two implementations agree on structure, transaction identity, ancestry, BRC-95
subject selection, and independently reconstructed Merkle roots. Bidirectional negative controls
demonstrate that the differential harness detects faults introduced independently into either
implementation. The same method underlies the two spec-derived header verifiers, which
reproduce the reference outcomes with zero divergences. A three-way conformance harness against
a third, external implementation (`@bsv/sdk`) is included; it runs when that SDK is installed in
a dev environment and otherwise reports that dimension as unavailable rather than approximating
it (this repository ships zero-dependency).

This is testing evidence, not a security proof: the project has not had an independent
third-party security audit, and the specification and both spec-derived verifiers share one
author. Confirm the checkpoint on multiple explorers, and commission an audit, before relying on
this for high-value transactions.

## License

MIT. Use at your own risk; this software handles cryptographic keys and financial transactions,
and is not independently security-audited.
